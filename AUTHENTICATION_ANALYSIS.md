# Zerodha Kite MCP Authentication System Analysis & Python Implementation Blueprint

This document provides a comprehensive analysis of the Zerodha Kite MCP authentication system and a detailed technical plan for implementing the same architecture using Python with FastMCP and FastAPI.

## Section 1: Extracted Code and Implementation Analysis

### Authentication Architecture Overview

The Kite MCP system implements a sophisticated multi-layered security architecture that ensures user credentials never directly touch AI systems. The authentication occurs strictly between users and the auth_server's secure servers, with AI assistants receiving only temporary, scoped access tokens.

### Core Authentication Components

#### 1. Session Signing System (`kc/session_signing.go`)

**Purpose**: Provides HMAC-based signing and verification of session parameters to prevent tampering.

```go
type SessionSigner struct {
    secretKey       []byte
    signatureExpiry time.Duration
}

func (s *SessionSigner) SignSessionID(sessionID string) string {
    timestamp := time.Now().Unix()
    payload := fmt.Sprintf("%s|%d", sessionID, timestamp)
    
    // Generate HMAC signature
    h := hmac.New(sha256.New, s.secretKey)
    h.Write([]byte(payload))
    signature := h.Sum(nil)
    
    encodedSig := base64.URLEncoding.EncodeToString(signature)
    return fmt.Sprintf("%s.%s", payload, encodedSig)
}

func (s *SessionSigner) VerifySessionID(signedParam string) (string, error) {
    // Splits payload and signature, verifies HMAC, checks timestamp expiry
    parts := strings.Split(signedParam, ".")
    if len(parts) != 2 {
        return "", ErrInvalidFormat
    }
    
    payload := parts[0]
    providedSig := parts[1]
    
    // Decode and verify signature using constant-time comparison
    decodedSig, err := base64.URLEncoding.DecodeString(providedSig)
    if err != nil {
        return "", ErrInvalidSignature
    }
    
    h := hmac.New(sha256.New, s.secretKey)
    h.Write([]byte(payload))
    expectedSig := h.Sum(nil)
    
    if !hmac.Equal(decodedSig, expectedSig) {
        return "", ErrTamperedSession
    }
    
    // Parse and validate timestamp (30min expiry + 5min clock skew tolerance)
    payloadParts := strings.Split(payload, "|")
    sessionID := payloadParts[0]
    timestamp, _ := strconv.ParseInt(payloadParts[1], 10, 64)
    
    signatureTime := time.Unix(timestamp, 0)
    if time.Now().Sub(signatureTime) > s.signatureExpiry+MaxClockSkew {
        return "", ErrExpiredSignature
    }
    
    return sessionID, nil
}
```

**Security Features**:
- 256-bit random secret key generation
- HMAC-SHA256 signature with constant-time verification
- Timestamp-based expiry (30 minutes default)
- Clock skew tolerance (5 minutes)
- Base64 URL-safe encoding

#### 2. Session Registry (`kc/session.go`)

**Purpose**: Manages MCP sessions with automatic cleanup and expiry handling.

```go
type MCPSession struct {
    ID         string
    Terminated bool
    CreatedAt  time.Time
    ExpiresAt  time.Time
    Data       any // Contains KiteSessionData
}

type SessionRegistry struct {
    sessions        map[string]*MCPSession
    mu              sync.RWMutex
    sessionDuration time.Duration
    cleanupHooks    []CleanupHook
    cleanupContext  context.Context
    cleanupCancel   context.CancelFunc
    logger          *slog.Logger
}

func (sm *SessionRegistry) GenerateWithData(data any) string {
    sm.mu.Lock()
    defer sm.mu.Unlock()
    
    sessionID := "kitemcp-" + uuid.New().String()
    now := time.Now()
    
    sm.sessions[sessionID] = &MCPSession{
        ID:         sessionID,
        Terminated: false,
        CreatedAt:  now,
        ExpiresAt:  now.Add(sm.sessionDuration),
        Data:       data,
    }
    
    return sessionID
}

func (sm *SessionRegistry) GetOrCreateSessionData(sessionID string, creator func() any) (any, bool, error) {
    // Thread-safe get-or-create operation eliminates TOCTOU race conditions
    sm.mu.Lock()
    defer sm.mu.Unlock()
    
    session, exists := sm.sessions[sessionID]
    if !exists || session.Terminated {
        data := creator()
        sm.sessions[sessionID] = &MCPSession{
            ID:         sessionID,
            Terminated: false,
            CreatedAt:  time.Now(),
            ExpiresAt:  time.Now().Add(sm.sessionDuration),
            Data:       data,
        }
        return data, true, nil
    }
    
    return session.Data, false, nil
}
```

**Features**:
- Thread-safe session operations with RWMutex
- Automatic session expiry (12 hours default)
- Cleanup hooks for resource management
- Background cleanup routine (30 minute intervals)
- UUID-based session IDs with prefix

#### 3. Authentication Manager (`kc/manager.go`)

**Purpose**: Central coordinator for authentication flow and session management.

```go
type KiteSessionData struct {
    Kite *KiteConnect
}

type Manager struct {
    apiKey         string
    apiSecret      string
    Logger         *slog.Logger
    templates      map[string]*template.Template
    Instruments    *instruments.Manager
    sessionManager *SessionRegistry
    sessionSigner  *SessionSigner
}

func (m *Manager) SessionLoginURL(mcpSessionID string) (string, error) {
    // Get or create Kite session data
    kiteData, isNew, err := m.GetOrCreateSession(mcpSessionID)
    if err != nil {
        return "", err
    }
    
    // Create signed redirect parameters
    signedParams, err := m.sessionSigner.SignRedirectParams(mcpSessionID)
    if err != nil {
        return "", fmt.Errorf("failed to create secure login URL: %w", err)
    }
    
    redirectParams := url.QueryEscape(signedParams)
    loginURL := kiteData.Kite.Client.GetLoginURL() + "&redirect_params=" + redirectParams
    
    return loginURL, nil
}

func (m *Manager) CompleteSession(mcpSessionID, kiteRequestToken string) error {
    kiteData, err := m.GetSession(mcpSessionID)
    if err != nil {
        return err
    }
    
    // Generate Kite session using OAuth2 request token
    userSess, err := kiteData.Kite.Client.GenerateSession(kiteRequestToken, m.apiSecret)
    if err != nil {
        return fmt.Errorf("failed to generate Kite session: %w", err)
    }
    
    // Set access token for API calls
    kiteData.Kite.Client.SetAccessToken(userSess.AccessToken)
    
    // Compliance logging
    m.Logger.Info("COMPLIANCE: User login completed successfully",
        "event", "user_login_success",
        "user_id", userSess.UserID,
        "session_id", mcpSessionID,
        "timestamp", time.Now().UTC().Format(time.RFC3339),
    )
    
    return nil
}
```

#### 4. OAuth2 Callback Handler

```go
func (m *Manager) HandleKiteCallback() func(w http.ResponseWriter, r *http.Request) {
    return func(w http.ResponseWriter, r *http.Request) {
        // Extract and verify signed parameters
        requestToken, mcpSessionID, err := m.extractCallbackParams(r)
        if err != nil {
            http.Error(w, "missing MCP session_id or Kite request_token", http.StatusBadRequest)
            return
        }
        
        // Complete OAuth2 flow
        if err := m.CompleteSession(mcpSessionID, requestToken); err != nil {
            http.Error(w, "error completing Kite session", http.StatusInternalServerError)
            return
        }
        
        // Render success template
        m.renderSuccessTemplate(w)
    }
}

func (m *Manager) extractCallbackParams(r *http.Request) (string, string, error) {
    qVals := r.URL.Query()
    kiteRequestToken := qVals.Get("request_token")
    signedSessionID := qVals.Get("session_id")
    
    if signedSessionID == "" || kiteRequestToken == "" {
        return "", "", errors.New("missing required parameters")
    }
    
    // Verify signed session ID for security
    mcpSessionID, err := m.sessionSigner.VerifySessionID(signedSessionID)
    if err != nil {
        return "", "", fmt.Errorf("invalid or tampered session parameter: %w", err)
    }
    
    return kiteRequestToken, mcpSessionID, nil
}
```

#### 5. MCP Login Tool (`mcp/setup_tools.go`)

**Purpose**: MCP tool that initiates the authentication flow.

```go
func (*LoginTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
    return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
        // Get MCP session from context
        mcpClientSession := server.ClientSessionFromContext(ctx)
        mcpSessionID := mcpClientSession.SessionID()
        
        // Check for existing valid session
        kiteSession, isNew, err := manager.GetOrCreateSession(mcpSessionID)
        if err != nil {
            return mcp.NewToolResultError("Failed to get or create Kite session"), nil
        }
        
        if !isNew {
            // Verify existing session by profile check
            profile, err := kiteSession.Kite.Client.GetUserProfile()
            if err != nil {
                // Clear invalid session and recreate
                manager.ClearSessionData(mcpSessionID)
                _, _, err = manager.GetOrCreateSession(mcpSessionID)
                if err != nil {
                    return mcp.NewToolResultError("Failed to create new Kite session"), nil
                }
            } else {
                return &mcp.CallToolResult{
                    Content: []mcp.Content{
                        mcp.TextContent{
                            Type: "text",
                            Text: fmt.Sprintf("You are already logged in as %s", profile.UserName),
                        },
                    },
                }, nil
            }
        }
        
        // Generate secure login URL
        url, err := manager.SessionLoginURL(mcpSessionID)
        if err != nil {
            return mcp.NewToolResultError("Failed to generate Kite login URL"), nil
        }
        
        return &mcp.CallToolResult{
            Content: []mcp.Content{
                mcp.TextContent{
                    Type: "text",
                    Text: fmt.Sprintf("⚠️ **WARNING: AI systems are unpredictable. Proceed at your own risk.**\n\nLogin link: [Login to Kite](%s)", url),
                },
            },
        }, nil
    }
}
```

#### 6. Frontend Success Page Template

```html
<!-- kc/templates/login_success.html -->
{{define "content"}}
<div class="card">
    <div class="icon">
        <svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
            <circle cx="12" cy="12" r="12" fill="var(--success)" />
            <path d="M7.5 12.5l3 3l6-6" fill="none" stroke="#fff" stroke-width="2"/>
        </svg>
    </div>
    <h1>Login Successful</h1>
    <div class="status">Authentication Complete</div>
    <p>Your login was successful. You can now return to your MCP client to continue your session.</p>
</div>
{{end}}
```

### Security Architecture Summary

1. **Token Isolation**: AI systems never see user credentials or raw session identifiers
2. **Signed Parameters**: All callback parameters are HMAC-signed to prevent tampering
3. **Time-based Expiry**: Sessions and signatures have built-in expiration
4. **Session Verification**: Active session validation with profile checks
5. **Cleanup Automation**: Automatic cleanup of expired sessions and resources
6. **Compliance Logging**: Detailed audit logs for security compliance

---

## Section 2: Python Implementation Blueprint

### Technology Stack

- **FastMCP**: For MCP server implementation
- **FastAPI**: For HTTP server and OAuth2 endpoints
- **SQLAlchemy**: For session persistence (optional upgrade from in-memory)
- **Pydantic**: For data validation and serialization
- **cryptography**: For HMAC signing and verification
- **Jinja2**: For HTML template rendering
- **httpx**: For async HTTP client operations

### Step-by-Step Implementation Plan

#### Step 1: Project Structure Setup

```
kite-mcp-python/
├── app/
│   ├── __init__.py
│   ├── main.py              # FastAPI application entry point
│   ├── config.py            # Configuration management
│   └── auth/
│       ├── __init__.py
│       ├── session_signer.py    # HMAC signing implementation
│       ├── session_manager.py   # Session registry
│       ├── oauth_manager.py     # OAuth2 flow management
│       └── models.py           # Data models
├── mcp/
│   ├── __init__.py
│   ├── server.py           # FastMCP server implementation
│   ├── tools/
│   │   ├── __init__.py
│   │   └── auth_tools.py   # Login tool implementation
├── templates/
│   ├── base.html
│   └── login_success.html
├── static/
│   └── styles.css
├── requirements.txt
└── README.md
```

#### Step 2: Core Authentication Classes

**File: `app/auth/session_signer.py`**

```python
import hmac
import hashlib
import base64
import time
import secrets
from typing import Optional
from datetime import datetime, timedelta

class SessionSigningError(Exception):
    """Base exception for session signing errors"""
    pass

class InvalidSignatureError(SessionSigningError):
    """Raised when signature verification fails"""
    pass

class ExpiredSignatureError(SessionSigningError):
    """Raised when signature has expired"""
    pass

class TamperedSessionError(SessionSigningError):
    """Raised when session parameters have been tampered with"""
    pass

class SessionSigner:
    """HMAC-based session parameter signing and verification"""
    
    DEFAULT_EXPIRY = timedelta(minutes=30)
    MAX_CLOCK_SKEW = timedelta(minutes=5)
    
    def __init__(self, secret_key: Optional[bytes] = None, signature_expiry: Optional[timedelta] = None):
        self.secret_key = secret_key or secrets.token_bytes(32)  # 256-bit key
        self.signature_expiry = signature_expiry or self.DEFAULT_EXPIRY
    
    def sign_session_id(self, session_id: str) -> str:
        """Create a signed session parameter with timestamp and HMAC signature"""
        timestamp = int(time.time())
        payload = f"{session_id}|{timestamp}"
        
        # Generate HMAC signature
        signature = hmac.new(
            self.secret_key,
            payload.encode(),
            hashlib.sha256
        ).digest()
        
        # Encode signature as base64
        encoded_sig = base64.urlsafe_b64encode(signature).decode()
        
        return f"{payload}.{encoded_sig}"
    
    def verify_session_id(self, signed_param: str) -> str:
        """Verify a signed session parameter and extract the session ID"""
        try:
            # Split payload and signature
            parts = signed_param.split(".")
            if len(parts) != 2:
                raise InvalidSignatureError("Invalid format")
            
            payload, provided_sig = parts
            
            # Decode provided signature
            try:
                decoded_sig = base64.urlsafe_b64decode(provided_sig.encode())
            except Exception:
                raise InvalidSignatureError("Invalid base64 encoding")
            
            # Generate expected signature
            expected_sig = hmac.new(
                self.secret_key,
                payload.encode(),
                hashlib.sha256
            ).digest()
            
            # Verify using constant-time comparison
            if not hmac.compare_digest(decoded_sig, expected_sig):
                raise TamperedSessionError("Session parameter has been tampered with")
            
            # Parse payload
            payload_parts = payload.split("|")
            if len(payload_parts) != 2:
                raise InvalidSignatureError("Invalid payload format")
            
            session_id, timestamp_str = payload_parts
            
            try:
                timestamp = int(timestamp_str)
            except ValueError:
                raise InvalidSignatureError("Invalid timestamp")
            
            # Validate timestamp
            signature_time = datetime.fromtimestamp(timestamp)
            now = datetime.now()
            
            # Check expiry
            if now - signature_time > self.signature_expiry + self.MAX_CLOCK_SKEW:
                raise ExpiredSignatureError("Session signature has expired")
            
            # Check for future timestamps (clock skew)
            if signature_time - now > self.MAX_CLOCK_SKEW:
                raise InvalidSignatureError("Invalid timestamp")
            
            return session_id
            
        except SessionSigningError:
            raise
        except Exception as e:
            raise InvalidSignatureError(f"Verification failed: {e}")
    
    def sign_redirect_params(self, session_id: str) -> str:
        """Create signed redirect parameters for OAuth2 callback"""
        signed_session_id = self.sign_session_id(session_id)
        return f"session_id={signed_session_id}"
```

**File: `app/auth/session_manager.py`**

```python
import asyncio
import time
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Callable, Tuple, List
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)

@dataclass
class MCPSession:
    """Represents an MCP session with associated data"""
    id: str
    terminated: bool
    created_at: datetime
    expires_at: datetime
    data: Any = None

class SessionRegistry:
    """Thread-safe session registry with automatic cleanup"""
    
    DEFAULT_SESSION_DURATION = timedelta(hours=12)
    DEFAULT_CLEANUP_INTERVAL = timedelta(minutes=30)
    MCP_SESSION_PREFIX = "kitemcp-"
    
    def __init__(self, 
                 session_duration: Optional[timedelta] = None,
                 cleanup_interval: Optional[timedelta] = None):
        self.sessions: Dict[str, MCPSession] = {}
        self.session_duration = session_duration or self.DEFAULT_SESSION_DURATION
        self.cleanup_interval = cleanup_interval or self.DEFAULT_CLEANUP_INTERVAL
        self.cleanup_hooks: List[Callable[[MCPSession], None]] = []
        self.cleanup_task: Optional[asyncio.Task] = None
        self._lock = asyncio.Lock()
    
    async def generate_with_data(self, data: Any = None) -> str:
        """Generate a new session ID with associated data"""
        async with self._lock:
            session_id = f"{self.MCP_SESSION_PREFIX}{uuid.uuid4()}"
            now = datetime.now()
            
            session = MCPSession(
                id=session_id,
                terminated=False,
                created_at=now,
                expires_at=now + self.session_duration,
                data=data
            )
            
            self.sessions[session_id] = session
            logger.info(f"Generated new session: {session_id}")
            
            return session_id
    
    async def get_or_create_session_data(self, 
                                       session_id: str, 
                                       creator: Callable[[], Any]) -> Tuple[Any, bool]:
        """Get existing session data or create new session atomically"""
        async with self._lock:
            session = self.sessions.get(session_id)
            
            if not session or session.terminated:
                # Create new session
                data = creator()
                now = datetime.now()
                
                new_session = MCPSession(
                    id=session_id,
                    terminated=False,
                    created_at=now,
                    expires_at=now + self.session_duration,
                    data=data
                )
                
                self.sessions[session_id] = new_session
                logger.info(f"Created new session data: {session_id}")
                return data, True
            
            return session.data, False
    
    async def get_session_data(self, session_id: str) -> Any:
        """Get session data"""
        async with self._lock:
            session = self.sessions.get(session_id)
            if not session or session.terminated:
                raise ValueError("Session not found or terminated")
            
            return session.data
    
    async def validate_session(self, session_id: str) -> bool:
        """Validate if session exists and is not terminated"""
        async with self._lock:
            session = self.sessions.get(session_id)
            return session is not None and not session.terminated
    
    async def terminate_session(self, session_id: str) -> bool:
        """Terminate a session and trigger cleanup hooks"""
        async with self._lock:
            session = self.sessions.get(session_id)
            if not session:
                return False
            
            session.terminated = True
            
            # Execute cleanup hooks
            for hook in self.cleanup_hooks:
                try:
                    hook(session)
                except Exception as e:
                    logger.error(f"Cleanup hook failed for session {session_id}: {e}")
            
            logger.info(f"Terminated session: {session_id}")
            return True
    
    async def update_session_data(self, session_id: str, data: Any) -> bool:
        """Update session data"""
        async with self._lock:
            session = self.sessions.get(session_id)
            if not session or session.terminated:
                return False
            
            session.data = data
            return True
    
    def add_cleanup_hook(self, hook: Callable[[MCPSession], None]):
        """Add a cleanup hook for session termination"""
        self.cleanup_hooks.append(hook)
    
    async def cleanup_expired_sessions(self) -> int:
        """Clean up expired sessions"""
        now = datetime.now()
        expired_sessions = []
        
        async with self._lock:
            for session_id, session in list(self.sessions.items()):
                if now > session.expires_at:
                    expired_sessions.append(session)
                    del self.sessions[session_id]
        
        # Execute cleanup hooks outside of lock
        for session in expired_sessions:
            for hook in self.cleanup_hooks:
                try:
                    hook(session)
                except Exception as e:
                    logger.error(f"Cleanup hook failed for expired session {session.id}: {e}")
        
        if expired_sessions:
            logger.info(f"Cleaned up {len(expired_sessions)} expired sessions")
        
        return len(expired_sessions)
    
    async def start_cleanup_routine(self):
        """Start background cleanup routine"""
        if self.cleanup_task and not self.cleanup_task.done():
            return
        
        async def cleanup_loop():
            while True:
                try:
                    await self.cleanup_expired_sessions()
                    await asyncio.sleep(self.cleanup_interval.total_seconds())
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger.error(f"Cleanup routine error: {e}")
                    await asyncio.sleep(60)  # Retry after 1 minute
        
        self.cleanup_task = asyncio.create_task(cleanup_loop())
        logger.info("Started session cleanup routine")
    
    async def stop_cleanup_routine(self):
        """Stop background cleanup routine"""
        if self.cleanup_task:
            self.cleanup_task.cancel()
            try:
                await self.cleanup_task
            except asyncio.CancelledError:
                pass
            logger.info("Stopped session cleanup routine")
    
    async def get_active_session_count(self) -> int:
        """Get count of active sessions"""
        async with self._lock:
            return len([s for s in self.sessions.values() if not s.terminated])
```

#### Step 3: OAuth2 Manager

**File: `app/auth/oauth_manager.py`**

```python
import httpx
from typing import Dict, Any, Optional
from urllib.parse import urlencode, quote
import logging

logger = logging.getLogger(__name__)

class KiteConnectError(Exception):
    """Kite Connect API error"""
    pass

class KiteOAuth2Manager:
    """Manages OAuth2 flow for Kite Connect API"""
    
    def __init__(self, api_key: str, api_secret: str):
        self.api_key = api_key
        self.api_secret = api_secret
        self.base_url = "https://kite.zerodha.com"
        self.api_base_url = "https://api.kite.trade"
    
    def get_login_url(self, redirect_params: Optional[str] = None) -> str:
        """Generate Kite Connect login URL"""
        login_url = f"{self.base_url}/connect/login?api_key={self.api_key}&v=3"
        
        if redirect_params:
            login_url += f"&redirect_params={quote(redirect_params)}"
        
        return login_url
    
    async def generate_session(self, request_token: str) -> Dict[str, Any]:
        """Generate access token from request token"""
        url = f"{self.api_base_url}/session/token"
        
        data = {
            "api_key": self.api_key,
            "request_token": request_token,
            "checksum": self._generate_checksum(request_token)
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(url, data=data)
            
            if response.status_code != 200:
                raise KiteConnectError(f"Failed to generate session: {response.text}")
            
            result = response.json()
            
            if result.get("status") != "success":
                raise KiteConnectError(f"API error: {result.get('message', 'Unknown error')}")
            
            return result["data"]
    
    async def get_user_profile(self, access_token: str) -> Dict[str, Any]:
        """Get user profile using access token"""
        url = f"{self.api_base_url}/user/profile"
        headers = {"Authorization": f"token {self.api_key}:{access_token}"}
        
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=headers)
            
            if response.status_code != 200:
                raise KiteConnectError(f"Failed to get profile: {response.text}")
            
            result = response.json()
            
            if result.get("status") != "success":
                raise KiteConnectError(f"API error: {result.get('message', 'Unknown error')}")
            
            return result["data"]
    
    async def invalidate_access_token(self, access_token: str) -> bool:
        """Invalidate access token"""
        url = f"{self.api_base_url}/session/token"
        headers = {"Authorization": f"token {self.api_key}:{access_token}"}
        
        async with httpx.AsyncClient() as client:
            response = await client.delete(url, headers=headers)
            return response.status_code == 200
    
    def _generate_checksum(self, request_token: str) -> str:
        """Generate checksum for session generation"""
        import hashlib
        
        checksum_string = f"{self.api_key}{request_token}{self.api_secret}"
        return hashlib.sha256(checksum_string.encode()).hexdigest()
```

#### Step 4: FastAPI Application

**File: `app/main.py`**

```python
from fastapi import FastAPI, Request, HTTPException, Query
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
import logging
from contextlib import asynccontextmanager

from app.auth.session_signer import SessionSigner
from app.auth.session_manager import SessionRegistry
from app.auth.oauth_manager import KiteOAuth2Manager
from app.config import settings

logger = logging.getLogger(__name__)

# Global state
session_registry: SessionRegistry
session_signer: SessionSigner
oauth_manager: KiteOAuth2Manager
templates: Jinja2Templates

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan management"""
    global session_registry, session_signer, oauth_manager, templates
    
    # Initialize components
    session_registry = SessionRegistry()
    session_signer = SessionSigner()
    oauth_manager = KiteOAuth2Manager(settings.KITE_API_KEY, settings.KITE_API_SECRET)
    templates = Jinja2Templates(directory="templates")
    
    # Start cleanup routine
    await session_registry.start_cleanup_routine()
    
    logger.info("FastAPI application started")
    
    yield
    
    # Cleanup
    await session_registry.stop_cleanup_routine()
    logger.info("FastAPI application shutdown")

app = FastAPI(
    title="Kite MCP Server",
    description="MCP server for Kite Connect API",
    version="1.0.0",
    lifespan=lifespan
)

# Static files
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/", response_class=HTMLResponse)
async def status_page(request: Request):
    """Status page"""
    active_sessions = await session_registry.get_active_session_count()
    
    return templates.TemplateResponse("status.html", {
        "request": request,
        "title": "Kite MCP Server",
        "active_sessions": active_sessions,
        "version": "1.0.0"
    })

@app.get("/callback")
async def oauth_callback(
    request_token: str = Query(...),
    session_id: str = Query(...)
):
    """OAuth2 callback handler"""
    try:
        # Verify signed session ID
        mcp_session_id = session_signer.verify_session_id(session_id)
        logger.info(f"Processing callback for session: {mcp_session_id}")
        
        # Generate Kite session
        session_data = await oauth_manager.generate_session(request_token)
        access_token = session_data["access_token"]
        
        # Store access token in session
        session_registry.update_session_data(mcp_session_id, {
            "access_token": access_token,
            "user_id": session_data["user_id"],
            "user_name": session_data["user_name"],
            "user_type": session_data["user_type"]
        })
        
        # Compliance logging
        logger.info(
            "COMPLIANCE: User login completed successfully",
            extra={
                "event": "user_login_success",
                "user_id": session_data["user_id"],
                "session_id": mcp_session_id,
                "user_name": session_data["user_name"],
                "user_type": session_data["user_type"]
            }
        )
        
        return templates.TemplateResponse("login_success.html", {
            "request": request,
            "title": "Login Successful"
        })
        
    except Exception as e:
        logger.error(f"OAuth callback error: {e}")
        raise HTTPException(status_code=400, detail="Authentication failed")

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    active_sessions = await session_registry.get_active_session_count()
    return {
        "status": "healthy",
        "active_sessions": active_sessions
    }
```

#### Step 5: FastMCP Integration

**File: `mcp/server.py`**

```python
from typing import Any, Dict
import logging
from fastmcp import FastMCP, Context
from fastmcp.resources import Resource
from fastmcp.tools import Tool

from app.auth.session_signer import SessionSigner
from app.auth.session_manager import SessionRegistry
from app.auth.oauth_manager import KiteOAuth2Manager

logger = logging.getLogger(__name__)

class KiteMCPServer:
    """MCP server for Kite Connect API"""
    
    def __init__(self, 
                 session_registry: SessionRegistry,
                 session_signer: SessionSigner,
                 oauth_manager: KiteOAuth2Manager):
        self.session_registry = session_registry
        self.session_signer = session_signer
        self.oauth_manager = oauth_manager
        
        # Initialize FastMCP
        self.mcp = FastMCP("Kite MCP Server")
        self._register_tools()
    
    def _register_tools(self):
        """Register MCP tools"""
        
        @self.mcp.tool()
        async def login(ctx: Context) -> str:
            """Login to Kite API and get authorization URL"""
            
            session_id = ctx.session_id
            logger.info(f"Login tool called for session: {session_id}")
            
            # Check for existing valid session
            try:
                existing_data = await self.session_registry.get_session_data(session_id)
                if existing_data and "access_token" in existing_data:
                    # Verify access token by getting profile
                    try:
                        profile = await self.oauth_manager.get_user_profile(
                            existing_data["access_token"]
                        )
                        return f"You are already logged in as {profile['user_name']}"
                    except Exception:
                        # Token invalid, clear session data
                        await self.session_registry.update_session_data(session_id, None)
            except ValueError:
                # Session doesn't exist, will create new one
                pass
            
            # Create new session data
            await self.session_registry.get_or_create_session_data(
                session_id, 
                lambda: {}
            )
            
            # Generate secure login URL
            signed_params = self.session_signer.sign_redirect_params(session_id)
            login_url = self.oauth_manager.get_login_url(signed_params)
            
            return (
                "⚠️ **WARNING: AI systems are unpredictable and non-deterministic. "
                "By continuing, you agree to interact with your Zerodha account via AI at your own risk.**\n\n"
                f"Please click this link to login: [{login_url}]({login_url})\n\n"
                "After completing the login in your browser, let me know and I'll continue with your request."
            )
        
        @self.mcp.tool()
        async def get_profile(ctx: Context) -> Dict[str, Any]:
            """Get user profile information"""
            
            session_data = await self._get_session_data(ctx.session_id)
            access_token = session_data["access_token"]
            
            profile = await self.oauth_manager.get_user_profile(access_token)
            return profile
        
        # Add more tools as needed...
    
    async def _get_session_data(self, session_id: str) -> Dict[str, Any]:
        """Get session data with validation"""
        try:
            data = await self.session_registry.get_session_data(session_id)
            if not data or "access_token" not in data:
                raise ValueError("No valid session found")
            return data
        except ValueError:
            raise Exception("Please log in first using the login tool")
    
    def get_mcp_instance(self) -> FastMCP:
        """Get the FastMCP instance"""
        return self.mcp
```

#### Step 6: Configuration Management

**File: `app/config.py`**

```python
from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    """Application settings"""
    
    # Required Kite Connect API credentials
    KITE_API_KEY: str
    KITE_API_SECRET: str
    
    # Server configuration
    APP_MODE: str = "http"
    APP_HOST: str = "localhost"
    APP_PORT: int = 8080
    
    # Logging
    LOG_LEVEL: str = "INFO"
    
    # Optional tool exclusions
    EXCLUDED_TOOLS: Optional[str] = None
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

settings = Settings()
```

#### Step 7: HTML Templates

**File: `templates/base.html`**

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ title }} - Kite MCP Server</title>
    <style>
        :root {
            --primary: #4285f4;
            --success: #34a853;
            --error: #ea4335;
            --warning: #fbbc05;
            --background: #f8f9fa;
            --surface: #ffffff;
            --text: #202124;
            --border: #dadce0;
        }
        
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: var(--background);
            color: var(--text);
            line-height: 1.6;
        }
        
        .container {
            max-width: 600px;
            margin: 50px auto;
            padding: 20px;
        }
        
        .card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 40px;
            text-align: center;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        
        .icon {
            width: 64px;
            height: 64px;
            margin: 0 auto 20px;
        }
        
        h1 {
            font-size: 24px;
            margin-bottom: 10px;
            color: var(--text);
        }
        
        .status {
            color: var(--success);
            font-weight: 500;
            margin-bottom: 20px;
        }
        
        p {
            color: #5f6368;
            margin-bottom: 15px;
        }
    </style>
</head>
<body>
    <div class="container">
        {% block content %}{% endblock %}
    </div>
</body>
</html>
```

**File: `templates/login_success.html`**

```html
{% extends "base.html" %}

{% block content %}
<div class="card">
    <div class="icon">
        <svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
            <circle cx="12" cy="12" r="12" fill="var(--success)" />
            <path d="M7.5 12.5l3 3l6-6" fill="none" stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />
        </svg>
    </div>
    <h1>Login Successful</h1>
    <div class="status">Authentication Complete</div>
    <p>Your login was successful. You can now return to your MCP client to continue your session. You can close this tab.</p>
</div>
{% endblock %}
```

#### Step 8: Requirements and Deployment

**File: `requirements.txt`**

```txt
fastapi>=0.104.0
fastmcp>=0.1.0
uvicorn[standard]>=0.24.0
httpx>=0.25.0
jinja2>=3.1.0
python-multipart>=0.0.6
pydantic>=2.5.0
pydantic-settings>=2.1.0
cryptography>=41.0.0
```

**File: `main.py` (Entry point)**

```python
import uvicorn
import logging
from app.config import settings

logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper()),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)

if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host=settings.APP_HOST,
        port=settings.APP_PORT,
        reload=True,
        log_level=settings.LOG_LEVEL.lower()
    )
```

### Security Architecture Mapping

| Go Implementation | Python Implementation | Security Benefit |
|------------------|----------------------|------------------|
| `SessionSigner` with HMAC-SHA256 | `SessionSigner` with `hmac` + `hashlib` | Prevents parameter tampering |
| `SessionRegistry` with RWMutex | `SessionRegistry` with `asyncio.Lock` | Thread-safe session operations |
| UUID-based session IDs | `uuid.uuid4()` with prefix | Unpredictable session identifiers |
| Template-based success page | Jinja2 templates | Consistent user experience |
| Background cleanup routine | `asyncio` task for cleanup | Automatic resource management |
| Compliance logging | Structured logging with `extra` | Audit trail for security |
| Time-based signature expiry | `datetime` + `timedelta` validation | Prevents replay attacks |
| Constant-time comparison | `hmac.compare_digest()` | Prevents timing attacks |

### Deployment Instructions

1. **Environment Setup**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux/Mac
   # or venv\Scripts\activate  # Windows
   pip install -r requirements.txt
   ```

2. **Configuration**:
   ```bash
   cp .env.example .env
   # Edit .env with your Kite Connect API credentials
   ```

3. **Development Server**:
   ```bash
   python main.py
   ```

4. **Production Deployment**:
   ```bash
   uvicorn app.main:app --host 0.0.0.0 --port 8080 --workers 4
   ```

5. **MCP Client Configuration**:
   ```json
   {
     "mcpServers": {
       "kite": {
         "command": "npx",
         "args": ["mcp-remote", "http://localhost:8080/mcp", "--allow-http"]
       }
     }
   }
   ```

### Advanced Features for Production

1. **Database Persistence**:
   - Replace in-memory session storage with SQLAlchemy + PostgreSQL
   - Add session migration and recovery capabilities

2. **Enhanced Security**:
   - Add rate limiting with `slowapi`
   - Implement CSRF protection
   - Add request ID correlation for audit logs

3. **Monitoring & Observability**:
   - Integrate with Prometheus for metrics
   - Add structured logging with correlation IDs
   - Health checks and readiness probes

4. **High Availability**:
   - Redis-based session sharing for multi-instance deployment
   - Load balancer configuration
   - Graceful shutdown handling

This implementation provides the same security architecture as the Go version while leveraging Python's async capabilities and modern web frameworks. The multi-layered security approach ensures user credentials remain isolated from AI systems while maintaining a smooth authentication experience.