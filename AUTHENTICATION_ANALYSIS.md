# MCP Authentication Analysis: Kite MCP Server

## Executive Summary

This document provides a comprehensive analysis of the authentication implementation in the Kite MCP Server, a sophisticated Model Context Protocol (MCP) server that provides AI assistants with secure access to the Kite Connect trading API. The analysis covers architectural patterns, security implementations, and provides a detailed re-implementation plan using Python, FastMCP, and FastAPI.

## 1. Architecture Overview

### 1.1 Key Components and Modules

The Kite MCP Server implements a multi-layered authentication architecture with the following core components:

#### Core Modules:
1. **App Layer** (`app/app.go`) - Main application orchestration and server mode management
2. **Kite Connect Manager** (`kc/manager.go`) - Central authentication and session management
3. **Session Registry** (`kc/session.go`) - MCP session lifecycle management
4. **Session Signing** (`kc/session_signing.go`) - HMAC-based security for callback URLs
5. **MCP Tools** (`mcp/`) - Tool registration and authentication handlers
6. **Common Handlers** (`mcp/common.go`) - Shared authentication logic

#### Supporting Components:
- **Metrics Manager** (`app/metrics/`) - Authentication event tracking
- **Instruments Manager** (`kc/instruments/`) - Trading instrument data management
- **Templates** (`kc/templates/`) - HTML templates for authentication flows

### 1.2 Authentication Flow Architecture

The authentication system follows an OAuth 2.0-like authorization code flow:

```
1. MCP Client → login tool → MCP Server
2. MCP Server → generates signed login URL → User Browser
3. User Browser → Kite Platform (authorization)
4. Kite Platform → callback with request_token → MCP Server
5. MCP Server → validates signature + completes session → Access Token
6. Subsequent API calls use established session
```

### 1.3 Third-Party Libraries and Protocols

- **MCP Protocol**: `github.com/mark3labs/mcp-go` - Model Context Protocol implementation
- **Kite Connect API**: `github.com/zerodha/gokiteconnect/v4` - Official Kite Connect Go SDK
- **Session Management**: Built-in Go `crypto/hmac` and `crypto/rand` for security
- **UUID Generation**: `github.com/google/uuid` for session ID generation

### 1.4 Server Mode Support

The server supports multiple deployment modes:
- **stdio**: Direct standard I/O communication
- **http**: Streamable HTTP for MCP endpoints
- **sse**: Server-Sent Events mode
- **hybrid**: Combined SSE and MCP endpoints

## 2. Detailed Code Walkthrough

### 2.1 Authentication Manager (`kc/manager.go`)

**Purpose**: Central orchestrator for Kite Connect authentication and session management.

**Key Code Snippets**:

```go
// Manager structure - core authentication component
type Manager struct {
    apiKey    string
    apiSecret string
    Logger    *slog.Logger
    metrics   *metrics.Manager
    
    templates      map[string]*template.Template
    Instruments    *instruments.Manager
    sessionManager *SessionRegistry
    sessionSigner  *SessionSigner
}

// GetOrCreateSession - atomic session management to prevent TOCTOU races
func (m *Manager) GetOrCreateSession(mcpSessionID string) (*KiteSessionData, bool, error) {
    if err := m.validateSessionID(mcpSessionID); err != nil {
        return nil, false, err
    }

    // Atomic operation eliminates race conditions
    data, isNew, err := m.sessionManager.GetOrCreateSessionData(mcpSessionID, func() any {
        return m.createKiteSessionData(mcpSessionID)
    })
    // ... error handling and type assertion
}
```

**Security Features**:
- HMAC session signing for callback protection
- Session validation with expiry enforcement
- Atomic session operations to prevent race conditions

### 2.2 Session Registry (`kc/session.go`)

**Purpose**: Manages MCP session lifecycle, expiration, and cleanup.

**Key Code Snippets**:

```go
// MCPSession structure
type MCPSession struct {
    ID         string
    Terminated bool
    CreatedAt  time.Time
    ExpiresAt  time.Time
    Data       any // Contains KiteSessionData
}

// Session validation with format checking
func checkSessionID(sessionID string) error {
    // Handles both internal format (kitemcp-<uuid>) and external format (plain uuid)
    if strings.HasPrefix(sessionID, mcpSessionPrefix) {
        if _, err := uuid.Parse(sessionID[len(mcpSessionPrefix):]); err != nil {
            return fmt.Errorf("%s: %w", errInvalidSessionIDFormat, err)
        }
        return nil
    }
    // Handle external format (plain UUID from SSE/stdio modes)
    if _, err := uuid.Parse(sessionID); err != nil {
        return fmt.Errorf("%s: %w", errInvalidSessionIDFormat, err)
    }
    return nil
}
```

**Session Management Features**:
- 12-hour default session duration
- Automatic cleanup with configurable intervals (30 minutes)
- Thread-safe operations with RWMutex
- Cleanup hooks for resource deallocation

### 2.3 Session Signing (`kc/session_signing.go`)

**Purpose**: HMAC-based security for preventing CSRF and tampering attacks.

**Key Code Snippets**:

```go
// SessionSigner - HMAC-based security
type SessionSigner struct {
    secretKey       []byte
    signatureExpiry time.Duration
}

// SignSessionID creates tamper-proof session parameters
func (s *SessionSigner) SignSessionID(sessionID string) string {
    timestamp := time.Now().Unix()
    payload := fmt.Sprintf("%s|%d", sessionID, timestamp)
    
    // HMAC-SHA256 signature
    h := hmac.New(sha256.New, s.secretKey)
    h.Write([]byte(payload))
    signature := h.Sum(nil)
    
    encodedSig := base64.URLEncoding.EncodeToString(signature)
    return fmt.Sprintf("%s.%s", payload, encodedSig)
}

// VerifySessionID verifies signature and prevents replay attacks
func (s *SessionSigner) VerifySessionID(signedParam string) (string, error) {
    // Parse and validate signature format
    parts := strings.Split(signedParam, ".")
    if len(parts) != 2 {
        return "", ErrInvalidFormat
    }
    
    // Constant-time signature comparison
    if !hmac.Equal(decodedSig, expectedSig) {
        return "", ErrTamperedSession
    }
    
    // Time-based replay protection
    if now.Sub(signatureTime) > s.signatureExpiry+MaxClockSkew {
        return "", ErrExpiredSignature
    }
    
    return sessionID, nil
}
```

**Security Features**:
- SHA-256 HMAC signatures
- Timestamp-based replay protection
- Clock skew tolerance (5 minutes)
- Constant-time comparison to prevent timing attacks

### 2.4 Login Tool (`mcp/setup_tools.go`)

**Purpose**: MCP tool interface for initiating authentication flow.

**Key Code Snippets**:

```go
func (*LoginTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
    return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
        handler := NewToolHandler(manager)
        handler.trackToolCall(ctx, "login")
        
        mcpClientSession := server.ClientSessionFromContext(ctx)
        mcpSessionID := mcpClientSession.SessionID()
        
        // Get or create Kite session atomically
        kiteSession, isNew, err := manager.GetOrCreateSession(mcpSessionID)
        if err != nil {
            handler.trackToolError(ctx, "login", "session_error")
            return mcp.NewToolResultError("Failed to get or create Kite session"), nil
        }
        
        if !isNew {
            // Verify existing session with profile check
            profile, err := kiteSession.Kite.Client.GetUserProfile()
            if err != nil {
                // Clear invalid session and recreate
                if clearErr := manager.ClearSessionData(mcpSessionID); clearErr != nil {
                    return mcp.NewToolResultError("Failed to clear session data"), nil
                }
                // ... recreate session
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
                    Text: fmt.Sprintf("IMPORTANT: Please display this warning to the user before proceeding:\n\n⚠️ **WARNING: AI systems are unpredictable and non-deterministic. By continuing, you agree to interact with your Zerodha account via AI at your own risk.**\n\nAfter showing the warning above, provide the user with this login link: [Login to Kite](%s)", url),
                },
            },
        }, nil
    }
}
```

### 2.5 Common Handler (`mcp/common.go`)

**Purpose**: Shared authentication logic and session validation for all MCP tools.

**Key Code Snippets**:

```go
// WithSession eliminates TOCTOU race conditions
func (h *ToolHandler) WithSession(ctx context.Context, toolName string, fn func(*kc.KiteSessionData) (*mcp.CallToolResult, error)) (*mcp.CallToolResult, error) {
    sess := server.ClientSessionFromContext(ctx)
    sessionID := sess.SessionID()
    
    // Atomic session retrieval/creation
    kiteSession, isNew, err := h.manager.GetOrCreateSession(sessionID)
    if err != nil {
        h.trackToolError(ctx, toolName, "session_error")
        return mcp.NewToolResultError("Failed to establish a session. Please try again."), nil
    }
    
    if isNew {
        h.trackToolError(ctx, toolName, "auth_required")
        return mcp.NewToolResultError("Please log in first using the login tool"), nil
    }
    
    return fn(kiteSession)
}
```

### 2.6 Configuration and Environment Management

**Environment Variables**:
- `KITE_API_KEY`: Required API key from Kite Connect
- `KITE_API_SECRET`: Required API secret
- `APP_MODE`: Server mode (stdio/http/sse/hybrid)
- `APP_PORT`: Server port for HTTP modes
- `APP_HOST`: Server host binding
- `EXCLUDED_TOOLS`: Comma-separated list of tools to exclude

**Configuration Validation**:
```go
func (app *App) LoadConfig() error {
    if app.Config.KiteAPIKey == "" || app.Config.KiteAPISecret == "" {
        return fmt.Errorf("KITE_API_KEY or KITE_API_SECRET is missing")
    }
    // Set defaults for optional configs
    if app.Config.AppMode == "" {
        app.Config.AppMode = DefaultAppMode
    }
    // ... other validations
    return nil
}
```

## 3. Security Considerations

### 3.1 Secure Credential Storage and Transmission

**Strengths**:
1. **Environment-based Configuration**: API credentials stored in environment variables, not hardcoded
2. **HMAC Signing**: All callback URLs signed with HMAC-SHA256 to prevent tampering
3. **Session Isolation**: Each MCP session has isolated Kite Connect client instances
4. **Token Security**: Access tokens stored in memory only, cleared on session termination

**Code Evidence**:
```go
// Secure token invalidation on cleanup
func (m *Manager) kiteSessionCleanupHook(session *MCPSession) {
    if kiteData, ok := session.Data.(*KiteSessionData); ok && kiteData != nil && kiteData.Kite != nil {
        m.Logger.Info("Cleaning up Kite session for MCP session ID", "session_id", session.ID)
        _, _ = kiteData.Kite.Client.InvalidateAccessToken()
    }
}
```

### 3.2 Session Security

**Security Measures**:
1. **Time-limited Sessions**: 12-hour default expiry with automatic cleanup
2. **Session Validation**: Format validation using UUID standards
3. **Atomic Operations**: Prevent race conditions in session management
4. **Replay Protection**: Timestamp-based signature validation

**Potential Vulnerabilities and Mitigations**:

| Vulnerability | Current Mitigation | Recommendation |
|---------------|-------------------|----------------|
| Session Fixation | UUID-based random session IDs | ✅ Adequate |
| CSRF Attacks | HMAC-signed callback URLs | ✅ Strong protection |
| Session Hijacking | Memory-only storage, automatic cleanup | ⚠️ Consider adding IP validation |
| Replay Attacks | Timestamp + clock skew tolerance | ✅ Well implemented |
| Brute Force | No explicit rate limiting | ⚠️ Consider adding rate limiting |

### 3.3 Authentication Flow Security

**Security Analysis**:
1. **Authorization Code Flow**: Follows OAuth 2.0 patterns securely
2. **State Parameter**: Uses signed session IDs as state parameter
3. **Callback Validation**: Verifies signatures before processing
4. **Error Handling**: Secure error messages without information leakage

## 4. Step-by-Step Re-Implementation Plan in Python (FastMCP + FastAPI)

### 4.1 Project Setup and Structure

**Step 1: Initialize Python Project**

```bash
# Create project structure
mkdir kite-mcp-python
cd kite-mcp-python

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Initialize project structure
mkdir -p {src/{auth,session,tools,models},tests,docs,config}
touch src/__init__.py src/auth/__init__.py src/session/__init__.py src/tools/__init__.py src/models/__init__.py
```

**Step 2: Dependencies Installation**

```bash
# Core dependencies
pip install fastapi fastmcp uvicorn pydantic
pip install python-jose[cryptography]  # JWT/HMAC support
pip install aiofiles python-multipart
pip install httpx aiohttp  # HTTP clients
pip install python-dotenv  # Environment management
pip install structlog  # Structured logging

# Development dependencies
pip install pytest pytest-asyncio black isort mypy
pip install pytest-cov pre-commit

# Create requirements.txt
pip freeze > requirements.txt
```

**Step 3: Environment Configuration**

```python
# config/settings.py
from pydantic import BaseSettings, Field
from typing import Optional, List
from enum import Enum

class ServerMode(str, Enum):
    STDIO = "stdio"
    HTTP = "http"
    SSE = "sse"
    HYBRID = "hybrid"

class Settings(BaseSettings):
    # Kite API Configuration
    kite_api_key: str = Field(..., env="KITE_API_KEY", description="Kite Connect API Key")
    kite_api_secret: str = Field(..., env="KITE_API_SECRET", description="Kite Connect API Secret")
    
    # Server Configuration
    app_mode: ServerMode = Field(ServerMode.HTTP, env="APP_MODE")
    app_host: str = Field("localhost", env="APP_HOST")
    app_port: int = Field(8080, env="APP_PORT")
    
    # Session Configuration
    session_duration_hours: int = Field(12, env="SESSION_DURATION_HOURS")
    cleanup_interval_minutes: int = Field(30, env="CLEANUP_INTERVAL_MINUTES")
    signature_expiry_minutes: int = Field(30, env="SIGNATURE_EXPIRY_MINUTES")
    
    # Security Configuration
    hmac_secret_key: Optional[str] = Field(None, env="HMAC_SECRET_KEY")
    max_clock_skew_minutes: int = Field(5, env="MAX_CLOCK_SKEW_MINUTES")
    
    # Tool Configuration
    excluded_tools: List[str] = Field([], env="EXCLUDED_TOOLS")
    
    # Logging Configuration
    log_level: str = Field("INFO", env="LOG_LEVEL")
    
    class Config:
        env_file = ".env"
        case_sensitive = False

# Global settings instance
settings = Settings()
```

### 4.2 Session Management Implementation

**Step 4: Session Models**

```python
# src/models/session.py
from pydantic import BaseModel, Field
from typing import Optional, Any, Dict
from datetime import datetime, timezone
from enum import Enum
import uuid

class SessionStatus(str, Enum):
    ACTIVE = "active"
    EXPIRED = "expired"
    TERMINATED = "terminated"

class MCPSession(BaseModel):
    id: str = Field(default_factory=lambda: f"kitemcp-{uuid.uuid4()}")
    status: SessionStatus = SessionStatus.ACTIVE
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime
    data: Optional[Dict[str, Any]] = None
    
    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) > self.expires_at
    
    def is_active(self) -> bool:
        return self.status == SessionStatus.ACTIVE and not self.is_expired()

class KiteSessionData(BaseModel):
    access_token: Optional[str] = None
    user_id: Optional[str] = None
    user_name: Optional[str] = None
    user_type: Optional[str] = None
    authenticated: bool = False
    last_verified: Optional[datetime] = None
```

**Step 5: HMAC Session Signing**

```python
# src/auth/session_signer.py
import hmac
import hashlib
import base64
import time
import secrets
from datetime import datetime, timezone, timedelta
from typing import Tuple, Optional
from dataclasses import dataclass

@dataclass
class SignatureConfig:
    secret_key: bytes
    expiry_minutes: int = 30
    max_clock_skew_minutes: int = 5

class SessionSignerError(Exception):
    pass

class InvalidSignatureError(SessionSignerError):
    pass

class ExpiredSignatureError(SessionSignerError):
    pass

class TamperedSessionError(SessionSignerError):
    pass

class SessionSigner:
    """HMAC-based session parameter signing for security"""
    
    def __init__(self, config: SignatureConfig):
        self.config = config
    
    @classmethod
    def generate_secret_key(cls) -> bytes:
        """Generate a cryptographically secure 256-bit key"""
        return secrets.token_bytes(32)
    
    def sign_session_id(self, session_id: str) -> str:
        """Create a signed session parameter with timestamp and HMAC signature"""
        timestamp = int(time.time())
        payload = f"{session_id}|{timestamp}"
        
        # Generate HMAC-SHA256 signature
        signature = hmac.new(
            self.config.secret_key,
            payload.encode('utf-8'),
            hashlib.sha256
        ).digest()
        
        # Base64 encode signature
        encoded_sig = base64.urlsafe_b64encode(signature).decode('ascii')
        
        # Return format: payload.signature
        return f"{payload}.{encoded_sig}"
    
    def verify_session_id(self, signed_param: str) -> str:
        """Verify signed session parameter and extract session ID"""
        try:
            # Split payload and signature
            parts = signed_param.split('.')
            if len(parts) != 2:
                raise InvalidSignatureError("Invalid signature format")
            
            payload, provided_sig = parts
            
            # Decode provided signature
            try:
                decoded_sig = base64.urlsafe_b64decode(provided_sig.encode('ascii'))
            except Exception:
                raise InvalidSignatureError("Invalid base64 encoding")
            
            # Generate expected signature
            expected_sig = hmac.new(
                self.config.secret_key,
                payload.encode('utf-8'),
                hashlib.sha256
            ).digest()
            
            # Constant-time comparison
            if not hmac.compare_digest(decoded_sig, expected_sig):
                raise TamperedSessionError("Session parameter has been tampered with")
            
            # Parse payload
            payload_parts = payload.split('|')
            if len(payload_parts) != 2:
                raise InvalidSignatureError("Invalid payload format")
            
            session_id, timestamp_str = payload_parts
            
            # Validate timestamp
            try:
                timestamp = int(timestamp_str)
            except ValueError:
                raise InvalidSignatureError("Invalid timestamp")
            
            # Check expiry and clock skew
            signature_time = datetime.fromtimestamp(timestamp, tz=timezone.utc)
            now = datetime.now(timezone.utc)
            
            expiry_delta = timedelta(minutes=self.config.expiry_minutes)
            clock_skew_delta = timedelta(minutes=self.config.max_clock_skew_minutes)
            
            # Check if expired
            if now - signature_time > expiry_delta + clock_skew_delta:
                raise ExpiredSignatureError("Session signature has expired")
            
            # Check for future timestamps (clock skew protection)
            if signature_time - now > clock_skew_delta:
                raise InvalidSignatureError("Invalid timestamp (future)")
            
            return session_id
            
        except SessionSignerError:
            raise
        except Exception as e:
            raise InvalidSignatureError(f"Signature verification failed: {str(e)}")
    
    def sign_redirect_params(self, session_id: str) -> str:
        """Create signed redirect parameters for Kite authentication"""
        signed_session_id = self.sign_session_id(session_id)
        return f"session_id={signed_session_id}"
```

**Step 6: Session Registry Implementation**

```python
# src/session/registry.py
import asyncio
import structlog
from typing import Dict, Optional, Callable, Any, Tuple, List
from datetime import datetime, timezone, timedelta
from contextlib import asynccontextmanager
from uuid import uuid4
import re

from ..models.session import MCPSession, SessionStatus, KiteSessionData
from ..auth.session_signer import SessionSigner

logger = structlog.get_logger()

class SessionRegistry:
    """Thread-safe session registry with automatic cleanup"""
    
    def __init__(
        self, 
        session_duration_hours: int = 12,
        cleanup_interval_minutes: int = 30,
        session_signer: Optional[SessionSigner] = None
    ):
        self.session_duration_hours = session_duration_hours
        self.cleanup_interval_minutes = cleanup_interval_minutes
        self.session_signer = session_signer
        
        # Thread-safe session storage
        self._sessions: Dict[str, MCPSession] = {}
        self._lock = asyncio.Lock()
        
        # Cleanup hooks
        self._cleanup_hooks: List[Callable[[MCPSession], None]] = []
        
        # Background cleanup task
        self._cleanup_task: Optional[asyncio.Task] = None
        self._shutdown_event = asyncio.Event()
    
    async def start_cleanup_routine(self):
        """Start background cleanup routine"""
        if self._cleanup_task is None:
            self._cleanup_task = asyncio.create_task(self._cleanup_routine())
            logger.info("Session cleanup routine started", 
                       interval_minutes=self.cleanup_interval_minutes)
    
    async def stop_cleanup_routine(self):
        """Stop background cleanup routine"""
        if self._cleanup_task:
            self._shutdown_event.set()
            await self._cleanup_task
            self._cleanup_task = None
            logger.info("Session cleanup routine stopped")
    
    def add_cleanup_hook(self, hook: Callable[[MCPSession], None]):
        """Add cleanup hook for session termination"""
        self._cleanup_hooks.append(hook)
    
    @staticmethod
    def validate_session_id(session_id: str) -> bool:
        """Validate session ID format (UUID with optional prefix)"""
        if session_id.startswith("kitemcp-"):
            uuid_part = session_id[8:]
        else:
            uuid_part = session_id
        
        # Validate UUID format
        uuid_pattern = re.compile(
            r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', 
            re.IGNORECASE
        )
        return bool(uuid_pattern.match(uuid_part))
    
    async def create_session(
        self, 
        session_id: Optional[str] = None,
        data: Optional[Dict[str, Any]] = None
    ) -> MCPSession:
        """Create new session with optional data"""
        if session_id is None:
            session_id = f"kitemcp-{uuid4()}"
        
        expires_at = datetime.now(timezone.utc) + timedelta(hours=self.session_duration_hours)
        
        session = MCPSession(
            id=session_id,
            expires_at=expires_at,
            data=data or {}
        )
        
        async with self._lock:
            self._sessions[session_id] = session
        
        logger.info("Session created", session_id=session_id, expires_at=expires_at)
        return session
    
    async def get_session(self, session_id: str) -> Optional[MCPSession]:
        """Get session by ID"""
        if not self.validate_session_id(session_id):
            return None
        
        async with self._lock:
            session = self._sessions.get(session_id)
            
            if session and session.is_expired():
                # Auto-expire session
                session.status = SessionStatus.EXPIRED
                return None
            
            return session
    
    async def get_or_create_session(
        self, 
        session_id: str, 
        data_factory: Optional[Callable[[], Dict[str, Any]]] = None
    ) -> Tuple[MCPSession, bool]:
        """Atomically get existing session or create new one"""
        if not self.validate_session_id(session_id):
            raise ValueError(f"Invalid session ID format: {session_id}")
        
        async with self._lock:
            session = self._sessions.get(session_id)
            
            # Check if session exists and is valid
            if session and session.is_active():
                return session, False
            
            # Create new session
            expires_at = datetime.now(timezone.utc) + timedelta(hours=self.session_duration_hours)
            
            new_session = MCPSession(
                id=session_id,
                expires_at=expires_at,
                data=data_factory() if data_factory else {}
            )
            
            self._sessions[session_id] = new_session
            logger.info("New session created", session_id=session_id, expires_at=expires_at)
            
            return new_session, True
    
    async def update_session_data(self, session_id: str, data: Dict[str, Any]) -> bool:
        """Update session data"""
        async with self._lock:
            session = self._sessions.get(session_id)
            if session and session.is_active():
                session.data = data
                return True
            return False
    
    async def terminate_session(self, session_id: str) -> bool:
        """Terminate session and run cleanup hooks"""
        async with self._lock:
            session = self._sessions.get(session_id)
            if session:
                session.status = SessionStatus.TERMINATED
                
                # Run cleanup hooks
                for hook in self._cleanup_hooks:
                    try:
                        hook(session)
                    except Exception as e:
                        logger.error("Cleanup hook failed", session_id=session_id, error=str(e))
                
                logger.info("Session terminated", session_id=session_id)
                return True
            return False
    
    async def cleanup_expired_sessions(self) -> int:
        """Clean up expired sessions"""
        cleaned = 0
        now = datetime.now(timezone.utc)
        
        async with self._lock:
            expired_sessions = []
            
            for session_id, session in self._sessions.items():
                if now > session.expires_at or session.status != SessionStatus.ACTIVE:
                    expired_sessions.append(session_id)
            
            for session_id in expired_sessions:
                session = self._sessions[session_id]
                if session.status == SessionStatus.ACTIVE:
                    session.status = SessionStatus.EXPIRED
                    
                    # Run cleanup hooks
                    for hook in self._cleanup_hooks:
                        try:
                            hook(session)
                        except Exception as e:
                            logger.error("Cleanup hook failed", session_id=session_id, error=str(e))
                
                del self._sessions[session_id]
                cleaned += 1
        
        if cleaned > 0:
            logger.info("Cleaned up expired sessions", count=cleaned)
        
        return cleaned
    
    async def list_active_sessions(self) -> List[MCPSession]:
        """List all active sessions"""
        async with self._lock:
            return [
                session for session in self._sessions.values()
                if session.is_active()
            ]
    
    async def _cleanup_routine(self):
        """Background cleanup routine"""
        interval = timedelta(minutes=self.cleanup_interval_minutes)
        
        while not self._shutdown_event.is_set():
            try:
                await self.cleanup_expired_sessions()
                await asyncio.wait_for(
                    self._shutdown_event.wait(), 
                    timeout=interval.total_seconds()
                )
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error("Cleanup routine error", error=str(e))
                await asyncio.sleep(60)  # Wait 1 minute before retry
```

**Step 7: Kite Connect Manager**

```python
# src/auth/kite_manager.py
import httpx
import structlog
from typing import Optional, Dict, Any, Tuple
from datetime import datetime, timezone
import asyncio
from urllib.parse import urlencode

from ..models.session import KiteSessionData
from ..session.registry import SessionRegistry
from ..auth.session_signer import SessionSigner
from ..config.settings import settings

logger = structlog.get_logger()

class KiteConnectError(Exception):
    pass

class AuthenticationError(KiteConnectError):
    pass

class KiteManager:
    """Central manager for Kite Connect authentication and API access"""
    
    def __init__(
        self,
        api_key: str,
        api_secret: str,
        session_registry: SessionRegistry,
        session_signer: SessionSigner,
        base_url: str = "https://api.kite.trade"
    ):
        self.api_key = api_key
        self.api_secret = api_secret
        self.session_registry = session_registry
        self.session_signer = session_signer
        self.base_url = base_url
        
        # HTTP client configuration
        self.http_client = httpx.AsyncClient(
            timeout=30.0,
            headers={"User-Agent": "Kite-MCP-Python/1.0"}
        )
        
        # Register cleanup hook for Kite sessions
        self.session_registry.add_cleanup_hook(self._kite_session_cleanup_hook)
    
    async def shutdown(self):
        """Cleanup resources"""
        await self.http_client.aclose()
        await self.session_registry.stop_cleanup_routine()
    
    def _kite_session_cleanup_hook(self, session):
        """Cleanup hook for invalidating Kite access tokens"""
        if session.data and session.data.get('kite_data', {}).get('access_token'):
            access_token = session.data['kite_data']['access_token']
            logger.info("Cleaning up Kite session", session_id=session.id)
            
            # Note: In real implementation, you'd call Kite's logout API
            # asyncio.create_task(self._invalidate_access_token(access_token))
    
    async def generate_login_url(self, mcp_session_id: str) -> str:
        """Generate secure login URL with signed session parameters"""
        # Create or get session
        session, is_new = await self.session_registry.get_or_create_session(
            mcp_session_id,
            lambda: {"kite_data": KiteSessionData().dict()}
        )
        
        if is_new:
            logger.info("Created new session for login", session_id=mcp_session_id)
        
        # Generate signed redirect parameters
        signed_params = self.session_signer.sign_redirect_params(mcp_session_id)
        
        # Build Kite login URL
        login_url = (
            f"https://kite.trade/connect/login"
            f"?api_key={self.api_key}"
            f"&redirect_params={urlencode({'redirect_params': signed_params})}"
        )
        
        logger.info("Generated login URL", session_id=mcp_session_id)
        return login_url
    
    async def complete_authentication(
        self, 
        signed_session_id: str, 
        request_token: str
    ) -> KiteSessionData:
        """Complete authentication flow with request token"""
        try:
            # Verify signed session ID
            mcp_session_id = self.session_signer.verify_session_id(signed_session_id)
            
            # Get session
            session = await self.session_registry.get_session(mcp_session_id)
            if not session:
                raise AuthenticationError("Session not found or expired")
            
            # Generate access token
            access_token = await self._generate_access_token(request_token)
            
            # Get user profile
            user_profile = await self._get_user_profile(access_token)
            
            # Update session data
            kite_data = KiteSessionData(
                access_token=access_token,
                user_id=user_profile.get('user_id'),
                user_name=user_profile.get('user_name'),
                user_type=user_profile.get('user_type'),
                authenticated=True,
                last_verified=datetime.now(timezone.utc)
            )
            
            await self.session_registry.update_session_data(
                mcp_session_id,
                {"kite_data": kite_data.dict()}
            )
            
            logger.info(
                "Authentication completed",
                session_id=mcp_session_id,
                user_id=user_profile.get('user_id'),
                user_name=user_profile.get('user_name')
            )
            
            return kite_data
            
        except Exception as e:
            logger.error("Authentication failed", error=str(e))
            raise AuthenticationError(f"Authentication failed: {str(e)}")
    
    async def get_authenticated_session(self, mcp_session_id: str) -> Optional[KiteSessionData]:
        """Get authenticated Kite session data"""
        session = await self.session_registry.get_session(mcp_session_id)
        if not session or not session.data:
            return None
        
        kite_data_dict = session.data.get('kite_data', {})
        if not kite_data_dict or not kite_data_dict.get('authenticated'):
            return None
        
        return KiteSessionData(**kite_data_dict)
    
    async def _generate_access_token(self, request_token: str) -> str:
        """Generate access token from request token"""
        import hashlib
        
        # Create checksum
        checksum = hashlib.sha256(
            f"{self.api_key}{request_token}{self.api_secret}".encode()
        ).hexdigest()
        
        # Make API request
        response = await self.http_client.post(
            f"{self.base_url}/session/token",
            data={
                "api_key": self.api_key,
                "request_token": request_token,
                "checksum": checksum
            }
        )
        
        if response.status_code != 200:
            raise AuthenticationError(f"Token generation failed: {response.text}")
        
        data = response.json()
        if data.get('status') != 'success':
            raise AuthenticationError(f"Token generation failed: {data.get('message')}")
        
        return data['data']['access_token']
    
    async def _get_user_profile(self, access_token: str) -> Dict[str, Any]:
        """Get user profile from Kite API"""
        response = await self.http_client.get(
            f"{self.base_url}/user/profile",
            headers={"Authorization": f"token {self.api_key}:{access_token}"}
        )
        
        if response.status_code != 200:
            raise AuthenticationError(f"Profile fetch failed: {response.text}")
        
        data = response.json()
        if data.get('status') != 'success':
            raise AuthenticationError(f"Profile fetch failed: {data.get('message')}")
        
        return data['data']
```

### 4.3 FastMCP Integration

**Step 8: MCP Tool Implementation**

```python
# src/tools/login_tool.py
from fastmcp import FastMCP
from pydantic import BaseModel
import structlog

from ..auth.kite_manager import KiteManager
from ..models.session import KiteSessionData

logger = structlog.get_logger()

class LoginTool:
    """MCP tool for Kite authentication"""
    
    def __init__(self, kite_manager: KiteManager):
        self.kite_manager = kite_manager
    
    def register_with_mcp(self, app: FastMCP):
        """Register login tool with FastMCP"""
        
        @app.tool()
        async def login(session_id: str) -> str:
            """
            Login to Kite API and generate authorization link.
            
            This tool helps you log in to the Kite API. If you are starting a new 
            conversation, call this tool first. Returns a link that the user should 
            click to authorize access.
            """
            try:
                # Check if already authenticated
                existing_session = await self.kite_manager.get_authenticated_session(session_id)
                if existing_session and existing_session.authenticated:
                    return f"You are already logged in as {existing_session.user_name}"
                
                # Generate login URL
                login_url = await self.kite_manager.generate_login_url(session_id)
                
                warning_message = (
                    "⚠️ **WARNING: AI systems are unpredictable and non-deterministic. "
                    "By continuing, you agree to interact with your Zerodha account via AI at your own risk.**\n\n"
                )
                
                return (
                    f"{warning_message}"
                    f"Please click the following link to authorize access: [Login to Kite]({login_url})\n\n"
                    f"If your client doesn't support clickable links, copy and paste this URL into your browser:\n"
                    f"{login_url}\n\n"
                    f"After completing the login in your browser, let me know and I'll continue with your request."
                )
                
            except Exception as e:
                logger.error("Login tool failed", session_id=session_id, error=str(e))
                return f"Login failed: {str(e)}"
```

**Step 9: FastAPI Integration**

```python
# src/main.py
import asyncio
import structlog
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, HTTPException, Query
from fastapi.responses import HTMLResponse
from fastmcp import FastMCP

from .config.settings import settings
from .auth.kite_manager import KiteManager
from .auth.session_signer import SessionSigner, SignatureConfig
from .session.registry import SessionRegistry
from .tools.login_tool import LoginTool

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger()

# Global components
session_registry: SessionRegistry
kite_manager: KiteManager
session_signer: SessionSigner

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan management"""
    global session_registry, kite_manager, session_signer
    
    logger.info("Starting Kite MCP Server", version="1.0.0", mode=settings.app_mode)
    
    # Initialize session signer
    if settings.hmac_secret_key:
        secret_key = settings.hmac_secret_key.encode()
    else:
        secret_key = SessionSigner.generate_secret_key()
        logger.warning("Using generated HMAC key - sessions won't persist across restarts")
    
    session_signer = SessionSigner(SignatureConfig(
        secret_key=secret_key,
        expiry_minutes=settings.signature_expiry_minutes,
        max_clock_skew_minutes=settings.max_clock_skew_minutes
    ))
    
    # Initialize session registry
    session_registry = SessionRegistry(
        session_duration_hours=settings.session_duration_hours,
        cleanup_interval_minutes=settings.cleanup_interval_minutes,
        session_signer=session_signer
    )
    
    # Initialize Kite manager
    kite_manager = KiteManager(
        api_key=settings.kite_api_key,
        api_secret=settings.kite_api_secret,
        session_registry=session_registry,
        session_signer=session_signer
    )
    
    # Start background tasks
    await session_registry.start_cleanup_routine()
    
    logger.info("Kite MCP Server started successfully")
    
    yield
    
    # Cleanup
    logger.info("Shutting down Kite MCP Server")
    await kite_manager.shutdown()
    logger.info("Kite MCP Server shutdown complete")

# Create FastAPI app
app = FastAPI(
    title="Kite MCP Server",
    description="Model Context Protocol server for Kite Connect trading API",
    version="1.0.0",
    lifespan=lifespan
)

# Create FastMCP instance
mcp_app = FastMCP("Kite MCP Server")

# Register tools
login_tool = LoginTool(kite_manager)
login_tool.register_with_mcp(mcp_app)

# Authentication callback endpoint
@app.get("/callback")
async def kite_callback(
    request_token: str = Query(..., description="Kite request token"),
    session_id: str = Query(..., description="Signed session ID")
):
    """Handle Kite Connect authentication callback"""
    try:
        kite_data = await kite_manager.complete_authentication(session_id, request_token)
        
        # Return success page
        return HTMLResponse(f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Login Successful</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; text-align: center; }}
                .success {{ color: green; }}
            </style>
        </head>
        <body>
            <h1 class="success">Login Successful!</h1>
            <p>Welcome, {kite_data.user_name}!</p>
            <p>You can now close this window and continue with your MCP client.</p>
        </body>
        </html>
        """)
        
    except Exception as e:
        logger.error("Callback processing failed", error=str(e))
        raise HTTPException(status_code=400, detail=f"Authentication failed: {str(e)}")

# Status endpoint
@app.get("/")
async def status():
    """Server status page"""
    active_sessions = await session_registry.list_active_sessions()
    
    return HTMLResponse(f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Kite MCP Server Status</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; }}
            .status {{ color: green; }}
        </style>
    </head>
    <body>
        <h1>Kite MCP Server</h1>
        <p class="status">Status: Running</p>
        <p>Mode: {settings.app_mode}</p>
        <p>Active Sessions: {len(active_sessions)}</p>
        <p>Version: 1.0.0</p>
    </body>
    </html>
    """)

# Mount MCP endpoints
app.mount("/mcp", mcp_app)

if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "src.main:app",
        host=settings.app_host,
        port=settings.app_port,
        reload=True,
        log_level=settings.log_level.lower()
    )
```

### 4.4 Testing Implementation

**Step 10: Comprehensive Test Suite**

```python
# tests/test_authentication.py
import pytest
import asyncio
from datetime import datetime, timezone, timedelta
import secrets

from src.auth.session_signer import SessionSigner, SignatureConfig
from src.auth.session_signer import InvalidSignatureError, ExpiredSignatureError, TamperedSessionError
from src.session.registry import SessionRegistry
from src.models.session import MCPSession, SessionStatus

class TestSessionSigner:
    """Test HMAC session signing functionality"""
    
    def setup_method(self):
        secret_key = secrets.token_bytes(32)
        self.signer = SessionSigner(SignatureConfig(
            secret_key=secret_key,
            expiry_minutes=30,
            max_clock_skew_minutes=5
        ))
    
    def test_sign_and_verify_session_id(self):
        """Test basic signing and verification"""
        session_id = "kitemcp-12345678-1234-1234-1234-123456789abc"
        
        # Sign session ID
        signed_param = self.signer.sign_session_id(session_id)
        
        # Verify signature
        verified_id = self.signer.verify_session_id(signed_param)
        
        assert verified_id == session_id
    
    def test_tampered_signature_detection(self):
        """Test detection of tampered signatures"""
        session_id = "kitemcp-12345678-1234-1234-1234-123456789abc"
        signed_param = self.signer.sign_session_id(session_id)
        
        # Tamper with signature
        parts = signed_param.split('.')
        tampered_sig = parts[0] + ".TAMPERED"
        
        with pytest.raises(TamperedSessionError):
            self.signer.verify_session_id(tampered_sig)
    
    def test_expired_signature_rejection(self):
        """Test rejection of expired signatures"""
        # Create signer with very short expiry
        short_expiry_signer = SessionSigner(SignatureConfig(
            secret_key=self.signer.config.secret_key,
            expiry_minutes=0,  # Immediate expiry
            max_clock_skew_minutes=0
        ))
        
        session_id = "kitemcp-12345678-1234-1234-1234-123456789abc"
        signed_param = short_expiry_signer.sign_session_id(session_id)
        
        # Wait for expiry (simulate time passage)
        import time
        time.sleep(1)
        
        with pytest.raises(ExpiredSignatureError):
            short_expiry_signer.verify_session_id(signed_param)

@pytest.mark.asyncio
class TestSessionRegistry:
    """Test session registry functionality"""
    
    async def test_session_creation_and_retrieval(self):
        """Test basic session operations"""
        registry = SessionRegistry(session_duration_hours=1)
        
        # Create session
        session = await registry.create_session(data={"test": "data"})
        
        # Retrieve session
        retrieved = await registry.get_session(session.id)
        
        assert retrieved is not None
        assert retrieved.id == session.id
        assert retrieved.data == {"test": "data"}
        assert retrieved.is_active()
    
    async def test_get_or_create_session(self):
        """Test atomic get-or-create operation"""
        registry = SessionRegistry(session_duration_hours=1)
        session_id = "kitemcp-12345678-1234-1234-1234-123456789abc"
        
        # First call should create
        session1, is_new1 = await registry.get_or_create_session(
            session_id, 
            lambda: {"created": True}
        )
        
        assert is_new1 is True
        assert session1.data == {"created": True}
        
        # Second call should retrieve existing
        session2, is_new2 = await registry.get_or_create_session(session_id)
        
        assert is_new2 is False
        assert session2.id == session1.id
    
    async def test_session_expiry(self):
        """Test session expiration"""
        # Create registry with very short duration
        registry = SessionRegistry(session_duration_hours=0)  # Immediate expiry
        
        session = await registry.create_session()
        
        # Session should be expired immediately
        retrieved = await registry.get_session(session.id)
        assert retrieved is None
    
    async def test_cleanup_expired_sessions(self):
        """Test cleanup of expired sessions"""
        registry = SessionRegistry(session_duration_hours=0)
        
        # Create expired sessions
        for i in range(5):
            await registry.create_session(f"session-{i}")
        
        # All should be cleaned up
        cleaned_count = await registry.cleanup_expired_sessions()
        assert cleaned_count == 5
        
        # No active sessions should remain
        active_sessions = await registry.list_active_sessions()
        assert len(active_sessions) == 0

# tests/test_integration.py
import pytest
from httpx import AsyncClient
from fastapi.testclient import TestClient

from src.main import app

@pytest.mark.asyncio
class TestIntegration:
    """Integration tests for the complete authentication flow"""
    
    async def test_status_endpoint(self):
        """Test status endpoint"""
        async with AsyncClient(app=app, base_url="http://test") as ac:
            response = await ac.get("/")
            assert response.status_code == 200
            assert "Kite MCP Server" in response.text
    
    async def test_mcp_endpoint_availability(self):
        """Test MCP endpoint is available"""
        async with AsyncClient(app=app, base_url="http://test") as ac:
            # MCP endpoints should be available under /mcp
            response = await ac.get("/mcp/")
            # Should not be 404
            assert response.status_code != 404
```

### 4.5 Deployment Configuration

**Step 11: Production Deployment Setup**

```python
# docker/Dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY src/ src/
COPY config/ config/

# Create non-root user
RUN useradd --create-home --shell /bin/bash kitemcp
USER kitemcp

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/ || exit 1

CMD ["python", "-m", "uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8080"]
```

```yaml
# docker-compose.yml
version: '3.8'

services:
  kite-mcp-server:
    build: .
    ports:
      - "8080:8080"
    environment:
      - KITE_API_KEY=${KITE_API_KEY}
      - KITE_API_SECRET=${KITE_API_SECRET}
      - APP_MODE=http
      - LOG_LEVEL=INFO
      - SESSION_DURATION_HOURS=12
      - SIGNATURE_EXPIRY_MINUTES=30
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/"]
      interval: 30s
      timeout: 10s
      retries: 3
```

```bash
# scripts/deploy.sh
#!/bin/bash

set -e

echo "Deploying Kite MCP Server..."

# Build and deploy
docker-compose down
docker-compose build
docker-compose up -d

echo "Deployment complete!"
echo "Server available at: http://localhost:8080"
```

## 5. Additional Recommendations

### 5.1 Security Enhancements

1. **Rate Limiting**:
```python
# Add rate limiting using slowapi
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

@app.get("/callback")
@limiter.limit("5/minute")  # Limit callback attempts
async def kite_callback(request: Request, ...):
    # ... existing code
```

2. **IP Validation**:
```python
# Add IP-based session validation
class IPValidatedSession(MCPSession):
    client_ip: Optional[str] = None
    
    def validate_ip(self, request_ip: str) -> bool:
        return self.client_ip is None or self.client_ip == request_ip
```

3. **Audit Logging**:
```python
# Enhanced compliance logging
async def log_security_event(event_type: str, session_id: str, details: Dict[str, Any]):
    logger.info(
        "SECURITY_EVENT",
        event_type=event_type,
        session_id=session_id,
        timestamp=datetime.now(timezone.utc).isoformat(),
        details=details
    )
```

### 5.2 Scalability Improvements

1. **Redis Session Storage**:
```python
# Replace in-memory sessions with Redis
import aioredis

class RedisSessionRegistry(SessionRegistry):
    def __init__(self, redis_url: str, **kwargs):
        super().__init__(**kwargs)
        self.redis = aioredis.from_url(redis_url)
    
    async def create_session(self, session_id: str = None, data: Dict = None):
        # Store session in Redis with TTL
        await self.redis.setex(
            f"session:{session_id}",
            timedelta(hours=self.session_duration_hours).total_seconds(),
            json.dumps(session.dict())
        )
```

2. **Horizontal Scaling**:
```python
# Load balancer configuration for multiple instances
# nginx.conf
upstream kite_mcp_backend {
    least_conn;
    server kite-mcp-1:8080;
    server kite-mcp-2:8080;
}

server {
    listen 80;
    location / {
        proxy_pass http://kite_mcp_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### 5.3 Monitoring and Observability

1. **Prometheus Metrics**:
```python
from prometheus_client import Counter, Histogram, Gauge
import time

# Metrics
REQUEST_COUNT = Counter('kite_mcp_requests_total', 'Total requests', ['method', 'endpoint'])
REQUEST_DURATION = Histogram('kite_mcp_request_duration_seconds', 'Request duration')
ACTIVE_SESSIONS = Gauge('kite_mcp_active_sessions', 'Number of active sessions')

@app.middleware("http")
async def metrics_middleware(request: Request, call_next):
    start_time = time.time()
    
    response = await call_next(request)
    
    REQUEST_COUNT.labels(method=request.method, endpoint=request.url.path).inc()
    REQUEST_DURATION.observe(time.time() - start_time)
    
    return response
```

2. **Health Checks**:
```python
@app.get("/health")
async def health_check():
    """Comprehensive health check"""
    checks = {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "components": {
            "session_registry": "healthy",
            "kite_manager": "healthy",
            "database": "healthy"  # If using database
        }
    }
    
    # Add actual health checks for each component
    try:
        active_sessions = await session_registry.list_active_sessions()
        checks["metrics"] = {
            "active_sessions": len(active_sessions),
            "uptime_seconds": time.time() - start_time
        }
    except Exception as e:
        checks["status"] = "unhealthy"
        checks["error"] = str(e)
    
    return checks
```

### 5.4 Development and Testing Improvements

1. **Mock Kite API for Testing**:
```python
# tests/mocks/kite_api.py
from fastapi import FastAPI
from fastapi.responses import JSONResponse

mock_kite_api = FastAPI()

@mock_kite_api.post("/session/token")
async def mock_generate_token(api_key: str, request_token: str, checksum: str):
    return JSONResponse({
        "status": "success",
        "data": {
            "access_token": "mock_access_token",
            "user_id": "test_user",
            "user_name": "Test User"
        }
    })
```

2. **Configuration Management**:
```python
# Enhanced configuration with validation
from pydantic import validator, Field

class Settings(BaseSettings):
    # ... existing fields
    
    @validator('kite_api_key')
    def validate_api_key(cls, v):
        if not v or len(v) < 10:
            raise ValueError('Invalid API key format')
        return v
    
    @validator('session_duration_hours')
    def validate_session_duration(cls, v):
        if not 1 <= v <= 24:
            raise ValueError('Session duration must be between 1-24 hours')
        return v
```

## Conclusion

This comprehensive analysis demonstrates that the Kite MCP Server implements a sophisticated, security-focused authentication system with excellent architectural patterns. The Python re-implementation plan provides a solid foundation for building equivalent functionality using modern Python frameworks while maintaining security best practices and scalability considerations.

**Key Strengths of Original Implementation**:
- Multi-mode server support
- HMAC-based security with replay protection  
- Atomic session operations preventing race conditions
- Comprehensive cleanup and resource management
- Excellent separation of concerns

**Python Implementation Benefits**:
- Type safety with Pydantic models
- Async/await for better performance
- Modern dependency injection patterns
- Comprehensive testing framework
- Enhanced monitoring and observability

The provided implementation plan offers a production-ready foundation that can be extended with additional features while maintaining the security and reliability standards established by the original Go implementation.
