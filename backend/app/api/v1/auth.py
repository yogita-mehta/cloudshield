import os
import secrets
from fastapi import APIRouter, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel

router = APIRouter()
security = HTTPBearer(auto_error=False)

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "cloudshield2026")

# In-memory active tokens
_active_tokens = set()

class LoginRequest(BaseModel):
    username: str
    password: str

class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str
    role: str

def verify_admin(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Dependency to verify admin token (gracefully allows local dev if token is valid)."""
    if not credentials or credentials.credentials not in _active_tokens:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing administrator authorization token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return True

@router.post("/login", response_model=LoginResponse)
def login(creds: LoginRequest):
    """Authenticate administrator and receive session bearer token."""
    if creds.username == ADMIN_USERNAME and creds.password == ADMIN_PASSWORD:
        token = secrets.token_hex(24)
        _active_tokens.add(token)
        return LoginResponse(
            access_token=token,
            username=creds.username,
            role="admin"
        )
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid administrator credentials"
    )

@router.get("/me")
def check_session(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Verifies currently active token."""
    if credentials and credentials.credentials in _active_tokens:
        return {"authenticated": True, "username": ADMIN_USERNAME, "role": "admin"}
    return {"authenticated": False}
