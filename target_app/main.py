"""Minimal FastAPI target app used by code-breaker for security tests."""

from datetime import datetime, timedelta, timezone
from typing import Annotated

import jwt
from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

SECRET_KEY = "super-secret-key"  # intentional, this is a test target

USERS = {
    "alice": {"password": "password1", "wallet": "W_A", "balance": 100},  # intentional, this is a test target
    "bob": {"password": "password2", "wallet": "W_B", "balance": 100},  # intentional, this is a test target
}

app = FastAPI(title="code-breaker target")
bearer = HTTPBearer(auto_error=False)


class LoginRequest(BaseModel):
    """Credentials submitted to /login."""

    username: str
    password: str


def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
) -> str:
    """Decode the bearer JWT and return its subject; 401 when missing, invalid, or expired."""
    if credentials is None:
        raise HTTPException(status_code=401, detail="Missing bearer token")
    try:
        claims = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=["HS256"])
        return claims["sub"]
    except (jwt.PyJWTError, KeyError):
        raise HTTPException(status_code=401, detail="Invalid or expired token")


@app.post("/login")
def login(payload: LoginRequest) -> dict[str, str]:
    """Return a 15-minute HS256 JWT when the credentials match a seed user."""
    user = USERS.get(payload.username)
    if user is None or user["password"] != payload.password:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    claims = {
        "sub": payload.username,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=15),
    }
    token = jwt.encode(claims, SECRET_KEY, algorithm="HS256")
    return {"access_token": token}


@app.get("/wallets/{wallet_id}")
def read_wallet(
    wallet_id: str,
    username: Annotated[str, Depends(get_current_user)],
) -> dict[str, str | int]:
    """Return a wallet by id. Intentionally IDOR-vulnerable: ownership is never checked."""
    # VULN: IDOR - no ownership check
    for owner, user in USERS.items():
        if user["wallet"] == wallet_id:
            return {"wallet_id": wallet_id, "owner": owner, "balance": user["balance"]}
    raise HTTPException(status_code=404, detail="Wallet not found")
