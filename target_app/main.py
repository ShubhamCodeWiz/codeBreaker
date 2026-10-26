"""Minimal FastAPI target app used by code-breaker for security tests."""

from datetime import datetime, timedelta, timezone

import jwt
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

SECRET_KEY = "super-secret-key"  # intentional, this is a test target

USERS = {
    "alice": {"password": "password1", "wallet": "W_A", "balance": 100},  # intentional, this is a test target
    "bob": {"password": "password2", "wallet": "W_B", "balance": 100},  # intentional, this is a test target
}

app = FastAPI(title="code-breaker target")


class LoginRequest(BaseModel):
    """Credentials submitted to /login."""

    username: str
    password: str


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
