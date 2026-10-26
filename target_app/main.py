"""Minimal FastAPI target app used by code-breaker for security tests."""

from datetime import datetime, timedelta, timezone
from typing import Annotated

import jwt
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

SECRET_KEY = "super-secret-key"  # intentional, this is a test target

USERS = {
    "alice": {"password": "password1", "wallet": "W_A", "balance": 100},  # intentional, this is a test target
    "bob": {"password": "password2", "wallet": "W_B", "balance": 100},  # intentional, this is a test target
}

TRANSACTIONS = {wallet: [{"type": "deposit", "amount": 100}] for wallet in ("W_A", "W_B")}

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


# VULN: missing auth - no token required
@app.get("/wallets/{wallet_id}/transactions")
def read_transactions(wallet_id: str) -> dict[str, str | list[dict[str, str | int]]]:
    """Return a wallet's transactions. Intentionally unauthenticated: no ownership or token check."""
    if wallet_id not in TRANSACTIONS:
        raise HTTPException(status_code=404, detail="Wallet not found")
    return {"wallet_id": wallet_id, "transactions": TRANSACTIONS[wallet_id]}


class WithdrawRequest(BaseModel):
    """Amount to withdraw."""

    amount: int


@app.post("/wallets/{wallet_id}/withdraw")
def withdraw(
    wallet_id: str,
    payload: WithdrawRequest,
    username: Annotated[str, Depends(get_current_user)],
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> dict[str, str | int]:
    """Withdraw funds. Intentionally ignores Idempotency-Key, so retrying a key debits twice."""
    user = USERS[username]
    if wallet_id not in TRANSACTIONS:
        raise HTTPException(status_code=404, detail="Wallet not found")
    if user["wallet"] != wallet_id:
        raise HTTPException(status_code=403, detail="Wallet does not belong to you")
    if payload.amount <= 0:
        raise HTTPException(status_code=400, detail="Amount must be positive")
    if user["balance"] < payload.amount:
        raise HTTPException(status_code=400, detail="Insufficient funds")
    # VULN: Idempotency-Key accepted but ignored
    user["balance"] -= payload.amount
    TRANSACTIONS[wallet_id].append({"type": "withdraw", "amount": payload.amount})
    return {"wallet_id": wallet_id, "balance": user["balance"]}
