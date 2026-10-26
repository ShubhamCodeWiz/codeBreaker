"""Prove the planted vulnerabilities exist and the correct checks still hold."""

import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio


async def test_bug_exists_idor(client: AsyncClient, auth_headers) -> None:
    """Alice's own token can read Bob's wallet."""
    headers = await auth_headers()
    response = await client.get("/wallets/W_B", headers=headers)
    assert response.status_code == 200
    assert response.json()["owner"] == "bob"


async def test_bug_exists_missing_auth(client: AsyncClient) -> None:
    """Wallet transactions are readable with no token at all."""
    response = await client.get("/wallets/W_B/transactions")
    assert response.status_code == 200


async def test_bug_exists_no_idempotency(client: AsyncClient, auth_headers) -> None:
    """Replaying the same Idempotency-Key debits the balance a second time."""
    headers = await auth_headers()
    body = {"amount": 20}
    replay = {"Idempotency-Key": "same-key-123"}
    first = await client.post("/wallets/W_A/withdraw", json=body, headers={**headers, **replay})
    second = await client.post("/wallets/W_A/withdraw", json=body, headers={**headers, **replay})
    assert first.status_code == 200
    assert second.status_code == 200
    wallet = await client.get("/wallets/W_A", headers=headers)
    assert wallet.json()["balance"] == 60


async def test_ok_login_wrong_password(client: AsyncClient) -> None:
    """Bad credentials are rejected."""
    response = await client.post("/login", json={"username": "alice", "password": "wrong"})
    assert response.status_code == 401


async def test_ok_wallet_requires_token(client: AsyncClient) -> None:
    """Wallet reads require a bearer token."""
    response = await client.get("/wallets/W_A")
    assert response.status_code == 401


async def test_ok_garbage_token_rejected(client: AsyncClient) -> None:
    """An unparsable token is rejected."""
    response = await client.get("/wallets/W_A", headers={"Authorization": "Bearer not-a-jwt"})
    assert response.status_code == 401


async def test_ok_withdraw_other_wallet_forbidden(client: AsyncClient, auth_headers) -> None:
    """Alice cannot withdraw from Bob's wallet."""
    headers = await auth_headers()
    response = await client.post("/wallets/W_B/withdraw", json={"amount": 20}, headers=headers)
    assert response.status_code == 403


async def test_ok_withdraw_validation(client: AsyncClient, auth_headers) -> None:
    """Non-positive and over-balance amounts are rejected."""
    headers = await auth_headers()
    negative = await client.post("/wallets/W_A/withdraw", json={"amount": -5}, headers=headers)
    too_large = await client.post("/wallets/W_A/withdraw", json={"amount": 1000}, headers=headers)
    assert negative.status_code == 400
    assert too_large.status_code == 400


async def test_ok_withdraw_once(client: AsyncClient, auth_headers) -> None:
    """A single withdrawal debits exactly once."""
    headers = await auth_headers()
    response = await client.post("/wallets/W_A/withdraw", json={"amount": 20}, headers=headers)
    assert response.status_code == 200
    assert response.json()["balance"] == 80