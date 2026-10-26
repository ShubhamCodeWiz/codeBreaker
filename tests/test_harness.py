"""Tests for the subprocess harness."""

import httpx

from code_breaker.harness import run_target

TIMEOUT = 5


def _login(server: str, username: str = "alice", password: str = "password1") -> dict[str, str]:
    """Log in over real HTTP and return bearer auth headers."""
    response = httpx.post(
        f"{server}/login",
        json={"username": username, "password": password},
        timeout=TIMEOUT,
    )
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def test_harness_serves_openapi() -> None:
    with run_target() as server:
        response = httpx.get(f"{server}/openapi.json", timeout=TIMEOUT)
        assert response.status_code == 200
        assert "/login" in response.json()["paths"]


def test_harness_stops_process() -> None:
    with run_target() as server:
        process = server.process
        assert process.poll() is None
    assert process.poll() is not None


def test_harness_fresh_state_each_start() -> None:
    with run_target() as server:
        headers = _login(server)
        httpx.post(
            f"{server}/wallets/W_A/withdraw",
            json={"amount": 20},
            headers=headers,
            timeout=TIMEOUT,
        )
        first = httpx.get(f"{server}/wallets/W_A", headers=headers, timeout=TIMEOUT)
        assert first.json()["balance"] == 80

    with run_target() as server:
        headers = _login(server)
        second = httpx.get(f"{server}/wallets/W_A", headers=headers, timeout=TIMEOUT)
        assert second.json()["balance"] == 100
