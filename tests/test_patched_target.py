"""Probes FAIL on the original target and PASS on the patched copy.

The patched fixture is a separate copy of the target with the three planted
bugs fixed; these tests pin both directions plus normal-behaviour regressions.
"""

from pathlib import Path

import httpx

from code_breaker.harness import run_target
from code_breaker.probes import (
    idor_probe,
    idempotency_probe,
    unauthenticated_access_probe,
)

PATCHED_DIR = (Path(__file__).parent / "fixtures" / "patched_target").resolve()

ALICE = {"username": "alice", "password": "password1", "wallet_id": "W_A"}
ALICE_CREDS = {"username": "alice", "password": "password1"}
BOB_CREDS = {"username": "bob", "password": "password2"}
TIMEOUT = 5


def _login(server: str, user: dict[str, str]) -> dict[str, str]:
    """Log in over real HTTP and return the bearer header."""
    response = httpx.post(f"{server}/login", json=user, timeout=TIMEOUT)
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def _patched():
    return run_target(app_dir=str(PATCHED_DIR))


def test_idor_probe_passes_on_patched() -> None:
    with _patched() as server:
        result = idor_probe(str(server), ALICE, "W_B")
    assert result.status == "PASS"


def test_unauth_probe_passes_on_patched_transactions() -> None:
    # Bob owns W_B, so his token satisfies the control request; the attack
    # then proves the same route is closed without a token.
    with _patched() as server:
        result = unauthenticated_access_probe(
            str(server), BOB_CREDS, "/wallets/W_B/transactions"
        )
    assert result.status == "PASS"
    assert result.evidence[-1].status_code == 401


def test_idempotency_probe_passes_on_patched() -> None:
    with _patched() as server:
        result = idempotency_probe(str(server), ALICE_CREDS, "W_A", amount=20)
    assert result.status == "PASS"
    assert "balance before: 100" in [item.note for item in result.evidence]
    assert "balance after: 80" in [item.note for item in result.evidence]


def test_idor_probe_on_transactions_fails_on_original() -> None:
    with run_target() as server:
        result = idor_probe(
            str(server),
            ALICE,
            "W_B",
            path_template="/wallets/{wallet_id}/transactions",
        )
    assert result.status == "FAIL"
    assert [item.status_code for item in result.evidence] == [200, 200, 200]


def test_idor_probe_on_transactions_passes_on_patched() -> None:
    with _patched() as server:
        result = idor_probe(
            str(server),
            ALICE,
            "W_B",
            path_template="/wallets/{wallet_id}/transactions",
        )
    assert result.status == "PASS"
    assert result.evidence[-1].status_code == 403


def test_patched_owner_can_read_own_wallet_and_transactions() -> None:
    with _patched() as server:
        headers = _login(server, ALICE_CREDS)
        wallet = httpx.get(f"{server}/wallets/W_A", headers=headers, timeout=TIMEOUT)
        transactions = httpx.get(
            f"{server}/wallets/W_A/transactions", headers=headers, timeout=TIMEOUT
        )
    assert wallet.status_code == 200
    assert transactions.status_code == 200
    assert wallet.json()["owner"] == "alice"


def test_patched_idempotency_key_debits_once() -> None:
    body = {"amount": 20}
    replay = {"Idempotency-Key": "regression-key"}
    with _patched() as server:
        headers = _login(server, ALICE_CREDS)
        first = httpx.post(
            f"{server}/wallets/W_A/withdraw",
            json=body,
            headers={**headers, **replay},
            timeout=TIMEOUT,
        )
        second = httpx.post(
            f"{server}/wallets/W_A/withdraw",
            json=body,
            headers={**headers, **replay},
            timeout=TIMEOUT,
        )
        balance = httpx.get(f"{server}/wallets/W_A", headers=headers, timeout=TIMEOUT)
    assert first.status_code == 200
    assert second.status_code == 200
    assert balance.json()["balance"] == 80


def test_patched_withdraw_without_key_debits_each_time() -> None:
    body = {"amount": 20}
    with _patched() as server:
        headers = _login(server, ALICE_CREDS)
        httpx.post(
            f"{server}/wallets/W_A/withdraw", json=body, headers=headers, timeout=TIMEOUT
        )
        httpx.post(
            f"{server}/wallets/W_A/withdraw", json=body, headers=headers, timeout=TIMEOUT
        )
        balance = httpx.get(f"{server}/wallets/W_A", headers=headers, timeout=TIMEOUT)
    assert balance.json()["balance"] == 60


def test_patched_target_really_serves_patched_code() -> None:
    # Guard: a wrong app_dir must not silently test the original app.
    with _patched() as server:
        headers = _login(server, ALICE_CREDS)
        response = httpx.get(f"{server}/wallets/W_B", headers=headers, timeout=TIMEOUT)
    assert response.status_code == 403