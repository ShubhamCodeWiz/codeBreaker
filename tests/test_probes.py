"""Tests for the probes against the vulnerable target.

IDOR PASS is not tested here: it is proven in a later session against a
patched copy. The unauthenticated-access probe does have a real PASS test
because /wallets/{id} genuinely requires a token.
"""

import httpx

from code_breaker.harness import run_target
from code_breaker.probes import (
    idor_probe,
    idempotency_probe,
    unauthenticated_access_probe,
)

ALICE = {"username": "alice", "password": "password1", "wallet_id": "W_A"}
ALICE_CREDS = {"username": "alice", "password": "password1"}


def _fetch_token(server: str) -> str:
    """Log in out of band so tests can prove tokens never reach the result."""
    response = httpx.post(
        f"{server}/login",
        json={"username": ALICE["username"], "password": ALICE["password"]},
        timeout=5,
    )
    return response.json()["access_token"]


def test_idor_probe_fails_on_vulnerable_target() -> None:
    with run_target() as server:
        result = idor_probe(str(server), ALICE, "W_B")
    assert result.status == "FAIL"
    assert len(result.evidence) == 3
    assert [item.status_code for item in result.evidence] == [200, 200, 200]


def test_idor_probe_inconclusive_on_bad_credentials() -> None:
    attacker = {**ALICE, "password": "wrong-password"}
    with run_target() as server:
        result = idor_probe(str(server), attacker, "W_B")
    assert result.status == "INCONCLUSIVE"
    assert len(result.evidence) == 1


def test_idor_probe_inconclusive_on_bad_control() -> None:
    attacker = {**ALICE, "wallet_id": "W_MISSING"}
    with run_target() as server:
        result = idor_probe(str(server), attacker, "W_B")
    assert result.status == "INCONCLUSIVE"
    assert len(result.evidence) == 2
    assert result.evidence[1].status_code == 404


def test_idor_probe_never_leaks_token() -> None:
    with run_target() as server:
        token = _fetch_token(str(server))
        result = idor_probe(str(server), ALICE, "W_B")
    serialized = result.model_dump_json()
    assert token not in serialized
    assert ALICE["password"] not in serialized


def test_idor_probe_still_fails_after_refactor() -> None:
    """Sharing the login helper must not change the verdict or the evidence notes."""
    with run_target() as server:
        result = idor_probe(str(server), ALICE, "W_B")
    assert result.status == "FAIL"
    assert [item.note for item in result.evidence] == [
        "attacker login",
        "control: attacker's own wallet",
        "attack: victim wallet",
    ]


def test_unauth_probe_fails_on_transactions() -> None:
    with run_target() as server:
        result = unauthenticated_access_probe(
            str(server), ALICE_CREDS, "/wallets/W_B/transactions"
        )
    assert result.status == "FAIL"
    assert [item.status_code for item in result.evidence] == [200, 200, 200]


def test_unauth_probe_passes_on_protected_wallet() -> None:
    # First real PASS test: /wallets/W_A rejects requests without a token.
    with run_target() as server:
        result = unauthenticated_access_probe(str(server), ALICE_CREDS, "/wallets/W_A")
    assert result.status == "PASS"
    assert result.evidence[-1].status_code == 401


def test_unauth_probe_inconclusive_on_missing_path() -> None:
    with run_target() as server:
        result = unauthenticated_access_probe(
            str(server), ALICE_CREDS, "/wallets/NOPE/transactions"
        )
    assert result.status == "INCONCLUSIVE"
    assert len(result.evidence) == 2
    assert result.evidence[1].status_code == 404


def test_unauth_probe_inconclusive_on_bad_credentials() -> None:
    with run_target() as server:
        result = unauthenticated_access_probe(
            str(server), {**ALICE_CREDS, "password": "wrong-password"}, "/wallets/W_A"
        )
    assert result.status == "INCONCLUSIVE"
    assert len(result.evidence) == 1


def test_unauth_probe_never_leaks_token() -> None:
    with run_target() as server:
        token = _fetch_token(str(server))
        result = unauthenticated_access_probe(
            str(server), ALICE_CREDS, "/wallets/W_B/transactions"
        )
    serialized = result.model_dump_json()
    assert token not in serialized
    assert ALICE["password"] not in serialized

# Idempotency PASS is proven in a later session against a patched copy,
# because the current target is the vulnerable one.
def test_idempotency_probe_fails_on_vulnerable_target() -> None:
    with run_target() as server:
        result = idempotency_probe(str(server), ALICE_CREDS, "W_A", amount=20)
    assert result.status == "FAIL"
    withdraws = [item for item in result.evidence if item.path.endswith("/withdraw")]
    assert len(withdraws) == 2
    assert "balance before: 100" in [item.note for item in result.evidence]
    assert "balance after: 60" in [item.note for item in result.evidence]


def test_idempotency_probe_inconclusive_on_low_balance() -> None:
    with run_target() as server:
        result = idempotency_probe(str(server), ALICE_CREDS, "W_A", amount=60)
    assert result.status == "INCONCLUSIVE"
    assert not any(item.path.endswith("/withdraw") for item in result.evidence)


def test_idempotency_probe_inconclusive_on_bad_credentials() -> None:
    bad_user = {**ALICE_CREDS, "password": "wrong-password"}
    with run_target() as server:
        result = idempotency_probe(str(server), bad_user, "W_A")
    assert result.status == "INCONCLUSIVE"
    assert len(result.evidence) == 1


def test_idempotency_probe_inconclusive_on_forbidden_wallet() -> None:
    with run_target() as server:
        result = idempotency_probe(str(server), ALICE_CREDS, "W_B")
    assert result.status == "INCONCLUSIVE"
    withdraws = [item for item in result.evidence if item.path.endswith("/withdraw")]
    assert len(withdraws) == 1
    assert withdraws[0].status_code == 403


def test_idempotency_probe_never_leaks_token() -> None:
    with run_target() as server:
        token = _fetch_token(str(server))
        result = idempotency_probe(str(server), ALICE_CREDS, "W_A")
    serialized = result.model_dump_json()
    assert token not in serialized
    assert ALICE["password"] not in serialized
