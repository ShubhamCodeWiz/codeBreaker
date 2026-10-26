"""Tests for the IDOR probe against the vulnerable target.

No PASS test is written here: PASS is proven in a later session against a
patched copy of the target, where the ownership check exists.
"""

import httpx

from code_breaker.probes import idor_probe
from code_breaker.harness import run_target

ALICE = {"username": "alice", "password": "password1", "wallet_id": "W_A"}


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
        token = httpx.post(
            f"{server}/login",
            json={"username": ALICE["username"], "password": ALICE["password"]},
            timeout=5,
        ).json()["access_token"]
        result = idor_probe(str(server), ALICE, "W_B")
    serialized = result.model_dump_json()
    assert token not in serialized
    assert ALICE["password"] not in serialized