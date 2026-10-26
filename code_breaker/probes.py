"""Deterministic probes. Each probe knows nothing about the target's internals."""

import httpx

from code_breaker.models import Evidence, ProbeResult

TIMEOUT = 5.0


def idor_probe(
    base_url: str,
    attacker: dict[str, str],
    victim_wallet_id: str,
    path_template: str = "/wallets/{wallet_id}",
    login_path: str = "/login",
) -> ProbeResult:
    """Try to read another user's wallet with the attacker's own token.

    A control request for the attacker's own wallet proves the attack request
    is meaningful before any verdict is given.
    """
    evidence: list[Evidence] = []

    with httpx.Client(base_url=base_url, timeout=TIMEOUT) as client:
        login = client.post(
            login_path,
            json={"username": attacker["username"], "password": attacker["password"]},
        )
        evidence.append(
            Evidence(
                method="POST",
                path=login_path,
                status_code=login.status_code,
                note="attacker login",
            )
        )
        if login.status_code != 200:
            return ProbeResult(
                probe="idor",
                endpoint=path_template,
                status="INCONCLUSIVE",
                summary="attacker login failed, so the probe could not run",
                evidence=evidence,
            )

        headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

        control_path = path_template.format(wallet_id=attacker["wallet_id"])
        control = client.get(control_path, headers=headers)
        evidence.append(
            Evidence(
                method="GET",
                path=control_path,
                status_code=control.status_code,
                note="control: attacker's own wallet",
            )
        )
        if control.status_code != 200:
            return ProbeResult(
                probe="idor",
                endpoint=path_template,
                status="INCONCLUSIVE",
                summary="control request for the attacker's own wallet failed",
                evidence=evidence,
            )

        victim_path = path_template.format(wallet_id=victim_wallet_id)
        attack = client.get(victim_path, headers=headers)
        evidence.append(
            Evidence(
                method="GET",
                path=victim_path,
                status_code=attack.status_code,
                note="attack: victim wallet",
            )
        )

        if attack.status_code == 200:
            return ProbeResult(
                probe="idor",
                endpoint=path_template,
                status="FAIL",
                summary="attacker read another user's wallet with their own token",
                evidence=evidence,
            )
        if attack.status_code in (401, 403, 404):
            return ProbeResult(
                probe="idor",
                endpoint=path_template,
                status="PASS",
                summary="target denied access to another user's wallet",
                evidence=evidence,
            )
        return ProbeResult(
            probe="idor",
            endpoint=path_template,
            status="INCONCLUSIVE",
            summary=f"unexpected attack response status {attack.status_code}",
            evidence=evidence,
        )