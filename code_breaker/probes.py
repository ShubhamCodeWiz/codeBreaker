"""Deterministic probes. Each probe knows nothing about the target's internals."""

import httpx

from code_breaker.models import Evidence, ProbeResult

TIMEOUT = 5.0


def _login(
    client: httpx.Client,
    login_path: str,
    user: dict[str, str],
    evidence: list[Evidence],
    note: str,
) -> str | None:
    """Log in, record the request, and return the token, or None on failure."""
    response = client.post(
        login_path,
        json={"username": user["username"], "password": user["password"]},
    )
    evidence.append(
        Evidence(
            method="POST",
            path=login_path,
            status_code=response.status_code,
            note=note,
        )
    )
    if response.status_code != 200:
        return None
    return response.json()["access_token"]


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
        token = _login(client, login_path, attacker, evidence, "attacker login")
        if token is None:
            return ProbeResult(
                probe="idor",
                endpoint=path_template,
                status="INCONCLUSIVE",
                summary="attacker login failed, so the probe could not run",
                evidence=evidence,
            )

        headers = {"Authorization": f"Bearer {token}"}

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


def unauthenticated_access_probe(
    base_url: str,
    user: dict[str, str],
    path: str,
    method: str = "GET",
    login_path: str = "/login",
) -> ProbeResult:
    """Check whether a concrete path answers without an Authorization header.

    The probe does not judge whether the endpoint is meant to be public; it
    only reports the fact that the endpoint is reachable without a token. The
    public/private decision belongs to the caller.
    """
    evidence: list[Evidence] = []

    with httpx.Client(base_url=base_url, timeout=TIMEOUT) as client:
        token = _login(client, login_path, user, evidence, "user login")
        if token is None:
            return ProbeResult(
                probe="unauthenticated_access",
                endpoint=path,
                status="INCONCLUSIVE",
                summary="login failed, so the probe could not run",
                evidence=evidence,
            )

        control = client.request(
            method, path, headers={"Authorization": f"Bearer {token}"}
        )
        evidence.append(
            Evidence(
                method=method,
                path=path,
                status_code=control.status_code,
                note="control: with token",
            )
        )
        if not control.is_success:
            return ProbeResult(
                probe="unauthenticated_access",
                endpoint=path,
                status="INCONCLUSIVE",
                summary="control request with a token did not succeed",
                evidence=evidence,
            )

        attack = client.request(method, path)
        evidence.append(
            Evidence(
                method=method,
                path=path,
                status_code=attack.status_code,
                note="attack: without token",
            )
        )

        if attack.is_success:
            return ProbeResult(
                probe="unauthenticated_access",
                endpoint=path,
                status="FAIL",
                summary="endpoint reachable without a token",
                evidence=evidence,
            )
        if attack.status_code in (401, 403):
            return ProbeResult(
                probe="unauthenticated_access",
                endpoint=path,
                status="PASS",
                summary="target rejected the request without a token",
                evidence=evidence,
            )
        return ProbeResult(
            probe="unauthenticated_access",
            endpoint=path,
            status="INCONCLUSIVE",
            summary=f"unexpected attack response status {attack.status_code}",
            evidence=evidence,
        )