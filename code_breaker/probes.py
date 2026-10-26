"""Deterministic probes. Each probe knows nothing about the target's internals."""

import uuid

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


def idempotency_probe(
    base_url: str,
    user: dict[str, str],
    wallet_id: str,
    amount: int = 20,
    wallet_path: str = "/wallets/{wallet_id}",
    withdraw_path: str = "/wallets/{wallet_id}/withdraw",
    balance_field: str = "balance",
    login_path: str = "/login",
) -> ProbeResult:
    """Replay one withdrawal with the same Idempotency-Key and compare balance deltas.

    This probe CHANGES target state (it withdraws money), so run it against a
    freshly started target. PASS means the same key debited once; FAIL means
    the same key debited twice. The verdict comes from the balance delta, not
    from the response status of the replay.
    """
    evidence: list[Evidence] = []
    wallet_route = wallet_path.format(wallet_id=wallet_id)
    withdraw_route = withdraw_path.format(wallet_id=wallet_id)

    with httpx.Client(base_url=base_url, timeout=TIMEOUT) as client:
        token = _login(client, login_path, user, evidence, "user login")
        if token is None:
            return ProbeResult(
                probe="idempotency",
                endpoint=withdraw_route,
                status="INCONCLUSIVE",
                summary="login failed, so the probe could not run",
                evidence=evidence,
            )
        auth = {"Authorization": f"Bearer {token}"}

        before = client.get(wallet_route, headers=auth)
        balance_before = (
            before.json().get(balance_field) if before.status_code == 200 else None
        )
        evidence.append(
            Evidence(
                method="GET",
                path=wallet_route,
                status_code=before.status_code,
                note=f"balance before: {balance_before}",
            )
        )
        if balance_before is None:
            return ProbeResult(
                probe="idempotency",
                endpoint=withdraw_route,
                status="INCONCLUSIVE",
                summary="could not read the starting balance",
                evidence=evidence,
            )

        if balance_before < 2 * amount:
            return ProbeResult(
                probe="idempotency",
                endpoint=withdraw_route,
                status="INCONCLUSIVE",
                summary="balance too low for this probe",
                evidence=evidence,
            )

        key = str(uuid.uuid4())
        withdraw_headers = {**auth, "Idempotency-Key": key}
        body = {"amount": amount}

        first = client.post(withdraw_route, json=body, headers=withdraw_headers)
        evidence.append(
            Evidence(
                method="POST",
                path=withdraw_route,
                status_code=first.status_code,
                note="withdraw: first attempt",
            )
        )
        if not first.is_success:
            return ProbeResult(
                probe="idempotency",
                endpoint=withdraw_route,
                status="INCONCLUSIVE",
                summary="first withdrawal did not succeed",
                evidence=evidence,
            )

        replay = client.post(withdraw_route, json=body, headers=withdraw_headers)
        evidence.append(
            Evidence(
                method="POST",
                path=withdraw_route,
                status_code=replay.status_code,
                note="withdraw: replay with the same key",
            )
        )

        after = client.get(wallet_route, headers=auth)
        balance_after = (
            after.json().get(balance_field) if after.status_code == 200 else None
        )
        evidence.append(
            Evidence(
                method="GET",
                path=wallet_route,
                status_code=after.status_code,
                note=f"balance after: {balance_after}",
            )
        )
        if balance_after is None:
            return ProbeResult(
                probe="idempotency",
                endpoint=withdraw_route,
                status="INCONCLUSIVE",
                summary="could not read the final balance",
                evidence=evidence,
            )

        delta = balance_before - balance_after
        if delta == amount:
            return ProbeResult(
                probe="idempotency",
                endpoint=withdraw_route,
                status="PASS",
                summary="replayed key debited the balance once",
                evidence=evidence,
            )
        if delta == 2 * amount:
            return ProbeResult(
                probe="idempotency",
                endpoint=withdraw_route,
                status="FAIL",
                summary="replayed key debited the balance twice",
                evidence=evidence,
            )
        return ProbeResult(
            probe="idempotency",
            endpoint=withdraw_route,
            status="INCONCLUSIVE",
            summary=f"unexpected balance delta {delta}",
            evidence=evidence,
        )