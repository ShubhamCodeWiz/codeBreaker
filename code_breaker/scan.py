"""Scan runner: execute a fixed probe plan against a target and print the report."""

import argparse
from pathlib import Path

import httpx

from code_breaker.harness import run_target
from code_breaker.models import ProbeResult
from code_breaker.probes import (
    idor_probe,
    idempotency_probe,
    unauthenticated_access_probe,
)
from code_breaker.report import render_comparison, render_report

PATCHED_DIR = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "patched_target"

ALICE = {"username": "alice", "password": "password1"}
BOB = {"username": "bob", "password": "password2"}


def _guarded(
    name: str, endpoint: str, call
) -> ProbeResult:
    """Run one probe, turning a transport failure into an INCONCLUSIVE result."""
    try:
        return call()
    except httpx.HTTPError as error:
        return ProbeResult(
            probe=name,
            endpoint=endpoint,
            status="INCONCLUSIVE",
            summary=f"probe crashed: {type(error).__name__}",
            evidence=[],
        )


def run_probes(base_url: str) -> list[ProbeResult]:
    """Run the fixed probe plan against an already running target."""
    # Fixed plan, in this order: the wallet IDOR, the same IDOR on the
    # transactions route, the missing token requirement on that route, then
    # idempotency. The two IDOR rows stay distinguishable by their endpoint.
    plan = [
        ("idor", "/wallets/{wallet_id}", lambda: idor_probe(base_url, {**ALICE, "wallet_id": "W_A"}, "W_B")),
        (
            "unauthenticated_access",
            "/wallets/W_B/transactions",
            lambda: unauthenticated_access_probe(base_url, BOB, "/wallets/W_B/transactions"),
        ),
        (
            "idor",
            "/wallets/{wallet_id}/transactions",
            lambda: idor_probe(
                base_url,
                {**ALICE, "wallet_id": "W_A"},
                "W_B",
                path_template="/wallets/{wallet_id}/transactions",
            ),
        ),
        ("idempotency", "/wallets/W_A/withdraw", lambda: idempotency_probe(base_url, ALICE, "W_A", amount=20)),
    ]
    return [_guarded(name, endpoint, call) for name, endpoint, call in plan]


def _scan(app_dir: str, title: str, console=None) -> list[ProbeResult]:
    """Start a fresh target, run the plan against it, and render its report."""
    with run_target(app_dir=app_dir) as server:
        results = run_probes(str(server))
    render_report(results, console=console, title=title)
    return results


def main(argv: list[str] | None = None) -> None:
    """CLI entry point for `python -m code_breaker.scan`."""
    parser = argparse.ArgumentParser(prog="code_breaker.scan", description="Run code-breaker probes")
    parser.add_argument(
        "--target",
        choices=("original", "patched", "both"),
        default="both",
        help="which target to scan (default: both)",
    )
    args = parser.parse_args(argv)

    if args.target == "original":
        _scan(".", "ORIGINAL target (vulnerable)")
    elif args.target == "patched":
        _scan(str(PATCHED_DIR), "PATCHED target")
    else:
        before = _scan(".", "ORIGINAL target (vulnerable)")
        after = _scan(str(PATCHED_DIR), "PATCHED target")
        render_comparison(before, after)


if __name__ == "__main__":
    main()