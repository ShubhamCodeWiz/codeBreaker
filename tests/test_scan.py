"""Tests for the scan runner's fixed probe plan."""

import io
from pathlib import Path

from rich.console import Console

from code_breaker.harness import run_target
from code_breaker.models import ProbeResult
from code_breaker.report import render_report
from code_breaker.scan import run_probes

PATCHED_DIR = (Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "patched_target").resolve()


def test_run_probes_all_fail_on_original() -> None:
    with run_target() as server:
        results = run_probes(str(server))
    assert [result.status for result in results] == ["FAIL", "FAIL", "FAIL", "FAIL"]
    assert [(result.probe, result.endpoint) for result in results] == [
        ("idor", "/wallets/{wallet_id}"),
        ("unauthenticated_access", "/wallets/W_B/transactions"),
        ("idor", "/wallets/{wallet_id}/transactions"),
        ("idempotency", "/wallets/W_A/withdraw"),
    ]


def test_run_probes_all_pass_on_patched() -> None:
    with run_target(app_dir=str(PATCHED_DIR)) as server:
        results = run_probes(str(server))
    assert [result.status for result in results] == ["PASS", "PASS", "PASS", "PASS"]


def test_run_probes_dead_server_is_inconclusive() -> None:
    results = run_probes("http://127.0.0.1:1")
    assert len(results) == 4
    assert all(result.status == "INCONCLUSIVE" for result in results)
    assert all(result.summary == "probe crashed: ConnectError" for result in results)


def test_report_title_labels_the_original_target() -> None:
    stream = io.StringIO()
    console = Console(file=stream, width=120)
    results = [
        ProbeResult(
            probe="idor",
            endpoint="/wallets/{wallet_id}",
            status="FAIL",
            summary="attacker read another user's wallet with their own token",
            evidence=[],
        )
    ]
    render_report(results, console=console, title="ORIGINAL target (vulnerable)")
    assert "ORIGINAL target (vulnerable)" in stream.getvalue()