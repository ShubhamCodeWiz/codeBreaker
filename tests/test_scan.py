"""Tests for the scan runner's fixed probe plan."""

from pathlib import Path

from code_breaker.harness import run_target
from code_breaker.scan import run_probes

PATCHED_DIR = (Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "patched_target").resolve()


def test_run_probes_all_fail_on_original() -> None:
    with run_target() as server:
        results = run_probes(str(server))
    assert [result.status for result in results] == ["FAIL", "FAIL", "FAIL"]


def test_run_probes_all_pass_on_patched() -> None:
    with run_target(app_dir=str(PATCHED_DIR)) as server:
        results = run_probes(str(server))
    assert [result.status for result in results] == ["PASS", "PASS", "PASS"]


def test_run_probes_dead_server_is_inconclusive() -> None:
    results = run_probes("http://127.0.0.1:1")
    assert len(results) == 3
    assert all(result.status == "INCONCLUSIVE" for result in results)
    assert all(result.summary == "probe crashed: ConnectError" for result in results)