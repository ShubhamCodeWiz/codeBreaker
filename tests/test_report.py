"""Rendering tests. No server: ProbeResult objects are built by hand."""

import io

import pytest
from rich.console import Console

from code_breaker.models import Evidence, ProbeResult
from code_breaker.report import render_comparison, render_report


def make_result(
    status: str,
    probe: str = "idor",
    endpoint: str = "/wallets/{wallet_id}",
    summary: str = "summary text",
    evidence: list[Evidence] | None = None,
) -> ProbeResult:
    return ProbeResult(
        probe=probe,
        endpoint=endpoint,
        status=status,
        summary=summary,
        evidence=evidence or [Evidence(method="GET", path="/wallets/W_B", status_code=200)],
    )


def render(build) -> str:
    stream = io.StringIO()
    console = Console(file=stream, width=120)
    build(console)
    return stream.getvalue()


def test_report_shows_every_status_and_counts() -> None:
    results = [make_result("PASS"), make_result("FAIL"), make_result("INCONCLUSIVE")]
    output = render(lambda console: render_report(results, console=console))
    assert "PASS" in output
    assert "FAIL" in output
    assert "INCONCLUSIVE" in output
    assert "1 PASS · 1 FAIL · 1 INCONCLUSIVE" in output


def test_evidence_hidden_for_pass_unless_verbose_but_always_for_fail() -> None:
    results = [
        make_result("PASS", evidence=[Evidence(method="GET", path="/pass-evidence", status_code=200)]),
        make_result("FAIL", probe="idempotency", evidence=[Evidence(method="POST", path="/fail-evidence", status_code=200)]),
    ]
    plain = render(lambda console: render_report(results, console=console))
    assert "/pass-evidence" not in plain
    assert "/fail-evidence" in plain

    verbose = render(lambda console: render_report(results, console=console, verbose=True))
    assert "/pass-evidence" in verbose
    assert "/fail-evidence" in verbose


def test_markup_in_result_text_is_printed_literally() -> None:
    hostile = "[red]x[/red]"
    results = [make_result("FAIL", summary=hostile, evidence=[Evidence(method="GET", path=hostile, status_code=403, note=hostile)])]
    output = render(lambda console: render_report(results, console=console))
    assert hostile in output


@pytest.mark.parametrize(
    ("before_status", "after_status", "expected"),
    [
        ("PASS", "FAIL", "REGRESSION"),
        ("FAIL", "FAIL", "STILL VULNERABLE"),
        ("FAIL", "INCONCLUSIVE", "UNVERIFIED"),
        ("FAIL", "PASS", "FIXED"),
        ("PASS", "PASS", "UNCHANGED"),
        ("INCONCLUSIVE", "PASS", "UNVERIFIED"),
    ],
)
def test_comparison_outcome_rules(before_status: str, after_status: str, expected: str) -> None:
    output = render(
        lambda console: render_comparison(
            [make_result(before_status)], [make_result(after_status)], console=console
        )
    )
    assert expected in output


def test_comparison_missing_counterpart() -> None:
    only_before = render(lambda console: render_comparison([make_result("PASS")], [], console=console))
    only_after = render(lambda console: render_comparison([], [make_result("PASS")], console=console))
    assert "MISSING" in only_before
    assert "MISSING" in only_after


def test_comparison_prints_disclaimer() -> None:
    output = render(lambda console: render_comparison([make_result("FAIL")], [make_result("PASS")], console=console))
    assert "not a proof of security" in output.lower()
