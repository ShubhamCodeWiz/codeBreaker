"""Terminal rendering for probe results. No probing or HTTP happens here."""

from collections.abc import Iterable

from rich.console import Console
from rich.markup import escape
from rich.table import Table
from rich.text import Text

from code_breaker.models import ProbeResult

STATUS_STYLE = {"PASS": "green", "FAIL": "red", "INCONCLUSIVE": "yellow"}

DISCLAIMER = (
    "FIXED = FAIL before, PASS after, against these probes only. "
    "Not a proof of security."
)


def _status_cell(status: str) -> Text:
    """Status is always spelled out, so colour is never the only signal."""
    return Text(status, style=STATUS_STYLE.get(status, ""))


def _evidence_table(result: ProbeResult) -> Table:
    table = Table(title=Text(f"evidence: {result.probe} {result.endpoint}"), title_justify="left")
    table.add_column("Method")
    table.add_column("Path")
    table.add_column("Status code")
    table.add_column("Note")
    for item in result.evidence:
        table.add_row(
            Text(item.method),
            Text(item.path),
            Text(str(item.status_code)),
            Text(item.note or ""),
        )
    return table


def render_report(
    results: Iterable[ProbeResult],
    console: Console | None = None,
    title: str = "code-breaker report",
    verbose: bool = False,
) -> None:
    """Print a results table, evidence for anything not PASS, and status counts."""
    console = console or Console()
    results = list(results)

    table = Table(title=Text(title))
    table.add_column("Probe")
    table.add_column("Endpoint")
    table.add_column("Status")
    table.add_column("Summary")
    for result in results:
        table.add_row(
            Text(result.probe),
            Text(result.endpoint),
            _status_cell(result.status),
            Text(result.summary),
        )
    console.print(table)

    for result in results:
        if result.status != "PASS" or verbose:
            console.print(_evidence_table(result))

    counts = {status: 0 for status in STATUS_STYLE}
    for result in results:
        counts[result.status] = counts.get(result.status, 0) + 1
    summary = " · ".join(f"{counts[status]} {status}" for status in STATUS_STYLE)
    console.print(Text(summary))


def _outcome(before: ProbeResult | None, after: ProbeResult | None) -> str:
    """Classify a matched pair, checking the rules in the documented order."""
    if before is None or after is None:
        return "MISSING"
    if before.status == "PASS" and after.status == "FAIL":
        return "REGRESSION"
    if after.status == "FAIL":
        return "STILL VULNERABLE"
    if after.status == "INCONCLUSIVE":
        return "UNVERIFIED"
    if before.status == "FAIL" and after.status == "PASS":
        return "FIXED"
    if before.status == "PASS" and after.status == "PASS":
        return "UNCHANGED"
    if before.status == "INCONCLUSIVE" and after.status == "PASS":
        return "UNVERIFIED"
    return "UNVERIFIED"


def render_comparison(
    before: Iterable[ProbeResult],
    after: Iterable[ProbeResult],
    console: Console | None = None,
    title: str = "before / after",
) -> None:
    """Print before/after outcomes per (probe, endpoint), matched by that pair."""
    console = console or Console()

    before_map = {(result.probe, result.endpoint): result for result in before}
    after_map = {(result.probe, result.endpoint): result for result in after}
    keys = list(before_map) + [key for key in after_map if key not in before_map]

    table = Table(title=Text(title))
    table.add_column("Probe")
    table.add_column("Endpoint")
    table.add_column("Before")
    table.add_column("After")
    table.add_column("Outcome")
    for key in keys:
        prior = before_map.get(key)
        later = after_map.get(key)
        table.add_row(
            Text(key[0]),
            Text(key[1]),
            _status_cell(prior.status) if prior else Text("—"),
            _status_cell(later.status) if later else Text("—"),
            Text(_outcome(prior, later), style="bold"),
        )
    console.print(table)
    console.print(Text(escape(DISCLAIMER), style="dim"))
