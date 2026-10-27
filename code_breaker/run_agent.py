"""End-to-end CLI: probe the original, let the agent patch IDOR, re-probe, compare."""

import argparse
import json
import os
import re
import sys
import traceback
from pathlib import Path

from dotenv import load_dotenv
from pydantic_ai.exceptions import UsageLimitExceeded
from rich.console import Console
from rich.text import Text

from code_breaker.agent import (
    AgentDeps,
    RepeatedToolCallError,
    build_agent,
    run_idor_agent,
)
from code_breaker.harness import run_target
from code_breaker.patch import cleanup_workspace, make_workspace
from code_breaker.report import render_comparison, render_report
from code_breaker.scan import run_probes

DEFAULT_MODEL = "groq:openai/gpt-oss-120b"
REPO_ROOT = Path(__file__).resolve().parents[1]
ALICE = {"username": "alice", "password": "password1", "wallet_id": "W_A"}
MISSING_KEY_HINT = "copy .env.example to .env and fill in GROQ_API_KEY."
FAILURE_HINT = "the run stopped here; re-run with --debug for the tool transcript."
CLIP_CHARS = 300
TRANSCRIPT_ARG_CHARS = 120

REDACTIONS = (
    re.compile(r"Bearer[ \t]+\S+", re.IGNORECASE),
    re.compile(r"gsk_[A-Za-z0-9_\-]{6,}"),
    re.compile(r"\b[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"),
    re.compile(r"(?i)\b(api[_-]?key|access[_-]?token|password)\b\s*[:=]\s*[\"']?[^\s,}\"']{4,}"),
)


def _scrub(text: str) -> str:
    """Replace anything token- or key-shaped before it can reach the terminal."""
    for pattern in REDACTIONS:
        text = pattern.sub("<redacted>", text)
    return text


def _clip(value: object, limit: int = CLIP_CHARS) -> str:
    """Scrub a value and truncate it for the transcript."""
    text = _scrub(str(value))
    return text if len(text) <= limit else f"{text[:limit]}…"


def _status_code(error: BaseException) -> int | None:
    for candidate in (
        getattr(error, "status_code", None),
        getattr(getattr(error, "response", None), "status_code", None),
    ):
        if isinstance(candidate, int):
            return candidate
    return None


def _describe_error(error: BaseException, model_name: str) -> str:
    """Class name, module, HTTP status and model name. Never the message."""
    parts = [f"{type(error).__module__}.{type(error).__name__}"]
    status = _status_code(error)
    if status is not None:
        parts.append(f"HTTP {status}")
    parts.append(f"model={model_name}")
    parts.append(FAILURE_HINT)
    return " | ".join(parts)


def _traceback_without_message() -> str:
    """Frames only: the final 'ExceptionType: message' line is replaced by the type."""
    exc_type, exc, tb = sys.exc_info()
    if exc_type is None:
        return ""
    lines = traceback.format_exception(exc_type, exc, tb)
    lines[-1] = f"{exc_type.__module__}.{exc_type.__name__}\n"
    return "".join(lines)


def _render_transcript(deps: AgentDeps | None, usage: dict | None, console: Console) -> None:
    """Print every tool call the model made, clipped and scrubbed, plus usage."""
    console.print(Text("--- transcript ---", style="bold"))
    entries = deps.transcript if deps is not None else []
    if not entries:
        console.print(Text("(no tool calls recorded)"))
    for entry in entries:
        console.print(Text(f"tool: {entry['tool']}"))
        console.print(Text(f"  args: {_clip(entry['args'])}"))
        console.print(Text(f"  result: {_clip(entry['result'])}"))
    console.print(Text(f"usage: {usage if usage else 'unavailable'}"))


def _make_reporter(console: Console):
    """Stream one scrubbed line per tool call, as it happens."""

    def report(entry: dict) -> None:
        line = (
            f"tool {entry['index']}: {entry['tool']} "
            f"{_clip(entry['args'], TRANSCRIPT_ARG_CHARS)} -> {entry['outcome']}"
        )
        console.print(Text(line))

    return report


def _payload(results_before, results_after, outcome) -> dict:
    """JSON-safe report of a run; contains no credentials or tokens."""
    return {
        "results_before": [result.model_dump() for result in results_before],
        "results_after": [result.model_dump() for result in results_after],
        "agent": {
            "endpoint_tried": outcome["endpoint_tried"],
            "final_status": outcome["final_status"],
            "attempts": outcome["attempts"],
        },
        "diff": outcome["diff"],
    }


def main(argv: list[str] | None = None) -> int:
    """Run the whole flow and return a process exit code."""
    parser = argparse.ArgumentParser(
        prog="code_breaker.run_agent",
        description="Probe the original target, let the agent fix IDOR, then compare.",
    )
    parser.add_argument("--save", type=Path, default=None, help="write the run report as JSON here")
    parser.add_argument(
        "--debug",
        action="store_true",
        help="on failure, also print the tool transcript, usage and a message-free traceback",
    )
    args = parser.parse_args(argv)

    load_dotenv()
    console = Console()
    model_name = os.environ.get("CODE_BREAKER_MODEL", DEFAULT_MODEL)

    if not os.environ.get("GROQ_API_KEY"):
        console.print(Text(f"GROQ_API_KEY is not set - {MISSING_KEY_HINT}", style="red"))
        return 2

    workspace: Path | None = None
    deps: AgentDeps | None = None
    usage: dict | None = None
    try:
        console.print(Text("BEFORE: probing the original target", style="bold"))
        with run_target() as server:
            results_before = run_probes(str(server))

        workspace = make_workspace(REPO_ROOT)
        console.print(Text(f"PATCH: agent {model_name} working in {workspace}", style="bold"))
        agent = build_agent(model_name)
        with run_target(app_dir=str(workspace)) as initial:
            deps = AgentDeps(
                base_url=str(initial),
                workspace=workspace,
                attacker=ALICE,
                victim_wallet_id="W_B",
                report=_make_reporter(console),
            )
            outcome = run_idor_agent(agent, deps)
        usage = outcome["usage"]

        console.print(
            Text(
                f"agent: endpoint tried {outcome['endpoint_tried']} · "
                f"final status {outcome['final_status']} · attempts {outcome['attempts']}"
            )
        )
        if outcome["diff"]:
            console.print(Text(outcome["diff"]))

        console.print(Text("AFTER: probing the agent-patched workspace", style="bold"))
        with run_target(app_dir=str(workspace)) as server:
            results_after = run_probes(str(server))

        render_report(results_before, console=console, title="BEFORE: original target")
        render_report(results_after, console=console, title="AFTER: agent-patched workspace")
        render_comparison(results_before, results_after, console=console)

        if args.save is not None:
            args.save.parent.mkdir(parents=True, exist_ok=True)
            args.save.write_text(
                json.dumps(_payload(results_before, results_after, outcome), indent=2),
                encoding="utf-8",
            )
            console.print(Text(f"saved report to {args.save}"))

        if args.debug:
            _render_transcript(deps, usage, console)
    except KeyboardInterrupt:
        console.print(Text("stopped: interrupted - transcript so far", style="red"))
        _render_transcript(deps, usage, console)
        return 130
    except RepeatedToolCallError as error:
        console.print(
            Text(f"stopped: model repeated the same call {error.count} times", style="red")
        )
        _render_transcript(deps, usage, console)
        return 1
    except UsageLimitExceeded:
        console.print(Text("stopped: model request limit reached", style="red"))
        _render_transcript(deps, usage, console)
        return 1
    except Exception as error:  # noqa: BLE001 - diagnose without ever printing the message
        console.print(Text(_describe_error(error, model_name), style="red"))
        if args.debug:
            _render_transcript(deps, usage, console)
            console.print(Text("--- traceback (message removed) ---", style="bold"))
            console.print(Text(_traceback_without_message()))
        return 1
    finally:
        if workspace is not None:
            cleanup_workspace(workspace)

    return 0


if __name__ == "__main__":
    sys.exit(main())