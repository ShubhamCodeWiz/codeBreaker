"""End-to-end CLI: probe the original, let the agent patch IDOR, re-probe, compare."""

import argparse
import json
import os
import sys
from pathlib import Path

from dotenv import load_dotenv
from rich.console import Console
from rich.text import Text

from code_breaker.agent import AgentDeps, build_agent, run_idor_agent
from code_breaker.harness import run_target
from code_breaker.patch import cleanup_workspace, make_workspace
from code_breaker.report import render_comparison, render_report
from code_breaker.scan import run_probes

DEFAULT_MODEL = "groq:openai/gpt-oss-120b"
REPO_ROOT = Path(__file__).resolve().parents[1]
ALICE = {"username": "alice", "password": "password1", "wallet_id": "W_A"}
MISSING_KEY_HINT = "copy .env.example to .env and fill in GROQ_API_KEY."
FAILURE_HINT = "model call failed (rate limit, network or bad key); check your key and retry."


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
    args = parser.parse_args(argv)

    load_dotenv()
    console = Console()
    model_name = os.environ.get("CODE_BREAKER_MODEL", DEFAULT_MODEL)

    if not os.environ.get("GROQ_API_KEY"):
        console.print(Text(f"GROQ_API_KEY is not set - {MISSING_KEY_HINT}", style="red"))
        return 2

    workspace: Path | None = None
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
            )
            outcome = run_idor_agent(agent, deps)

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
    except Exception as error:  # noqa: BLE001 - never leak the message, it may hold secrets
        console.print(Text(f"{type(error).__name__}: {FAILURE_HINT}", style="red"))
        return 1
    finally:
        if workspace is not None:
            cleanup_workspace(workspace)

    return 0


if __name__ == "__main__":
    sys.exit(main())