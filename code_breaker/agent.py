"""Pydantic AI agent that finds and fixes the IDOR bug through tools."""

import contextlib
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

import httpx
from pydantic_ai import Agent, RunContext
from pydantic_ai.messages import ToolCallPart, ToolReturnPart

from code_breaker import patch
from code_breaker.harness import run_target
from code_breaker.probes import idor_probe

SYSTEM_PROMPT = """You are code-breaker, a security agent with exactly one job:
find and fix the IDOR bug on the wallet-read endpoint of the target API.

Work only through your tools:
1. Call list_target_endpoints to find the wallet-read endpoint (a GET route
   containing {wallet_id}).
2. Confirm the bug with run_idor_probe using that endpoint's path as a
   template, for example /wallets/{wallet_id}.
3. Read the Python file that implements it with read_target_file.
4. Write ONE exact-match edit with apply_patch. `old` must be a snippet that
   appears exactly once in the current file, and `new` must add an ownership
   check that returns 403 when the wallet does not belong to the caller.
5. Re-run run_idor_probe against the same path template to verify the fix.

If the probe still does not pass, read the file again and try a different
exact edit, within the attempt limit you are given. Never claim the bug is
fixed in your own words: your final answer must report only the final probe
status (PASS, FAIL or INCONCLUSIVE)."""

USER_PROMPT = "Find the wallet-read endpoint, confirm the IDOR bug, fix it, and verify the fix."


@dataclass
class AgentDeps:
    """Everything the tools need: a live target, a workspace copy and the identities."""

    base_url: str
    workspace: Path
    attacker: dict[str, str]
    victim_wallet_id: str
    # Set by run_idor_agent: reboots the target from the workspace after a real edit,
    # because a running server keeps the module it imported at startup.
    restart: Callable[[], None] | None = field(default=None, repr=False)


def build_agent(model=None) -> Agent[AgentDeps, str]:
    """Create the IDOR agent with its four tools; model defaults to the provider default."""
    agent: Agent[AgentDeps, str] = Agent(
        model,
        deps_type=AgentDeps,
        system_prompt=SYSTEM_PROMPT,
        name="code-breaker-idor",
    )

    @agent.tool
    def list_target_endpoints(ctx: RunContext[AgentDeps]) -> list[dict[str, object]]:
        """List the target's endpoints with their method, path and auth requirement."""
        schema = httpx.get(f"{ctx.deps.base_url}/openapi.json", timeout=5).json()
        endpoints = []
        for path, operations in schema.get("paths", {}).items():
            for method, operation in operations.items():
                if method.lower() not in {"get", "post", "put", "patch", "delete"}:
                    continue
                endpoints.append(
                    {
                        "method": method.upper(),
                        "path": path,
                        "requires_auth": bool(operation.get("security")),
                    }
                )
        return endpoints

    @agent.tool
    def run_idor_probe(ctx: RunContext[AgentDeps], path_template: str) -> dict:
        """Attack the victim's wallet with the attacker's token and return the probe result."""
        result = idor_probe(
            ctx.deps.base_url,
            ctx.deps.attacker,
            ctx.deps.victim_wallet_id,
            path_template=path_template,
        )
        return result.model_dump()

    @agent.tool
    def read_target_file(ctx: RunContext[AgentDeps], rel_path: str) -> str:
        """Read a .py file from the workspace copy of the target app."""
        return patch.read_file(ctx.deps.workspace, rel_path)

    @agent.tool
    def apply_patch(ctx: RunContext[AgentDeps], rel_path: str, old: str, new: str) -> dict:
        """Apply one exact-match edit to the workspace copy and return ok, message and diff."""
        result = patch.apply_edit(ctx.deps.workspace, rel_path, old, new)
        if result.ok and ctx.deps.restart is not None:
            ctx.deps.restart()
        return {"ok": result.ok, "message": result.message, "diff": result.diff}

    return agent


def run_idor_agent(agent: Agent[AgentDeps, str], deps: AgentDeps, max_attempts: int = 3) -> dict:
    """Run the agent until the IDOR probe passes or max_attempts patches are spent.

    The return values come from the tool traffic, not from the model's prose:
    endpoint_tried is the last run_idor_probe path template, attempts counts
    apply_patch calls, final_status is the last run_idor_probe status, and
    diff is the last non-empty apply_patch diff.
    """
    endpoint_tried: str | None = None
    final_status = "INCONCLUSIVE"
    attempts = 0
    diff: str | None = None
    history = None

    with contextlib.ExitStack() as stack:

        def restart() -> None:
            server = stack.enter_context(run_target(app_dir=str(deps.workspace)))
            deps.base_url = str(server)

        deps.restart = restart

        while attempts < max_attempts and final_status != "PASS":
            patches_before = attempts
            result = agent.run_sync(USER_PROMPT, deps=deps, message_history=history)
            history = result.all_messages()

            for message in result.new_messages():
                for part in getattr(message, "parts", []):
                    if isinstance(part, ToolCallPart) and part.tool_name == "run_idor_probe":
                        if isinstance(part.args, dict):
                            endpoint_tried = part.args.get("path_template", endpoint_tried)
                    elif isinstance(part, ToolCallPart) and part.tool_name == "apply_patch":
                        attempts += 1
                    elif isinstance(part, ToolReturnPart) and part.tool_name == "run_idor_probe":
                        if isinstance(part.content, dict):
                            final_status = str(part.content.get("status", final_status))
                    elif isinstance(part, ToolReturnPart) and part.tool_name == "apply_patch":
                        if isinstance(part.content, dict) and part.content.get("diff"):
                            diff = str(part.content["diff"])

            if attempts == patches_before:
                break

    return {
        "endpoint_tried": endpoint_tried,
        "final_status": final_status,
        "attempts": attempts,
        "diff": diff,
    }