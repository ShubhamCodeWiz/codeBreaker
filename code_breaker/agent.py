"""Pydantic AI agent that finds and fixes the IDOR bug through tools."""

import contextlib
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

import httpx
from pydantic_ai import Agent, RunContext
from pydantic_ai.messages import ToolCallPart, ToolReturnPart
from pydantic_ai.usage import UsageLimits

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

Tools return an object with "error" when they fail. Read it and correct your
next call instead of repeating the same arguments. Repeating one identical
call is a hard error: never send the same tool call twice without changing
the arguments.

If the probe still does not pass, read the file again and try a different
exact edit, within the attempt limit you are given. Never claim the bug is
fixed in your own words: your final answer must report only the final probe
status (PASS, FAIL or INCONCLUSIVE)."""

USER_PROMPT = "Find the wallet-read endpoint, confirm the IDOR bug, fix it, and verify the fix."

MAX_RECORDED_CHARS = 2000
TOOL_FAILURE_TEXT = "tool failed; check the arguments and try again"
REPEAT_LIMIT = 3
REQUEST_LIMIT = 10


class RepeatedToolCallError(RuntimeError):
    """Raised when the model repeats one identical tool call too many times in a run."""

    def __init__(self, tool: str, count: int) -> None:
        super().__init__(f"stopped: model repeated the same call {count} times")
        self.tool = tool
        self.count = count


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
    # One entry per tool call: {"tool": ..., "args": ..., "result": ...}.
    transcript: list[dict] = field(default_factory=list)
    # Called the moment a tool finishes, so the CLI can stream live progress.
    report: Callable[[dict], None] | None = field(default=None, repr=False)
    # Index in the transcript where the current run_sync started; the repeat guard
    # only looks at calls made inside the current run.
    turn_start: int = field(default=0, repr=False)


def _outcome(result: object) -> str:
    """A short label for the progress line: ok, the probe status, or the error class."""
    if isinstance(result, dict):
        if result.get("error"):
            return f"error {result['error']}"
        if result.get("ok") is False:
            return "error"
        if result.get("ok") is True:
            return "ok"
        if "status" in result:
            return str(result["status"])
    return "ok"


def _finish(deps: AgentDeps, tool: str, args: dict, result: object) -> None:
    """Record, announce and guard one tool call; raise if the model repeats itself."""
    stored = result
    if isinstance(stored, str) and len(stored) > MAX_RECORDED_CHARS:
        stored = stored[:MAX_RECORDED_CHARS]
    deps.transcript.append({"tool": tool, "args": args, "result": stored})

    if deps.report is not None:
        deps.report(
            {
                "index": len(deps.transcript),
                "tool": tool,
                "args": args,
                "outcome": _outcome(result),
            }
        )

    identical = sum(
        1
        for entry in deps.transcript[deps.turn_start :]
        if entry["tool"] == tool and entry["args"] == args
    )
    if identical >= REPEAT_LIMIT:
        raise RepeatedToolCallError(tool, identical)


def _failure(deps: AgentDeps, tool: str, args: dict, error: BaseException) -> dict:
    """Build a fixed-text error result: class name only, never the raw message."""
    result = {"ok": False, "error": type(error).__name__, "message": TOOL_FAILURE_TEXT}
    _finish(deps, tool, args, result)
    return result


def build_agent(model=None) -> Agent[AgentDeps, str]:
    """Create the IDOR agent with its four tools; model defaults to the provider default."""
    agent: Agent[AgentDeps, str] = Agent(
        model,
        deps_type=AgentDeps,
        system_prompt=SYSTEM_PROMPT,
        name="code-breaker-idor",
    )

    @agent.tool
    def list_target_endpoints(ctx: RunContext[AgentDeps]) -> list[dict] | dict:
        """List the target's endpoints with their method, path and auth requirement."""
        args: dict = {}
        try:
            schema = httpx.get(f"{ctx.deps.base_url}/openapi.json", timeout=5).json()
        except (httpx.HTTPError, ValueError) as error:
            return _failure(ctx.deps, "list_target_endpoints", args, error)

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
        _finish(ctx.deps, "list_target_endpoints", args, endpoints)
        return endpoints

    @agent.tool
    def run_idor_probe(ctx: RunContext[AgentDeps], path_template: str) -> dict:
        """Attack the victim's wallet with the attacker's token and return the probe result."""
        args = {"path_template": path_template}
        try:
            result = idor_probe(
                ctx.deps.base_url,
                ctx.deps.attacker,
                ctx.deps.victim_wallet_id,
                path_template=path_template,
            )
        except httpx.HTTPError as error:
            return _failure(ctx.deps, "run_idor_probe", args, error)

        payload = result.model_dump()
        _finish(ctx.deps, "run_idor_probe", args, payload)
        return payload

    @agent.tool
    def read_target_file(ctx: RunContext[AgentDeps], rel_path: str) -> str | dict:
        """Read a .py file from the workspace copy of the target app."""
        args = {"rel_path": rel_path}
        try:
            text = patch.read_file(ctx.deps.workspace, rel_path)
        except (ValueError, OSError, httpx.HTTPError) as error:
            return _failure(ctx.deps, "read_target_file", args, error)

        _finish(ctx.deps, "read_target_file", args, text)
        return text

    @agent.tool
    def apply_patch(ctx: RunContext[AgentDeps], rel_path: str, old: str, new: str) -> dict:
        """Apply one exact-match edit to the workspace copy and return ok, message and diff."""
        args = {"rel_path": rel_path, "old": old, "new": new}
        try:
            result = patch.apply_edit(ctx.deps.workspace, rel_path, old, new)
        except (ValueError, OSError, httpx.HTTPError) as error:
            return _failure(ctx.deps, "apply_patch", args, error)

        if result.ok and ctx.deps.restart is not None:
            ctx.deps.restart()
        payload = {"ok": result.ok, "message": result.message, "diff": result.diff}
        _finish(ctx.deps, "apply_patch", args, payload)
        return payload

    return agent


def run_idor_agent(
    agent: Agent[AgentDeps, str],
    deps: AgentDeps,
    max_attempts: int = 3,
    request_limit: int = REQUEST_LIMIT,
) -> dict:
    """Run the agent until the IDOR probe passes or max_attempts patches are spent.

    Each run_sync call carries a hard UsageLimits request cap, and the tools
    refuse an identical third call, so neither the model nor the loop can spin.
    The return values come from the tool traffic, not from the model's prose.
    """
    endpoint_tried: str | None = None
    final_status = "INCONCLUSIVE"
    attempts = 0
    diff: str | None = None
    usage: dict | None = None
    history = None

    with contextlib.ExitStack() as stack:

        def restart() -> None:
            server = stack.enter_context(run_target(app_dir=str(deps.workspace)))
            deps.base_url = str(server)

        deps.restart = restart

        while attempts < max_attempts and final_status != "PASS":
            patches_before = attempts
            deps.turn_start = len(deps.transcript)
            result = agent.run_sync(
                USER_PROMPT,
                deps=deps,
                message_history=history,
                usage_limits=UsageLimits(request_limit=request_limit),
            )
            history = result.all_messages()

            run_usage = getattr(result, "usage", None)
            if run_usage is not None and hasattr(run_usage, "model_dump"):
                usage = run_usage.model_dump()

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
        "usage": usage,
    }