"""Pydantic AI agents that find and fix the IDOR and missing-auth bugs through tools."""

import contextlib
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

import httpx
from pydantic_ai import Agent, RunContext
from pydantic_ai.usage import UsageLimits

from code_breaker import patch
from code_breaker.harness import run_target
from code_breaker.probes import idor_probe, unauthenticated_access_probe

SYSTEM_PROMPT = """You are code-breaker, a security agent with one job: find and
fix the IDOR bug on the wallet-read endpoint of the target API.

Follow this order:
1. list_target_endpoints and pick the wallet-read endpoint, a GET route
   containing {wallet_id}.
2. run_idor_probe on that path template to confirm the bug.
3. list_target_files and pick the file that contains that route. Every path
   must come from list_target_files; never guess or invent a file name.
4. read_target_file on that path. Read a window of about 40 lines around the
   route if the tool supports start_line/end_line, otherwise read the file once.
5. apply_patch with ONE exact-match edit that adds an ownership check returning
   403 when the wallet does not belong to the authenticated caller.
6. run_idor_probe again on the same path template to verify the fix.
7. Report only the final probe status (PASS, FAIL or INCONCLUSIVE). Never claim
   the bug is fixed in your own words.

Tools return an object with "error" and "valid_files" when a path fails. Use
the listed valid_files on your next call instead of guessing another path.
Repeating one identical call is a hard error: never send the same tool call
twice without changing the arguments."""

USER_PROMPT = "Find the wallet-read endpoint, confirm the IDOR bug, fix it, and verify the fix."

AUTH_SYSTEM_PROMPT = """You are code-breaker, a security agent with one job: close the
missing-auth bug on the wallet-transactions endpoint of the target API.

Follow this order:
1. list_target_endpoints and pick the GET endpoint whose path contains {wallet_id}
   and whose requires_auth is False. Keep its path as the template.
2. Confirm the bug with BOTH run_unauth_probe and run_idor_probe on that same path
   template.
3. list_target_files and pick the file that contains that route. Every path must
   come from list_target_files; never guess or invent a file name.
4. read_target_file on that path once.
5. apply_patch with ONE exact-match edit that (a) makes the endpoint require
   get_current_user and (b) returns 403 when the wallet belongs to another user,
   while keeping 404 for an unknown wallet.
6. Re-run BOTH probes on the same path template.
7. If either probe is not PASS, read the file once more and try one more edit, at
   most 3 patch attempts in total.
8. Report only the probe statuses (PASS, FAIL or INCONCLUSIVE). Never claim the
   bug is fixed in your own words.

Tools return an object with "error" and "valid_files" when a path fails. Use the
listed valid_files on your next call instead of guessing another path.
Repeating one identical call is a hard error: never send the same tool call twice
without changing the arguments."""

AUTH_USER_PROMPT = (
    "Find the transactions endpoint that needs no token, confirm the bug with both "
    "probes, fix it, and verify both probes pass."
)

AUTH_TEMPLATE = "/wallets/{wallet_id}/transactions"

MAX_RECORDED_CHARS = 2000
TOOL_FAILURE_TEXT = "tool failed; check the arguments and try again"
REPEAT_LIMIT = 3
REQUEST_LIMIT = 12


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
    owner: dict[str, str]
    victim_wallet_id: str
    # Set by run_idor_agent and run_auth_agent: reboots the target from the
    # workspace after a real edit, because a running server keeps the module it
    # imported at startup.
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


def _valid_files(workspace: Path) -> list[str]:
    """The workspace paths the model may use, so it never has to guess a name."""
    try:
        return patch.list_files(workspace)
    except OSError:
        return []


def _failure(
    deps: AgentDeps,
    tool: str,
    args: dict,
    error: BaseException,
    with_paths: bool = False,
) -> dict:
    """Build a fixed-text error result: class name only, never the raw message."""
    result: dict = {"ok": False, "error": type(error).__name__, "message": TOOL_FAILURE_TEXT}
    if with_paths:
        result["valid_files"] = _valid_files(deps.workspace)
    _finish(deps, tool, args, result)
    return result


def _build_agent(model, system_prompt: str, name: str) -> Agent[AgentDeps, str]:
    """Create an agent with the shared toolset and the given prompt."""
    agent: Agent[AgentDeps, str] = Agent(
        model,
        deps_type=AgentDeps,
        system_prompt=system_prompt,
        name=name,
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
    def list_target_files(ctx: RunContext[AgentDeps]) -> list[str]:
        """List the workspace's .py paths, e.g. 'target_app/main.py'; use these, never guess."""
        args: dict = {}
        paths = _valid_files(ctx.deps.workspace)
        _finish(ctx.deps, "list_target_files", args, paths)
        return paths

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
    def run_unauth_probe(ctx: RunContext[AgentDeps], path_template: str) -> dict:
        """Reach the victim's route without a token and return the probe result.

        The victim's wallet id is substituted into the template, and the owner's
        token is used for the control request, so the probe can tell a closed
        route apart from one that was merely broken.
        """
        args = {"path_template": path_template}
        path = path_template.format(wallet_id=ctx.deps.victim_wallet_id)
        try:
            result = unauthenticated_access_probe(ctx.deps.base_url, ctx.deps.owner, path)
        except httpx.HTTPError as error:
            return _failure(ctx.deps, "run_unauth_probe", args, error)

        payload = result.model_dump()
        _finish(ctx.deps, "run_unauth_probe", args, payload)
        return payload

    @agent.tool
    def read_target_file(ctx: RunContext[AgentDeps], rel_path: str) -> str | dict:
        """Read a .py file from the workspace copy of the target app."""
        args = {"rel_path": rel_path}
        try:
            text = patch.read_file(ctx.deps.workspace, rel_path)
        except (ValueError, OSError, httpx.HTTPError) as error:
            return _failure(ctx.deps, "read_target_file", args, error, with_paths=True)

        _finish(ctx.deps, "read_target_file", args, text)
        return text

    @agent.tool
    def apply_patch(ctx: RunContext[AgentDeps], rel_path: str, old: str, new: str) -> dict:
        """Apply one exact-match edit to the workspace copy and return ok, message and diff."""
        args = {"rel_path": rel_path, "old": old, "new": new}
        try:
            result = patch.apply_edit(ctx.deps.workspace, rel_path, old, new)
        except (ValueError, OSError, httpx.HTTPError) as error:
            return _failure(ctx.deps, "apply_patch", args, error, with_paths=True)

        if result.ok and ctx.deps.restart is not None:
            ctx.deps.restart()
        payload: dict = {"ok": result.ok, "message": result.message, "diff": result.diff}
        if not result.ok:
            payload["valid_files"] = _valid_files(ctx.deps.workspace)
        _finish(ctx.deps, "apply_patch", args, payload)
        return payload

    return agent


def build_agent(model=None) -> Agent[AgentDeps, str]:
    """Create the IDOR agent; model defaults to the provider default."""
    return _build_agent(model, SYSTEM_PROMPT, "code-breaker-idor")


def build_auth_agent(model=None) -> Agent[AgentDeps, str]:
    """Create the missing-auth agent for the transactions endpoint."""
    return _build_agent(model, AUTH_SYSTEM_PROMPT, "code-breaker-auth")


def _summary(transcript: list[dict]) -> dict:
    """Read the run's headline facts from the tool traffic, never from the model's prose."""
    endpoint_tried: str | None = None
    final_status = "NOT_RUN"
    attempts = 0
    diff: str | None = None

    for entry in transcript:
        tool = entry.get("tool")
        args = entry.get("args")
        result = entry.get("result")
        if tool == "run_idor_probe":
            if isinstance(args, dict):
                endpoint_tried = args.get("path_template", endpoint_tried)
            if isinstance(result, dict) and "status" in result:
                final_status = str(result["status"])
        elif tool == "apply_patch":
            attempts += 1
            if isinstance(result, dict) and result.get("ok") is True and result.get("diff"):
                diff = str(result["diff"])

    return {
        "endpoint_tried": endpoint_tried,
        "final_status": final_status,
        "attempts": attempts,
        "diff": diff,
    }


def _auth_summary(transcript: list[dict]) -> dict:
    """Read the auth run's facts from its own tool traffic, not the model's prose."""
    endpoint_tried: str | None = None
    unauth_status: str | None = None
    idor_status: str | None = None
    unauth_ran = False
    idor_ran = False
    attempts = 0
    diff: str | None = None

    for entry in transcript:
        tool = entry.get("tool")
        args = entry.get("args")
        result = entry.get("result")
        if tool == "run_unauth_probe":
            unauth_ran = True
            if isinstance(args, dict):
                endpoint_tried = args.get("path_template", endpoint_tried)
            if isinstance(result, dict) and "status" in result:
                unauth_status = str(result["status"])
        elif tool == "run_idor_probe":
            if isinstance(args, dict) and args.get("path_template") == AUTH_TEMPLATE:
                idor_ran = True
                endpoint_tried = args.get("path_template", endpoint_tried)
                if isinstance(result, dict) and "status" in result:
                    idor_status = str(result["status"])
        elif tool == "apply_patch":
            attempts += 1
            if isinstance(result, dict) and result.get("ok") is True and result.get("diff"):
                diff = str(result["diff"])

    if not unauth_ran or not idor_ran:
        final_status = "NOT_RUN"
    elif unauth_status == "PASS" and idor_status == "PASS":
        final_status = "PASS"
    else:
        final_status = "FAIL"

    return {
        "endpoint_tried": endpoint_tried,
        "final_status": final_status,
        "attempts": attempts,
        "diff": diff,
        "probe_statuses": {
            "unauthenticated_access": unauth_status,
            "idor_transactions": idor_status,
        },
    }


def run_idor_agent(
    agent: Agent[AgentDeps, str],
    deps: AgentDeps,
    max_attempts: int = 3,
    request_limit: int = REQUEST_LIMIT,
) -> dict:
    """Run the agent until the IDOR probe passes or max_attempts patches are spent.

    Each run_sync call carries a hard UsageLimits request cap, and the tools
    refuse an identical third call, so neither the model nor the loop can spin.
    The return values are derived from deps.transcript, which records every tool
    call and its result, so they survive how a provider splits its messages.
    """
    start = len(deps.transcript)
    summary = _summary(deps.transcript[start:])
    usage: dict | None = None
    history = None

    with contextlib.ExitStack() as stack:

        def restart() -> None:
            server = stack.enter_context(run_target(app_dir=str(deps.workspace)))
            deps.base_url = str(server)

        deps.restart = restart

        while summary["attempts"] < max_attempts and summary["final_status"] != "PASS":
            patches_before = summary["attempts"]
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

            summary = _summary(deps.transcript[start:])
            if summary["attempts"] == patches_before:
                break

    return {**summary, "usage": usage}


def run_auth_agent(
    agent: Agent[AgentDeps, str],
    deps: AgentDeps,
    max_attempts: int = 3,
    request_limit: int = REQUEST_LIMIT,
) -> dict:
    """Run the agent until both transactions probes pass or max_attempts are spent.

    Only the tool calls this run records are considered, so the earlier IDOR
    run's transcript cannot change the verdict. The request cap, the repeat
    guard and the restart mechanism are the same ones run_idor_agent uses.
    """
    start = len(deps.transcript)
    summary = _auth_summary(deps.transcript[start:])
    history = None

    with contextlib.ExitStack() as stack:

        def restart() -> None:
            server = stack.enter_context(run_target(app_dir=str(deps.workspace)))
            deps.base_url = str(server)

        deps.restart = restart

        while summary["attempts"] < max_attempts and summary["final_status"] != "PASS":
            patches_before = summary["attempts"]
            deps.turn_start = len(deps.transcript)
            result = agent.run_sync(
                AUTH_USER_PROMPT,
                deps=deps,
                message_history=history,
                usage_limits=UsageLimits(request_limit=request_limit),
            )
            history = result.all_messages()

            summary = _auth_summary(deps.transcript[start:])
            if summary["attempts"] == patches_before:
                break

    return summary