"""Agent tests: the tools run for real, only the model is scripted (FunctionModel)."""

import hashlib
import os
from pathlib import Path

import pytest
from pydantic_ai.messages import (
    ModelResponse,
    TextPart,
    ToolCallPart,
    ToolReturnPart,
    UserPromptPart,
)
from pydantic_ai.models.function import FunctionModel

os.environ.setdefault("PYDANTIC_AI_NO_BANNER", "1")

from code_breaker.agent import AgentDeps, build_agent, run_idor_agent  # noqa: E402
from code_breaker.harness import run_target  # noqa: E402
from code_breaker.patch import cleanup_workspace, make_workspace, read_file  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]
MAIN = "target_app/main.py"
ALICE = {"username": "alice", "password": "password1", "wallet_id": "W_A"}

IDOR_OLD = """    # VULN: IDOR - no ownership check
    for owner, user in USERS.items():
        if user["wallet"] == wallet_id:
            return {"wallet_id": wallet_id, "owner": owner, "balance": user["balance"]}
"""

IDOR_NEW = """    # FIXED: ownership check
    for owner, user in USERS.items():
        if user["wallet"] == wallet_id:
            if owner != username:
                raise HTTPException(status_code=403, detail="Wallet does not belong to you")
            return {"wallet_id": wallet_id, "owner": owner, "balance": user["balance"]}
"""


def _calls_this_turn(messages) -> int:
    """Count tool calls made since the latest user prompt, across run histories."""
    count = 0
    for message in reversed(messages):
        parts = getattr(message, "parts", [])
        if any(isinstance(part, UserPromptPart) for part in parts):
            break
        count += sum(1 for part in parts if isinstance(part, ToolCallPart))
    return count


def scripted_model(steps: list[tuple[str, dict]]):
    """Return a FunctionModel that replays (tool_name, args) in order, one per turn."""

    def script(messages, info) -> ModelResponse:
        index = _calls_this_turn(messages)
        if index < len(steps):
            name, args = steps[index]
            return ModelResponse(parts=[ToolCallPart(name, args)])
        return ModelResponse(parts=[TextPart("reporting the final probe status")])

    return FunctionModel(script)


def _deps(server: str, workspace: Path) -> AgentDeps:
    return AgentDeps(base_url=server, workspace=workspace, attacker=ALICE, victim_wallet_id="W_B")


def test_agent_happy_path() -> None:
    workspace = make_workspace(REPO_ROOT)
    try:
        with run_target(app_dir=str(workspace)) as server:
            steps = [
                ("list_target_endpoints", {}),
                ("run_idor_probe", {"path_template": "/wallets/{wallet_id}"}),
                ("read_target_file", {"rel_path": MAIN}),
                ("apply_patch", {"rel_path": MAIN, "old": IDOR_OLD, "new": IDOR_NEW}),
                ("run_idor_probe", {"path_template": "/wallets/{wallet_id}"}),
            ]
            agent = build_agent(scripted_model(steps))
            outcome = run_idor_agent(agent, _deps(str(server), workspace))
    finally:
        cleanup_workspace(workspace)

    assert outcome["final_status"] == "PASS"
    assert outcome["attempts"] == 1
    assert outcome["endpoint_tried"] == "/wallets/{wallet_id}"
    assert outcome["diff"]
    assert "403" in outcome["diff"]


def test_agent_gives_up_after_max_attempts() -> None:
    workspace = make_workspace(REPO_ROOT)
    try:
        with run_target(app_dir=str(workspace)) as server:
            steps = [
                (
                    "apply_patch",
                    {"rel_path": MAIN, "old": "snippet that is not in the file", "new": "x"},
                )
            ]
            agent = build_agent(scripted_model(steps))
            outcome = run_idor_agent(agent, _deps(str(server), workspace), max_attempts=3)
    finally:
        cleanup_workspace(workspace)

    assert outcome["attempts"] == 3
    assert outcome["final_status"] != "PASS"


@pytest.mark.parametrize("bad_path", ["../main.py", str(REPO_ROOT / MAIN)])
def test_agent_never_patches_outside_workspace(bad_path: str) -> None:
    real_main = REPO_ROOT / MAIN
    before = hashlib.sha256(real_main.read_bytes()).hexdigest()
    workspace = make_workspace(REPO_ROOT)
    try:
        with run_target(app_dir=str(workspace)) as server:
            steps = [
                (
                    "apply_patch",
                    {
                        "rel_path": bad_path,
                        "old": 'SECRET_KEY = "super-secret-key"',
                        "new": 'SECRET_KEY = "hijacked"',
                    },
                )
            ]
            agent = build_agent(scripted_model(steps))
            result = agent.run_sync("go", deps=_deps(str(server), workspace))

        returns = [
            part
            for message in result.new_messages()
            for part in getattr(message, "parts", [])
            if isinstance(part, ToolReturnPart) and part.tool_name == "apply_patch"
        ]
        assert returns, "apply_patch was never called"
        assert returns[0].content["ok"] is False
        assert "escapes" in returns[0].content["message"]

        assert hashlib.sha256(real_main.read_bytes()).hexdigest() == before
        assert 'SECRET_KEY = "super-secret-key"' in read_file(workspace, MAIN)
    finally:
        cleanup_workspace(workspace)

def test_read_target_file_bad_path_is_reported_to_the_model() -> None:
    """A rejected path comes back as an error the model can correct, not a crash."""
    workspace = make_workspace(REPO_ROOT)
    try:
        with run_target(app_dir=str(workspace)) as server:
            steps = [
                ("read_target_file", {"rel_path": "../main.py"}),
                ("read_target_file", {"rel_path": MAIN}),
            ]
            agent = build_agent(scripted_model(steps))
            deps = _deps(str(server), workspace)
            outcome = run_idor_agent(agent, deps)
    finally:
        cleanup_workspace(workspace)

    rejected, accepted = deps.transcript
    assert rejected["tool"] == "read_target_file"
    assert rejected["result"]["ok"] is False
    assert rejected["result"]["error"] == "ValueError"
    assert "def get_current_user" in accepted["result"]
    assert outcome["final_status"] != "PASS"


def test_apply_patch_bad_path_is_reported_to_the_model() -> None:
    """A rejected edit comes back as ok=False with a reason, then the good edit applies."""
    workspace = make_workspace(REPO_ROOT)
    try:
        with run_target(app_dir=str(workspace)) as server:
            steps = [
                ("apply_patch", {"rel_path": "../main.py", "old": IDOR_OLD, "new": IDOR_NEW}),
                ("apply_patch", {"rel_path": MAIN, "old": IDOR_OLD, "new": IDOR_NEW}),
            ]
            agent = build_agent(scripted_model(steps))
            deps = _deps(str(server), workspace)
            run_idor_agent(agent, deps, max_attempts=2)
    finally:
        cleanup_workspace(workspace)

    rejected, accepted = deps.transcript
    assert rejected["tool"] == "apply_patch"
    assert rejected["result"]["ok"] is False
    assert "escapes" in rejected["result"]["message"]
    assert accepted["result"]["ok"] is True
    assert "403" in accepted["result"]["diff"]
