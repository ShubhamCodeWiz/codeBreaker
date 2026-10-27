"""Agent tests: the tools run for real, only the model is scripted (FunctionModel)."""

import hashlib
import os
from pathlib import Path

import pytest
from pydantic_ai.exceptions import UsageLimitExceeded
from pydantic_ai.messages import (
    ModelResponse,
    TextPart,
    ToolCallPart,
    ToolReturnPart,
    UserPromptPart,
)
from pydantic_ai.models.function import FunctionModel

os.environ.setdefault("PYDANTIC_AI_NO_BANNER", "1")

from code_breaker.agent import (  # noqa: E402
    TOOL_FAILURE_TEXT,
    AgentDeps,
    RepeatedToolCallError,
    build_agent,
    build_auth_agent,
    run_auth_agent,
    run_idor_agent,
)
from code_breaker.harness import run_target  # noqa: E402
from code_breaker.patch import cleanup_workspace, make_workspace, read_file  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]
MAIN = "target_app/main.py"
ALICE = {"username": "alice", "password": "password1", "wallet_id": "W_A"}
BOB = {"username": "bob", "password": "password2"}
AUTH_TEMPLATE = "/wallets/{wallet_id}/transactions"

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

AUTH_OLD = '''# VULN: missing auth - no token required
@app.get("/wallets/{wallet_id}/transactions")
def read_transactions(wallet_id: str) -> dict[str, str | list[dict[str, str | int]]]:
    """Return a wallet's transactions. Intentionally unauthenticated: no ownership or token check."""
    if wallet_id not in TRANSACTIONS:
        raise HTTPException(status_code=404, detail="Wallet not found")
    return {"wallet_id": wallet_id, "transactions": TRANSACTIONS[wallet_id]}
'''

# First attempt: the token requirement alone. The wallet still belongs to
# someone else, so the IDOR probe on this same route must still FAIL.
AUTH_ONLY_NEW = '''# PARTIAL: token required, ownership still unchecked
@app.get("/wallets/{wallet_id}/transactions")
def read_transactions(
    wallet_id: str,
    username: Annotated[str, Depends(get_current_user)],
) -> dict[str, str | list[dict[str, str | int]]]:
    """Return a wallet's transactions to any authenticated caller."""
    if wallet_id not in TRANSACTIONS:
        raise HTTPException(status_code=404, detail="Wallet not found")
    return {"wallet_id": wallet_id, "transactions": TRANSACTIONS[wallet_id]}
'''

AUTH_ONLY_OLD = '''    """Return a wallet's transactions to any authenticated caller."""
    if wallet_id not in TRANSACTIONS:
        raise HTTPException(status_code=404, detail="Wallet not found")
    return {"wallet_id": wallet_id, "transactions": TRANSACTIONS[wallet_id]}
'''

AUTH_OWNERSHIP_NEW = '''    """Return a wallet's transactions to its owner only."""
    if wallet_id not in TRANSACTIONS:
        raise HTTPException(status_code=404, detail="Wallet not found")
    for owner, user in USERS.items():
        if user["wallet"] == wallet_id:
            if owner != username:
                raise HTTPException(status_code=403, detail="Wallet does not belong to you")
            break
    return {"wallet_id": wallet_id, "transactions": TRANSACTIONS[wallet_id]}
'''

AUTH_NEW = '''# FIXED: auth + ownership check
@app.get("/wallets/{wallet_id}/transactions")
def read_transactions(
    wallet_id: str,
    username: Annotated[str, Depends(get_current_user)],
) -> dict[str, str | list[dict[str, str | int]]]:
    """Return a wallet's transactions to its owner only."""
    if wallet_id not in TRANSACTIONS:
        raise HTTPException(status_code=404, detail="Wallet not found")
    for owner, user in USERS.items():
        if user["wallet"] == wallet_id:
            if owner != username:
                raise HTTPException(status_code=403, detail="Wallet does not belong to you")
            break
    return {"wallet_id": wallet_id, "transactions": TRANSACTIONS[wallet_id]}
'''


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


def scripted_turns(turns: list[list[tuple[str, dict]]]):
    """Return a FunctionModel that plays one script per run_sync turn."""

    def script(messages, info) -> ModelResponse:
        turn = (
            sum(
                isinstance(part, UserPromptPart)
                for message in messages
                for part in getattr(message, "parts", [])
            )
            - 1
        )
        steps = turns[turn] if 0 <= turn < len(turns) else []
        index = _calls_this_turn(messages)
        if index < len(steps):
            name, args = steps[index]
            return ModelResponse(parts=[ToolCallPart(name, args)])
        return ModelResponse(parts=[TextPart("reporting the final probe statuses")])

    return FunctionModel(script)


def _last_user_prompt(messages) -> str:
    """The text of the most recent user prompt in a run history."""
    for message in reversed(messages):
        for part in reversed(getattr(message, "parts", [])):
            if isinstance(part, UserPromptPart):
                return str(part.content)
    return ""


def scripted_by_prompt(scripts: dict[str, list[tuple[str, dict]]]):
    """Return a FunctionModel that picks its script from the latest user prompt."""

    def script(messages, info) -> ModelResponse:
        steps = scripts.get(_last_user_prompt(messages), [])
        index = _calls_this_turn(messages)
        if index < len(steps):
            name, args = steps[index]
            return ModelResponse(parts=[ToolCallPart(name, args)])
        return ModelResponse(parts=[TextPart("reporting the final probe statuses")])

    return FunctionModel(script)


def _deps(server: str, workspace: Path) -> AgentDeps:
    return AgentDeps(
        base_url=server,
        workspace=workspace,
        attacker=ALICE,
        owner=BOB,
        victim_wallet_id="W_B",
    )


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


LIVE_STEPS = [
    ("list_target_endpoints", {}),
    ("run_idor_probe", {"path_template": "/wallets/{wallet_id}"}),
    ("list_target_files", {}),
    ("read_target_file", {"rel_path": MAIN}),
    ("apply_patch", {"rel_path": MAIN, "old": IDOR_OLD, "new": IDOR_NEW}),
    ("run_idor_probe", {"path_template": "/wallets/{wallet_id}"}),
]


def test_summary_comes_from_the_transcript_on_the_live_sequence() -> None:
    """The live provider can split its messages differently; the tools still tell the story."""
    workspace = make_workspace(REPO_ROOT)
    try:
        with run_target(app_dir=str(workspace)) as server:
            agent = build_agent(scripted_model(LIVE_STEPS))
            deps = _deps(str(server), workspace)
            outcome = run_idor_agent(agent, deps)
    finally:
        cleanup_workspace(workspace)

    assert [entry["tool"] for entry in deps.transcript] == [name for name, _ in LIVE_STEPS]
    assert outcome["endpoint_tried"] == "/wallets/{wallet_id}"
    assert outcome["attempts"] == 1
    assert outcome["final_status"] == "PASS"
    assert outcome["diff"]


def test_no_probe_call_reports_not_run_without_crashing() -> None:
    workspace = make_workspace(REPO_ROOT)
    try:
        with run_target(app_dir=str(workspace)) as server:
            steps = [("list_target_files", {}), ("read_target_file", {"rel_path": MAIN})]
            agent = build_agent(scripted_model(steps))
            outcome = run_idor_agent(agent, _deps(str(server), workspace))
    finally:
        cleanup_workspace(workspace)

    assert outcome["final_status"] == "NOT_RUN"
    assert outcome["endpoint_tried"] is None
    assert outcome["attempts"] == 0


AUTH_STEPS = [
    ("list_target_endpoints", {}),
    ("run_unauth_probe", {"path_template": AUTH_TEMPLATE}),
    ("run_idor_probe", {"path_template": AUTH_TEMPLATE}),
    ("list_target_files", {}),
    ("read_target_file", {"rel_path": MAIN}),
    ("apply_patch", {"rel_path": MAIN, "old": AUTH_OLD, "new": AUTH_NEW}),
    ("run_unauth_probe", {"path_template": AUTH_TEMPLATE}),
    ("run_idor_probe", {"path_template": AUTH_TEMPLATE}),
]


def test_run_unauth_probe_tool_is_recorded() -> None:
    workspace = make_workspace(REPO_ROOT)
    try:
        with run_target(app_dir=str(workspace)) as server:
            steps = [("run_unauth_probe", {"path_template": AUTH_TEMPLATE})]
            deps = _deps(str(server), workspace)
            run_auth_agent(build_auth_agent(scripted_model(steps)), deps)
    finally:
        cleanup_workspace(workspace)

    entry = deps.transcript[0]
    assert entry["tool"] == "run_unauth_probe"
    assert entry["args"] == {"path_template": AUTH_TEMPLATE}
    assert entry["result"]["probe"] == "unauthenticated_access"
    assert entry["result"]["endpoint"] == "/wallets/W_B/transactions"
    assert entry["result"]["status"] == "FAIL"


def test_auth_agent_happy_path() -> None:
    workspace = make_workspace(REPO_ROOT)
    try:
        with run_target(app_dir=str(workspace)) as server:
            deps = _deps(str(server), workspace)
            outcome = run_auth_agent(build_auth_agent(scripted_model(AUTH_STEPS)), deps)
    finally:
        cleanup_workspace(workspace)

    assert outcome["endpoint_tried"] == AUTH_TEMPLATE
    assert outcome["attempts"] == 1
    assert outcome["final_status"] == "PASS"
    assert outcome["probe_statuses"] == {
        "unauthenticated_access": "PASS",
        "idor_transactions": "PASS",
    }
    assert outcome["diff"]


def test_auth_agent_rejects_an_auth_only_fix_and_retries() -> None:
    """A token check alone leaves the IDOR open, so the second edit must add ownership."""
    first_turn = [
        ("list_target_endpoints", {}),
        ("run_unauth_probe", {"path_template": AUTH_TEMPLATE}),
        ("run_idor_probe", {"path_template": AUTH_TEMPLATE}),
        ("read_target_file", {"rel_path": MAIN}),
        ("apply_patch", {"rel_path": MAIN, "old": AUTH_OLD, "new": AUTH_ONLY_NEW}),
        ("run_unauth_probe", {"path_template": AUTH_TEMPLATE}),
        ("run_idor_probe", {"path_template": AUTH_TEMPLATE}),
    ]
    second_turn = [
        ("read_target_file", {"rel_path": MAIN}),
        ("apply_patch", {"rel_path": MAIN, "old": AUTH_ONLY_OLD, "new": AUTH_OWNERSHIP_NEW}),
        ("run_unauth_probe", {"path_template": AUTH_TEMPLATE}),
        ("run_idor_probe", {"path_template": AUTH_TEMPLATE}),
    ]
    workspace = make_workspace(REPO_ROOT)
    try:
        with run_target(app_dir=str(workspace)) as server:
            deps = _deps(str(server), workspace)
            agent = build_auth_agent(scripted_turns([first_turn, second_turn]))
            outcome = run_auth_agent(agent, deps)
    finally:
        cleanup_workspace(workspace)

    probes = [
        (entry["tool"], entry["result"]["status"])
        for entry in deps.transcript
        if entry["tool"] in {"run_unauth_probe", "run_idor_probe"}
    ]
    # After the auth-only edit the token requirement passes, ownership does not.
    assert probes[2] == ("run_unauth_probe", "PASS")
    assert probes[3] == ("run_idor_probe", "FAIL")
    assert outcome["attempts"] == 2
    assert outcome["final_status"] == "PASS"
    assert outcome["probe_statuses"] == {
        "unauthenticated_access": "PASS",
        "idor_transactions": "PASS",
    }


def test_auth_agent_without_probes_reports_not_run() -> None:
    workspace = make_workspace(REPO_ROOT)
    try:
        with run_target(app_dir=str(workspace)) as server:
            steps = [("list_target_files", {}), ("read_target_file", {"rel_path": MAIN})]
            agent = build_auth_agent(scripted_model(steps))
            outcome = run_auth_agent(agent, _deps(str(server), workspace))
    finally:
        cleanup_workspace(workspace)

    assert outcome["final_status"] == "NOT_RUN"
    assert outcome["probe_statuses"] == {
        "unauthenticated_access": None,
        "idor_transactions": None,
    }
    assert outcome["attempts"] == 0


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


def _repeating_model(tool: str, args: dict) -> FunctionModel:
    """A model that keeps issuing the exact same tool call forever."""

    def script(messages, info) -> ModelResponse:
        return ModelResponse(parts=[ToolCallPart(tool, args)])

    return FunctionModel(script)


def _endless_distinct_model() -> FunctionModel:
    """A model that issues a different (never-repeating) call every time."""

    def script(messages, info) -> ModelResponse:
        used = sum(
            1
            for message in messages
            for part in getattr(message, "parts", [])
            if isinstance(part, ToolCallPart)
        )
        return ModelResponse(parts=[ToolCallPart("read_target_file", {"rel_path": f"missing{used}.py"})])

    return FunctionModel(script)


def test_repeat_guard_stops_an_identical_call_after_three_tries() -> None:
    workspace = make_workspace(REPO_ROOT)
    try:
        with run_target(app_dir=str(workspace)) as server:
            agent = build_agent(_repeating_model("read_target_file", {"rel_path": "../main.py"}))
            deps = _deps(str(server), workspace)
            with pytest.raises(RepeatedToolCallError) as caught:
                run_idor_agent(agent, deps)
    finally:
        cleanup_workspace(workspace)

    assert "repeated the same call 3 times" in str(caught.value)
    identical = [entry for entry in deps.transcript if entry["tool"] == "read_target_file"]
    assert len(identical) == 3


def test_request_limit_stops_endless_distinct_calls() -> None:
    workspace = make_workspace(REPO_ROOT)
    try:
        with run_target(app_dir=str(workspace)) as server:
            agent = build_agent(_endless_distinct_model())
            deps = _deps(str(server), workspace)
            with pytest.raises(UsageLimitExceeded):
                run_idor_agent(agent, deps)
    finally:
        cleanup_workspace(workspace)

    assert len(deps.transcript) > 1


def test_keyboard_interrupt_escapes_a_tool_call(monkeypatch) -> None:
    def interrupt(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr("code_breaker.agent.patch.read_file", interrupt)
    workspace = make_workspace(REPO_ROOT)
    try:
        with run_target(app_dir=str(workspace)) as server:
            steps = [
                ("list_target_endpoints", {}),
                ("read_target_file", {"rel_path": MAIN}),
            ]
            agent = build_agent(scripted_model(steps))
            deps = _deps(str(server), workspace)
            with pytest.raises(KeyboardInterrupt):
                run_idor_agent(agent, deps)
    finally:
        cleanup_workspace(workspace)

    assert [entry["tool"] for entry in deps.transcript] == ["list_target_endpoints"]


HAPPY_STEPS_WITH_WRONG_GUESS = [
    ("list_target_endpoints", {}),
    ("run_idor_probe", {"path_template": "/wallets/{wallet_id}"}),
    ("read_target_file", {"rel_path": "wallets.py"}),
    ("read_target_file", {"rel_path": MAIN}),
    ("apply_patch", {"rel_path": MAIN, "old": IDOR_OLD, "new": IDOR_NEW}),
    ("run_idor_probe", {"path_template": "/wallets/{wallet_id}"}),
]


def test_guessed_path_recovers_via_valid_files_and_reaches_pass() -> None:
    workspace = make_workspace(REPO_ROOT)
    try:
        with run_target(app_dir=str(workspace)) as server:
            agent = build_agent(scripted_model(HAPPY_STEPS_WITH_WRONG_GUESS))
            deps = _deps(str(server), workspace)
            outcome = run_idor_agent(agent, deps)
    finally:
        cleanup_workspace(workspace)

    guessed = deps.transcript[2]
    assert guessed["args"] == {"rel_path": "wallets.py"}
    assert guessed["result"]["ok"] is False
    assert MAIN in guessed["result"]["valid_files"]
    assert outcome["final_status"] == "PASS"


def test_list_target_files_tool_reports_paths_and_is_recorded() -> None:
    workspace = make_workspace(REPO_ROOT)
    try:
        with run_target(app_dir=str(workspace)) as server:
            agent = build_agent(scripted_model([("list_target_files", {})]))
            deps = _deps(str(server), workspace)
            run_idor_agent(agent, deps)
    finally:
        cleanup_workspace(workspace)

    entry = deps.transcript[0]
    assert entry["tool"] == "list_target_files"
    assert MAIN in entry["result"]
    assert "target_app/__init__.py" in entry["result"]


def test_apply_patch_bad_path_also_returns_valid_files() -> None:
    workspace = make_workspace(REPO_ROOT)
    try:
        with run_target(app_dir=str(workspace)) as server:
            steps = [("apply_patch", {"rel_path": "app/wallets.py", "old": IDOR_OLD, "new": IDOR_NEW})]
            agent = build_agent(scripted_model(steps))
            deps = _deps(str(server), workspace)
            run_idor_agent(agent, deps, max_attempts=1)
    finally:
        cleanup_workspace(workspace)

    result = deps.transcript[0]["result"]
    assert result["ok"] is False
    assert MAIN in result["valid_files"]


def test_path_error_dicts_have_no_raw_exception_message() -> None:
    workspace = make_workspace(REPO_ROOT)
    try:
        with run_target(app_dir=str(workspace)) as server:
            steps = [
                ("read_target_file", {"rel_path": "../../etc/passwd"}),
                ("apply_patch", {"rel_path": "../../etc/passwd", "old": "x", "new": "y"}),
            ]
            agent = build_agent(scripted_model(steps))
            deps = _deps(str(server), workspace)
            run_idor_agent(agent, deps, max_attempts=2)
    finally:
        cleanup_workspace(workspace)

    read_result = deps.transcript[0]["result"]
    patch_result = deps.transcript[1]["result"]

    # the raised ValueError is replaced by fixed text, never its message
    assert read_result["message"] == TOOL_FAILURE_TEXT
    # apply_patch rejects with patch.py's own guard sentence, not an exception message
    assert patch_result["message"] == "path escapes target_app: ../../etc/passwd"
    assert "Traceback" not in patch_result["message"]
    assert MAIN in patch_result["valid_files"]
    assert "valid_files" in read_result
