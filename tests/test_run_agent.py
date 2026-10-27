"""Tests for the end-to-end CLI. The model is faked with FunctionModel; no LLM is called."""

import json

from code_breaker import run_agent
from code_breaker.agent import build_agent
from tests.test_agent import IDOR_NEW, IDOR_OLD, MAIN, scripted_model

STEPS = [
    ("list_target_endpoints", {}),
    ("run_idor_probe", {"path_template": "/wallets/{wallet_id}"}),
    ("read_target_file", {"rel_path": MAIN}),
    ("apply_patch", {"rel_path": MAIN, "old": IDOR_OLD, "new": IDOR_NEW}),
    ("run_idor_probe", {"path_template": "/wallets/{wallet_id}"}),
]

DUMMY_KEY = "gsk_dummy_secret_value_000111222333"


def _fake_environment(monkeypatch) -> None:
    monkeypatch.setattr(run_agent, "load_dotenv", lambda *args, **kwargs: None)
    monkeypatch.setenv("GROQ_API_KEY", DUMMY_KEY)
    monkeypatch.setenv("COLUMNS", "200")
    monkeypatch.setattr(
        run_agent, "build_agent", lambda model: build_agent(scripted_model(STEPS))
    )


def test_run_agent_exits_cleanly_without_key(monkeypatch, capsys) -> None:
    monkeypatch.setattr(run_agent, "load_dotenv", lambda *args, **kwargs: None)
    monkeypatch.delenv("GROQ_API_KEY", raising=False)

    code = run_agent.main([])
    captured = capsys.readouterr()
    output = captured.out + captured.err

    assert code != 0
    assert "GROQ_API_KEY" in output
    assert "gsk" not in output


def test_run_agent_full_flow_with_function_model(tmp_path, monkeypatch, capsys) -> None:
    _fake_environment(monkeypatch)
    save = tmp_path / "last_run.json"

    code = run_agent.main(["--save", str(save)])
    output = capsys.readouterr().out

    assert code == 0
    assert "FIXED" in output
    assert "STILL VULNERABLE" in output

    payload = json.loads(save.read_text(encoding="utf-8"))
    assert [result["status"] for result in payload["results_before"]] == ["FAIL", "FAIL", "FAIL"]
    after = {result["probe"]: result["status"] for result in payload["results_after"]}
    assert after["idor"] == "PASS"
    assert after["unauthenticated_access"] == "FAIL"
    assert after["idempotency"] == "FAIL"
    assert payload["agent"]["final_status"] == "PASS"
    assert payload["agent"]["endpoint_tried"] == "/wallets/{wallet_id}"
    assert "403" in payload["diff"]


def test_save_file_has_no_secrets(tmp_path, monkeypatch, capsys) -> None:
    _fake_environment(monkeypatch)
    save = tmp_path / "last_run.json"

    code = run_agent.main(["--save", str(save)])
    capsys.readouterr()

    assert code == 0
    text = save.read_text(encoding="utf-8")
    assert DUMMY_KEY not in text
    assert "access_token" not in text
    assert "Authorization" not in text