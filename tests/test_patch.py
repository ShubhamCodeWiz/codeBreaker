"""Tests for the temp-copy patch workspace."""

import hashlib
from pathlib import Path

import pytest

from code_breaker.harness import run_target
from code_breaker.patch import (
    apply_edit,
    cleanup_workspace,
    list_files,
    make_workspace,
    read_file,
)
from code_breaker.probes import idor_probe

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


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture
def workspace():
    ws = make_workspace(REPO_ROOT)
    try:
        yield ws
    finally:
        cleanup_workspace(ws)


def test_workspace_copy_is_separate_from_original(workspace: Path) -> None:
    before = _sha(REPO_ROOT / MAIN)
    result = apply_edit(
        workspace,
        MAIN,
        '"""Minimal FastAPI target app used by code-breaker for security tests."""',
        '"""Patched target app."""',
    )
    assert result.ok
    assert _sha(REPO_ROOT / MAIN) == before
    assert "Patched target app." in read_file(workspace, MAIN)


def test_apply_edit_unique_old_applies_and_shows_diff(workspace: Path) -> None:
    result = apply_edit(workspace, MAIN, 'SECRET_KEY = "super-secret-key"', 'SECRET_KEY = "rotated"')
    assert result.ok
    assert '-SECRET_KEY = "super-secret-key"' in result.diff
    assert '+SECRET_KEY = "rotated"' in result.diff
    assert 'SECRET_KEY = "rotated"' in read_file(workspace, MAIN)


def test_apply_edit_missing_old_is_rejected(workspace: Path) -> None:
    before = read_file(workspace, MAIN)
    result = apply_edit(workspace, MAIN, "this text is not in the file", "anything")
    assert not result.ok
    assert "not found" in result.message
    assert result.diff == ""
    assert read_file(workspace, MAIN) == before


def test_apply_edit_ambiguous_old_is_rejected(workspace: Path) -> None:
    before = read_file(workspace, MAIN)
    result = apply_edit(workspace, MAIN, "USERS", "ACCOUNTS")
    assert not result.ok
    assert "exactly once" in result.message
    assert read_file(workspace, MAIN) == before


def test_apply_edit_syntax_error_is_rejected(workspace: Path) -> None:
    before = read_file(workspace, MAIN)
    result = apply_edit(
        workspace,
        MAIN,
        "def login(payload: LoginRequest) -> dict[str, str]:",
        "def login(payload: LoginRequest) -> dict[str, str]:\n    (",
    )
    assert not result.ok
    assert "SyntaxError" in result.message
    assert read_file(workspace, MAIN) == before


@pytest.mark.parametrize(
    "bad_path",
    ["../main.py", "/etc/passwd", "target_app/notes.txt", "target_app/missing.py"],
)
def test_path_guard_rejects_bad_paths(workspace: Path, bad_path: str) -> None:
    (workspace / "target_app" / "notes.txt").write_text("not python", encoding="utf-8")

    result = apply_edit(workspace, bad_path, "x", "y")
    assert not result.ok

    with pytest.raises(ValueError):
        read_file(workspace, bad_path)


def test_path_guard_rejects_symlink_escape(workspace: Path) -> None:
    outside = workspace.parent / "outside-target.py"
    outside.write_text("SENTINEL = 1\n", encoding="utf-8")
    link = workspace / "target_app" / "escaped.py"
    link.symlink_to(outside)
    try:
        result = apply_edit(workspace, "target_app/escaped.py", "SENTINEL = 1", "SENTINEL = 2")
        assert not result.ok
        with pytest.raises(ValueError):
            read_file(workspace, "target_app/escaped.py")
        assert outside.read_text(encoding="utf-8") == "SENTINEL = 1\n"
    finally:
        outside.unlink()


def test_list_files_returns_workspace_relative_paths(workspace: Path) -> None:
    assert list_files(workspace) == ["target_app/__init__.py", "target_app/main.py"]


def test_idor_fix_in_workspace_makes_probe_pass() -> None:
    workspace = make_workspace(REPO_ROOT)
    try:
        result = apply_edit(workspace, MAIN, IDOR_OLD, IDOR_NEW)
        assert result.ok

        with run_target(app_dir=str(workspace)) as server:
            patched = idor_probe(str(server), ALICE, "W_B")
        with run_target() as server:
            original = idor_probe(str(server), ALICE, "W_B")
    finally:
        cleanup_workspace(workspace)

    assert patched.status == "PASS"
    assert original.status == "FAIL"