"""Patch workspace: edit a temp copy of the target, never the original."""

import difflib
import shutil
import tempfile
from pathlib import Path

from pydantic import BaseModel

MAX_FILE_BYTES = 50 * 1024


class PatchResult(BaseModel):
    """Outcome of one attempted edit; diff is empty unless the edit was applied."""

    ok: bool
    message: str
    diff: str


def make_workspace(src_root: Path) -> Path:
    """Copy src_root/target_app into a fresh temp dir and return that dir."""
    workspace = Path(tempfile.mkdtemp(prefix="code-breaker-"))
    shutil.copytree(
        Path(src_root) / "target_app",
        workspace / "target_app",
        ignore=shutil.ignore_patterns("__pycache__"),
    )
    return workspace


def cleanup_workspace(workspace: Path) -> None:
    """Remove a workspace directory, ignoring filesystem errors."""
    shutil.rmtree(workspace, ignore_errors=True)


def _guard(workspace: Path, rel_path: str) -> Path:
    """Resolve rel_path inside workspace/target_app or raise ValueError."""
    root = (Path(workspace) / "target_app").resolve()
    candidate = (Path(workspace) / rel_path).resolve()
    if not candidate.is_relative_to(root):
        raise ValueError(f"path escapes target_app: {rel_path}")
    if candidate.suffix != ".py":
        raise ValueError(f"not a Python file: {rel_path}")
    if not candidate.is_file():
        raise ValueError(f"file does not exist: {rel_path}")
    if candidate.stat().st_size > MAX_FILE_BYTES:
        raise ValueError(f"file is larger than {MAX_FILE_BYTES} bytes: {rel_path}")
    return candidate


def list_files(workspace: Path) -> list[str]:
    """Relative .py paths under workspace/target_app, e.g. 'target_app/main.py'."""
    root = Path(workspace)
    files = []
    for path in sorted((root / "target_app").rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        files.append(path.relative_to(root).as_posix())
    return files


def read_file(workspace: Path, rel_path: str) -> str:
    """Return the text of a guarded .py file inside the workspace."""
    return _guard(workspace, rel_path).read_text(encoding="utf-8")


def _unified_diff(rel_path: str, old_text: str, new_text: str) -> str:
    lines = difflib.unified_diff(
        old_text.splitlines(keepends=True),
        new_text.splitlines(keepends=True),
        fromfile=rel_path,
        tofile=rel_path,
    )
    return "".join(lines)


def apply_edit(workspace: Path, rel_path: str, old: str, new: str) -> PatchResult:
    """Replace exactly one exact occurrence of old and write it if the result compiles."""
    try:
        path = _guard(workspace, rel_path)
    except ValueError as error:
        return PatchResult(ok=False, message=str(error), diff="")

    old_text = path.read_text(encoding="utf-8")
    occurrences = old_text.count(old)
    if occurrences == 0:
        return PatchResult(ok=False, message="old text not found", diff="")
    if occurrences > 1:
        return PatchResult(
            ok=False,
            message=f"old text appears {occurrences} times, expected exactly once",
            diff="",
        )

    new_text = old_text.replace(old, new, 1)
    try:
        compile(new_text, rel_path, "exec")
    except SyntaxError as error:
        return PatchResult(
            ok=False,
            message=f"edit would break syntax: {error.__class__.__name__}",
            diff="",
        )

    diff = _unified_diff(rel_path, old_text, new_text)
    path.write_text(new_text, encoding="utf-8")
    return PatchResult(ok=True, message=f"applied edit to {rel_path}", diff=diff)