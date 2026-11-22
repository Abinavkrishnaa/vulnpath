"""Find and load the lockfile for a project directory."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from vulnpath.inputs.models import Inventory
from vulnpath.inputs.requirements import read_requirements
from vulnpath.inputs.toml_locks import read_poetry_lock, read_pylock, read_uv_lock

# Most precise formats first: a full lock beats a hand-maintained requirements file.
SEARCH_ORDER = ("uv.lock", "pylock.toml", "poetry.lock", "requirements.txt")


class LockfileNotFoundError(FileNotFoundError):
    pass


class UnsupportedLockfileError(ValueError):
    pass


def discover_lockfile(project_dir: Path) -> Path:
    for name in SEARCH_ORDER:
        candidate = project_dir / name
        if candidate.is_file():
            return candidate
    named_pylocks = sorted(project_dir.glob("pylock.*.toml"))
    if named_pylocks:
        return named_pylocks[0]
    msg = (
        f"no lockfile found in {project_dir} (looked for {', '.join(SEARCH_ORDER)}, "
        "pylock.*.toml); pass one explicitly with --lockfile"
    )
    raise LockfileNotFoundError(msg)


def _reader_for(path: Path) -> Callable[[Path], Inventory]:
    name = path.name
    if name == "uv.lock":
        return read_uv_lock
    if name == "poetry.lock":
        return read_poetry_lock
    if name == "pylock.toml" or (name.startswith("pylock.") and name.endswith(".toml")):
        return read_pylock
    if name.endswith(".txt"):
        return read_requirements
    msg = f"unsupported lockfile: {name}"
    raise UnsupportedLockfileError(msg)


def load_lockfile(path: Path) -> Inventory:
    if not path.is_file():
        msg = f"lockfile not found: {path}"
        raise LockfileNotFoundError(msg)
    return _reader_for(path)(path)
