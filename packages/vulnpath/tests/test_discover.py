from pathlib import Path

import pytest

from vulnpath.inputs import LockfileNotFoundError, discover_lockfile, load_lockfile
from vulnpath.inputs.discover import UnsupportedLockfileError


def test_prefers_uv_lock_over_requirements(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("six==1.16.0\n", encoding="utf-8")
    (tmp_path / "uv.lock").write_text("version = 1\n", encoding="utf-8")
    assert discover_lockfile(tmp_path).name == "uv.lock"


def test_falls_back_to_named_pylock(tmp_path: Path) -> None:
    (tmp_path / "pylock.prod.toml").write_text("", encoding="utf-8")
    assert discover_lockfile(tmp_path).name == "pylock.prod.toml"


def test_raises_when_nothing_found(tmp_path: Path) -> None:
    with pytest.raises(LockfileNotFoundError, match="--lockfile"):
        discover_lockfile(tmp_path)


@pytest.mark.parametrize(
    ("name", "content", "fmt"),
    [
        ("uv.lock", "version = 1\n", "uv.lock"),
        ("poetry.lock", "", "poetry.lock"),
        ("pylock.toml", "", "pylock.toml"),
        ("pylock.dev.toml", "", "pylock.toml"),
        ("requirements-prod.txt", "six==1.16.0\n", "requirements"),
    ],
)
def test_load_dispatches_on_name(tmp_path: Path, name: str, content: str, fmt: str) -> None:
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    assert load_lockfile(path).format == fmt


def test_load_rejects_unknown_and_missing(tmp_path: Path) -> None:
    other = tmp_path / "Pipfile.lock"
    other.write_text("{}", encoding="utf-8")
    with pytest.raises(UnsupportedLockfileError):
        load_lockfile(other)
    with pytest.raises(LockfileNotFoundError):
        load_lockfile(tmp_path / "missing.lock")
