from pathlib import Path

from vulnpath.inputs.models import SourceKind
from vulnpath.inputs.toml_locks import read_poetry_lock, read_pylock, read_uv_lock

UV_LOCK = """
version = 1
requires-python = ">=3.12"

[[package]]
name = "myapp"
version = "0.1.0"
source = { editable = "." }

[[package]]
name = "Django"
version = "5.1.4"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "forked-lib"
version = "1.2.0"
source = { git = "https://github.com/example/forked-lib?rev=main#abc123" }

[[package]]
name = "tarball-lib"
version = "0.3.0"
source = { url = "https://example.org/tarball-lib-0.3.0.tar.gz" }

[[package]]
name = "workspace-member"
source = { virtual = "packages/member" }

[[package]]
name = "dynamic-thing"
source = { registry = "https://pypi.org/simple" }
"""

POETRY_LOCK = """
[[package]]
name = "celery"
version = "5.4.0"
description = ""

[[package]]
name = "local-pkg"
version = "0.0.1"
source = { type = "directory", url = "../local-pkg" }

[[package]]
name = "git-pkg"
version = "2.0.0"
source = { type = "git", url = "https://github.com/example/git-pkg.git", reference = "main" }

[[package]]
name = "no-version"
"""

PYLOCK = """
lock-version = "1.0"
created-by = "test"

[[packages]]
name = "Jinja2"
version = "3.1.5"

[[packages]]
name = "local"
directory = { path = "." }

[[packages]]
name = "vcs-pkg"
version = "1.0.0"
vcs = { type = "git", url = "https://github.com/example/vcs-pkg", commit-id = "abc" }

[[packages]]
name = "archive-pkg"
version = "0.9"
archive = { url = "https://example.org/archive-pkg-0.9.zip" }

[[packages]]
name = "unversioned"
"""


def test_uv_lock_skips_first_party_and_records_sources(tmp_path: Path) -> None:
    path = tmp_path / "uv.lock"
    path.write_text(UV_LOCK, encoding="utf-8")
    inv = read_uv_lock(path)
    found = {(d.name, d.version, d.source) for d in inv.dependencies}
    assert found == {
        ("django", "5.1.4", SourceKind.REGISTRY),
        ("forked-lib", "1.2.0", SourceKind.GIT),
        ("tarball-lib", "0.3.0", SourceKind.URL),
    }
    assert inv.warnings == ("dynamic-thing: no version in uv.lock",)
    assert inv.format == "uv.lock"


def test_poetry_lock(tmp_path: Path) -> None:
    path = tmp_path / "poetry.lock"
    path.write_text(POETRY_LOCK, encoding="utf-8")
    inv = read_poetry_lock(path)
    found = {(d.name, d.version, d.source) for d in inv.dependencies}
    assert found == {
        ("celery", "5.4.0", SourceKind.REGISTRY),
        ("git-pkg", "2.0.0", SourceKind.GIT),
    }
    assert inv.warnings == ("no-version: no version in poetry.lock",)


def test_pylock(tmp_path: Path) -> None:
    path = tmp_path / "pylock.toml"
    path.write_text(PYLOCK, encoding="utf-8")
    inv = read_pylock(path)
    found = {(d.name, d.version, d.source) for d in inv.dependencies}
    assert found == {
        ("jinja2", "3.1.5", SourceKind.REGISTRY),
        ("vcs-pkg", "1.0.0", SourceKind.GIT),
        ("archive-pkg", "0.9", SourceKind.URL),
    }
    assert inv.warnings == ("unversioned: no version in pylock.toml",)


def test_empty_lockfiles(tmp_path: Path) -> None:
    for name, reader in (
        ("uv.lock", read_uv_lock),
        ("poetry.lock", read_poetry_lock),
        ("pylock.toml", read_pylock),
    ):
        path = tmp_path / name
        path.write_text("", encoding="utf-8")
        assert reader(path).dependencies == ()
