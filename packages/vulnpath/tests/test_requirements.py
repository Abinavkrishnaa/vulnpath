from pathlib import Path

import pytest

from vulnpath.inputs.models import Dependency
from vulnpath.inputs.requirements import read_requirements


def _write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


def _pairs(inv_deps: tuple[Dependency, ...]) -> set[tuple[str, str]]:
    return {(d.name, d.version) for d in inv_deps}


def test_exact_pins_are_read_and_names_normalised(tmp_path: Path) -> None:
    req = _write(
        tmp_path / "requirements.txt",
        "Django==5.1.4\nPyYAML==6.0.2\nrequests[socks]==2.32.3 ; python_version >= '3.8'\n",
    )
    inv = read_requirements(req)
    assert _pairs(inv.dependencies) == {
        ("django", "5.1.4"),
        ("pyyaml", "6.0.2"),
        ("requests", "2.32.3"),
    }
    assert inv.warnings == ()


def test_comments_blank_lines_and_global_options_are_ignored(tmp_path: Path) -> None:
    req = _write(
        tmp_path / "requirements.txt",
        "# header\n\n--index-url https://example.org/simple\n-c constraints.txt\n"
        "celery==5.4.0  # trailing comment\n",
    )
    inv = read_requirements(req)
    assert _pairs(inv.dependencies) == {("celery", "5.4.0")}


def test_hash_continuations_are_joined(tmp_path: Path) -> None:
    req = _write(
        tmp_path / "requirements.txt",
        "werkzeug==3.0.6 \\\n    --hash=sha256:aaaa \\\n    --hash=sha256:bbbb\n",
    )
    inv = read_requirements(req)
    assert _pairs(inv.dependencies) == {("werkzeug", "3.0.6")}


def test_unpinned_and_wildcard_requirements_become_warnings(tmp_path: Path) -> None:
    req = _write(tmp_path / "requirements.txt", "flask>=3.0\njinja2==3.*\n")
    inv = read_requirements(req)
    assert inv.dependencies == ()
    assert len(inv.warnings) == 2
    assert all("not pinned" in w for w in inv.warnings)


@pytest.mark.parametrize(
    ("line", "needle"),
    [
        ("-e git+https://example.org/repo.git#egg=thing", "editable"),
        ("--editable=./local", "editable"),
        ("thing @ https://example.org/thing-1.0.tar.gz", "direct URL"),
        ("not a valid ===== line", "cannot parse"),
    ],
)
def test_unresolvable_lines_are_reported(tmp_path: Path, line: str, needle: str) -> None:
    inv = read_requirements(_write(tmp_path / "requirements.txt", line + "\n"))
    assert inv.dependencies == ()
    assert len(inv.warnings) == 1
    assert needle in inv.warnings[0]
    assert "requirements.txt:1" in inv.warnings[0]


@pytest.mark.parametrize(
    "include", ["-r base.txt", "-rbase.txt", "--requirement base.txt", "--requirement=base.txt"]
)
def test_includes_are_followed(tmp_path: Path, include: str) -> None:
    _write(tmp_path / "base.txt", "packaging==24.2\n")
    req = _write(tmp_path / "requirements.txt", f"{include}\npytest==8.3.4\n")
    inv = read_requirements(req)
    assert _pairs(inv.dependencies) == {("packaging", "24.2"), ("pytest", "8.3.4")}


def test_include_cycles_terminate(tmp_path: Path) -> None:
    _write(tmp_path / "a.txt", "-r b.txt\nattrs==24.2.0\n")
    _write(tmp_path / "b.txt", "-r a.txt\n")
    inv = read_requirements(tmp_path / "a.txt")
    assert _pairs(inv.dependencies) == {("attrs", "24.2.0")}
    assert any("cycle" in w for w in inv.warnings)


def test_duplicates_collapse(tmp_path: Path) -> None:
    req = _write(tmp_path / "requirements.txt", "Django==5.1.4\ndjango==5.1.4\n")
    assert len(read_requirements(req).dependencies) == 1


def test_trailing_continuation_at_eof(tmp_path: Path) -> None:
    req = _write(tmp_path / "requirements.txt", "six==1.16.0 \\")
    assert _pairs(read_requirements(req).dependencies) == {("six", "1.16.0")}
