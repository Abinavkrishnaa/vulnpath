import json
from pathlib import Path

from typer.testing import CliRunner

from vulnpath import __version__
from vulnpath.cli.main import app

runner = CliRunner()


def _project(tmp_path: Path) -> Path:
    (tmp_path / "requirements.txt").write_text("Django==5.1.4\nflask>=3\n", encoding="utf-8")
    return tmp_path


def test_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_inventory_text(tmp_path: Path) -> None:
    result = runner.invoke(app, ["inventory", str(_project(tmp_path))])
    assert result.exit_code == 0
    assert "django==5.1.4" in result.stdout
    assert "not pinned" in result.stderr


def test_inventory_json(tmp_path: Path) -> None:
    result = runner.invoke(app, ["inventory", str(_project(tmp_path)), "--format", "json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["format"] == "requirements"
    assert payload["dependencies"] == [{"name": "django", "version": "5.1.4", "source": "registry"}]
    assert len(payload["warnings"]) == 1


def test_inventory_shows_non_registry_sources(tmp_path: Path) -> None:
    (tmp_path / "poetry.lock").write_text(
        '[[package]]\nname = "g"\nversion = "1"\nsource = { type = "git", url = "u" }\n',
        encoding="utf-8",
    )
    result = runner.invoke(app, ["inventory", str(tmp_path)])
    assert "g==1  [git]" in result.stdout


def test_inventory_explicit_lockfile(tmp_path: Path) -> None:
    lock = tmp_path / "reqs-prod.txt"
    lock.write_text("six==1.16.0\n", encoding="utf-8")
    result = runner.invoke(app, ["inventory", "--lockfile", str(lock)])
    assert result.exit_code == 0
    assert "six==1.16.0" in result.stdout


def test_inventory_without_lockfile_is_a_tool_error(tmp_path: Path) -> None:
    result = runner.invoke(app, ["inventory", str(tmp_path)])
    assert result.exit_code == 2
    assert "no lockfile found" in result.stderr
