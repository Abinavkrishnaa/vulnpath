import json
from pathlib import Path

from typer.testing import CliRunner

from vulnpath import __version__
from vulnpath.cli.main import app
from vulnpath_schema.dataset import DatasetRecord, RecordStatus
from vulnpath_schema.osv import AffectedRange, RangeEvent, RangeType

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


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------


def _dataset(tmp_path: Path, *, affected_pkg: str = "requests", fixed: str = "3.0.0") -> Path:
    """Write a minimal one-record dataset JSONL file."""
    record = DatasetRecord(
        id="GHSA-2222-cccc-ffff",
        package=affected_pkg,
        affected=(
            AffectedRange(
                type=RangeType.ECOSYSTEM,
                events=(RangeEvent(introduced="0"), RangeEvent(fixed=fixed)),
            ),
        ),
        status=RecordStatus.VERIFIED,
    )
    path = tmp_path / "vulnpath.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(record.model_dump_json() + "\n", encoding="utf-8")
    return path


def _requirements(tmp_path: Path, content: str = "requests==2.0.0\n") -> Path:
    lock = tmp_path / "requirements.txt"
    lock.write_text(content, encoding="utf-8")
    return tmp_path


def test_scan_no_findings(tmp_path: Path) -> None:
    _requirements(tmp_path, "requests==3.0.0\n")  # fixed version
    ds = _dataset(tmp_path / "ds")
    result = runner.invoke(app, ["scan", str(tmp_path), "--dataset", str(ds)])
    assert result.exit_code == 0
    assert "No findings" in result.stdout


def test_scan_unknown_finding_text(tmp_path: Path) -> None:
    _requirements(tmp_path, "requests==2.0.0\n")
    ds = _dataset(tmp_path / "ds")
    result = runner.invoke(app, ["scan", str(tmp_path), "--dataset", str(ds)])
    assert result.exit_code == 0
    assert "requests==2.0.0" in result.stdout
    assert "unknown" in result.stdout
    assert "1 findings" in result.stdout


def test_scan_json_output(tmp_path: Path) -> None:
    _requirements(tmp_path, "requests==2.0.0\n")
    ds = _dataset(tmp_path / "ds")
    result = runner.invoke(app, ["scan", str(tmp_path), "--dataset", str(ds), "--format", "json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["findings"][0]["verdict"] == "unknown"
    assert payload["findings"][0]["package"] == "requests"


def test_scan_missing_lockfile_is_tool_error(tmp_path: Path) -> None:
    ds = _dataset(tmp_path / "ds")
    result = runner.invoke(app, ["scan", str(tmp_path), "--dataset", str(ds)])
    assert result.exit_code == 2


def test_scan_missing_dataset_is_tool_error(tmp_path: Path) -> None:
    _requirements(tmp_path)
    result = runner.invoke(
        app, ["scan", str(tmp_path), "--dataset", str(tmp_path / "nonexistent.jsonl")]
    )
    assert result.exit_code == 2


def test_scan_explicit_lockfile(tmp_path: Path) -> None:
    lock = tmp_path / "reqs.txt"
    lock.write_text("requests==2.0.0\n", encoding="utf-8")
    ds = _dataset(tmp_path / "ds")
    result = runner.invoke(app, ["scan", "--lockfile", str(lock), "--dataset", str(ds)])
    assert result.exit_code == 0
    assert "requests==2.0.0" in result.stdout
