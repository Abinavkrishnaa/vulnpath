import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from vulnpath_schema import (
    AffectedImport,
    Basis,
    Blocker,
    BlockerKind,
    DatasetRecord,
    Finding,
    PathHop,
    RangeEvent,
    RecordStatus,
    SearchStats,
    SymbolKind,
    Verdict,
)
from vulnpath_schema.export import export, main

HOP = PathHop(qualname="app.views.upload", file="app/views.py", line=12)
BLOCKER = Blocker(kind=BlockerKind.DYNAMIC_IMPORT, file="app/plugins.py", line=3)


def _finding(**overrides: object) -> Finding:
    base: dict[str, object] = {
        "advisory": "GHSA-2222-3333-4444",
        "package": "werkzeug",
        "version": "3.0.5",
    }
    base.update(overrides)
    return Finding.model_validate(base)


def test_reachable_requires_path() -> None:
    assert _finding(verdict=Verdict.REACHABLE, path=[HOP]).path == (HOP,)
    with pytest.raises(ValidationError, match="call path"):
        _finding(verdict=Verdict.REACHABLE)


def test_unknown_requires_blockers() -> None:
    _finding(verdict=Verdict.UNKNOWN, blockers=[BLOCKER])
    with pytest.raises(ValidationError, match="blocker"):
        _finding(verdict=Verdict.UNKNOWN)


def test_not_reachable_can_never_carry_blockers() -> None:
    ok = _finding(
        verdict=Verdict.NOT_REACHABLE,
        basis=Basis.SYMBOL_NOT_CALLED,
        search=SearchStats(entry_points=3, modules=40, call_sites=900),
    )
    assert ok.verdict is Verdict.NOT_REACHABLE
    with pytest.raises(ValidationError, match="must be unknown"):
        _finding(verdict=Verdict.NOT_REACHABLE, basis=Basis.SYMBOL_NOT_CALLED, blockers=[BLOCKER])
    with pytest.raises(ValidationError, match="basis"):
        _finding(verdict=Verdict.NOT_REACHABLE, basis=Basis.ADVISORY_LEVEL)


def test_affected_import_qualified_names() -> None:
    entry = AffectedImport(
        modules=("django.db.models", "django.db.models.fields.json"),
        attribute="JSONField",
        kind=SymbolKind.CLASS,
    )
    assert entry.qualified_names() == (
        "django.db.models.JSONField",
        "django.db.models.fields.json.JSONField",
    )
    whole = AffectedImport(modules=("yaml",), kind=SymbolKind.MODULE)
    assert whole.qualified_names() == ("yaml",)


@pytest.mark.parametrize(
    ("modules", "attribute"),
    [(("not a module",), None), (("ok",), "bad-name"), ((), None)],
)
def test_affected_import_rejects_bad_names(modules: tuple[str, ...], attribute: str | None) -> None:
    with pytest.raises(ValidationError):
        AffectedImport(modules=modules, attribute=attribute, kind=SymbolKind.FUNCTION)


def _record(**overrides: object) -> DatasetRecord:
    base: dict[str, object] = {
        "id": "GHSA-2222-3333-4444",
        "package": "werkzeug",
        "affected": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.0.6"}]}],
        "status": "verified",
        "imports": [
            {"modules": ["werkzeug.formparser"], "attribute": "parse_form_data", "kind": "function"}
        ],
    }
    base.update(overrides)
    return DatasetRecord.model_validate(base)


def test_dataset_record_usable_only_when_verified_with_symbols() -> None:
    assert _record().usable_for_verdicts
    assert not _record(status=RecordStatus.PROPOSED).usable_for_verdicts
    assert not _record(imports=[]).usable_for_verdicts


@pytest.mark.parametrize("bad_id", ["GHSA-aaaa-bbbb-1111", "CVE-12", "random"])
def test_dataset_record_id_format(bad_id: str) -> None:
    with pytest.raises(ValidationError):
        _record(id=bad_id)


@pytest.mark.parametrize("good_id", ["PYSEC-2024-42", "CVE-2024-12345"])
def test_dataset_record_accepts_other_id_kinds(good_id: str) -> None:
    assert _record(id=good_id).id == good_id


def test_range_event_needs_exactly_one_field() -> None:
    with pytest.raises(ValidationError, match="exactly one"):
        RangeEvent()
    with pytest.raises(ValidationError, match="exactly one"):
        RangeEvent(introduced="0", fixed="1")


def test_export_writes_valid_json_schemas(tmp_path: Path) -> None:
    paths = export(tmp_path)
    assert {p.name for p in paths} == {"dataset-record.schema.json", "report.schema.json"}
    for path in paths:
        assert json.loads(path.read_text(encoding="utf-8"))["type"] == "object"


def test_export_cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main([str(tmp_path)]) == 0
    assert "report.schema.json" in capsys.readouterr().out
    assert main([]) == 2
