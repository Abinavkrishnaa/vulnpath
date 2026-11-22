"""Tests for vulnpath.advisories.loader."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vulnpath.advisories import Dataset, DatasetLoadError, Match, load_dataset, match_inventory
from vulnpath.inputs.models import Dependency, Inventory, SourceKind
from vulnpath_schema.dataset import AffectedImport, DatasetRecord, RecordStatus
from vulnpath_schema.osv import AffectedRange, RangeEvent, RangeType

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ecosystem_range(introduced: str, fixed: str) -> AffectedRange:
    return AffectedRange(
        type=RangeType.ECOSYSTEM,
        events=(
            RangeEvent(introduced=introduced),
            RangeEvent(fixed=fixed),
        ),
    )


def _record(
    pkg: str = "requests",
    *,
    advisory_id: str = "GHSA-2222-cccc-ffff",
    introduced: str = "0",
    fixed: str = "2.32.0",
    status: RecordStatus = RecordStatus.VERIFIED,
    imports: tuple[AffectedImport, ...] = (),
) -> DatasetRecord:
    return DatasetRecord(
        id=advisory_id,
        package=pkg,
        affected=(_ecosystem_range(introduced, fixed),),
        status=status,
        imports=imports,
    )


def _write_jsonl(path: Path, records: list[DatasetRecord]) -> None:
    path.write_text(
        "\n".join(r.model_dump_json() for r in records) + "\n",
        encoding="utf-8",
    )


def _inventory(*deps: tuple[str, str]) -> Inventory:
    """Build an Inventory from (name, version) pairs."""
    return Inventory.build(
        Path("uv.lock"),
        "uv.lock",
        [Dependency.create(name, version) for name, version in deps],
        [],
    )


# ---------------------------------------------------------------------------
# load_dataset
# ---------------------------------------------------------------------------


class TestLoadDataset:
    def test_reads_valid_jsonl(self, tmp_path: Path) -> None:
        dataset_path = tmp_path / "vulnpath.jsonl"
        records = [_record("requests"), _record("urllib3", advisory_id="GHSA-3333-gggg-hhhh")]
        _write_jsonl(dataset_path, records)

        result = load_dataset(dataset_path)

        assert isinstance(result, Dataset)
        assert len(result.records) == 2
        assert result.warnings == ()

    def test_skips_invalid_json_lines(self, tmp_path: Path) -> None:
        dataset_path = tmp_path / "vulnpath.jsonl"
        good = _record()
        dataset_path.write_text(
            good.model_dump_json() + "\n" + "not-valid-json\n",
            encoding="utf-8",
        )

        result = load_dataset(dataset_path)

        assert len(result.records) == 1
        assert len(result.warnings) == 1
        assert "line 2" in result.warnings[0]

    def test_skips_lines_failing_validation(self, tmp_path: Path) -> None:
        dataset_path = tmp_path / "vulnpath.jsonl"
        bad = json.dumps({"id": "NOT-VALID", "package": "foo"})
        dataset_path.write_text(bad + "\n", encoding="utf-8")

        result = load_dataset(dataset_path)

        assert result.records == ()
        assert len(result.warnings) == 1

    def test_ignores_blank_lines(self, tmp_path: Path) -> None:
        dataset_path = tmp_path / "vulnpath.jsonl"
        good = _record()
        dataset_path.write_text("\n" + good.model_dump_json() + "\n\n", encoding="utf-8")

        result = load_dataset(dataset_path)

        assert len(result.records) == 1
        assert result.warnings == ()

    def test_raises_dataset_load_error_on_missing_file(self, tmp_path: Path) -> None:
        with pytest.raises(DatasetLoadError):
            load_dataset(tmp_path / "nonexistent.jsonl")

    def test_empty_file_returns_empty_dataset(self, tmp_path: Path) -> None:
        dataset_path = tmp_path / "empty.jsonl"
        dataset_path.write_text("", encoding="utf-8")

        result = load_dataset(dataset_path)

        assert result.records == ()
        assert result.warnings == ()

    def test_path_is_stored_on_result(self, tmp_path: Path) -> None:
        dataset_path = tmp_path / "vulnpath.jsonl"
        _write_jsonl(dataset_path, [_record()])

        result = load_dataset(dataset_path)

        assert result.path == dataset_path


# ---------------------------------------------------------------------------
# match_inventory
# ---------------------------------------------------------------------------


class TestMatchInventory:
    def test_returns_affected_match(self) -> None:
        inv = _inventory(("requests", "2.0.0"))
        record = _record("requests", fixed="3.0.0")

        results = match_inventory(inv, [record])

        assert len(results) == 1
        assert results[0].match is Match.AFFECTED
        assert results[0].version == "2.0.0"
        assert results[0].record is record

    def test_excludes_not_affected(self) -> None:
        inv = _inventory(("requests", "3.0.0"))
        record = _record("requests", fixed="3.0.0")  # 3.0.0 is the fix, so not affected

        results = match_inventory(inv, [record])

        assert results == []

    def test_includes_undetermined(self) -> None:
        """UNDETERMINED must not be silently cleared (soundness)."""
        inv = _inventory(("requests", "not-a-semver"))
        record = _record("requests", fixed="3.0.0")

        results = match_inventory(inv, [record])

        assert len(results) == 1
        assert results[0].match is Match.UNDETERMINED

    def test_normalizes_package_names(self) -> None:
        """'Pillow' in dataset must match 'pillow' in inventory and vice versa."""
        inv = _inventory(("Pillow", "9.0.0"))
        record = _record("pillow", advisory_id="GHSA-4444-jjjj-mmmm", fixed="10.0.0")

        results = match_inventory(inv, [record])

        assert len(results) == 1

    def test_no_match_for_absent_package(self) -> None:
        inv = _inventory(("urllib3", "1.26.0"))
        record = _record("requests", fixed="3.0.0")

        results = match_inventory(inv, [record])

        assert results == []

    def test_multiple_records_multiple_deps(self) -> None:
        inv = _inventory(("requests", "2.0.0"), ("urllib3", "1.26.0"))
        records = [
            _record("requests", advisory_id="GHSA-5555-pppp-qqqq", fixed="3.0.0"),
            _record("urllib3", advisory_id="GHSA-6666-rrrr-vvvv", fixed="2.0.0"),
        ]

        results = match_inventory(inv, records)

        assert len(results) == 2

    def test_uv_resolution_fork_matches_both_versions(self) -> None:
        """uv may lock two versions of the same package (resolution forks); both must match."""
        inv = Inventory.build(
            Path("uv.lock"),
            "uv.lock",
            [
                Dependency.create("requests", "2.0.0"),
                Dependency.create("requests", "2.5.0"),
            ],
            [],
        )
        record = _record("requests", fixed="3.0.0")

        results = match_inventory(inv, [record])

        assert len(results) == 2
        assert {r.version for r in results} == {"2.0.0", "2.5.0"}

    def test_matched_advisory_carries_package_canonical_name(self) -> None:
        inv = _inventory(("my-pkg", "1.0.0"))
        record = _record("my_pkg", advisory_id="GHSA-7777-wwww-xxxx", fixed="2.0.0")

        results = match_inventory(inv, [record])

        assert len(results) == 1
        assert results[0].package == "my-pkg"

    def test_non_registry_source_is_included(self) -> None:
        """Git/URL-sourced deps still need to be checked; we have no extra info to clear them."""
        inv = Inventory.build(
            Path("uv.lock"),
            "uv.lock",
            [Dependency.create("requests", "2.0.0", SourceKind.GIT)],
            [],
        )
        record = _record("requests", fixed="3.0.0")

        results = match_inventory(inv, [record])

        assert len(results) == 1

    def test_empty_records_returns_empty(self) -> None:
        inv = _inventory(("requests", "2.0.0"))
        assert match_inventory(inv, []) == []

    def test_empty_inventory_returns_empty(self) -> None:
        record = _record("requests", fixed="3.0.0")
        assert match_inventory(_inventory(), [record]) == []

    def test_matched_advisory_is_frozen(self) -> None:
        inv = _inventory(("requests", "2.0.0"))
        record = _record("requests", fixed="3.0.0")
        result = match_inventory(inv, [record])[0]

        with pytest.raises((AttributeError, TypeError)):
            result.version = "tampered"  # type: ignore[misc]
