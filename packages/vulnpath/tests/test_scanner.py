"""Tests for vulnpath.scanner."""

from __future__ import annotations

from pathlib import Path

from vulnpath import __version__
from vulnpath.inputs.models import Dependency, Inventory
from vulnpath.scanner import scan
from vulnpath_schema.dataset import DatasetRecord, RecordStatus
from vulnpath_schema.findings import BlockerKind, Verdict
from vulnpath_schema.osv import AffectedRange, RangeEvent, RangeType


def _ecosystem_range(introduced: str, fixed: str) -> AffectedRange:
    return AffectedRange(
        type=RangeType.ECOSYSTEM,
        events=(RangeEvent(introduced=introduced), RangeEvent(fixed=fixed)),
    )


def _record(
    pkg: str = "requests",
    *,
    advisory_id: str = "GHSA-2222-cccc-ffff",
    introduced: str = "0",
    fixed: str = "3.0.0",
) -> DatasetRecord:
    return DatasetRecord(
        id=advisory_id,
        package=pkg,
        affected=(_ecosystem_range(introduced, fixed),),
        status=RecordStatus.VERIFIED,
    )


def _inventory(*deps: tuple[str, str]) -> Inventory:
    return Inventory.build(
        Path("uv.lock"),
        "uv.lock",
        [Dependency.create(name, version) for name, version in deps],
        [],
    )


class TestScan:
    def test_no_matches_returns_empty_report(self) -> None:
        inv = _inventory(("requests", "3.0.0"))  # fixed version, not affected
        report = scan(inv, [_record()])
        assert report.findings == ()

    def test_matched_dep_produces_unknown_finding(self) -> None:
        inv = _inventory(("requests", "2.0.0"))
        report = scan(inv, [_record()])

        assert len(report.findings) == 1
        f = report.findings[0]
        assert f.verdict is Verdict.UNKNOWN
        assert f.advisory == "GHSA-2222-cccc-ffff"
        assert f.package == "requests"
        assert f.version == "2.0.0"

    def test_unknown_finding_has_no_symbol_data_blocker(self) -> None:
        inv = _inventory(("requests", "2.0.0"))
        report = scan(inv, [_record()])

        f = report.findings[0]
        assert len(f.blockers) == 1
        assert f.blockers[0].kind is BlockerKind.NO_SYMBOL_DATA

    def test_undetermined_version_still_produces_unknown_finding(self) -> None:
        """UNDETERMINED must not be silently cleared (soundness contract)."""
        inv = _inventory(("requests", "not-a-semver"))
        report = scan(inv, [_record()])

        assert len(report.findings) == 1
        f = report.findings[0]
        assert f.verdict is Verdict.UNKNOWN
        assert "could not be evaluated" in f.blockers[0].detail

    def test_affected_finding_has_reachability_detail(self) -> None:
        inv = _inventory(("requests", "2.0.0"))
        report = scan(inv, [_record()])
        assert "not yet analysed" in report.findings[0].blockers[0].detail

    def test_multiple_deps_multiple_records(self) -> None:
        inv = _inventory(("requests", "2.0.0"), ("urllib3", "1.26.0"))
        records = [
            _record("requests", advisory_id="GHSA-2222-cccc-ffff"),
            _record("urllib3", advisory_id="GHSA-3333-gggg-hhhh", fixed="2.0.0"),
        ]
        report = scan(inv, records)
        assert len(report.findings) == 2

    def test_dataset_version_is_forwarded(self) -> None:
        inv = _inventory()
        report = scan(inv, [], dataset_version="2026-11-01")
        assert report.dataset_version == "2026-11-01"

    def test_dataset_version_defaults_to_none(self) -> None:
        inv = _inventory()
        report = scan(inv, [])
        assert report.dataset_version is None

    def test_analyzer_version_is_set(self) -> None:
        inv = _inventory()
        report = scan(inv, [])
        assert report.analyzer_version == __version__

    def test_empty_inventory_empty_report(self) -> None:
        report = scan(_inventory(), [_record()])
        assert report.findings == ()

    def test_empty_records_empty_report(self) -> None:
        report = scan(_inventory(("requests", "2.0.0")), [])
        assert report.findings == ()
