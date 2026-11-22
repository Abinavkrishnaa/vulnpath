from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from vulnpath import __version__
from vulnpath.advisories.loader import MatchedAdvisory, match_inventory
from vulnpath.advisories.versions import Match
from vulnpath.analyzer.engine import analyse
from vulnpath.inputs.models import Inventory
from vulnpath_schema.dataset import DatasetRecord
from vulnpath_schema.findings import Blocker, BlockerKind, Finding, Report, Verdict


def _finding_no_analysis(m: MatchedAdvisory) -> Finding:
    detail = (
        "version range could not be evaluated"
        if m.match is Match.UNDETERMINED
        else "reachability not yet analysed"
    )
    return Finding(
        advisory=m.record.id,
        package=str(m.package),
        version=m.version,
        verdict=Verdict.UNKNOWN,
        blockers=(Blocker(kind=BlockerKind.NO_SYMBOL_DATA, detail=detail),),
    )


def _finding_with_analysis(m: MatchedAdvisory, project_root: Path) -> Finding:
    verdict, basis, path, blockers, search = analyse(m.record.imports, project_root)
    return Finding(
        advisory=m.record.id,
        package=str(m.package),
        version=m.version,
        verdict=verdict,
        basis=basis,
        path=path,
        blockers=blockers,
        search=search,
    )


def scan(
    inventory: Inventory,
    records: Iterable[DatasetRecord],
    *,
    project_root: Path | None = None,
    dataset_version: str | None = None,
) -> Report:
    """Return a Report with one Finding per (advisory, affected dependency) pair.

    When project_root is supplied and a record has symbol data, the call-graph
    analyser runs and may produce reachable or not_reachable verdicts. Without
    project_root or symbol data, every finding is unknown (soundness default).
    UNDETERMINED version-range matches are kept rather than cleared (soundness).
    """
    matched = match_inventory(inventory, records)
    findings: list[Finding] = []
    for m in matched:
        if project_root is not None and m.record.usable_for_verdicts:
            findings.append(_finding_with_analysis(m, project_root))
        else:
            findings.append(_finding_no_analysis(m))
    return Report(
        analyzer_version=__version__,
        dataset_version=dataset_version,
        findings=tuple(findings),
    )
