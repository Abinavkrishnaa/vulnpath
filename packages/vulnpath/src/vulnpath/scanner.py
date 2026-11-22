from __future__ import annotations

from collections.abc import Iterable

from vulnpath import __version__
from vulnpath.advisories.loader import MatchedAdvisory, match_inventory
from vulnpath.advisories.versions import Match
from vulnpath.inputs.models import Inventory
from vulnpath_schema.dataset import DatasetRecord
from vulnpath_schema.findings import Blocker, BlockerKind, Finding, Report, Verdict


def _finding_for(m: MatchedAdvisory) -> Finding:
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


def scan(
    inventory: Inventory,
    records: Iterable[DatasetRecord],
    *,
    dataset_version: str | None = None,
) -> Report:
    """Return a Report with one Finding per (advisory, affected dependency) pair.
    Every finding is UNKNOWN until the call-graph analyser is wired in.
    UNDETERMINED version-range matches are kept rather than cleared (soundness).
    """
    matched = match_inventory(inventory, records)
    return Report(
        analyzer_version=__version__,
        dataset_version=dataset_version,
        findings=tuple(_finding_for(m) for m in matched),
    )
