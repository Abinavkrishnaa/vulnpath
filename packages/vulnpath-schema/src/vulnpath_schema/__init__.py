"""Shared data models for Vulnpath."""

from vulnpath_schema.dataset import (
    AffectedImport,
    ChangeKind,
    DatasetRecord,
    FixCommit,
    FixMethod,
    RecordStatus,
    SymbolKind,
)
from vulnpath_schema.findings import (
    Basis,
    Blocker,
    BlockerKind,
    Finding,
    PathHop,
    Report,
    SearchStats,
    Verdict,
)
from vulnpath_schema.osv import AffectedRange, RangeEvent, RangeType

__all__ = [
    "AffectedImport",
    "AffectedRange",
    "Basis",
    "Blocker",
    "BlockerKind",
    "ChangeKind",
    "DatasetRecord",
    "Finding",
    "FixCommit",
    "FixMethod",
    "PathHop",
    "RangeEvent",
    "RangeType",
    "RecordStatus",
    "Report",
    "SearchStats",
    "SymbolKind",
    "Verdict",
]

SCHEMA_VERSION = "1"
