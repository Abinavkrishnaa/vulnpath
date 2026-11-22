"""Analyzer output: one Finding per (advisory, package)."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Verdict(str, Enum):
    REACHABLE = "reachable"
    NOT_REACHABLE = "not_reachable"
    UNKNOWN = "unknown"


class Basis(str, Enum):
    SYMBOL_CALLED = "symbol_called"
    SYMBOL_NOT_CALLED = "symbol_not_called"
    PACKAGE_NOT_IMPORTED = "package_not_imported"
    ADVISORY_LEVEL = "advisory_level"


class BlockerKind(str, Enum):
    NO_SYMBOL_DATA = "no_symbol_data"
    DYNAMIC_IMPORT = "dynamic_import"
    DYNAMIC_ATTRIBUTE = "dynamic_attribute"
    EVAL_EXEC = "eval_exec"
    PLUGIN_LOADING = "plugin_loading"
    UNRESOLVED_CALL = "unresolved_call"
    PARSE_ERROR = "parse_error"
    MISSING_SOURCE = "missing_source"


class PathHop(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    qualname: str
    file: str
    line: int = Field(ge=1)


class Blocker(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: BlockerKind
    file: str | None = None
    line: int | None = Field(default=None, ge=1)
    detail: str = ""


class SearchStats(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    entry_points: int = Field(ge=0)
    modules: int = Field(ge=0)
    call_sites: int = Field(ge=0)


class Finding(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    advisory: str
    package: str
    version: str
    verdict: Verdict
    basis: Basis | None = None
    path: tuple[PathHop, ...] = ()
    blockers: tuple[Blocker, ...] = ()
    search: SearchStats | None = None

    @model_validator(mode="after")
    def _evidence_matches_verdict(self) -> Finding:
        """Enforce the soundness contract: every verdict carries its own evidence."""
        if self.verdict is Verdict.REACHABLE and not self.path:
            msg = "a reachable finding must include the call path"
            raise ValueError(msg)
        if self.verdict is Verdict.UNKNOWN and not self.blockers:
            msg = "an unknown finding must list at least one blocker"
            raise ValueError(msg)
        if self.verdict is Verdict.NOT_REACHABLE:
            if self.blockers:
                msg = "a not_reachable finding cannot have blockers; it must be unknown"
                raise ValueError(msg)
            if self.basis not in (Basis.SYMBOL_NOT_CALLED, Basis.PACKAGE_NOT_IMPORTED):
                msg = (
                    "a not_reachable finding needs basis symbol_not_called or package_not_imported"
                )
                raise ValueError(msg)
        return self


class Report(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = "1"
    analyzer_version: str
    dataset_version: str | None = None
    findings: tuple[Finding, ...] = ()
