"""Records of the vulnpath-data dataset (one per advisory)."""

from __future__ import annotations

import re
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_validator

from vulnpath_schema.osv import AffectedRange

_IDENTIFIER_PART = r"[A-Za-z_][A-Za-z0-9_]*"
_DOTTED = rf"^{_IDENTIFIER_PART}(\.{_IDENTIFIER_PART})*$"


class SymbolKind(str, Enum):
    FUNCTION = "function"
    METHOD = "method"
    CLASS = "class"
    MODULE = "module"


class ChangeKind(str, Enum):
    MODIFIED = "modified"
    REMOVED = "removed"
    DERIVED = "derived"


class RecordStatus(str, Enum):
    PROPOSED = "proposed"
    VERIFIED = "verified"
    REJECTED = "rejected"
    NEEDS_MANUAL = "needs_manual"


class FixMethod(str, Enum):
    REFERENCE = "reference"
    PR_MERGE = "pr_merge"
    TAG_DIFF = "tag_diff"


class AffectedImport(BaseModel):
    """Mirrors PyPA `ecosystem_specific.imports`, plus Vulnpath extensions.

    `kind` and `change` are dropped when exporting upstream.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    modules: tuple[str, ...] = Field(min_length=1)
    attribute: str | None = Field(
        default=None,
        description="Name inside the module, e.g. 'parse' or 'Parser.parse'. None = whole module.",
    )
    kind: SymbolKind
    change: ChangeKind = ChangeKind.MODIFIED

    @field_validator("modules")
    @classmethod
    def _valid_modules(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for module in value:
            if not re.fullmatch(_DOTTED, module):
                msg = f"not a dotted module path: {module!r}"
                raise ValueError(msg)
        return value

    @field_validator("attribute")
    @classmethod
    def _valid_attribute(cls, value: str | None) -> str | None:
        if value is not None and not re.fullmatch(_DOTTED, value):
            msg = f"not a valid attribute path: {value!r}"
            raise ValueError(msg)
        return value

    def qualified_names(self) -> tuple[str, ...]:
        """All fully qualified names this entry refers to."""
        if self.attribute is None:
            return self.modules
        return tuple(f"{module}.{self.attribute}" for module in self.modules)


class FixCommit(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    url: HttpUrl
    method: FixMethod


class DatasetRecord(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(
        pattern=r"^(GHSA(-[23456789cfghjmpqrvwx]{4}){3}|PYSEC-\d{4}-\d+|CVE-\d{4}-\d+)$"
    )
    aliases: tuple[str, ...] = ()
    package: str = Field(min_length=1)
    affected: tuple[AffectedRange, ...] = Field(min_length=1)
    fix_commits: tuple[FixCommit, ...] = ()
    imports: tuple[AffectedImport, ...] = ()
    status: RecordStatus
    notes: str | None = None
    record_version: int = Field(default=1, ge=1)

    @property
    def usable_for_verdicts(self) -> bool:
        """Only verified records with symbols may drive a function-level verdict."""
        return self.status is RecordStatus.VERIFIED and len(self.imports) > 0
