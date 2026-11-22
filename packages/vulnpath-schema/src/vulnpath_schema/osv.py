"""Subset of the OSV schema needed to describe affected version ranges.

See https://ossf.github.io/osv-schema/#affectedranges-field
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, model_validator


class RangeType(str, Enum):
    ECOSYSTEM = "ECOSYSTEM"
    SEMVER = "SEMVER"
    GIT = "GIT"


class RangeEvent(BaseModel):
    """Exactly one of the four fields is set, as in OSV."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    introduced: str | None = None
    fixed: str | None = None
    last_affected: str | None = None
    limit: str | None = None

    @model_validator(mode="after")
    def _exactly_one(self) -> RangeEvent:
        set_fields = [
            name
            for name in ("introduced", "fixed", "last_affected", "limit")
            if getattr(self, name) is not None
        ]
        if len(set_fields) != 1:
            msg = f"a range event must set exactly one field, got {set_fields or 'none'}"
            raise ValueError(msg)
        return self


class AffectedRange(BaseModel):
    model_config = ConfigDict(frozen=True, extra="ignore")

    type: RangeType
    events: tuple[RangeEvent, ...]
