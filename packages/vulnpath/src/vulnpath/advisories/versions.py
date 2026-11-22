"""Decide whether a PyPI version falls inside OSV affected ranges.

Implements the evaluation described in the OSV schema
(https://ossf.github.io/osv-schema/#evaluation) for ECOSYSTEM ranges with PEP 440 ordering.

The result is three-valued on purpose: if a version or range cannot be interpreted, the
answer is UNDETERMINED, never "not affected". Callers turn that into an `unknown` verdict.
"""

from __future__ import annotations

from collections.abc import Iterable
from enum import Enum

from packaging.version import InvalidVersion, Version

from vulnpath_schema.osv import AffectedRange, RangeEvent, RangeType


class Match(str, Enum):
    AFFECTED = "affected"
    NOT_AFFECTED = "not_affected"
    UNDETERMINED = "undetermined"


class _Undetermined(Exception):  # noqa: N818 - internal control flow, not an error API
    pass


def _parse(raw: str) -> Version:
    try:
        return Version(raw)
    except InvalidVersion as exc:
        raise _Undetermined(raw) from exc


def _event_version(event: RangeEvent) -> Version | None:
    """Sort key; `introduced: "0"` means 'from the beginning' and sorts first."""
    raw = event.introduced or event.fixed or event.last_affected or event.limit
    if raw is None:  # pragma: no cover - RangeEvent validation guarantees one field
        raise _Undetermined("empty event")
    if event.introduced == "0":
        return None
    return _parse(raw)


def _in_range(version: Version, events: tuple[RangeEvent, ...]) -> bool:
    keyed = [(_event_version(e), e) for e in events]
    keyed.sort(key=lambda item: (item[0] is not None, item[0] or Version("0")))

    limits = [v for v, e in keyed if e.limit is not None and v is not None]
    if limits and all(version >= limit for limit in limits):
        return False

    vulnerable = False
    for event_version, event in keyed:
        if event.introduced is not None:
            if event_version is None or version >= event_version:
                vulnerable = True
        elif event.fixed is not None:
            if event_version is not None and version >= event_version:
                vulnerable = False
        elif (
            event.last_affected is not None
            and event_version is not None
            and version > event_version
        ):
            vulnerable = False
    return vulnerable


def match_version(
    version: str,
    ranges: Iterable[AffectedRange],
    versions: Iterable[str] = (),
) -> Match:
    """Is `version` affected according to OSV `ranges` and the explicit `versions` list?"""
    try:
        target = _parse(version)
        if any(_parse(v) == target for v in versions):
            return Match.AFFECTED

        saw_unsupported = False
        for affected_range in ranges:
            if affected_range.type is not RangeType.ECOSYSTEM:
                saw_unsupported = True  # GIT/SEMVER ranges cannot be mapped to PyPI versions
                continue
            if _in_range(target, affected_range.events):
                return Match.AFFECTED
    except _Undetermined:
        return Match.UNDETERMINED

    return Match.UNDETERMINED if saw_unsupported else Match.NOT_AFFECTED
