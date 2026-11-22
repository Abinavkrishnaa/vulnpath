from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from packaging.utils import NormalizedName, canonicalize_name
from pydantic import ValidationError

from vulnpath.advisories.versions import Match, match_version
from vulnpath.inputs.models import Dependency, Inventory
from vulnpath_schema.dataset import DatasetRecord


class DatasetLoadError(OSError):
    """Raised when the dataset file cannot be opened."""


@dataclass(frozen=True)
class Dataset:
    """Records read from one JSONL dataset file.

    ``warnings`` lists lines that could not be parsed. A bad line never raises; it
    produces a warning so the caller can surface it. This is intentionally *not*
    sound: an unreadable record cannot produce a verdict at all, so we surface the
    warning rather than silently dropping it.
    """

    path: Path
    records: tuple[DatasetRecord, ...]
    warnings: tuple[str, ...] = field(default=())


@dataclass(frozen=True)
class MatchedAdvisory:
    """An advisory whose affected range covers a dependency in the scanned inventory.

    ``match`` is always ``AFFECTED`` or ``UNDETERMINED``; ``NOT_AFFECTED`` is filtered
    out before constructing this object.
    """

    record: DatasetRecord
    package: NormalizedName
    version: str
    match: Match


def load_dataset(path: Path) -> Dataset:
    """Read a JSONL dataset file and return a :class:`Dataset`.

    Each non-empty line must be a JSON object that validates as a
    :class:`~vulnpath_schema.dataset.DatasetRecord`. Lines that fail JSON parsing or
    Pydantic validation are collected as warnings and skipped.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise DatasetLoadError(str(exc)) from exc

    records: list[DatasetRecord] = []
    warnings: list[str] = []
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line:
            continue
        try:
            records.append(DatasetRecord.model_validate_json(line))
        except (ValidationError, json.JSONDecodeError) as exc:
            warnings.append(f"line {lineno}: skipped ({exc})")

    return Dataset(path=path, records=tuple(records), warnings=tuple(warnings))


def match_inventory(
    inventory: Inventory,
    records: Iterable[DatasetRecord],
) -> list[MatchedAdvisory]:
    """Return every (record, dependency) pair where the dependency version is affected.

    ``NOT_AFFECTED`` results are excluded. ``UNDETERMINED`` results are kept: by the
    soundness contract a version that cannot be classified must not be cleared.

    Package name lookup is normalised (PEP 503) so ``Pillow`` and ``pillow`` match the
    same inventory entry.
    """
    by_name: dict[NormalizedName, list[Dependency]] = {}
    for dep in inventory.dependencies:
        by_name.setdefault(dep.name, []).append(dep)

    matched: list[MatchedAdvisory] = []
    for record in records:
        norm = canonicalize_name(record.package)
        for dep in by_name.get(norm, []):
            result = match_version(dep.version, record.affected)
            if result is Match.NOT_AFFECTED:
                continue
            matched.append(
                MatchedAdvisory(
                    record=record,
                    package=dep.name,
                    version=dep.version,
                    match=result,
                )
            )
    return matched
