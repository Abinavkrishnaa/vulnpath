from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from packaging.utils import NormalizedName, canonicalize_name


class SourceKind(str, Enum):
    REGISTRY = "registry"
    GIT = "git"
    URL = "url"


@dataclass(frozen=True, order=True)
class Dependency:
    """A third-party distribution pinned to one version."""

    name: NormalizedName
    version: str
    source: SourceKind = SourceKind.REGISTRY

    @classmethod
    def create(
        cls, name: str, version: str, source: SourceKind = SourceKind.REGISTRY
    ) -> Dependency:
        return cls(name=canonicalize_name(name), version=version.strip(), source=source)


@dataclass(frozen=True)
class Inventory:
    """Everything read from one lockfile.

    `warnings` lists entries that could not be pinned (editable installs, unpinned
    requirements, missing versions). The analyzer turns them into `unknown` evidence
    instead of silently dropping them.
    """

    lockfile: Path
    format: str
    dependencies: tuple[Dependency, ...]
    warnings: tuple[str, ...] = field(default=())

    @staticmethod
    def build(lockfile: Path, fmt: str, deps: list[Dependency], warnings: list[str]) -> Inventory:
        unique: dict[tuple[str, str], Dependency] = {}
        for dep in deps:
            unique.setdefault((dep.name, dep.version), dep)
        return Inventory(
            lockfile=lockfile,
            format=fmt,
            dependencies=tuple(sorted(unique.values())),
            warnings=tuple(warnings),
        )
