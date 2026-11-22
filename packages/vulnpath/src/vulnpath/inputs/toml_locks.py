"""Readers for TOML lockfiles: uv.lock, poetry.lock and PEP 751 pylock.toml."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from vulnpath._toml import tomllib
from vulnpath.inputs.models import Dependency, Inventory, SourceKind

# Sources that point at first-party code inside the project; never third-party deps.
_UV_LOCAL_SOURCES = frozenset({"editable", "virtual", "directory", "workspace", "path"})
_POETRY_LOCAL_SOURCES = frozenset({"directory", "file"})


def _load(path: Path) -> dict[str, Any]:
    with path.open("rb") as handle:
        data: dict[str, Any] = tomllib.load(handle)
    return data


def read_uv_lock(path: Path) -> Inventory:
    """Read uv.lock.

    uv may lock several versions of one package for different environments (resolution
    forks by Python version or platform). All of them are kept: analysing a version that
    is never installed costs time, but skipping one that is installed could hide a hit.
    """
    data = _load(path)
    deps: list[Dependency] = []
    warnings: list[str] = []
    for pkg in data.get("package", []):
        name = pkg.get("name")
        source: dict[str, Any] = pkg.get("source", {})
        if not name or _UV_LOCAL_SOURCES & source.keys():
            continue
        version = pkg.get("version")
        if not version:
            warnings.append(f"{name}: no version in uv.lock")
            continue
        kind = SourceKind.GIT if "git" in source else SourceKind.REGISTRY
        if "url" in source:
            kind = SourceKind.URL
        deps.append(Dependency.create(name, str(version), kind))
    return Inventory.build(path, "uv.lock", deps, warnings)


def read_poetry_lock(path: Path) -> Inventory:
    data = _load(path)
    deps: list[Dependency] = []
    warnings: list[str] = []
    for pkg in data.get("package", []):
        name = pkg.get("name")
        source: dict[str, Any] = pkg.get("source", {})
        source_type = source.get("type")
        if not name or source_type in _POETRY_LOCAL_SOURCES:
            continue
        version = pkg.get("version")
        if not version:
            warnings.append(f"{name}: no version in poetry.lock")
            continue
        kind = {"git": SourceKind.GIT, "url": SourceKind.URL}.get(
            source_type or "", SourceKind.REGISTRY
        )
        deps.append(Dependency.create(name, str(version), kind))
    return Inventory.build(path, "poetry.lock", deps, warnings)


def read_pylock(path: Path) -> Inventory:
    """PEP 751 lockfile (`pylock.toml` or `pylock.<name>.toml`)."""
    data = _load(path)
    deps: list[Dependency] = []
    warnings: list[str] = []
    for pkg in data.get("packages", []):
        name = pkg.get("name")
        if not name or "directory" in pkg:
            continue
        version = pkg.get("version")
        if not version:
            warnings.append(f"{name}: no version in {path.name}")
            continue
        kind = SourceKind.REGISTRY
        if "vcs" in pkg:
            kind = SourceKind.GIT
        elif "archive" in pkg:
            kind = SourceKind.URL
        deps.append(Dependency.create(name, str(version), kind))
    return Inventory.build(path, "pylock.toml", deps, warnings)
