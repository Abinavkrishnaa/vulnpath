"""Reader for pinned pip requirements files.

Only exact pins (`name==1.2.3`) count as resolved dependencies. Anything else is reported
as a warning, because analysing an unknown version could hide a vulnerable one.
"""

from __future__ import annotations

import re
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement

from vulnpath.inputs.models import Dependency, Inventory, SourceKind

_INLINE_OPTION = re.compile(r"\s+--?[A-Za-z]")
_COMMENT = re.compile(r"(^|\s)#.*$")


def _logical_lines(text: str) -> list[tuple[int, str]]:
    """Join backslash continuations and strip comments; keep the first physical line number."""
    lines: list[tuple[int, str]] = []
    buffer = ""
    start = 0
    for number, raw in enumerate(text.splitlines(), start=1):
        if not buffer:
            start = number
        stripped = raw.rstrip()
        if stripped.endswith("\\"):
            buffer += stripped[:-1] + " "
            continue
        buffer += stripped
        line = _COMMENT.sub("", buffer).strip()
        if line:
            lines.append((start, line))
        buffer = ""
    if buffer.strip():
        lines.append((start, _COMMENT.sub("", buffer).strip()))
    return lines


def _option_value(line: str, short: str, long: str) -> str | None:
    """Value of `-r FILE`, `-rFILE`, `--requirement FILE` or `--requirement=FILE` style options."""
    for prefix in (long + "=", long + " "):
        if line.startswith(prefix):
            return line[len(prefix) :].strip() or None
    if line.startswith(short) and not line.startswith("--"):
        return line[len(short) :].strip() or None
    return None


def _exact_pin(req: Requirement) -> str | None:
    specs = list(req.specifier)
    if len(specs) != 1 or specs[0].operator not in ("==", "==="):
        return None
    version = specs[0].version
    return None if version.endswith(".*") else version


def read_requirements(path: Path, _seen: frozenset[Path] = frozenset()) -> Inventory:
    resolved = path.resolve()
    if resolved in _seen:
        return Inventory.build(path, "requirements", [], [f"{path}: include cycle skipped"])
    seen = _seen | {resolved}

    deps: list[Dependency] = []
    warnings: list[str] = []
    for number, line in _logical_lines(path.read_text(encoding="utf-8")):
        where = f"{path.name}:{number}"
        include = _option_value(line, "-r", "--requirement")
        if include is not None:
            child = read_requirements(path.parent / include, seen)
            deps.extend(child.dependencies)
            warnings.extend(child.warnings)
            continue
        if _option_value(line, "-e", "--editable") is not None:
            warnings.append(f"{where}: editable install is not pinned: {line}")
            continue
        if line.startswith("-"):
            continue  # index URLs, constraints, global options: no dependency here
        requirement_text = _INLINE_OPTION.split(line, maxsplit=1)[0].strip()
        try:
            req = Requirement(requirement_text)
        except InvalidRequirement:
            warnings.append(f"{where}: cannot parse requirement: {line}")
            continue
        if req.url:
            warnings.append(f"{where}: direct URL requirement is not version-pinned: {req.name}")
            continue
        version = _exact_pin(req)
        if version is None:
            warnings.append(f"{where}: not pinned with '==': {requirement_text}")
            continue
        deps.append(Dependency.create(req.name, version, SourceKind.REGISTRY))
    return Inventory.build(path, "requirements", deps, warnings)
