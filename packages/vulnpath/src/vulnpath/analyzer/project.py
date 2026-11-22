"""Collect and analyse all Python source files in a project directory."""

from __future__ import annotations

from pathlib import Path

from vulnpath.analyzer.walker import FileAnalysis, analyse_file

_SKIP_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "__pycache__",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
        "build",
        "dist",
        ".venv",
        "venv",
        "env",
        ".env",
        "node_modules",
        ".tox",
        ".nox",
        "site-packages",
    }
)


def collect_py_files(root: Path) -> list[Path]:
    """Return all .py files under root, skipping generated / vendor directories."""
    files: list[Path] = []
    for path in root.rglob("*.py"):
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        files.append(path)
    return sorted(files)


def analyse_project(root: Path) -> list[FileAnalysis]:
    """Analyse every Python file in the project; parse errors become FileAnalysis.error."""
    return [analyse_file(f) for f in collect_py_files(root)]
