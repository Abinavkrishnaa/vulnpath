"""Platform-appropriate cache directory for vulnpath."""

from __future__ import annotations

import os
import sys
from pathlib import Path


def cache_dir() -> Path:
    """Return the platform cache directory for vulnpath.

    Windows : %LOCALAPPDATA%\\vulnpath
    macOS   : ~/Library/Caches/vulnpath
    other   : $XDG_CACHE_HOME/vulnpath  (default: ~/.cache/vulnpath)
    """
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Caches"
    else:
        base = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
    return base / "vulnpath"


def cached_dataset_path() -> Path:
    """Return the path where the downloaded dataset is stored."""
    return cache_dir() / "dataset.jsonl"


def dataset_is_cached() -> bool:
    """Return True when a local dataset file is present."""
    return cached_dataset_path().is_file()
