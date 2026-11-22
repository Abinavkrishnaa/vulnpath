"""Tests for vulnpath.cache."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from vulnpath.cache import cache_dir, cached_dataset_path, dataset_is_cached

_POSIX_ONLY = pytest.mark.skipif(
    sys.platform == "win32", reason="POSIX-path test, skipped on Windows"
)


class TestCacheDir:
    def test_returns_path(self) -> None:
        assert isinstance(cache_dir(), Path)

    def test_ends_with_vulnpath(self) -> None:
        assert cache_dir().name == "vulnpath"

    def test_windows_uses_localappdata(self) -> None:
        fake = "C:\\Users\\user\\AppData\\Local"
        with patch.dict(os.environ, {"LOCALAPPDATA": fake}), patch("os.name", "nt"):
            result = cache_dir()
        assert result == Path(fake) / "vulnpath"

    @_POSIX_ONLY
    def test_linux_uses_xdg_cache_home(self) -> None:
        fake = "/var/cache/custom"
        with (
            patch.dict(os.environ, {"XDG_CACHE_HOME": fake}),
            patch("os.name", "posix"),
            patch("sys.platform", "linux"),
        ):
            result = cache_dir()
        assert result == Path(fake) / "vulnpath"

    @_POSIX_ONLY
    def test_linux_falls_back_to_home_cache(self) -> None:
        env = {k: v for k, v in os.environ.items() if k != "XDG_CACHE_HOME"}
        with (
            patch.dict(os.environ, env, clear=True),
            patch("os.name", "posix"),
            patch("sys.platform", "linux"),
        ):
            result = cache_dir()
        assert result == Path.home() / ".cache" / "vulnpath"

    @_POSIX_ONLY
    def test_macos_uses_library_caches(self) -> None:
        with patch("os.name", "posix"), patch("sys.platform", "darwin"):
            result = cache_dir()
        assert result == Path.home() / "Library" / "Caches" / "vulnpath"


class TestCachedDatasetPath:
    def test_is_inside_cache_dir(self) -> None:
        assert cached_dataset_path().parent == cache_dir()

    def test_filename_is_dataset_jsonl(self) -> None:
        assert cached_dataset_path().name == "dataset.jsonl"


class TestDatasetIsCached:
    def test_true_when_file_exists(self, tmp_path: Path) -> None:
        fake = tmp_path / "dataset.jsonl"
        fake.write_text("", encoding="utf-8")
        with patch("vulnpath.cache.cached_dataset_path", return_value=fake):
            assert dataset_is_cached() is True

    def test_false_when_file_absent(self, tmp_path: Path) -> None:
        fake = tmp_path / "dataset.jsonl"
        with patch("vulnpath.cache.cached_dataset_path", return_value=fake):
            assert dataset_is_cached() is False
