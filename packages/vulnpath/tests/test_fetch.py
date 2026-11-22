"""Tests for vulnpath.advisories.fetch."""

from __future__ import annotations

import io
import urllib.error
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from vulnpath.advisories.fetch import DATASET_URL, DownloadError, download_dataset


def _mock_response(data: bytes) -> MagicMock:
    """Return a mock that behaves like urllib.request.urlopen()'s context manager."""
    bio = io.BytesIO(data)
    mock = MagicMock()
    mock.__enter__ = lambda s: s
    mock.__exit__ = MagicMock(return_value=False)
    mock.read = bio.read
    return mock


class TestDatasetUrl:
    def test_is_non_empty_string(self) -> None:
        assert isinstance(DATASET_URL, str)
        assert DATASET_URL


class TestDownloadDataset:
    def test_writes_content_to_dest(self, tmp_path: Path) -> None:
        content = b'{"id": "GHSA-2222-cccc-ffff"}\n'
        dest = tmp_path / "dataset.jsonl"
        with patch("urllib.request.urlopen", return_value=_mock_response(content)):
            download_dataset("https://example.com/dataset.jsonl", dest)
        assert dest.read_bytes() == content

    def test_creates_parent_directory(self, tmp_path: Path) -> None:
        content = b"data\n"
        dest = tmp_path / "subdir" / "dataset.jsonl"
        with patch("urllib.request.urlopen", return_value=_mock_response(content)):
            download_dataset("https://example.com/dataset.jsonl", dest)
        assert dest.exists()

    def test_atomic_write_no_tmp_on_success(self, tmp_path: Path) -> None:
        dest = tmp_path / "dataset.jsonl"
        with patch("urllib.request.urlopen", return_value=_mock_response(b"ok\n")):
            download_dataset("https://example.com/dataset.jsonl", dest)
        assert not dest.with_suffix(".tmp").exists()

    def test_no_partial_file_on_http_error(self, tmp_path: Path) -> None:
        dest = tmp_path / "dataset.jsonl"
        exc = urllib.error.HTTPError("url", 404, "Not Found", {}, None)  # type: ignore[arg-type]
        with patch("urllib.request.urlopen", side_effect=exc), pytest.raises(DownloadError):
            download_dataset("https://example.com/dataset.jsonl", dest)
        assert not dest.exists()
        assert not dest.with_suffix(".tmp").exists()

    def test_no_partial_file_on_network_error(self, tmp_path: Path) -> None:
        dest = tmp_path / "dataset.jsonl"
        exc = urllib.error.URLError("connection refused")
        with patch("urllib.request.urlopen", side_effect=exc), pytest.raises(DownloadError):
            download_dataset("https://example.com/dataset.jsonl", dest)
        assert not dest.with_suffix(".tmp").exists()

    def test_http_error_raises_download_error_with_code(self, tmp_path: Path) -> None:
        dest = tmp_path / "dataset.jsonl"
        exc = urllib.error.HTTPError("url", 403, "Forbidden", {}, None)  # type: ignore[arg-type]
        with (
            patch("urllib.request.urlopen", side_effect=exc),
            pytest.raises(DownloadError, match="403"),
        ):
            download_dataset("https://example.com/dataset.jsonl", dest)

    def test_url_error_raises_download_error(self, tmp_path: Path) -> None:
        dest = tmp_path / "dataset.jsonl"
        exc = urllib.error.URLError("name resolution failed")
        with (
            patch("urllib.request.urlopen", side_effect=exc),
            pytest.raises(DownloadError, match="Network error"),
        ):
            download_dataset("https://example.com/dataset.jsonl", dest)

    def test_overwrites_existing_file(self, tmp_path: Path) -> None:
        dest = tmp_path / "dataset.jsonl"
        dest.write_bytes(b"old content\n")
        new_content = b"new content\n"
        with patch("urllib.request.urlopen", return_value=_mock_response(new_content)):
            download_dataset("https://example.com/dataset.jsonl", dest)
        assert dest.read_bytes() == new_content

    def test_existing_file_preserved_on_error(self, tmp_path: Path) -> None:
        """A failed download must not destroy the previously cached dataset."""
        dest = tmp_path / "dataset.jsonl"
        dest.write_bytes(b"good data\n")
        exc = urllib.error.HTTPError("url", 500, "Server Error", {}, None)  # type: ignore[arg-type]
        with patch("urllib.request.urlopen", side_effect=exc), pytest.raises(DownloadError):
            download_dataset("https://example.com/dataset.jsonl", dest)
        assert dest.read_bytes() == b"good data\n"
