"""Download the vulnpath dataset from a URL."""

from __future__ import annotations

import urllib.error
import urllib.request
from pathlib import Path

DATASET_URL = "https://github.com/vulnpath/vulnpath-data/releases/latest/download/vulnpath.jsonl"

_CHUNK = 65_536


class DownloadError(OSError):
    """Raised when the dataset cannot be downloaded."""


def download_dataset(url: str, dest: Path) -> None:
    """Download ``url`` to ``dest`` atomically.

    Writes to ``dest.with_suffix('.tmp')`` first; on success renames it to
    ``dest`` so a failed or interrupted download never leaves a partial file.
    """
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(".tmp")
    try:
        with urllib.request.urlopen(url) as resp, tmp.open("wb") as fh:  # noqa: S310
            while chunk := resp.read(_CHUNK):
                fh.write(chunk)
        tmp.replace(dest)
    except urllib.error.HTTPError as exc:
        tmp.unlink(missing_ok=True)
        raise DownloadError(f"HTTP {exc.code} fetching {url}") from exc
    except urllib.error.URLError as exc:
        tmp.unlink(missing_ok=True)
        raise DownloadError(f"Network error fetching {url}: {exc.reason}") from exc
    except Exception:
        tmp.unlink(missing_ok=True)
        raise
