"""tomllib on 3.11+, tomli on 3.10."""

import sys

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised only on 3.10 in CI
    import tomli as tomllib

__all__ = ["tomllib"]
