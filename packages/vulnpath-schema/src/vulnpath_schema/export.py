"""Write JSON Schemas for the public models: `python -m vulnpath_schema.export OUT_DIR`."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from pydantic import BaseModel

from vulnpath_schema.dataset import DatasetRecord
from vulnpath_schema.findings import Report

MODELS: dict[str, type[BaseModel]] = {"dataset-record": DatasetRecord, "report": Report}


def export(out_dir: Path) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for name, model in MODELS.items():
        path = out_dir / f"{name}.schema.json"
        schema = model.model_json_schema()
        path.write_text(json.dumps(schema, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        written.append(path)
    return written


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("usage: python -m vulnpath_schema.export OUT_DIR", file=sys.stderr)
        return 2
    for path in export(Path(args[0])):
        print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
