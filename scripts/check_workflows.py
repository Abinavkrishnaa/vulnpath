"""Guard for GitHub Actions workflows.

Fails if any workflow:
- uses a third-party action not pinned to a full 40-character commit SHA, or
- runs on a runner label that is not a free standard GitHub-hosted runner.

Standard runners are free for public repositories; larger runners are always billed.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

WORKFLOW_DIR = Path(".github/workflows")
USES = re.compile(r"^\s*-?\s*uses:\s*(?P<ref>\S+)")
RUNS_ON = re.compile(r"^\s*runs-on:\s*(?P<label>.+?)\s*$")
PINNED = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")
STANDARD_RUNNERS = {
    "ubuntu-latest",
    "ubuntu-24.04",
    "ubuntu-22.04",
    "macos-latest",
    "macos-15",
    "macos-14",
    "windows-latest",
    "windows-2025",
    "windows-2022",
    "${{ matrix.os }}",
}


def check(path: Path) -> list[str]:
    problems: list[str] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if (match := USES.match(line)) is not None:
            ref = match["ref"]
            if not ref.startswith("./") and not PINNED.match(ref):
                problems.append(f"{path}:{number}: action not pinned to a commit SHA: {ref}")
        if (match := RUNS_ON.match(line)) is not None:
            label = match["label"].strip("'\"")
            if label not in STANDARD_RUNNERS:
                problems.append(f"{path}:{number}: runner is not a free standard runner: {label}")
    return problems


def main() -> int:
    problems = [p for wf in sorted(WORKFLOW_DIR.glob("*.y*ml")) for p in check(wf)]
    for problem in problems:
        print(problem, file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
