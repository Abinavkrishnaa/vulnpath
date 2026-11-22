# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development commands

Requires [uv](https://docs.astral.sh/uv/).

```bash
uv sync                          # create .venv with all workspace packages + dev tools
uv run ruff check .              # lint
uv run ruff format .             # format (use --check to only check)
uv run mypy                      # strict type check (Python 3.10 target)
uv run pytest --cov              # tests with coverage (90% gate enforced)
uv run pytest packages/vulnpath/tests/test_versions.py  # run a single test file
uv run vulnpath inventory .      # try the CLI on a project directory
```

All four CI checks (ruff check, ruff format --check, mypy, pytest --cov) must pass before opening a PR.

## Architecture

This is a `uv` workspace with two packages:

- **`packages/vulnpath/`** — the analyzer + CLI (published to PyPI). Entry point is `packages/vulnpath/src/vulnpath/cli/main.py` (Typer app).
- **`packages/vulnpath-schema/`** — shared Pydantic models and JSON Schemas used by both the analyzer and any external consumers.

### Core pipeline

1. **Lockfile ingestion** (`vulnpath/inputs/`): `discover.py` auto-detects `uv.lock`, `pylock.toml`, `poetry.lock`, or `requirements.txt` (in that priority order) and routes to the appropriate reader. Result is a frozen `Inventory` dataclass.

2. **Advisory matching** (`vulnpath/advisories/versions.py`): Implements OSV-schema version range evaluation with PEP 440 ordering. Returns a three-valued `Match` (AFFECTED / NOT_AFFECTED / UNDETERMINED) — UNDETERMINED is preferred over false negatives.

3. **Call graph / reachability** (not yet implemented as of M0/M1): The planned algorithm is a demand-driven backward search starting from each affected symbol, expanding callers until an entry point is reached or the frontier is empty. Name resolution will be behind a `CallResolver` interface (ADR-0002). The analyzer uses `ast` (stdlib only, no Rust, no LibCST) (ADR-0001).

4. **Verdict output** (`vulnpath_schema/findings.py`): Three-valued: `reachable` (must include call path), `not_reachable` (must have basis `symbol_not_called` or `package_not_imported`, no blockers), or `unknown` (must list at least one `Blocker`). The Pydantic `Finding` model enforces these invariants via `model_validator`.

### Soundness contract

**Soundness first** (from CONTRIBUTING.md): a change must never cause Vulnpath to report `not_reachable` where a path could exist. When uncertain, return `unknown` with a reason. This is enforced at the schema level in `Finding._evidence_matches_verdict`.

### Tests

- `packages/vulnpath/tests/` — integration and unit tests; no `fixtures/` directory yet (golden fixtures for the resolver go there when the call-graph work starts).
- `packages/vulnpath-schema/tests/` — schema model tests.
- Hypothesis is available for property-based testing.
- `S101` (assert) and `PLR0913` (too many args) are suppressed in test files.

## ADRs

Significant design choices are in `docs/adr/`. Key decisions:
- **ADR-0001**: Pure Python + stdlib `ast` (no native build).
- **ADR-0002**: Demand-driven backward search behind a `CallResolver` interface.
- **ADR-0003**: Three verdicts; `unknown` is the safe default; every verdict carries evidence.

New significant design choices need an ADR before implementation.

## Commit style

Short imperative subject (`Add poetry.lock reader`), body explaining why when non-obvious.
