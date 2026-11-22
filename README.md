# Vulnpath

**Does your code actually call the vulnerable function?** Vulnpath answers that for every
dependency vulnerability alert in a Python project, and shows its evidence.

> Status: **alpha** (v0.1.0). Core pipeline works end-to-end. See [releases](https://github.com/Abinavkrishnaa/vulnpath/releases) for the latest version.

## What it does

For each advisory that matches your locked dependencies, Vulnpath returns one verdict:

| Verdict | Meaning | Evidence |
| --- | --- | --- |
| `reachable` | A call path exists from an entry point to the affected function | The full call path, file and line per hop |
| `not_reachable` | A complete search found no path | What was searched |
| `unknown` | Something could hide a call (dynamic import, `eval`, plugin loading) or no symbol data exists | Each blocker with file and line |

Vulnpath is **sound by default**: when it cannot prove a function is unreachable, it says
`unknown`, never `not_reachable`.

## Principles

- Your code never leaves your machine.
- Verified affected-symbol data is open (CC-BY-4.0) and contributed upstream to the
  [PyPA Advisory Database](https://github.com/pypa/advisory-database).
- Runs entirely on free infrastructure.

## Repository layout

```
packages/vulnpath/          analyzer + CLI (published to PyPI)
packages/vulnpath-schema/   shared Pydantic models and JSON Schemas
docs/adr/                   architecture decision records
benchmark/                  labelled benchmark corpus (coming in M1)
```

## Development

Requires [uv](https://docs.astral.sh/uv/).

```bash
uv sync                      # create .venv with all workspace packages + dev tools
uv run ruff check .          # lint
uv run ruff format --check . # format check
uv run mypy                  # strict type check
uv run pytest --cov          # tests with coverage (90% gate)
uv run vulnpath inventory .  # try the CLI on a project directory
```

## License

Code: Apache-2.0. Dataset (separate `vulnpath-data` repo): CC-BY-4.0.
