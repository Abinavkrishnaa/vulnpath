# Contributing to Vulnpath

Thanks for your interest. The project is early, so issues and design discussion are as
valuable as code.

## Ground rules

1. **Soundness first.** A change must never make Vulnpath report `not_reachable` where a path
   could exist. When in doubt, return `unknown` with a reason.
2. **Every behaviour has a test.** New Python features handled by the resolver need a golden
   fixture in `packages/vulnpath/tests/fixtures/`.
3. **No recurring costs.** The project runs on free infrastructure only. A change that adds a
   paid service needs an ADR first.

## Setup

```bash
uv sync
uv run pytest
```

## Before opening a PR

```bash
uv run ruff check .
uv run ruff format .
uv run mypy
uv run pytest --cov
```

All four must pass; CI runs the same commands.

## Commit style

Short imperative subject (`Add poetry.lock reader`), body explaining why when it is not
obvious.

## Architecture decisions

Significant design choices are recorded in `docs/adr/`. Copy `docs/adr/template.md`,
number it, and open a PR for discussion.
