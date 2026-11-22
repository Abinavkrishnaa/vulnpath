# vulnpath

**Does your code actually call the vulnerable function?**

Vulnpath cuts through CVE noise by running your project's call graph against
the specific function that was patched. Each matched advisory gets one of three
evidence-backed verdicts:

| Verdict | Meaning |
|---|---|
| `reachable` | A direct call to the vulnerable function was found, with file and line |
| `not_reachable` | The package isn't imported, or the symbol is never called — with proof |
| `unknown` | Dynamic code, `eval`, or a parse error prevents a confident answer |

**Sound by design**: Vulnpath never clears a verdict it cannot prove. Dynamic
code, parse errors, or missing symbol data produce `unknown` — not a false
`not_reachable`.

## Install

```bash
pip install vulnpath
```

Requires Python 3.10+. No native build step — single wheel for all platforms.

## Quick start

```bash
# Download the vulnerability dataset to the platform cache directory
vulnpath update

# Scan your project (default: current directory)
vulnpath scan .
```

## Example output

```
Scanned 42 dependencies against 1,247 advisories.

  pydantic==1.10.0  GHSA-m5p6-rcfg-hjmp  reachable
    └─ src/api/models.py:94  pydantic.BaseModel.model_validate

  requests==2.28.2  GHSA-j2r3-vw56-cfgh  not_reachable
       (package not imported)

  urllib3==1.26.14  GHSA-q3r4-vwfg-hjm2  unknown
    ! dynamic_import  src/utils/http.py:12

3 findings: 1 reachable, 1 not_reachable, 1 unknown
```

Exit codes: `0` = no reachable findings · `1` = at least one reachable · `2` = tool error.

## Machine-readable output

```bash
vulnpath scan . --format json
```

The JSON report follows the [vulnpath-schema](https://pypi.org/project/vulnpath-schema/)
structure, with each finding carrying its verdict, evidence path, basis, and blockers.

## Commands

| Command | Description |
|---|---|
| `vulnpath update [--url URL]` | Download the latest vulnerability dataset |
| `vulnpath scan [PATH] [--dataset FILE] [--lockfile FILE] [--format text\|json]` | Scan the project |
| `vulnpath inventory [PATH] [--lockfile FILE] [--format text\|json]` | List scanned dependencies |

Pass `--help` to any command for the full option list.

## Supported lockfile formats

- `uv.lock`
- `requirements.txt` / `requirements*.txt`
- `pyproject.toml` (PEP 621 / uv inline dependencies)

## How it works

1. **Lockfile** — reads your pinned dependency versions from the lockfile
2. **Match** — compares each version against the vulnpath dataset: PyPA advisories
   enriched with the specific symbol (function / method / class) that was patched
3. **Analyse** — the AST analyser walks your project's Python files, resolves import
   bindings (including aliases), and looks for direct call sites of the affected symbol

Dynamic code (`eval`, `exec`, `__import__`, `importlib.import_module`) produces an
`unknown` verdict with a `dynamic_import` or `eval_exec` blocker rather than
silently missing a potential call.

## Principles

- Your code never leaves your machine
- Pure Python, stdlib `ast` — no native build step, no extra dependencies beyond
  `pydantic` and `typer`
- Dataset is open (CC-BY-4.0) and contributed upstream to the
  [PyPA Advisory Database](https://github.com/pypa/advisory-database)

## Status

Alpha. The call graph analyser handles direct function calls and import-alias
chains across all Python files in the project. Full entry-point-to-function path
search and cross-module call chains are roadmapped.

## License

Apache-2.0
