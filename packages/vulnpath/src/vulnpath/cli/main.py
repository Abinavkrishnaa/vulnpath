"""Command-line interface."""

from __future__ import annotations

import json
from enum import Enum
from pathlib import Path
from typing import Annotated

import typer

from vulnpath import __version__
from vulnpath.inputs import LockfileNotFoundError, discover_lockfile, load_lockfile
from vulnpath.inputs.discover import UnsupportedLockfileError

EXIT_OK = 0
EXIT_TOOL_ERROR = 2

app = typer.Typer(
    name="vulnpath",
    help="Does your code actually call the vulnerable function?",
    no_args_is_help=True,
    add_completion=False,
)


class OutputFormat(str, Enum):
    TEXT = "text"
    JSON = "json"


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"vulnpath {__version__}")
        raise typer.Exit(EXIT_OK)


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option("--version", callback=_version_callback, is_eager=True, help="Show version."),
    ] = False,
) -> None:
    """Vulnpath command line."""


@app.command()
def inventory(
    path: Annotated[Path, typer.Argument(help="Project directory.")] = Path(),
    lockfile: Annotated[
        Path | None, typer.Option("--lockfile", help="Use this lockfile instead of discovery.")
    ] = None,
    output: Annotated[OutputFormat, typer.Option("--format", help="Output format.")] = (
        OutputFormat.TEXT
    ),
) -> None:
    """List the locked third-party dependencies Vulnpath will analyse."""
    try:
        chosen = lockfile if lockfile is not None else discover_lockfile(path)
        result = load_lockfile(chosen)
    except (LockfileNotFoundError, UnsupportedLockfileError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(EXIT_TOOL_ERROR) from exc

    if output is OutputFormat.JSON:
        payload = {
            "lockfile": str(result.lockfile),
            "format": result.format,
            "dependencies": [
                {"name": d.name, "version": d.version, "source": d.source.value}
                for d in result.dependencies
            ],
            "warnings": list(result.warnings),
        }
        typer.echo(json.dumps(payload, indent=2))
        return

    typer.echo(f"{result.lockfile} ({result.format}): {len(result.dependencies)} dependencies")
    for dep in result.dependencies:
        suffix = "" if dep.source.value == "registry" else f"  [{dep.source.value}]"
        typer.echo(f"  {dep.name}=={dep.version}{suffix}")
    for warning in result.warnings:
        typer.echo(f"warning: {warning}", err=True)
