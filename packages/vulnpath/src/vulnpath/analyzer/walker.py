"""AST-based per-file analysis: imports, call sites, and dynamic code patterns."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class CallSite:
    qualname: str
    file: str
    line: int


@dataclass(frozen=True)
class DynamicUse:
    kind: str  # "eval_exec" | "dynamic_import"
    file: str
    line: int
    detail: str


@dataclass(frozen=True)
class FileAnalysis:
    path: Path
    imports: dict[str, str]  # local_name → canonical qualified name
    calls: tuple[CallSite, ...]
    dynamic_uses: tuple[DynamicUse, ...]
    error: str | None


def _build_imports(tree: ast.Module) -> dict[str, str]:
    """Map every local binding introduced by an import to its canonical dotted name."""
    imports: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local = alias.asname if alias.asname else alias.name.split(".")[0]
                imports[local] = alias.name
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                local = alias.asname if alias.asname else alias.name
                canonical = f"{module}.{alias.name}" if module else alias.name
                imports[local] = canonical
    return imports


def _attr_chain(node: ast.expr) -> str | None:
    """Flatten a.b.c into 'a.b.c', or return None for non-name/attribute nodes."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _attr_chain(node.value)
        return f"{base}.{node.attr}" if base is not None else None
    return None


def _qualify(name: str, imports: dict[str, str]) -> str:
    """Replace the leading component of name with its canonical form when known."""
    head, _, tail = name.partition(".")
    if head in imports:
        base = imports[head]
        return f"{base}.{tail}" if tail else base
    return name


_EVAL_EXEC = frozenset({"eval", "exec"})
_DYN_IMPORT = frozenset({"__import__"})
_IMPORTLIB_METHODS = frozenset({"import_module", "reload"})


class _CallVisitor(ast.NodeVisitor):
    def __init__(self, path: str, imports: dict[str, str]) -> None:
        self._path = path
        self._imports = imports
        self.calls: list[CallSite] = []
        self.dynamic: list[DynamicUse] = []

    def visit_Call(self, node: ast.Call) -> None:
        chain = _attr_chain(node.func)
        if chain is not None:
            head = chain.split(".")[0]
            qualified = _qualify(chain, self._imports)
            last = chain.rsplit(".", 1)[-1]
            if head in _EVAL_EXEC:
                self.dynamic.append(DynamicUse("eval_exec", self._path, node.lineno, chain))
            elif head in _DYN_IMPORT:
                self.dynamic.append(DynamicUse("dynamic_import", self._path, node.lineno, chain))
            elif last in _IMPORTLIB_METHODS and "importlib" in qualified:
                self.dynamic.append(
                    DynamicUse("dynamic_import", self._path, node.lineno, qualified)
                )
            else:
                self.calls.append(CallSite(qualified, self._path, node.lineno))
        self.generic_visit(node)


def analyse_file(path: Path) -> FileAnalysis:
    """Parse a Python source file and extract import bindings, call sites, and dynamic uses."""
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source, filename=str(path))
    except SyntaxError as exc:
        return FileAnalysis(path=path, imports={}, calls=(), dynamic_uses=(), error=str(exc))
    except OSError as exc:
        return FileAnalysis(path=path, imports={}, calls=(), dynamic_uses=(), error=str(exc))

    imports = _build_imports(tree)
    visitor = _CallVisitor(str(path), imports)
    visitor.visit(tree)
    return FileAnalysis(
        path=path,
        imports=imports,
        calls=tuple(visitor.calls),
        dynamic_uses=tuple(visitor.dynamic),
        error=None,
    )
