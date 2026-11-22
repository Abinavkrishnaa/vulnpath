"""Reachability engine: determine whether affected symbols are reachable in the project."""

from __future__ import annotations

from pathlib import Path

from vulnpath.analyzer.project import analyse_project
from vulnpath.analyzer.walker import FileAnalysis
from vulnpath_schema.dataset import AffectedImport
from vulnpath_schema.findings import Basis, Blocker, BlockerKind, PathHop, SearchStats, Verdict


def _target_names(imports: tuple[AffectedImport, ...]) -> frozenset[str]:
    names: set[str] = set()
    for imp in imports:
        names.update(imp.qualified_names())
    return frozenset(names)


def _affected_packages(imports: tuple[AffectedImport, ...]) -> frozenset[str]:
    return frozenset(mod.split(".")[0] for imp in imports for mod in imp.modules)


def _imports_package(analysis: FileAnalysis, packages: frozenset[str]) -> bool:
    return any(canonical.split(".")[0] in packages for canonical in analysis.imports.values())


_Result = tuple[Verdict, Basis | None, tuple[PathHop, ...], tuple[Blocker, ...], SearchStats]


def _collect_blockers(analyses: list[FileAnalysis]) -> list[Blocker]:
    blockers: list[Blocker] = []
    for a in analyses:
        if a.error:
            blockers.append(Blocker(kind=BlockerKind.PARSE_ERROR, file=str(a.path), detail=a.error))
        for dyn in a.dynamic_uses:
            kind = BlockerKind.EVAL_EXEC if dyn.kind == "eval_exec" else BlockerKind.DYNAMIC_IMPORT
            blockers.append(Blocker(kind=kind, file=dyn.file, line=dyn.line, detail=dyn.detail))
    return blockers


def _not_imported_result(blockers: list[Blocker], stats: SearchStats) -> _Result:
    uncertain = any(
        b.kind in (BlockerKind.DYNAMIC_IMPORT, BlockerKind.PARSE_ERROR) for b in blockers
    )
    if uncertain:
        return Verdict.UNKNOWN, None, (), tuple(blockers), stats
    return Verdict.NOT_REACHABLE, Basis.PACKAGE_NOT_IMPORTED, (), (), stats


def _first_call_site(
    analyses: list[FileAnalysis],
    targets: frozenset[str],
) -> PathHop | None:
    for a in analyses:
        for call in a.calls:
            if call.qualname in targets:
                return PathHop(qualname=call.qualname, file=call.file, line=call.line)
    return None


def check_reachability(
    affected_imports: tuple[AffectedImport, ...],
    analyses: list[FileAnalysis],
) -> _Result:
    """Pure reachability check given pre-computed file analyses.

    Soundness rules applied in order:
    1. No symbol data → unknown (NO_SYMBOL_DATA).
    2. No import of the affected package, no uncertain blockers → not_reachable
       (PACKAGE_NOT_IMPORTED). Parse errors or dynamic imports block this.
    3. Whole-module import (attribute=None) → reachable at the import site.
    4. Direct call site found for a target qualified name → reachable.
    5. Package imported, no call site, blockers present → unknown.
    6. Package imported, no call site, no blockers → not_reachable (SYMBOL_NOT_CALLED).
    """
    n_modules = len(analyses)
    n_call_sites = sum(len(a.calls) for a in analyses)
    stats = SearchStats(entry_points=0, modules=n_modules, call_sites=n_call_sites)

    if not affected_imports:
        return (
            Verdict.UNKNOWN,
            None,
            (),
            (Blocker(kind=BlockerKind.NO_SYMBOL_DATA, detail="no affected-symbol data"),),
            stats,
        )

    blockers = _collect_blockers(analyses)
    packages = _affected_packages(affected_imports)
    importing_files = [a for a in analyses if _imports_package(a, packages)]

    if not importing_files:
        return _not_imported_result(blockers, stats)

    if all(imp.attribute is None for imp in affected_imports):
        a = importing_files[0]
        for canonical in a.imports.values():
            if canonical.split(".")[0] in packages:
                hop = PathHop(qualname=canonical, file=str(a.path), line=1)
                return Verdict.REACHABLE, None, (hop,), (), stats

    call_hop = _first_call_site(analyses, _target_names(affected_imports))
    if call_hop is not None:
        return Verdict.REACHABLE, None, (call_hop,), (), stats

    if blockers:
        return Verdict.UNKNOWN, None, (), tuple(blockers), stats

    return Verdict.NOT_REACHABLE, Basis.SYMBOL_NOT_CALLED, (), (), stats


def analyse(
    affected_imports: tuple[AffectedImport, ...],
    project_root: Path,
) -> tuple[Verdict, Basis | None, tuple[PathHop, ...], tuple[Blocker, ...], SearchStats]:
    """Analyse the project at project_root and return the reachability result."""
    return check_reachability(affected_imports, analyse_project(project_root))
