"""Tests for vulnpath.analyzer.engine."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from vulnpath.analyzer.engine import analyse, check_reachability
from vulnpath.analyzer.walker import analyse_file
from vulnpath_schema.dataset import AffectedImport, SymbolKind
from vulnpath_schema.findings import Basis, BlockerKind, Verdict


def _imp(
    module: str = "requests",
    attribute: str | None = "get",
    kind: SymbolKind = SymbolKind.FUNCTION,
) -> AffectedImport:
    return AffectedImport(modules=(module,), attribute=attribute, kind=kind)


def _write_py(tmp_path: Path, name: str, source: str) -> Path:
    p = tmp_path / name
    p.write_text(textwrap.dedent(source), encoding="utf-8")
    return p


class TestCheckReachability:
    def test_empty_imports_returns_no_symbol_data(self) -> None:
        verdict, _, _, blockers, _ = check_reachability((), [])
        assert verdict is Verdict.UNKNOWN
        assert blockers[0].kind is BlockerKind.NO_SYMBOL_DATA

    def test_no_project_files_package_not_imported(self) -> None:
        verdict, basis, _, _, _ = check_reachability((_imp(),), [])
        assert verdict is Verdict.NOT_REACHABLE
        assert basis is Basis.PACKAGE_NOT_IMPORTED

    def test_package_not_imported_in_any_file(self, tmp_path: Path) -> None:
        p = _write_py(tmp_path, "a.py", "import os\nos.path.join('a', 'b')\n")
        verdict, basis, _, _, _ = check_reachability((_imp(),), [analyse_file(p)])
        assert verdict is Verdict.NOT_REACHABLE
        assert basis is Basis.PACKAGE_NOT_IMPORTED

    def test_package_imported_but_symbol_not_called(self, tmp_path: Path) -> None:
        p = _write_py(tmp_path, "a.py", "import requests\n# requests.get not called\n")
        verdict, basis, _, _, _ = check_reachability((_imp(),), [analyse_file(p)])
        assert verdict is Verdict.NOT_REACHABLE
        assert basis is Basis.SYMBOL_NOT_CALLED

    def test_symbol_called_returns_reachable(self, tmp_path: Path) -> None:
        p = _write_py(tmp_path, "a.py", "import requests\nrequests.get('http://x')\n")
        verdict, _, path, _, _ = check_reachability((_imp(),), [analyse_file(p)])
        assert verdict is Verdict.REACHABLE
        assert len(path) == 1
        assert path[0].qualname == "requests.get"

    def test_from_import_call_returns_reachable(self, tmp_path: Path) -> None:
        src = "from pydantic import BaseModel\nBaseModel.model_validate({})\n"
        p = _write_py(tmp_path, "a.py", src)
        imp = _imp("pydantic", "BaseModel.model_validate", SymbolKind.METHOD)
        verdict, _, path, _, _ = check_reachability((imp,), [analyse_file(p)])
        assert verdict is Verdict.REACHABLE
        assert path[0].qualname == "pydantic.BaseModel.model_validate"

    def test_reachable_path_hop_has_correct_line(self, tmp_path: Path) -> None:
        p = _write_py(tmp_path, "a.py", "import requests\n\nrequests.get('x')\n")
        verdict, _, path, _, _ = check_reachability((_imp(),), [analyse_file(p)])
        assert verdict is Verdict.REACHABLE
        assert path[0].line == 3

    def test_eval_in_project_returns_unknown(self, tmp_path: Path) -> None:
        p = _write_py(tmp_path, "a.py", "import requests\neval('requests.get()')\n")
        verdict, _, _, blockers, _ = check_reachability((_imp(),), [analyse_file(p)])
        assert verdict is Verdict.UNKNOWN
        assert any(b.kind is BlockerKind.EVAL_EXEC for b in blockers)

    def test_dynamic_import_with_no_static_import_returns_unknown(self, tmp_path: Path) -> None:
        p = _write_py(tmp_path, "a.py", "__import__('requests')\n")
        verdict, _, _, blockers, _ = check_reachability((_imp(),), [analyse_file(p)])
        assert verdict is Verdict.UNKNOWN
        assert any(b.kind is BlockerKind.DYNAMIC_IMPORT for b in blockers)

    def test_parse_error_returns_unknown(self, tmp_path: Path) -> None:
        p = _write_py(tmp_path, "bad.py", "def f(\n")
        verdict, _, _, blockers, _ = check_reachability((_imp(),), [analyse_file(p)])
        assert verdict is Verdict.UNKNOWN
        assert any(b.kind is BlockerKind.PARSE_ERROR for b in blockers)

    def test_module_only_import_reachable_when_imported(self, tmp_path: Path) -> None:
        p = _write_py(tmp_path, "a.py", "import requests\n")
        imp = _imp("requests", None, SymbolKind.MODULE)
        verdict, _, path, _, _ = check_reachability((imp,), [analyse_file(p)])
        assert verdict is Verdict.REACHABLE
        assert len(path) == 1

    def test_search_stats_count_modules_and_calls(self, tmp_path: Path) -> None:
        p1 = _write_py(tmp_path, "a.py", "import requests\nrequests.post('x')\n")
        p2 = _write_py(tmp_path, "b.py", "x = 1\n")
        _, _, _, _, stats = check_reachability((_imp(),), [analyse_file(p1), analyse_file(p2)])
        assert stats.modules == 2
        assert stats.call_sites >= 1

    def test_multiple_targets_first_match_wins(self, tmp_path: Path) -> None:
        p = _write_py(tmp_path, "a.py", "import requests\nrequests.post('x')\n")
        imp1 = _imp("requests", "get")
        imp2 = _imp("requests", "post")
        verdict, _, path, _, _ = check_reachability((imp1, imp2), [analyse_file(p)])
        assert verdict is Verdict.REACHABLE
        assert path[0].qualname == "requests.post"


class TestAnalyse:
    def test_analyse_project_directory(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text("import requests\nrequests.get('x')\n", encoding="utf-8")
        verdict, _, path, _, _ = analyse((_imp(),), tmp_path)
        assert verdict is Verdict.REACHABLE
        assert path[0].qualname == "requests.get"

    def test_skips_venv_directory(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text("import os\n", encoding="utf-8")
        venv = tmp_path / ".venv" / "lib"
        venv.mkdir(parents=True)
        (venv / "requests_shim.py").write_text(
            "import requests\nrequests.get('x')\n", encoding="utf-8"
        )
        verdict, basis, _, _, _ = analyse((_imp(),), tmp_path)
        assert verdict is Verdict.NOT_REACHABLE
        assert basis is Basis.PACKAGE_NOT_IMPORTED

    def test_empty_directory_returns_package_not_imported(self, tmp_path: Path) -> None:
        verdict, basis, _, _, _ = analyse((_imp(),), tmp_path)
        assert verdict is Verdict.NOT_REACHABLE
        assert basis is Basis.PACKAGE_NOT_IMPORTED

    @pytest.mark.parametrize(
        "skip_dir",
        ["__pycache__", "build", "dist", ".venv", "node_modules"],
    )
    def test_skips_known_directories(self, tmp_path: Path, skip_dir: str) -> None:
        (tmp_path / "real.py").write_text("import os\n", encoding="utf-8")
        skip = tmp_path / skip_dir
        skip.mkdir()
        (skip / "trap.py").write_text("import requests\nrequests.get('x')\n", encoding="utf-8")
        verdict, _, _, _, _ = analyse((_imp(),), tmp_path)
        assert verdict is Verdict.NOT_REACHABLE
