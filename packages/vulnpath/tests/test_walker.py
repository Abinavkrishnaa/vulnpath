"""Tests for vulnpath.analyzer.walker."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from vulnpath.analyzer.walker import CallSite, FileAnalysis, analyse_file


def _write_py(tmp_path: Path, name: str, source: str) -> Path:
    p = tmp_path / name
    p.write_text(textwrap.dedent(source), encoding="utf-8")
    return p


class TestImportResolution:
    def test_bare_import(self, tmp_path: Path) -> None:
        p = _write_py(tmp_path, "a.py", "import requests\nrequests.get('http://x')\n")
        fa = analyse_file(p)
        assert fa.imports == {"requests": "requests"}

    def test_import_as(self, tmp_path: Path) -> None:
        p = _write_py(tmp_path, "a.py", "import requests as req\nreq.get('http://x')\n")
        fa = analyse_file(p)
        assert fa.imports.get("req") == "requests"

    def test_from_import(self, tmp_path: Path) -> None:
        p = _write_py(tmp_path, "a.py", "from pydantic import BaseModel\n")
        fa = analyse_file(p)
        assert fa.imports.get("BaseModel") == "pydantic.BaseModel"

    def test_from_import_as(self, tmp_path: Path) -> None:
        p = _write_py(tmp_path, "a.py", "from pydantic import BaseModel as BM\n")
        fa = analyse_file(p)
        assert fa.imports.get("BM") == "pydantic.BaseModel"

    def test_dotted_from_import(self, tmp_path: Path) -> None:
        p = _write_py(tmp_path, "a.py", "from pydantic.v1 import BaseModel\n")
        fa = analyse_file(p)
        assert fa.imports.get("BaseModel") == "pydantic.v1.BaseModel"


class TestCallResolution:
    def test_bare_module_call(self, tmp_path: Path) -> None:
        p = _write_py(tmp_path, "a.py", "import requests\nrequests.get('http://x')\n")
        fa = analyse_file(p)
        assert any(c.qualname == "requests.get" for c in fa.calls)

    def test_from_import_call(self, tmp_path: Path) -> None:
        src = "from pydantic import BaseModel\nBaseModel.model_validate({})\n"
        p = _write_py(tmp_path, "a.py", src)
        fa = analyse_file(p)
        assert any(c.qualname == "pydantic.BaseModel.model_validate" for c in fa.calls)

    def test_aliased_import_call(self, tmp_path: Path) -> None:
        p = _write_py(tmp_path, "a.py", "import requests as req\nreq.get('http://x')\n")
        fa = analyse_file(p)
        assert any(c.qualname == "requests.get" for c in fa.calls)

    def test_call_site_line_number(self, tmp_path: Path) -> None:
        p = _write_py(tmp_path, "a.py", "import requests\n\nrequests.get('x')\n")
        fa = analyse_file(p)
        site = next(c for c in fa.calls if c.qualname == "requests.get")
        assert site.line == 3

    def test_unresolved_call_kept_as_is(self, tmp_path: Path) -> None:
        p = _write_py(tmp_path, "a.py", "some_obj.method()\n")
        fa = analyse_file(p)
        assert any(c.qualname == "some_obj.method" for c in fa.calls)

    def test_call_site_is_frozen(self, tmp_path: Path) -> None:
        p = _write_py(tmp_path, "a.py", "import x\nx.f()\n")
        fa = analyse_file(p)
        site: CallSite = fa.calls[0]
        with pytest.raises((AttributeError, TypeError)):
            site.qualname = "tampered"  # type: ignore[misc]


class TestDynamicUses:
    def test_eval_detected(self, tmp_path: Path) -> None:
        p = _write_py(tmp_path, "a.py", "eval('1+1')\n")
        fa = analyse_file(p)
        assert any(d.kind == "eval_exec" for d in fa.dynamic_uses)

    def test_exec_detected(self, tmp_path: Path) -> None:
        p = _write_py(tmp_path, "a.py", "exec('pass')\n")
        fa = analyse_file(p)
        assert any(d.kind == "eval_exec" for d in fa.dynamic_uses)

    def test_dunder_import_detected(self, tmp_path: Path) -> None:
        p = _write_py(tmp_path, "a.py", "__import__('os')\n")
        fa = analyse_file(p)
        assert any(d.kind == "dynamic_import" for d in fa.dynamic_uses)

    def test_importlib_import_module_detected(self, tmp_path: Path) -> None:
        p = _write_py(
            tmp_path,
            "a.py",
            "import importlib\nimportlib.import_module('os')\n",
        )
        fa = analyse_file(p)
        assert any(d.kind == "dynamic_import" for d in fa.dynamic_uses)

    def test_dynamic_use_not_added_to_calls(self, tmp_path: Path) -> None:
        p = _write_py(tmp_path, "a.py", "eval('x')\n")
        fa = analyse_file(p)
        assert not any(c.qualname == "eval" for c in fa.calls)


class TestErrorHandling:
    def test_syntax_error_produces_error_field(self, tmp_path: Path) -> None:
        p = _write_py(tmp_path, "bad.py", "def f(\n")
        fa = analyse_file(p)
        assert fa.error is not None
        assert fa.calls == ()
        assert fa.imports == {}

    def test_missing_file_produces_error_field(self, tmp_path: Path) -> None:
        fa = analyse_file(tmp_path / "nonexistent.py")
        assert fa.error is not None

    def test_valid_file_has_no_error(self, tmp_path: Path) -> None:
        p = _write_py(tmp_path, "ok.py", "x = 1\n")
        fa = analyse_file(p)
        assert fa.error is None

    def test_file_analysis_is_frozen(self, tmp_path: Path) -> None:
        p = _write_py(tmp_path, "a.py", "x = 1\n")
        fa = analyse_file(p)
        assert isinstance(fa, FileAnalysis)
        with pytest.raises((AttributeError, TypeError)):
            fa.error = "tampered"  # type: ignore[misc]
