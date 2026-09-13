"""Enforces the layer boundaries declared in AGENTS.md, "Layer boundaries".

Walks the AST of every module under ``src/linceo`` — rather than importing
modules and inspecting ``sys.modules`` — so a forbidden import is caught
even if it is only reachable inside a function body (a deferred import),
never executed by any test, or guarded behind a branch that never runs in
this environment. Relative imports (``from .. import x``) are resolved to
their absolute dotted name before being checked, so a boundary cannot be
crossed by using ``..adapters`` instead of ``linceo.adapters``.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest

SRC_DIR = Path(__file__).resolve().parents[2] / "src"
PACKAGE_ROOT = SRC_DIR / "linceo"

#: Top-level modules importable anywhere without violating "no third-party
#: dependency in core": the standard library itself.
_STDLIB_ROOTS = frozenset(sys.stdlib_module_names)


def _iter_modules(package_dir: Path) -> list[Path]:
    """List every ``*.py`` file under ``package_dir``."""
    return sorted(package_dir.rglob("*.py"))


def _dotted_name(path: Path) -> str:
    """Return the dotted module name of ``path``, e.g. ``linceo.core.foo``."""
    parts = path.relative_to(SRC_DIR).with_suffix("").parts
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _resolve_import_from(node: ast.ImportFrom, path: Path) -> list[str]:
    """Return the absolute dotted name(s) an ``ImportFrom`` node refers to.

    Handles relative imports (``node.level > 0``) by resolving them against
    the importing module's own package, following the same rule Python's
    import system uses at runtime.
    """
    if node.level == 0:
        return [node.module] if node.module else []

    importing_module = _dotted_name(path)
    is_package_init = path.name == "__init__.py"
    package = importing_module if is_package_init else importing_module.rpartition(".")[0]
    base = package.rsplit(".", node.level - 1)[0]

    if node.module:
        return [f"{base}.{node.module}" if base else node.module]
    # `from . import a, b as c` — each alias names a submodule/attribute of `base`.
    return [f"{base}.{alias.name}" if base else alias.name for alias in node.names]


def _imported_names(path: Path) -> list[str]:
    """Collect every module name reached by ``import`` or ``from ... import`` in ``path``."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            names.extend(_resolve_import_from(node, path))
    return names


def _environ_references(path: Path) -> list[str]:
    """Find every way ``path`` could read ``os.environ``: attribute or direct import."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    findings: list[str] = []
    for node in ast.walk(tree):
        is_os_environ_attribute = (
            isinstance(node, ast.Attribute)
            and node.attr == "environ"
            and isinstance(node.value, ast.Name)
            and node.value.id == "os"
        )
        if is_os_environ_attribute:
            findings.append("os.environ")
        elif (
            isinstance(node, ast.ImportFrom)
            and node.level == 0
            and node.module == "os"
            and any(alias.name == "environ" for alias in node.names)
        ):
            findings.append("from os import environ")
    return findings


def _is_allowed_in_core(name: str) -> bool:
    """A core module may import the standard library and other core modules only."""
    if name == "linceo.core" or name.startswith("linceo.core."):
        return True
    root = name.split(".", maxsplit=1)[0]
    return root in _STDLIB_ROOTS


def test_core_imports_only_stdlib_and_core() -> None:
    """linceo.core imports nothing but the standard library and itself (§4/R1)."""
    core_files = _iter_modules(PACKAGE_ROOT / "core")
    assert core_files, "expected at least one module under src/linceo/core — found none"

    violations = {
        str(path.relative_to(SRC_DIR)): forbidden
        for path in core_files
        if (forbidden := [name for name in _imported_names(path) if not _is_allowed_in_core(name)])
    }

    assert not violations, f"linceo.core imported outside stdlib/linceo.core: {violations}"


def test_core_never_reads_os_environ() -> None:
    """linceo.core never reads os.environ, directly or via `from os import environ` (§4/R1)."""
    core_files = _iter_modules(PACKAGE_ROOT / "core")
    assert core_files, "expected at least one module under src/linceo/core — found none"

    violations = {
        str(path.relative_to(SRC_DIR)): found
        for path in core_files
        if (found := _environ_references(path))
    }

    assert not violations, f"linceo.core read os.environ in: {violations}"


@pytest.mark.parametrize("layer", ["adapters", "providers"])
def test_adapters_and_providers_never_import_the_cli_framework(layer: str) -> None:
    """adapters/ and providers/ never import Typer, Click, or linceo.cli (AGENTS.md)."""
    layer_files = _iter_modules(PACKAGE_ROOT / layer)
    assert layer_files, f"expected at least one module under src/linceo/{layer} — found none"

    def _is_forbidden(name: str) -> bool:
        root = name.split(".", maxsplit=1)[0]
        return root in {"typer", "click"} or name == "linceo.cli" or name.startswith("linceo.cli.")

    violations = {
        str(path.relative_to(SRC_DIR)): forbidden
        for path in layer_files
        if (forbidden := [name for name in _imported_names(path) if _is_forbidden(name)])
    }

    assert not violations, f"linceo.{layer} imported the CLI framework: {violations}"
