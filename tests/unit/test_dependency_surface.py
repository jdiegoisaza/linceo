"""Enforces §8.3's "Typer is the base package's only third-party dependency"
invariant against the resolved lockfile, not just the range declared in
``pyproject.toml`` — see ADR §8.3's amendment on ``typer-slim`` inverting its
relationship with ``typer`` at version 0.22.0.

Walks ``uv.lock`` itself, starting from ``linceo``'s own runtime
``dependencies`` entry, rather than importing modules and inspecting what
happens to be installed in the current environment: dev-only tools (e.g.
``pytest`` depending on ``pygments`` for traceback highlighting) have their
own dependency trees that were never covered by this invariant, and a naive
"is it importable right now" check would wrongly flag them. Reading the lock
directly answers the only question that matters: is a forbidden package
reachable from ``linceo``'s *runtime* dependencies — the set someone
installing this package with ``pip install linceo`` actually gets — as
opposed to ``uv.lock``'s separate ``dev`` dependency group.
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

LOCKFILE = Path(__file__).resolve().parents[2] / "uv.lock"

#: Everything that arrives if typer-slim ever resolves back to depending on
#: typer itself (>= 0.22.0) instead of click + typing-extensions (ADR §8.3).
FORBIDDEN = {
    "typer",
    "rich",
    "shellingham",
    "pygments",
    "markdown-it-py",
    "mdurl",
    "annotated-doc",
}


def _locked_packages() -> dict[str, dict[str, Any]]:
    """Map each locked package's name to its ``uv.lock`` table."""
    data = tomllib.loads(LOCKFILE.read_text(encoding="utf-8"))
    return {package["name"]: package for package in data["package"]}


def _runtime_dependency_closure(packages: dict[str, dict[str, Any]], root: str) -> set[str]:
    """Transitive closure of ``root``'s runtime ``dependencies`` only.

    Deliberately never follows ``package.dev-dependencies`` or any optional
    extra: those describe this project's own development environment, not
    what ``linceo``'s base package pulls in for an end user.
    """
    closure: set[str] = set()
    stack = [root]
    while stack:
        name = stack.pop()
        if name in closure:
            continue
        closure.add(name)
        for dependency in packages[name].get("dependencies", []):
            stack.append(dependency["name"])
    closure.discard(root)
    return closure


def test_base_package_dependency_closure_excludes_typers_full_tree() -> None:
    """§8.3: linceo's base runtime dependencies are typer-slim and click only.

    typer-slim 0.22.0 inverted its own relationship with typer — instead of
    depending on click + typing-extensions, it now depends on typer itself,
    which drags in rich, shellingham, pygments, markdown-it-py, mdurl, and
    annotated-doc. This fails the moment a dependency bump resolves back to
    that shape, so the invariant is enforced, not just documented.
    """
    packages = _locked_packages()
    closure = _runtime_dependency_closure(packages, "linceo")

    leaked = closure & FORBIDDEN
    assert not leaked, (
        f"{sorted(leaked)} leaked into linceo's base runtime dependency closure "
        f"(full closure: {sorted(closure)}) — typer-slim likely resolved to "
        "0.22.0 or later, which depends on typer instead of click + "
        "typing-extensions. See ADR §8.3."
    )
