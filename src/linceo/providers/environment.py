"""The single, explicit ``os.environ`` read allowed anywhere in the project.

AGENTS.md, "Layer boundaries", confines reading the process environment to
``providers/``. That rule is written with ``ContextProvider`` adapters in
mind (a CI platform provider reads runner-injected variables to resolve
``ExecutionContext``), but at least one other concern — resolving
``linceo.core.config.Config`` through its ``LINCEO_*`` environment-variable
layer (ADR §5/R5) — also needs the current process environment and has
nothing to do with any specific ``ContextProvider``. Rather than read
``os.environ`` from wherever that need shows up next (``cli/`` today),
every such caller goes through this one function instead, so the
constraint stays true by construction rather than by each caller's
discipline.
"""

from __future__ import annotations

import os
from collections.abc import Mapping


def process_environment() -> Mapping[str, str]:
    """Return a snapshot of the current process's environment variables."""
    return dict(os.environ)
