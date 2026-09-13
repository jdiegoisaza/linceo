"""Domain and ports.

This package holds the orchestrator's domain model and the port contracts
it depends on (``ContextProvider``, ``ToolExecutor``, ``ToolIntegration``).

It imports nothing beyond the standard library and other ``linceo.core``
modules — no ``adapters``, ``providers``, ``cli``, or third-party package —
and never reads ``os.environ`` directly. See ``AGENTS.md``, "Layer
boundaries", for the full rule and
``tests/unit/test_import_boundaries.py`` for how it is enforced.
"""
