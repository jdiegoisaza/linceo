"""Concrete context providers.

Implementations of the core ``ContextProvider`` port for specific CI
platforms — ``local`` and ``azure_devops`` in the reference build (see
``docs/adr/ADR-000-arquitectura-base-y-alcance-v0.1.md``, §10). This is the
only package in the project allowed to read ``os.environ`` directly — see
``AGENTS.md``, "Layer boundaries". Empty until the first provider lands.
"""
