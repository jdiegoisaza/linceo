"""Deterministic, versioned finding fingerprints (ADR §5).

Format: ``v1:<hex>``, with the algorithm version embedded in the value
itself rather than carried in a sibling field — so a fingerprint produced
by a future ``v2`` algorithm can never silently compare equal to a ``v1``
one. Ingredients are fixed per category and deliberately exclude line
numbers, timestamps, absolute paths, and the reporting tool's name: the
first three would make the same finding produce a different fingerprint
just because code moved or two machines scanned it, and including the tool
would make intra-run deduplication of the same fact reported by two
different tools impossible by construction (ADR §5, "Decisión: la
herramienta no entra en la huella").
"""

from __future__ import annotations

import hashlib

#: Current fingerprint algorithm version, embedded in every value this
#: module produces. Bumping it is a breaking change requiring a migration
#: note (ADR §5).
FINGERPRINT_VERSION = "v1"

#: Separator between ingredients before hashing. The unit separator control
#: character is not expected to occur in any ingredient value, which keeps
#: e.g. ``("ab", "c")`` and ``("a", "bc")`` from hashing identically.
_INGREDIENT_SEPARATOR = "\x1f"


def _digest(*ingredients: str) -> str:
    """Hash ``ingredients`` deterministically, in the order given."""
    payload = _INGREDIENT_SEPARATOR.join(ingredients)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def secret_fingerprint(*, rule_id: str, path: str, secret_hash: str) -> str:
    """Compute the ``secrets`` category fingerprint (ADR §5).

    Ingredients: ``rule_id``, the repository-relative ``path`` where the
    secret was found, and a hash of the detected secret — never the
    secret's plaintext value.
    """
    return f"{FINGERPRINT_VERSION}:{_digest(rule_id, path, secret_hash)}"


def sca_fingerprint(
    *,
    package_name: str,
    package_version: str,
    vulnerability_id: str,
    manifest_path: str,
) -> str:
    """Compute the ``sca`` category fingerprint (ADR §5).

    Ingredients: package name, installed version, vulnerability identifier
    (CVE/GHSA), and the manifest path that declares the dependency.
    """
    return (
        f"{FINGERPRINT_VERSION}:"
        f"{_digest(package_name, package_version, vulnerability_id, manifest_path)}"
    )
