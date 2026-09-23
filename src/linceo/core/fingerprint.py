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
from collections.abc import Iterable

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


def iac_fingerprint(*, rule_id: str, path: str, resource: str) -> str:
    """Compute the ``iac`` category fingerprint (ADR §5 amendment, 2026-09-21).

    Ingredients: ``rule_id`` (a Checkov check id, e.g. ``CKV_AWS_19``), the
    repository-relative ``path`` where the resource is declared, and the
    resource's own address (e.g. ``aws_s3_bucket.logs``). ``resource`` is
    required, not optional: two distinct resources of the same type,
    flagged by the same rule, in the same file — an ordinary Terraform
    file with several similar blocks — would otherwise collide onto one
    fingerprint, silently dropping one of two genuinely distinct findings
    during intra-run dedup. Line numbers are excluded, as for every other
    category (ADR §5): a resource block moving inside its own file must
    not churn the fingerprint. Renaming the resource itself, however, is
    not code movement — it changes the finding's identity, the same way a
    package version bump changes an `sca` finding's identity — and is
    expected to invalidate a baseline entry pointing at it, recoverable
    through the same orphaned-entry mechanism ADR §8.2 already provides
    for a fingerprint version bump or a tool renaming a `rule_id`.
    """
    return f"{FINGERPRINT_VERSION}:{_digest(rule_id, path, resource)}"


def short_fingerprints(fingerprints: Iterable[str], *, min_length: int = 8) -> dict[str, str]:
    """Compute a display-safe short form of each of ``fingerprints`` (ADR §7, "FP").

    Every value must carry the ``FINGERPRINT_VERSION`` prefix this module
    produces (``v1:<hex>``); the returned short form keeps that same
    version prefix, so a value copied out of a console report is still
    recognizably a versioned fingerprint that an exclusion's ``fingerprint``
    field can match by prefix (ADR §8.2).

    The hex portion is truncated to the shortest length, no less than
    ``min_length``, that keeps every value in ``fingerprints`` distinct from
    every other value *in this same call* — uniqueness is guaranteed only
    for the exact set passed in here, never across separate runs, since a
    future run's finding could plausibly share a short prefix with one from
    today.

    Raises:
        ValueError: if any value does not carry the current
            ``FINGERPRINT_VERSION`` prefix.
    """
    hexes: dict[str, str] = {}
    for value in sorted(set(fingerprints)):
        version, separator, hex_part = value.partition(":")
        if not separator or version != FINGERPRINT_VERSION:
            msg = f"not a {FINGERPRINT_VERSION} fingerprint: {value!r}"
            raise ValueError(msg)
        hexes[value] = hex_part

    max_length = max((len(hex_part) for hex_part in hexes.values()), default=min_length)
    length = min_length
    while length < max_length:
        prefixes = [hex_part[:length] for hex_part in hexes.values()]
        if len(set(prefixes)) == len(prefixes):
            break
        length += 1

    return {
        value: f"{FINGERPRINT_VERSION}:{hex_part[:length]}" for value, hex_part in hexes.items()
    }
