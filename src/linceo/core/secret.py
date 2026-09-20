"""`Secret`: a value inert against every ordinary accidental-exposure path (ADR §9).

The structural reinforcement ADR §9 describes so "no secret leaks" does not
depend only on the discipline of whoever writes new code: a value wrapped in
`Secret` renders as `***` through `str()`, `repr()`, an f-string (with or
without a format spec), and `json.dumps(..., default=str)` — by construction
of the type, not by review catching every call site that might format it.
The real value is available only through `.reveal()`, called explicitly at
the one point it is actually needed —
`linceo.providers.azure_devops.AzureDevOpsPolicySource.fetch` is that one
point for a remote policy source's bearer token (ADR §8.4).

`SecretRedactingFilter` is the second, independent layer ADR §9 also
describes: defense in depth for a `Secret`'s revealed value reaching a
*third-party* library this project does not control, which could log it
through the standard `logging` module on its own — httpx/httpcore's
internal DEBUG-level tracing does not currently include request headers in
the version this project pins, verified by reading their source rather than
assumed, but a third-party library's internal logging behavior is not a
contract this project can rely on staying that way across every version the
`linceo[remote-config]` extra's version range allows. This filter is the
guard for exactly that case not previously being true, or stopping being
true in some future release.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Secret:
    """A string value that never appears in its own `str()`/`repr()`/format output (ADR §9).

    The single leading underscore on `_value` is a privacy convention, the
    same one used throughout this project's own modules — nothing in the
    language makes a field truly inaccessible. The guarantee this type
    gives is against *accidental* exposure (an f-string, an uncaught
    exception's traceback, a default JSON encoder), never against
    deliberate, code-reviewed access, which `.reveal()` already covers
    explicitly and by name.
    """

    _value: str

    def reveal(self) -> str:
        """The real value — call only at the one point it is actually needed (ADR §9)."""
        return self._value

    def __str__(self) -> str:
        """Always `"***"` — never the real value."""
        return "***"

    def __repr__(self) -> str:
        """Always `"Secret('***')"` — never the real value."""
        return "Secret('***')"

    def __format__(self, format_spec: str) -> str:
        """Always `"***"`, regardless of `format_spec` — never raises, never leaks."""
        return "***"


class SecretRedactingFilter(logging.Filter):
    """Redacts every registered `Secret`'s revealed value from any log record it sees (ADR §9).

    The second, independent layer: even if a `Secret`'s value reaches a
    third-party library that logs it through the standard `logging` module
    on its own, this filter still catches it before any handler renders the
    record — as long as it is attached to the relevant logger(s) before
    that logging happens (`linceo.providers.azure_devops`'s `fetch` attaches
    one to the `httpx` and `httpcore` loggers before every request that
    carries a token).
    """

    def __init__(self, *secrets: Secret) -> None:
        """Register every one of `secrets`' revealed values for redaction."""
        super().__init__()
        self._values = tuple(secret.reveal() for secret in secrets if secret.reveal())

    def filter(self, record: logging.LogRecord) -> bool:
        """Redact `record`'s message in place if it contains any registered secret's value.

        Always returns `True` — this redacts records, it never suppresses
        them (a `logging.Filter` that returned `False` would drop the
        record instead, which is not this filter's job).
        """
        if not self._values:
            return True
        message = record.getMessage()
        redacted = message
        for value in self._values:
            redacted = redacted.replace(value, "***")
        if redacted != message:
            record.msg = redacted
            record.args = ()
        return True


__all__ = ["Secret", "SecretRedactingFilter"]
