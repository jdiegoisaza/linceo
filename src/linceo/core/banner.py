"""The console report's banner: product-name branding, governed like `[tool_defaults]` (ADR §7).

`banner` is a flat top-level scalar in the policy document — `"linceo"` if
absent — that names the product a console report opens with. It joins the
**governed** side of the ADR §8.4 boundary, not the local-only side
`linceo.core.policy.SeverityOverride` lives on, and for the opposite
reason: a severity override is an escape hatch from the gate and needs the
same per-entry audit trail an exclusion does (ADR §6); a banner has no
effect on the gate or on any finding's evidence at all — it is exactly the
kind of thing security decides once, org-wide, and every pipeline inherits
without copying anything, the same motivation ADR §8.4 already gives for
`fail_on`/`[thresholds]`/`[tool_defaults]`. No CLI flag or environment
variable exists for it, for the same reason none exists for
`[tool_defaults]`/`[tools.<name>]`: an identity string decided a few times
a year has no use for a per-invocation override.

**Why a remote-injected banner needs its own limits.** Unlike every other
governed key, this one's *value* is printed verbatim into a console a
human reads — a remote policy document is content from a repository the
consuming pipeline does not control, and ADR §9's discipline about not
trusting a value's origin applies here even though nothing here is a
credential: printable-ASCII-only (0x20-0x7E) rejects every control
character in one check, `ESC` (0x1B) included, which is what actually
closes the door on an ANSI escape sequence rewriting a terminal's output —
never a longer "no known escape sequence" denylist, which only ever covers
sequences someone thought to enumerate. The same check rejects an embedded
newline or carriage return for free, since neither is printable, so
"single line" is a consequence of "printable ASCII" rather than a second
rule to maintain in parallel.
`MAX_BANNER_LENGTH` bounds a mistake, not an attack a length limit alone
would stop: even a compliant banner should read as an org's name, not a
paragraph pasted into the wrong field.

**Validated in two places, deliberately not the same way.** A *local*
document's invalid `banner` is exactly as fatal as any other local mistake
— `linceo.core.config.load_config` raises `ConfigurationError` (exit 2)
the same way an unknown `[thresholds]` severity would. A *remote*
document's invalid `banner` is instead treated as a failed fetch
(`linceo.core.remote_policy._decode_and_validate` calls `validate_banner`
right alongside `validate_remote_document`) and degrades to the cached or
local banner, WARN, never a hard failure — deliberately more forgiving
than `fail_on`/`[thresholds]` get from the exact same remote document
today. That asymmetry is intentional, not an oversight this module should
someday "fix" to match: a bad remote threshold is a security-relevant
mistake worth learning about immediately, at the cost of the one pipeline
that fetches it next; a bad remote banner has zero security consequence
either way, and forcing every pipeline in the organization to fail
immediately over a cosmetic typo would trade a blast radius of "one wrong
line of text" for "every consuming pipeline's build goes red," for no
corresponding safety gained.

**Absent from JSON and SARIF, on purpose.** Both are data contracts, not
presentation: `render_json` promises no loss "respecto al modelo `Finding`
interno" and SARIF exists so GitHub Code Scanning/the Azure DevOps panel
can consume evidence natively (ADR §7) — neither has a place for "what a
human would have seen printed above the report," and inventing one would
mix presentation into a contract a machine consumer parses. The exact
precedent already exists in this document: `--max-rows` is "exclusivamente
una opción de consola" for the same reason (ADR §7) — this is that same
rule, applied to a second console-only concern.
"""

from __future__ import annotations

from linceo.core import ascii_box
from linceo.core.policy import PolicyConfigurationError

#: This run's banner when nothing in the policy document (local or
#: remote-governed) declares one.
DEFAULT_BANNER = "linceo"

#: A generous single line, not a paragraph — see the module docstring for
#: why this bounds a mistake, not an attack.
MAX_BANNER_LENGTH = 72

#: Printable ASCII only (space through tilde) — see the module docstring
#: for why this one range closes off control characters, escape
#: sequences, and embedded newlines all at once.
_MIN_PRINTABLE = 0x20
_MAX_PRINTABLE = 0x7E


def validate_banner(value: object) -> str:
    """Validate `value` as this run's banner text, local or remote-governed alike.

    Raises:
        PolicyConfigurationError: if `value` is not a string, is empty,
            exceeds `MAX_BANNER_LENGTH` characters, or contains any
            character outside printable ASCII (0x20-0x7E) — which already
            covers a newline, a carriage return, and any ANSI escape
            sequence, none of which is printable.
    """
    if not isinstance(value, str):
        msg = f"banner must be a string, got {type(value).__name__}"
        raise PolicyConfigurationError(msg)
    if not value:
        msg = "banner must not be empty"
        raise PolicyConfigurationError(msg)
    if len(value) > MAX_BANNER_LENGTH:
        msg = f"banner exceeds the {MAX_BANNER_LENGTH}-character maximum (got {len(value)})"
        raise PolicyConfigurationError(msg)
    if not all(_MIN_PRINTABLE <= ord(char) <= _MAX_PRINTABLE for char in value):
        msg = (
            "banner must contain only printable ASCII characters (0x20-0x7E): no control "
            "characters, no escape sequences, no newlines"
        )
        raise PolicyConfigurationError(msg)
    return value


def render_banner(text: str) -> str:
    """Render `text` as a single-line ASCII box, sized exactly to its own content (ADR §7).

    No minimum width, no padding beyond `ascii_box.row`'s own one space a
    side: a banner renders next to findings tables of every possible
    width, so matching any one of them would be arbitrary — the box only
    ever promises to fit its own text.
    """
    width = (len(text),)
    top = ascii_box.border(width)
    return "\n".join([top, ascii_box.row((text,), width), top])
