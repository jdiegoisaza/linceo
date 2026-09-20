"""Tests for `linceo.core.secret` (ADR §9): the structural reinforcement against leaking a value.

Covers every "usual accidental exposure path" ADR §9 names explicitly:
`str()`, `repr()`, f-string interpolation (with and without a format spec),
default JSON encoding, and an uncaught exception's own message — each
asserted never to contain the real value, only `.reveal()` ever does.
"""

from __future__ import annotations

import json
import logging

import pytest

from linceo.core.secret import Secret, SecretRedactingFilter

_REAL_VALUE = "super-secret-token-value"


def test_reveal_returns_the_real_value() -> None:
    assert Secret(_REAL_VALUE).reveal() == _REAL_VALUE


def test_str_never_shows_the_real_value() -> None:
    assert str(Secret(_REAL_VALUE)) == "***"


def test_repr_never_shows_the_real_value() -> None:
    assert repr(Secret(_REAL_VALUE)) == "Secret('***')"
    assert _REAL_VALUE not in repr(Secret(_REAL_VALUE))


def test_fstring_interpolation_never_shows_the_real_value() -> None:
    secret = Secret(_REAL_VALUE)
    assert f"{secret}" == "***"


def test_fstring_with_a_format_spec_never_shows_the_real_value() -> None:
    secret = Secret(_REAL_VALUE)
    assert f"{secret:>20}" == "***"


def test_default_json_encoding_never_shows_the_real_value() -> None:
    payload = json.dumps({"token": Secret(_REAL_VALUE)}, default=str)
    assert _REAL_VALUE not in payload
    assert json.loads(payload)["token"] == "***"  # noqa: S105 -- asserting redaction, not a secret


def test_an_uncaught_exceptions_message_never_shows_the_real_value() -> None:
    secret = Secret(_REAL_VALUE)

    with pytest.raises(ValueError, match="request failed") as exc_info:
        raise ValueError(f"request failed with token {secret}")

    assert _REAL_VALUE not in str(exc_info.value)


def test_two_secrets_with_the_same_value_compare_equal() -> None:
    """Equality is not itself a leak — it never prints anything."""
    assert Secret(_REAL_VALUE) == Secret(_REAL_VALUE)


# --- SecretRedactingFilter -------------------------------------------------------


def _record(message: str) -> logging.LogRecord:
    return logging.LogRecord(
        name="test",
        level=logging.DEBUG,
        pathname=__file__,
        lineno=1,
        msg=message,
        args=(),
        exc_info=None,
    )


def test_filter_redacts_a_registered_secrets_value_from_a_log_record() -> None:
    filter_ = SecretRedactingFilter(Secret(_REAL_VALUE))
    record = _record(f"Authorization: Bearer {_REAL_VALUE}")

    kept = filter_.filter(record)

    assert kept is True
    assert _REAL_VALUE not in record.getMessage()
    assert "***" in record.getMessage()


def test_filter_leaves_an_unrelated_message_untouched() -> None:
    filter_ = SecretRedactingFilter(Secret(_REAL_VALUE))
    record = _record("nothing sensitive here")

    filter_.filter(record)

    assert record.getMessage() == "nothing sensitive here"


def test_filter_with_no_secrets_is_a_no_op() -> None:
    filter_ = SecretRedactingFilter()
    record = _record(f"token={_REAL_VALUE}")

    filter_.filter(record)

    assert record.getMessage() == f"token={_REAL_VALUE}"


def test_filter_attached_to_a_logger_redacts_percent_style_arguments_too() -> None:
    """`logger.debug("... %s", value)` — the record's args, not just its literal `msg` string.

    This is the shape `httpx`/`httpcore`'s own tracing uses (ADR §9,
    `linceo.providers.azure_devops._redact_from_http_client_logs`):
    `record.getMessage()` resolves `%`-args before this filter ever
    compares against the registered secret's value, so a value passed as
    an argument is caught exactly like one already baked into the message.
    """
    logger = logging.getLogger("linceo.test.secret_redaction")
    logger.setLevel(logging.DEBUG)
    records: list[logging.LogRecord] = []
    handler = logging.Handler()
    handler.emit = records.append  # type: ignore[assignment]
    logger.addHandler(handler)
    logger.addFilter(SecretRedactingFilter(Secret(_REAL_VALUE)))

    try:
        logger.debug("Authorization: Bearer %s", _REAL_VALUE)
    finally:
        logger.handlers.clear()
        logger.filters.clear()

    [record] = records
    assert _REAL_VALUE not in record.getMessage()
    assert "***" in record.getMessage()
