"""The report timezone: one process-wide setting, ``SOC_THIEF_TIMEZONE``.

A report day runs 08:00 to 08:00 in this zone, and every local time a report, page or status line
shows is in it. The value is an IANA name such as ``Europe/Berlin``; unset means ``UTC``. A zone
with daylight saving makes some report days 23 or 25 hours long, which the runner allows for.

The setting is read from the process environment on every call rather than at import, so a test
or a long-lived process sees the value it was started with and nothing is cached across changes.
An invalid name raises ``TimezoneError`` with fixed text; entrypoints call ``check`` before doing
anything else so a typo stops the run at startup instead of mid-window.
"""

from __future__ import annotations

import os
from typing import Mapping
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

ENV = "SOC_THIEF_TIMEZONE"
DEFAULT = "UTC"


class TimezoneError(ValueError):
    """The configured timezone is not a usable IANA name. The text never echoes the value."""

    def __init__(self) -> None:
        super().__init__(f"{ENV} is not a valid IANA timezone name (for example UTC or Europe/Berlin)")


def name(env: Mapping[str, str] | None = None) -> str:
    """The configured zone name, validated."""
    value = (os.environ if env is None else env).get(ENV, DEFAULT)
    report_zone_for(value)
    return value


def report_zone_for(value: object) -> ZoneInfo:
    if type(value) is not str or not value or len(value) > 64:
        raise TimezoneError
    try:
        return ZoneInfo(value)
    except (ZoneInfoNotFoundError, ValueError, OSError):
        raise TimezoneError from None


def report_zone(env: Mapping[str, str] | None = None) -> ZoneInfo:
    """The report zone from ``env`` (default: the process environment)."""
    return report_zone_for((os.environ if env is None else env).get(ENV, DEFAULT))


def check(env: Mapping[str, str] | None = None) -> str | None:
    """Return a fixed error line for an invalid setting, or None. For entrypoints."""
    try:
        report_zone(env)
    except TimezoneError as error:
        return str(error)
    return None
