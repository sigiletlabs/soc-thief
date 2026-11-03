"""A small TOON encoder for the CLI's output.

TOON (Token-Oriented Object Notation) is specified at https://github.com/toon-format/spec.
This follows spec version 4.4 (2026-10-08) for the subset the CLI needs:

- objects, nested by two-space indentation;
- primitives: strings, integers, finite floats, booleans and null;
- arrays of primitives, inline: ``key[N]: a,b,c``;
- arrays of objects that share one set of primitive-valued keys, as tables:
  ``key[N]{f1,f2}:`` with one row per object;
- empty arrays as ``key: []`` (the spec forbids emitting the legacy ``key[0]:``).

Anything outside that subset (arrays of arrays, objects with differing keys, nested values
in a table row) raises ``TypeError`` rather than being written in a form this module has not
been checked against. The delimiter is always a comma.

The encoder escapes, it does not clean. A string with a newline or a control character is
quoted and escaped, so no value can end a line early or start a fake one. Removing terminal
escape sequences and invisible characters is the caller's job (``soc_thief.query.clean_text``).

``help_block`` writes AXI's ``help[N]:`` suggestion lines, which are the one non-TOON shape
on stdout; it strips line breaks from each suggestion for the same reason.
"""

from __future__ import annotations

import math
import re
from decimal import Decimal
from typing import Any, Iterable, Mapping

INDENT = "  "
DELIMITER = ","

_NUMERIC_LIKE = re.compile(r"^[+-]?[0-9]+(?:\.[0-9]+)?(?:e[+-]?[0-9]+)?$", re.IGNORECASE)
_BARE_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*$")
_MUST_QUOTE_CHARS = frozenset(':"\\[]{}' + DELIMITER)
_ESCAPES = {"\\": "\\\\", '"': '\\"', "\n": "\\n", "\r": "\\r", "\t": "\\t"}


def needs_quotes(text: str) -> bool:
    """Spec section 7.2: when a string value must be quoted."""
    if text == "" or text != text.strip(" \t"):
        return True
    if text in ("true", "false", "null") or _NUMERIC_LIKE.match(text):
        return True
    if text[0] in "-#":
        return True
    return any(ch in _MUST_QUOTE_CHARS or ord(ch) < 0x20 for ch in text)


def quote(text: str) -> str:
    """Spec section 7.1: only \\\\ \\" \\n \\r \\t, and \\u00xx for other C0 controls."""
    out = []
    for ch in text:
        if ch in _ESCAPES:
            out.append(_ESCAPES[ch])
        elif ord(ch) < 0x20:
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


def string(text: str) -> str:
    return quote(text) if needs_quotes(text) else text


def key(name: str) -> str:
    """Spec section 7.3: keys matching the identifier pattern stay bare, others are quoted."""
    return name if _BARE_KEY.match(name) else quote(name)


def number(value: int | float) -> str:
    """Spec section 2: no exponent, no trailing fractional zeros, -0 as 0, non-finite as null."""
    if isinstance(value, int):
        return str(value)
    if not math.isfinite(value):
        return "null"
    if value == 0:
        return "0"
    text = format(Decimal(repr(value)), "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return text


def primitive(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return number(value)
    if isinstance(value, str):
        return string(value)
    raise TypeError(f"not a TOON primitive: {type(value).__name__}")


def _is_primitive(value: Any) -> bool:
    return value is None or isinstance(value, (bool, int, float, str))


def _array(name: str, items: list[Any], depth: int) -> list[str]:
    pad = INDENT * depth
    head = key(name)
    if not items:
        return [f"{pad}{head}: []"]
    if all(_is_primitive(item) for item in items):
        return [f"{pad}{head}[{len(items)}]: " + DELIMITER.join(primitive(item) for item in items)]
    if all(isinstance(item, Mapping) for item in items):
        fields = list(items[0].keys())
        if not fields:
            raise TypeError(f"{name}: a table needs objects with at least one key")
        for item in items:
            if set(item.keys()) != set(fields):
                raise TypeError(f"{name}: table rows must share one set of keys")
            if not all(_is_primitive(item[field]) for field in fields):
                raise TypeError(f"{name}: table cells must be primitives")
        lines = [f"{pad}{head}[{len(items)}]{{{DELIMITER.join(key(f) for f in fields)}}}:"]
        row_pad = INDENT * (depth + 1)
        lines.extend(row_pad + DELIMITER.join(primitive(item[f]) for f in fields) for item in items)
        return lines
    raise TypeError(f"{name}: only primitive arrays and uniform tables are supported")


def _object(obj: Mapping[str, Any], depth: int) -> list[str]:
    pad = INDENT * depth
    lines: list[str] = []
    for name, value in obj.items():
        if not isinstance(name, str):
            raise TypeError("TOON keys must be strings")
        if isinstance(value, Mapping):
            lines.append(f"{pad}{key(name)}:")
            lines.extend(_object(value, depth + 1))
        elif isinstance(value, (list, tuple)):
            lines.extend(_array(name, list(value), depth))
        else:
            lines.append(f"{pad}{key(name)}: {primitive(value)}")
    return lines


def encode(obj: Mapping[str, Any]) -> str:
    """Encode a root object. Returns the document without a trailing newline (spec section 12)."""
    if not isinstance(obj, Mapping):
        raise TypeError("the root must be an object")
    return "\n".join(_object(obj, 0))


def help_block(suggestions: Iterable[str], name: str = "help") -> str:
    """AXI's next-step block. Returns "" for no suggestions, so callers can skip it."""
    lines = [" ".join(line.split()) for line in suggestions]
    lines = [line for line in lines if line]
    if not lines:
        return ""
    return "\n".join([f"{key(name)}[{len(lines)}]:"] + [INDENT + line for line in lines])
