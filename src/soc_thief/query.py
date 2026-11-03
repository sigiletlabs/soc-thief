"""Read-only queries over a Soc Thief snapshot (docs/SNAPSHOT.md).

This is the layer the CLI and, later, an MCP server share. It loads one snapshot file,
validates it against the contract, cleans every string, and answers questions about it with
plain dicts and lists. It formats nothing and changes nothing: there is no function here that
can alter delivery, tuning or state.

Every string in a snapshot came from alert fields and is untrusted. ``load`` passes each one
through ``clean_text``, which removes terminal escape sequences, control characters and
invisible formatting characters, so a caller never has to remember to.
"""

from __future__ import annotations

import json
import re
import unicodedata
from typing import Any

MAX_BYTES = 8 * 1024 * 1024
SUPPORTED_MAJOR = 1
CATEGORIES = ("failed", "new", "spike", "recurring")  # Digest order.
STATUSES = ("ok", "attention", "failed")
TUNINGS = ("none", "low", "mute")
SOURCES = ("demo", "state")
DEFAULT_LIMIT = 100

_SCHEMA = re.compile(r"^soc-thief\.snapshot/([0-9]+)(?:\.[0-9]+)?$")

# ESC-introduced sequences: CSI (ESC [), OSC/DCS/SOS/PM/APC (ESC ] P X ^ _) up to their
# terminator or the end of the string, and two-character escapes. Then the 8-bit C1 forms.
_ESCAPE_SEQUENCE = re.compile(
    r"\x1b\[[0-?]*[ -/]*[@-~]?"
    r"|\x1b[\]PX^_][^\x07\x1b\x9c]*(?:\x07|\x1b\\|\x9c)?"
    r"|\x1b[ -/]*[0-~]?"
    r"|\x9b[0-?]*[ -/]*[@-~]?"
    r"|[\x9d\x90\x98\x9e\x9f][^\x07\x1b\x9c]*(?:\x07|\x1b\\|\x9c)?"
)


class SnapshotError(Exception):
    """The snapshot is missing, too large, not JSON, or breaks the contract."""


def clean_text(value: str) -> str:
    """Make an untrusted string safe to show in a terminal or hand to a model.

    Escape sequences go first, whole, so ``ESC[2J`` leaves nothing behind. Line breaks and
    other whitespace become single spaces. Remaining control characters (Cc) and format
    characters (Cf: bidi overrides, zero-width joiners, BOM) are dropped.
    """
    text = _ESCAPE_SEQUENCE.sub("", value)
    out = []
    for ch in text:
        if ch.isspace():
            out.append(" ")
        elif unicodedata.category(ch) in ("Cc", "Cf", "Cs", "Co", "Cn"):
            continue
        else:
            out.append(ch)
    return " ".join("".join(out).split())


# --- loading and validation -------------------------------------------------------------


def load(path: str) -> dict[str, Any]:
    """Read, size-check, parse and validate a snapshot file."""
    try:
        with open(path, "rb") as stream:
            data = stream.read(MAX_BYTES + 1)
    except FileNotFoundError:
        raise SnapshotError(f"no snapshot at {clean_text(path)}") from None
    except IsADirectoryError:
        raise SnapshotError(f"{clean_text(path)} is a directory, not a snapshot file") from None
    except OSError as error:
        raise SnapshotError(f"cannot read {clean_text(path)}: {error.strerror or 'read failed'}") from None
    return parse(data)


def parse(data: bytes) -> dict[str, Any]:
    if len(data) > MAX_BYTES:
        raise SnapshotError("snapshot is larger than 8 MiB")
    try:
        document = json.loads(data.decode("utf-8"), parse_constant=_reject_constant)
    except UnicodeDecodeError:
        raise SnapshotError("snapshot is not UTF-8") from None
    except (ValueError, RecursionError):
        raise SnapshotError("snapshot is not valid JSON") from None
    return validate(document)


def _reject_constant(name: str) -> None:
    raise ValueError(name)


def validate(document: Any) -> dict[str, Any]:
    """Check a parsed document against the contract and return a cleaned copy.

    Unknown fields are dropped. A missing or mistyped field the contract defines is refused,
    naming the field, so a broken writer fails loud instead of showing a plausible blank.
    """
    root = _obj(document, "snapshot")
    schema = _str(root, "schema", "snapshot")
    match = _SCHEMA.match(schema)
    if not match:
        raise SnapshotError(f"schema {schema!r} is not a soc-thief snapshot schema")
    if int(match.group(1)) != SUPPORTED_MAJOR:
        raise SnapshotError(
            f"schema {schema} is not supported; this soc-thief reads soc-thief.snapshot/{SUPPORTED_MAJOR}"
        )
    window = _obj(root.get("window"), "window")
    health = _obj(root.get("health"), "health")
    return {
        "schema": schema,
        "generated_at": _str(root, "generated_at", "snapshot"),
        "source": _enum(root, "source", "snapshot", SOURCES),
        "timezone": _str(root, "timezone", "snapshot"),
        "window": {
            "start": _str(window, "start", "window"),
            "end": _str(window, "end", "window"),
            "events": _count(window, "events", "window"),
            "groups": _count(window, "groups", "window"),
            "duplicates": _count(window, "duplicates", "window"),
            "muted_by_tuning": _count(window, "muted_by_tuning", "window"),
        },
        "health": {
            "status": _enum(health, "status", "health", STATUSES),
            "checks": [_check(item, f"health.checks[{i}]")
                       for i, item in enumerate(_list(health, "checks", "health"))],
        },
        "groups": [_group(item, f"groups[{i}]") for i, item in enumerate(_list(root, "groups", "snapshot"))],
        "breaches": [_breach(item, f"breaches[{i}]") for i, item in enumerate(_list(root, "breaches", "snapshot"))],
        "history": [_window(item, f"history[{i}]") for i, item in enumerate(_list(root, "history", "snapshot"))],
    }


def _check(value: Any, where: str) -> dict[str, Any]:
    item = _obj(value, where)
    return {"name": _str(item, "name", where), "status": _enum(item, "status", where, STATUSES),
            "detail": _str(item, "detail", where, default="")}


def _group(value: Any, where: str) -> dict[str, Any]:
    item = _obj(value, where)
    decision = _obj(item.get("decision"), f"{where}.decision")
    model = item.get("model")
    return {
        "id": _str(item, "id", where, nonempty=True),
        "rule_id": _str(item, "rule_id", where, default=""),
        "rule_description": _str(item, "rule_description", where, default=""),
        "level": _count(item, "level", where),
        "count": _count(item, "count", where),
        "agents": _strings(item, "agents", where),
        "first_seen": _str(item, "first_seen", where, default=""),
        "last_seen": _str(item, "last_seen", where, default=""),
        "category": _enum(item, "category", where, CATEGORIES),
        "protected": _bool(item, "protected", where, default=False),
        "tuning": _enum(item, "tuning", where, TUNINGS, default="none"),
        "decision": {
            "delivery_required": _bool(decision, "delivery_required", f"{where}.decision"),
            "health_failure": _bool(decision, "health_failure", f"{where}.decision", default=False),
            "reason": _str(decision, "reason", f"{where}.decision", default=""),
        },
        "model": None if model is None else _model(model, f"{where}.model"),
        "breach_signals": _strings(item, "breach_signals", where),
    }


def _model(value: Any, where: str) -> dict[str, Any]:
    item = _obj(value, where)
    confidence = item.get("confidence")
    if confidence is not None:
        if isinstance(confidence, bool) or not isinstance(confidence, (int, float)) or not 0 <= confidence <= 1:
            raise SnapshotError(f"{where}.confidence must be a number from 0 to 1")
    return {
        "name": _str(item, "name", where, default=""),
        "verdict": _str(item, "verdict", where, default=""),
        "confidence": confidence,
        "tags": _strings(item, "tags", where),
        "summary": _str(item, "summary", where, default=""),
    }


def _breach(value: Any, where: str) -> dict[str, Any]:
    item = _obj(value, where)
    return {"name": _str(item, "name", where), "signals": _strings(item, "signals", where),
            "agent": _str(item, "agent", where, default=""), "at": _str(item, "at", where),
            "paged": _bool(item, "paged", where)}


def _window(value: Any, where: str) -> dict[str, Any]:
    item = _obj(value, where)
    return {"start": _str(item, "start", where), "end": _str(item, "end", where),
            "events": _count(item, "events", where), "groups": _count(item, "groups", where),
            "delivered": _bool(item, "delivered", where),
            "health_failure": _bool(item, "health_failure", where)}


_MISSING = object()


def _obj(value: Any, where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SnapshotError(f"{where} must be an object")
    return value


def _list(obj: dict[str, Any], name: str, where: str) -> list[Any]:
    value = obj.get(name, _MISSING)
    if not isinstance(value, list):
        raise SnapshotError(f"{where}.{name} must be a list")
    return value


def _str(obj: dict[str, Any], name: str, where: str, *, default: Any = _MISSING, nonempty: bool = False) -> str:
    value = obj.get(name, _MISSING)
    if value is _MISSING or (value is None and default is not _MISSING):
        if default is _MISSING:
            raise SnapshotError(f"{where}.{name} is missing")
        return default
    if not isinstance(value, str):
        raise SnapshotError(f"{where}.{name} must be a string")
    text = clean_text(value)
    if nonempty and not text:
        raise SnapshotError(f"{where}.{name} must not be empty")
    return text


def _strings(obj: dict[str, Any], name: str, where: str) -> list[str]:
    value = obj.get(name)
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise SnapshotError(f"{where}.{name} must be a list of strings")
    return [clean_text(v) for v in value]


def _count(obj: dict[str, Any], name: str, where: str) -> int:
    value = obj.get(name, _MISSING)
    if value is _MISSING:
        raise SnapshotError(f"{where}.{name} is missing")
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise SnapshotError(f"{where}.{name} must be a non-negative integer")
    return value


def _bool(obj: dict[str, Any], name: str, where: str, *, default: Any = _MISSING) -> bool:
    value = obj.get(name, _MISSING)
    if value is _MISSING:
        if default is _MISSING:
            raise SnapshotError(f"{where}.{name} is missing")
        return default
    if not isinstance(value, bool):
        raise SnapshotError(f"{where}.{name} must be true or false")
    return value


def _enum(obj: dict[str, Any], name: str, where: str, allowed: tuple[str, ...], *, default: Any = _MISSING) -> str:
    value = _str(obj, name, where, default=default)
    if value not in allowed:
        raise SnapshotError(f"{where}.{name} must be one of {', '.join(allowed)}")
    return value


# --- queries ----------------------------------------------------------------------------


def digest_order(groups: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Failed, new, spike, recurring; then level high to low; then count high to low."""
    rank = {name: i for i, name in enumerate(CATEGORIES)}
    return sorted(groups, key=lambda g: (rank[g["category"]], -g["level"], -g["count"], g["id"]))


def overview(snapshot: dict[str, Any], *, top: int = 5) -> dict[str, Any]:
    """Everything an operator or agent needs first, with the counts already done."""
    groups = snapshot["groups"]
    required = [g for g in digest_order(groups) if g["decision"]["delivery_required"]]
    breach_list = snapshot["breaches"]
    return {
        "generated_at": snapshot["generated_at"],
        "source": snapshot["source"],
        "timezone": snapshot["timezone"],
        "window": dict(snapshot["window"]),
        "listed_groups": len(groups),
        "categories": {name: sum(1 for g in groups if g["category"] == name) for name in CATEGORIES},
        "delivery_required": len(required),
        "protected": sum(1 for g in groups if g["protected"]),
        "group_health_failures": sum(1 for g in groups if g["decision"]["health_failure"]),
        "health": {
            "status": snapshot["health"]["status"],
            "checks": len(snapshot["health"]["checks"]),
            "not_ok": [c for c in snapshot["health"]["checks"] if c["status"] != "ok"],
        },
        "breaches": {
            "total": len(breach_list),
            "paged": [b for b in breach_list if b["paged"]],
        },
        "top": required[:top],
    }


def list_groups(snapshot: dict[str, Any], *, category: str | None = None, text: str | None = None,
                limit: int = DEFAULT_LIMIT) -> dict[str, Any]:
    """Groups in digest order, filtered by category and a case-insensitive substring.

    The substring matches the id, rule id, rule description and agent names.
    """
    if category is not None and category not in CATEGORIES:
        raise ValueError(f"category must be one of {', '.join(CATEGORIES)}")
    if limit < 1:
        raise ValueError("limit must be at least 1")
    needle = clean_text(text).casefold() if text else ""
    matched = [
        g for g in digest_order(snapshot["groups"])
        if (category is None or g["category"] == category)
        and (not needle or needle in _haystack(g))
    ]
    return {
        "window_groups": snapshot["window"]["groups"],
        "listed_groups": len(snapshot["groups"]),
        "matched": len(matched),
        "groups": matched[:limit],
    }


def _haystack(group: dict[str, Any]) -> str:
    return " ".join([group["id"], group["rule_id"], group["rule_description"], *group["agents"]]).casefold()


def get_group(snapshot: dict[str, Any], group_id: str) -> dict[str, Any] | None:
    wanted = clean_text(group_id)
    return next((g for g in snapshot["groups"] if g["id"] == wanted), None)


def list_breaches(snapshot: dict[str, Any]) -> dict[str, Any]:
    items = snapshot["breaches"]
    return {"total": len(items), "paged": sum(1 for b in items if b["paged"]), "breaches": list(items)}


def get_health(snapshot: dict[str, Any]) -> dict[str, Any]:
    checks = snapshot["health"]["checks"]
    return {"status": snapshot["health"]["status"],
            "not_ok": sum(1 for c in checks if c["status"] != "ok"),
            "checks": list(checks)}


def list_history(snapshot: dict[str, Any]) -> dict[str, Any]:
    items = snapshot["history"]
    return {"windows": len(items),
            "delivered": sum(1 for w in items if w["delivered"]),
            "health_failures": sum(1 for w in items if w["health_failure"]),
            "history": list(items)}
