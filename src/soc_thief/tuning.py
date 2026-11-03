"""Operator tuning file: mute or downgrade known noise by rule and optional agent.

Tuning is consulted only for groups that deterministic preflight leaves to model review, so it
can never affect protected, critical, invalid, or failed groups. Entry notes are validated and
then discarded: they are never rendered, logged, sent to the model, or stored in state.
"""

from __future__ import annotations

import json
import os
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

from soc_thief.collector import owner_controlled


MAX_FILE_BYTES = 256 * 1024
MAX_ENTRIES = 2_000
ACTIONS = ("mute", "low")
_REQUIRED = {"rule_id", "action"}
_OPTIONAL = {"agent_id", "expires", "note"}


class TuningError(RuntimeError):
    """A fixed-text tuning file failure; the caller applies no tuning and reports health."""

    def __init__(self) -> None:
        super().__init__("tuning file is invalid")


@dataclass(frozen=True)
class TuningEntry:
    rule_id: str
    action: str
    agent_id: str | None = None
    expires: datetime | None = None


@dataclass(frozen=True)
class Tuning:
    """Immutable matcher. The most specific active entry (rule and agent over rule only) wins."""

    entries: tuple[TuningEntry, ...] = ()
    _index: Mapping[tuple[str, str | None], TuningEntry] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if type(self.entries) is not tuple or len(self.entries) > MAX_ENTRIES:
            raise TuningError
        index: dict[tuple[str, str | None], TuningEntry] = {}
        for entry in self.entries:
            if (type(entry) is not TuningEntry or not _identifier(entry.rule_id) or entry.action not in ACTIONS
                    or (entry.agent_id is not None and not _identifier(entry.agent_id))
                    or (entry.expires is not None and (type(entry.expires) is not datetime
                                                       or entry.expires.utcoffset() != timedelta(0)))
                    or (entry.rule_id, entry.agent_id) in index):
                raise TuningError
            index[(entry.rule_id, entry.agent_id)] = entry
        object.__setattr__(self, "_index", MappingProxyType(index))

    def action(self, rule_id: str, agent_id: str, at: datetime) -> str | None:
        if type(at) is not datetime or at.utcoffset() is None:
            raise ValueError("tuning instant is invalid")
        for key in ((rule_id, agent_id), (rule_id, None)):
            entry = self._index.get(key)
            if entry is not None and (entry.expires is None or at < entry.expires):
                return entry.action
        return None


def _identifier(value: object) -> bool:
    return (type(value) is str and 0 < len(value) <= 64 and bool(value.strip())
            and not any(unicodedata.category(c).startswith("C") for c in value))


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in pairs:
        if name in result:
            raise ValueError
        result[name] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError


def _read(path: Path) -> str:
    """Read a bounded private regular file without following a final symlink."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not owner_controlled(stream.fileno(), info):
            raise ValueError
        raw = stream.read(MAX_FILE_BYTES + 1)
    if len(raw) > MAX_FILE_BYTES:
        raise ValueError
    return raw.decode("utf-8")


def _entry(value: object) -> TuningEntry:
    if type(value) is not dict or not _REQUIRED <= value.keys() <= _REQUIRED | _OPTIONAL:
        raise ValueError
    if not _identifier(value["rule_id"]) or value["action"] not in ACTIONS or type(value["action"]) is not str:
        raise ValueError
    if "agent_id" in value and not _identifier(value["agent_id"]):
        raise ValueError
    if "note" in value and (type(value["note"]) is not str or len(value["note"]) > 200):
        raise ValueError
    expires = None
    if "expires" in value:
        if type(value["expires"]) is not str:
            raise ValueError
        expires = datetime.fromisoformat(value["expires"].replace("Z", "+00:00"))
        if expires.utcoffset() != timedelta(0):
            raise ValueError
    return TuningEntry(value["rule_id"], value["action"], value.get("agent_id"), expires)


def load_tuning(env: Mapping[str, str]) -> Tuning:
    """Load ``SOC_THIEF_TUNING_FILE``; unset means no tuning. Any other problem raises TuningError."""
    if "SOC_THIEF_TUNING_FILE" not in env:
        return Tuning()
    try:
        path = env["SOC_THIEF_TUNING_FILE"]
        if type(path) is not str or not path:
            raise ValueError
        document = json.loads(_read(Path(path)), object_pairs_hook=_unique_object,
                              parse_constant=_reject_constant)
        if (type(document) is not dict or set(document) != {"version", "entries"}
                or type(document["version"]) is not int or document["version"] != 1
                or type(document["entries"]) is not list or len(document["entries"]) > MAX_ENTRIES):
            raise ValueError
        return Tuning(tuple(_entry(item) for item in document["entries"]))
    except Exception:
        # Never echo file content, paths, or parser detail.
        raise TuningError from None
