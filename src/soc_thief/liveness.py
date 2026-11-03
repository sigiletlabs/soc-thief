"""Agent liveness on the fast path: an expected agent that goes quiet is paged like a breach.

The operator keeps an inventory of the agents that must report, read through
``SOC_THIEF_AGENT_INVENTORY_FILE`` (a credential, like tuning)::

    {"version": 1, "agents": [{"agent_id": "001", "max_silence_minutes": 180, "note": "..."}]}

Each fast-path run makes one bounded, aggregation-only indexer read: the latest alert time for
each listed agent over the longest allowed silence. An agent with no alert inside its own allowed
silence pages once per agent per ``fastpath.REPAGE_AFTER``, and again as soon as it comes back and
goes quiet again. A page carries only a fixed signal name, the agent id, a time and the allowed
silence; notes are validated and discarded.

"Reported" means "produced at least one alert in the indexer", because the indexer is the only
source Soc Thief can read. A quiet but healthy agent needs a gap long enough to cover its normal
alert rhythm; the noise profile shows that rhythm.

Fail closed: a missing or invalid inventory, an unreadable state file or a failed indexer read is
a FAILED run with a fixed journal line. The status check reads those lines and withholds the
heartbeat (e.g. an Uptime Kuma push monitor), which is how a liveness failure reaches the
operator's phone.

Journal lines (parsed by ``soc_thief.status``; keep them in step):
``agent liveness: N expected, M silent`` with an optional ``; page failed`` suffix, or a line
starting ``agent liveness unavailable``.

Left out on purpose: per-agent last-seen history in state (each run re-derives it from the
indexer), the Wazuh manager API's own connection status (no credential for it here), and a
"recovered" page.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping

from soc_thief import fastpath
from soc_thief.runner import _identity_key
from soc_thief.state import opaque_key
from soc_thief.tuning import _read, _reject_constant, _unique_object
from soc_thief.zone import report_zone

STATE_NAME = "liveness.json"
MAX_AGENTS = 500
MIN_SILENCE = timedelta(minutes=30)  # Three fast-path intervals; anything shorter would flap.
MAX_SILENCE = timedelta(days=7)  # Bounds the aggregation to eight daily indices.
SIGNAL = "agent_silent"
_AGENT = re.compile(r"[0-9]{3,8}")
_ENTRY_KEYS = {"agent_id", "max_silence_minutes"}


class LivenessError(RuntimeError):
    """A fixed-text liveness failure; never carries file content or parser detail."""


@dataclass(frozen=True)
class Expected:
    agent_id: str
    max_silence: timedelta


def load_inventory(env: Mapping[str, str]) -> tuple[Expected, ...]:
    """Load the inventory. Unset, empty, invalid or duplicated entries all raise LivenessError."""
    try:
        path = env.get("SOC_THIEF_AGENT_INVENTORY_FILE")
        if type(path) is not str or not path:
            raise ValueError
        document = json.loads(_read(Path(path)), object_pairs_hook=_unique_object,
                              parse_constant=_reject_constant)
        if (type(document) is not dict or set(document) != {"version", "agents"}
                or type(document["version"]) is not int or document["version"] != 1
                or type(document["agents"]) is not list or not 1 <= len(document["agents"]) <= MAX_AGENTS):
            raise ValueError
        entries, seen = [], set()
        for item in document["agents"]:
            if type(item) is not dict or not _ENTRY_KEYS <= item.keys() <= _ENTRY_KEYS | {"note"}:
                raise ValueError
            agent, minutes = item["agent_id"], item["max_silence_minutes"]
            if (type(agent) is not str or _AGENT.fullmatch(agent) is None or agent in seen
                    or type(minutes) is not int
                    or not MIN_SILENCE <= timedelta(minutes=minutes) <= MAX_SILENCE
                    or ("note" in item and (type(item["note"]) is not str or len(item["note"]) > 200))):
                raise ValueError
            seen.add(agent)
            entries.append(Expected(agent, timedelta(minutes=minutes)))
        return tuple(entries)
    except Exception:
        raise LivenessError("agent inventory is missing or invalid") from None


def silent(inventory: tuple[Expected, ...], last_seen: Mapping[str, datetime],
           now: datetime) -> list[tuple[Expected, datetime | None]]:
    """Agents whose latest alert is older than their allowed silence, or absent altogether."""
    quiet = []
    for expected in inventory:
        seen = last_seen.get(expected.agent_id)
        if seen is None or now - seen > expected.max_silence:
            quiet.append((expected, seen))
    return quiet


def _load(path: Path) -> dict[str, datetime]:
    try:
        raw = path.read_text()
    except FileNotFoundError:
        return {}
    except OSError:
        raise LivenessError("liveness state is unreadable") from None
    try:
        value = json.loads(raw)
        if type(value) is not dict or set(value) != {"version", "paged"} or value["version"] != 1:
            raise ValueError
        if type(value["paged"]) is not dict:
            raise ValueError
        return {key: fastpath._utc(when) for key, when in value["paged"].items() if type(key) is str}
    except (ValueError, TypeError, AttributeError, RecursionError):
        raise LivenessError("liveness state is unreadable") from None


def _save(path: Path, paged: Mapping[str, datetime]) -> None:
    body = json.dumps({"version": 1, "paged": {key: when.isoformat() for key, when in sorted(paged.items())}},
                      separators=(",", ":"))
    temporary = path.with_name(path.name + ".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        stream.write(body)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def _page(expected: Expected, seen: datetime | None, window: timedelta) -> Any:
    hours = lambda span: f"{span.total_seconds() / 3600:g} hours"
    last = (seen.astimezone(report_zone()).strftime("%Y-%m-%d %H:%M %Z") if seen is not None
            else f"not in the last {hours(window)}")
    body = (f"Signal: {SIGNAL}\nAgent: {expected.agent_id}\nLast seen: {last}\n"
            f"Allowed silence: {hours(expected.max_silence)}")
    return fastpath.Page(f"Soc Thief breach: {SIGNAL}", body, "urgent", "rotating_light")


def _summary(count: int) -> Any:
    return fastpath.Page(f"Soc Thief breach: {SIGNAL} (several)",
                         f"{count} more expected agents are silent. Run the fast path by hand or "
                         f"check the Wazuh manager.", "urgent", "rotating_light")


def check(*, env: Mapping[str, str], now: datetime, collector: Any, pager: Any) -> int:
    """One liveness check. Prints exactly one fixed journal line; never raises."""
    try:
        code, line = _check(env=env, now=now, collector=collector, pager=pager)
    except Exception:
        code, line = fastpath.FAILED, "agent liveness unavailable: check failed"
    print(line)
    return code


def _check(*, env: Mapping[str, str], now: datetime, collector: Any, pager: Any) -> tuple[int, str]:
    try:
        inventory = load_inventory(env)
    except LivenessError:
        return fastpath.FAILED, "agent liveness unavailable: inventory is missing or invalid"
    state_dir = env.get("STATE_PATH")
    if not state_dir:
        return fastpath.FAILED, "agent liveness unavailable: configuration is invalid"
    path = Path(state_dir) / STATE_NAME
    key = _identity_key(env)
    try:
        paged = _load(path)
    except LivenessError:
        return fastpath.FAILED, "agent liveness unavailable: state is unreadable"
    end = now.astimezone(timezone.utc).replace(microsecond=0)
    window = max(expected.max_silence for expected in inventory)
    try:
        last_seen = collector.agent_last_seen([e.agent_id for e in inventory], end - window, end)
    except Exception:
        return fastpath.FAILED, "agent liveness unavailable: indexer check failed"
    quiet = silent(inventory, last_seen, end)
    names = {expected.agent_id: opaque_key(key, "page", SIGNAL, expected.agent_id) for expected, _ in quiet}
    # Keep marks only for agents still silent, so one that recovers and goes quiet again pages at once.
    paged = {name: when for name, when in paged.items()
             if name in names.values() and now - when < fastpath.REPAGE_AFTER}
    due = [(expected, seen) for expected, seen in quiet if names[expected.agent_id] not in paged]
    outgoing = [(_page(expected, seen, window), [names[expected.agent_id]])
                for expected, seen in due[:fastpath.MAX_PAGES]]
    if len(due) > fastpath.MAX_PAGES:
        outgoing.append((_summary(len(due) - fastpath.MAX_PAGES),
                         [names[expected.agent_id] for expected, _ in due[fastpath.MAX_PAGES:]]))
    failed = False
    for page, marks in outgoing:
        try:
            pager.send(page)
        except Exception:
            failed = True
            continue
        for mark in marks:
            paged[mark] = now
    _save(path, paged)
    line = f"agent liveness: {len(inventory)} expected, {len(quiet)} silent" + ("; page failed" if failed else "")
    return (fastpath.FAILED if quiet or failed else fastpath.OK), line
