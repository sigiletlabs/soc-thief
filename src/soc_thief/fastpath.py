"""Near-real-time breach check that pages through ntfy.

A short timer runs this every few minutes. It reads one recent window through the same read-only
collector and the same grouping and validation as the daily runner, keeps only the breach
signals (``soc_thief.breach``), and pages once per (signal, agent). There is no model, no tuning and no Discord before
the page: tuning cannot suppress a breach, and the model cannot delay one. The daily digest stays the
audit record and delivers every one of these groups again.

A page carries only a fixed signal name, the Wazuh agent id, the earliest time, an event count and
the opaque case id. No description, hostname, path, address or other alert text leaves here.

State is one private JSON file: the end of the last fully checked interval and when each
(signal, agent) pair last paged, both keyed opaquely. The checkpoint advances only after every
page in the run was accepted, so a failed page is retried by the next run.

After the pages and the saved checkpoint, ``autoinvestigate`` sends one follow-up per page
accepted in this run. It cannot change, delay or withdraw a page.

Left out on purpose: follow-up "still active" updates for an ongoing incident (the daily digest
carries those) and a Discord copy of the page. Coverage and agent liveness are proven
separately: see ``soc_thief.liveness`` and ``soc_thief.status``.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener

from soc_thief import breach, liveness
from soc_thief.collector import CollectorConfig, CollectorError, WazuhIndexerCollector, read_secret
from soc_thief.runner import RunnerError, RunnerLimits, _case_token, _group, _identity_key, approval_valid
from soc_thief.state import opaque_key
from soc_thief.zone import check as check_zone, report_zone

# Wazuh indexes an alert within seconds; two minutes keeps the window end behind ingestion.
LAG = timedelta(minutes=2)
# Each run re-reads this much before its checkpoint, so an alert indexed up to an hour late is
# still seen, and a brute-force alert and the success after it can correlate across runs.
LOOKBACK = timedelta(hours=1)
# After an outage, check at most the last day; anything older is a coverage gap, reported.
MAX_SPAN = timedelta(hours=24)
# An ongoing incident pages once per (signal, agent) in this period.
REPAGE_AFTER = timedelta(hours=24)
# More distinct pages than this in one run become one summary page.
MAX_PAGES = 10
DEADLINE_SECONDS = 300
STATE_NAME = "fastpath.json"

_TOPIC = re.compile(r"/[A-Za-z0-9_-]{1,64}")
_TOKEN = re.compile(r"[A-Za-z0-9_]{1,128}")
_USER_AGENT = "soc-thief-fastpath/1"

OK, FAILED, REFUSED = 0, 1, 2


class FastPathError(RuntimeError):
    """A fixed-text fast-path failure."""


@dataclass(frozen=True)
class Page:
    title: str
    body: str
    priority: str
    tags: str


@dataclass(frozen=True)
class NtfyConfig:
    """``SOC_THIEF_NTFY_FILE`` holds one JSON object: {"url": "https://host/topic"} plus an
    optional "token" (an ntfy access token). Both are operator decisions."""
    config_file: Path
    timeout_seconds: int = 10

    @classmethod
    def from_environment(cls, env: Mapping[str, str]) -> NtfyConfig:
        value = env.get("SOC_THIEF_NTFY_FILE")
        if not value:
            raise FastPathError("ntfy configuration is invalid")
        return cls(Path(value))

    def target(self) -> tuple[str, str | None]:
        try:
            value = json.loads(read_secret(self.config_file))
            if type(value) is not dict or not set(value) <= {"url", "token"} or type(value.get("url")) is not str:
                raise ValueError
            url, token = value["url"], value.get("token")
            parsed = urlsplit(url)
            parsed.port  # Raises ValueError on a malformed port.
            if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
                    or parsed.password is not None or parsed.query or parsed.fragment
                    or _TOPIC.fullmatch(parsed.path) is None):
                raise ValueError
            if token is not None and (type(token) is not str or _TOKEN.fullmatch(token) is None):
                raise ValueError
            return url, token
        except (CollectorError, ValueError, TypeError, json.JSONDecodeError, RecursionError):
            raise FastPathError("ntfy configuration is invalid") from None


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        fp.close()
        raise FastPathError("ntfy redirect refused")


class NtfyPager:
    def __init__(self, config: NtfyConfig, opener: Any = None, sleep: Callable[[float], None] = time.sleep):
        self._config, self._sleep = config, sleep
        self._opener = opener or build_opener(ProxyHandler({}), _NoRedirect(), HTTPSHandler())

    def send(self, page: Page) -> None:
        url, token = self._config.target()
        headers = {"Title": page.title, "Priority": page.priority, "Tags": page.tags,
                   "Content-Type": "text/plain; charset=utf-8", "User-Agent": _USER_AGENT}
        if token is not None:
            headers["Authorization"] = "Bearer " + token
        for attempt in range(2):
            try:
                request = Request(url, page.body.encode(), headers, method="POST")
                with self._opener.open(request, timeout=self._config.timeout_seconds) as response:
                    if getattr(response, "status", response.getcode()) == 200:
                        return
            except HTTPError as error:
                error.close()
                if error.code < 500 and error.code != 429:
                    break
            except (URLError, OSError, ValueError):
                pass
            if attempt == 0:
                self._sleep(2)
        raise FastPathError("ntfy page failed")


def _load_state(path: Path) -> tuple[datetime | None, dict[str, datetime]]:
    try:
        raw = path.read_text()
    except FileNotFoundError:
        return None, {}
    except OSError:
        raise FastPathError("fast path state is unreadable") from None
    try:
        value = json.loads(raw)
        if type(value) is not dict or set(value) != {"version", "checkpoint", "paged"} or value["version"] != 1:
            raise ValueError
        checkpoint = None if value["checkpoint"] is None else _utc(value["checkpoint"])
        if type(value["paged"]) is not dict:
            raise ValueError
        return checkpoint, {key: _utc(when) for key, when in value["paged"].items() if type(key) is str}
    except (ValueError, TypeError, AttributeError, RecursionError):
        raise FastPathError("fast path state is unreadable") from None


def _utc(value: object) -> datetime:
    if type(value) is not str:
        raise ValueError
    instant = datetime.fromisoformat(value)
    if instant.utcoffset() is None:
        raise ValueError
    return instant.astimezone(timezone.utc)


def _save_state(path: Path, checkpoint: datetime | None, paged: Mapping[str, datetime]) -> None:
    body = json.dumps({"version": 1, "checkpoint": None if checkpoint is None else checkpoint.isoformat(),
                       "paged": {key: when.isoformat() for key, when in sorted(paged.items())}},
                      separators=(",", ":"))
    temporary = path.with_name(path.name + ".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        stream.write(body)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def window(now: datetime, checkpoint: datetime | None) -> tuple[datetime, datetime, bool]:
    """Return (start, end, gap). ``gap`` means some time since the checkpoint went unchecked.

    Bounds are whole seconds. The indexer compares dates in milliseconds, so a microsecond start
    returns an event just before it, which the collector then rightly refuses (measured on a
    live indexer).
    """
    end = now.replace(microsecond=0) - LAG
    if checkpoint is None:
        return end - LOOKBACK, end, False
    earliest = end - MAX_SPAN
    if checkpoint < earliest:
        return earliest, end, True
    return min(checkpoint, end) - LOOKBACK, end, False


def _pages(groups: list[dict[str, object]], breaches: Mapping[int, str], key: bytes
           ) -> dict[tuple[str, str], dict[str, Any]]:
    """Aggregate breach groups by (signal, agent): earliest time, total count, case ids."""
    found: dict[tuple[str, str], dict[str, Any]] = {}
    for index, reason in sorted(breaches.items()):
        group = groups[index]
        signal = reason.removeprefix("breach_")
        entry = found.setdefault((signal, str(group["agent_id"])), {"first": None, "count": 0, "cases": set()})
        instant = _utc(group["timestamp"])
        entry["first"] = instant if entry["first"] is None else min(entry["first"], instant)
        entry["count"] += int(group["count"])
        entry["cases"].add(_case_token(key, group))
    return found


def _page(signal: str, agent: str, entry: Mapping[str, Any]) -> Page:
    cases = sorted(entry["cases"])
    first = entry["first"].astimezone(report_zone()).strftime("%Y-%m-%d %H:%M %Z")
    body = (f"Signal: {signal}\nAgent: {agent}\nFirst seen: {first}\nEvents: {entry['count']}\n"
            f"Case: {cases[0]}" + (f" (+{len(cases) - 1} more)" if len(cases) > 1 else ""))
    return Page(f"Soc Thief breach: {signal}", body, "urgent", "rotating_light")


def _summary(count: int) -> Page:
    return Page("Soc Thief breach: several signals",
                f"{count} more breach signals in this check. See the daily digest or run the "
                f"fast path by hand.", "urgent", "rotating_light")


def _gap_page(checkpoint: datetime) -> Page:
    since = checkpoint.astimezone(report_zone()).strftime("%Y-%m-%d %H:%M %Z")
    return Page("Soc Thief fast path gap",
                f"The fast path did not check alerts from {since} for more than "
                f"{int(MAX_SPAN.total_seconds() // 3600)} hours. Only the last day was checked; "
                f"the daily digest still covers the rest.", "high", "warning")


def run(*, env: Mapping[str, str], now: datetime, collector: Any, pager: Any,
        limits: RunnerLimits = RunnerLimits(), monotonic: Callable[[], float] = time.monotonic) -> tuple[int, str]:
    """One fast-path check. Returns (exit code, fixed status text)."""
    state_dir = env.get("STATE_PATH")
    if not state_dir:
        raise FastPathError("fast path configuration is invalid")
    path = Path(state_dir) / STATE_NAME
    key = _identity_key(env)
    checkpoint, paged = _load_state(path)
    start, end, gap = window(now, checkpoint)
    deadline = monotonic() + DEADLINE_SECONDS
    _, groups, _, breaches = _group(collector.collect(start, end), start=start, end=end, store=None,
                                    key=key, limits=limits, expired=lambda: monotonic() > deadline)
    paged = {name: when for name, when in paged.items() if now - when < REPAGE_AFTER}
    due = [(signal, agent, entry) for (signal, agent), entry in sorted(_pages(groups, breaches, key).items())
           if opaque_key(key, "page", signal, agent) not in paged]
    outgoing: list[tuple[Page, list[str]]] = []
    if gap:
        outgoing.append((_gap_page(checkpoint), []))
    for signal, agent, entry in due[:MAX_PAGES]:
        outgoing.append((_page(signal, agent, entry), [opaque_key(key, "page", signal, agent)]))
    if len(due) > MAX_PAGES:
        outgoing.append((_summary(len(due) - MAX_PAGES),
                         [opaque_key(key, "page", signal, agent) for signal, agent, _ in due[MAX_PAGES:]]))
    failed = False
    for page, names in outgoing:
        try:
            pager.send(page)
        except Exception:
            failed = True
            continue
        for name in names:
            paged[name] = now
    _save_state(path, checkpoint if failed else end, paged)
    from soc_thief import autoinvestigate  # Only after the pages went out and state is saved.
    followed = autoinvestigate.follow_up(env=env, now=now, collector=collector, pager=pager, key=key,
                                         groups=groups, breaches=breaches, due=due, paged=paged,
                                         deadline=deadline, monotonic=monotonic)
    sent = len(due)
    if failed:
        return FAILED, f"fast path page failed; {sent} pairs due; checkpoint not advanced"
    if gap:
        return FAILED, f"fast path coverage gap; last day checked; {sent} pairs paged"
    if not followed:
        return FAILED, f"fast path checked; {sent} pairs paged; investigation follow-up failed"
    return OK, f"fast path checked; {sent} pairs paged"


def _pager(env: Mapping[str, str]) -> NtfyPager:
    config = NtfyConfig.from_environment(env)
    config.target()  # Refuse before collecting if the page route is invalid.
    return NtfyPager(config)


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        self.exit(2, "Invalid fast path arguments; use --help.\n")


def main(argv: list[str] | None = None, *, env: Mapping[str, str] | None = None,
         now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
         collector_factory: Callable = lambda env: WazuhIndexerCollector(CollectorConfig.from_environment(env)),
         pager_factory: Callable = lambda env: _pager(env)) -> int:
    parser = _Parser(description="Check the most recent alerts for breach signals and page through ntfy.")
    try:
        parser.parse_args(argv)
    except SystemExit as exit:
        return exit.code if type(exit.code) is int else REFUSED
    env = os.environ if env is None else env
    problem = check_zone()
    if problem:
        print(problem)
        return REFUSED
    instant = now()
    # The runner approval gates this path too: deleting it stops every run, pages included.
    if not approval_valid(env, instant):
        print("Runner approval missing, invalid, or expired; no request made.")
        return REFUSED
    try:
        pager, collector = pager_factory(env), collector_factory(env)
    except Exception:
        print("Fast path configuration is invalid; no request made.")
        return REFUSED
    try:
        code, status = run(env=env, now=instant, collector=collector, pager=pager)
    except (FastPathError, RunnerError, CollectorError):
        code, status = FAILED, "Fast path check failed; checkpoint not advanced."
    except Exception:
        code, status = FAILED, "Fast path check failed unexpectedly; checkpoint not advanced."
    print(status)
    # Agent liveness runs whatever the breach check did, and prints its own fixed line.
    return max(code, liveness.check(env=env, now=instant, collector=collector, pager=pager))


if __name__ == "__main__":
    raise SystemExit(main())
