"""Approval-gated, resumable, rate-limited all-history backfill.

Each invocation processes at most one local (``SOC_THIEF_TIMEZONE``) 08:00-to-08:00 day, oldest first, on the
independent ``backfill`` stream. The range runs from an operator-supplied origin date up to the
``daily`` stream's first committed window, so backfill never overlaps or races ahead of the daily
report. Every window uses ``run_window`` unchanged: the same policy, model, state, and delivery.
"""

from __future__ import annotations

import argparse
import os
import re
from datetime import date, datetime, time as dt_time, timedelta, timezone
from pathlib import Path
from typing import Callable, Mapping
from zoneinfo import ZoneInfo

from soc_thief.collector import CollectorConfig, WazuhIndexerCollector
from soc_thief.delivery import DiscordConfig, DiscordDelivery
from soc_thief.model import ModelConfig, OllamaTriage
from soc_thief.runner import (
    DEADLINE_EXCEEDED, LATENESS_MARGIN, REPORT_BOUNDARY, WORKER_GRACE_SECONDS, RunnerLimits, RunResult,
    _FAILED_DELIVERED, _FAILED_UNDELIVERED, _STATUSES as _RUNNER_STATUSES, _Parser as _RunnerParser,
    _deliver_health, _identity_key, _rendered, _run_worker, _send_health, _tuning, approval_valid, run_window,
)
from soc_thief.state import StateStore, opaque_key
from soc_thief.zone import TimezoneError, check as check_zone, report_zone


STREAM = "backfill"
DAILY_STREAM = "daily"
# No backfill may start inside a quiet period (local report time), so the nonblocking state lock is never
# contended. [07:30, 09:30): a run started at 07:29:59 is killed by the unit timeout before 08:00,
# and the daily runner (08:20 + 5m jitter + its unit timeout) has finished by 09:30.
# [10:00, 11:15): likewise for the reconcile pass (10:30 + 5m jitter + its unit timeout).
QUIET_PERIODS = ((dt_time(7, 30), dt_time(9, 30)), (dt_time(10, 0), dt_time(11, 15)))
UNIT_TIMEOUT = timedelta(seconds=1800)  # Must equal TimeoutStartSec in soc-thief-backfill.service.
WORKER_TIMEOUT = RunnerLimits().deadline_seconds + WORKER_GRACE_SECONDS
_COMPLETE = "backfill complete; no collection performed"
_RANGE_INVALID = "backfill origin is after the daily origin; no collection performed"
_DEFERRED = "backfill deferred; daily report period"
# Fixed statuses only. Worker exit codes are 10 + 2 * index + health bit.
_STATUSES = _RUNNER_STATUSES + (_COMPLETE, _RANGE_INVALID)
_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")


def _zone() -> ZoneInfo:
    return report_zone()


def window_starting(start: datetime) -> tuple[datetime, datetime]:
    """Return the local report day beginning exactly at ``start`` (23 to 25 hours) in UTC."""
    if start.tzinfo is None or start.utcoffset() is None:
        raise ValueError("backfill window is invalid")
    zone = _zone()
    local = start.astimezone(zone)
    if local.time() != REPORT_BOUNDARY:
        raise ValueError("backfill window is invalid")
    end = datetime.combine(local.date() + timedelta(days=1), REPORT_BOUNDARY, tzinfo=zone)
    return start.astimezone(timezone.utc), end.astimezone(timezone.utc)


def _window_ending(end: datetime) -> tuple[datetime, datetime]:
    zone = _zone()
    local = end.astimezone(zone)
    if end.tzinfo is None or local.time() != REPORT_BOUNDARY:
        raise ValueError("backfill window is invalid")
    return window_starting(datetime.combine(local.date() - timedelta(days=1), REPORT_BOUNDARY, tzinfo=zone))


def parse_origin(value: str, now: datetime) -> datetime:
    """Parse a strict YYYY-MM-DD local date whose report day has already closed."""
    if type(value) is not str or not _DATE.fullmatch(value):
        raise ValueError("backfill origin is invalid")
    start = datetime.combine(date.fromisoformat(value), REPORT_BOUNDARY, tzinfo=_zone())
    start, end = window_starting(start)
    if end > now - LATENESS_MARGIN:
        raise ValueError("backfill origin is invalid")
    return start


def in_quiet_period(now: datetime) -> bool:
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("backfill clock is invalid")
    local = now.astimezone(_zone()).time()
    return any(start <= local < end for start, end in QUIET_PERIODS)


def _execute(origin: datetime, env: Mapping[str, str], *,
             delivery_factory: Callable = lambda env: DiscordDelivery(DiscordConfig.from_environment(env)),
             collector_factory: Callable = lambda env: WazuhIndexerCollector(CollectorConfig.from_environment(env)),
             model_factory: Callable = lambda env: OllamaTriage(ModelConfig.from_environment(env)),
             store_factory: Callable = lambda path: StateStore(path)) -> RunResult:
    """Run, retry, or decline exactly one backfill window; never raises."""
    try:
        delivery = delivery_factory(env)
    except Exception:
        return RunResult(False, False, True, _FAILED_UNDELIVERED)
    health = (origin, origin + timedelta(days=1))
    try:
        health = window_starting(origin)
        key = _identity_key(env)
        state = env["STATE_PATH"]
        if not state:
            raise ValueError
        with store_factory(Path(state)) as store:
            stream = opaque_key(key, "stream", STREAM)
            # Drain legacy and crash-surviving reports in stream order.  Checking only the
            # checkpoint's prior window can strand an older minimized payload after a prior
            # version advanced the stream despite it; no new history may be collected first.
            pending = store.oldest_pending_delivery(stream)
            if pending is not None:
                delivery.send(_rendered(pending.payload))
                store.acknowledge_delivery(stream, pending.start, pending.payload)
                store.prune_audit(now=datetime.now(timezone.utc))
                return RunResult(True, True, False, "pending delivery acknowledged")
            daily = store.origin(opaque_key(key, "stream", DAILY_STREAM))
            if daily is None:
                # Backfill's upper bound is unknown until the daily report has started.
                return _deliver_health(delivery, *health)
            if origin > daily:
                return RunResult(False, False, False, _RANGE_INVALID)
            started, checkpoint = store.origin(stream), store.checkpoint(stream)
            window = None
            if started is None:
                if checkpoint is not None:
                    return _deliver_health(delivery, *health)
                start = origin
            else:
                if started != origin or checkpoint is None:
                    # The operator range must not change silently once the stream has started.
                    return _deliver_health(delivery, *health)
                previous = _window_ending(checkpoint)
                health = previous
                start = checkpoint
            if window is None:
                if start == daily:
                    return RunResult(True, False, False, _COMPLETE)
                if start > daily:
                    return _deliver_health(delivery, *health)
                window = window_starting(start)
                health = window
                if window[1] > daily:
                    # A partial or overlapping day is never produced.
                    return _deliver_health(delivery, *health)
            collector, model = collector_factory(env), model_factory(env)
            tuning, tuning_failure = _tuning(env)
            return run_window(collector=collector, model=model, delivery=delivery, store=store,
                              identity_key=key, stream=STREAM, start=window[0], end=window[1],
                              tuning=tuning, tuning_failure=tuning_failure)
    except Exception:
        return _deliver_health(delivery, *health)


def _outcome_code(result: RunResult) -> int:
    return 10 + 2 * _STATUSES.index(result.status) + int(result.health_failure)


def _worker(origin: datetime, instant: datetime, stream: str = STREAM) -> None:
    # The shared runner spawner passes its stream argument; only the backfill stream is valid here.
    code = 1
    try:
        if stream != STREAM:
            raise ValueError
        code = _outcome_code(_execute(origin, os.environ))
    except Exception:
        pass
    raise SystemExit(code)


class _Parser(_RunnerParser):
    def error(self, message: str) -> None:
        self.exit(2, "Invalid backfill arguments; use --help.\n")


def main(argv: list[str] | None = None, *, env: Mapping[str, str] | None = None,
         now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
         run_worker: Callable = _run_worker, send_health: Callable = _send_health) -> int:
    parser = _Parser(description="Run at most one approved Soc Thief backfill window.")
    parser.add_argument("--from", dest="origin", required=True,
                        help="First local (SOC_THIEF_TIMEZONE) report date, YYYY-MM-DD (not secret)")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exit:
        return exit.code if type(exit.code) is int else 2
    env = os.environ if env is None else env
    problem = check_zone()
    if problem:
        print(problem)
        return 2
    instant = now()
    try:
        origin = parse_origin(args.origin, instant)
        quiet = in_quiet_period(instant)
    except (ValueError, TypeError, TimezoneError):
        print("Invalid backfill origin.")
        return 2
    if quiet:
        # Never contend for the state lock with the daily runner; no file or network is touched.
        print(_DEFERRED)
        return 0
    if not approval_valid(env, instant):
        print("Backfill approval missing, invalid, or expired; no request made.")
        return 2
    code = run_worker(origin, instant, stream=STREAM, timeout=WORKER_TIMEOUT, target=_worker)
    index, health = divmod(code - 10, 2) if type(code) is int and code >= 10 else (-1, 1)
    if 0 <= index < len(_STATUSES):
        status = _STATUSES[index]
        if status == _RANGE_INVALID:
            print(status)
            return 2
        failed = bool(health) or status in (_FAILED_DELIVERED, _FAILED_UNDELIVERED)
        print(status + ("; health review required" if health and not status.startswith("window failed") else ""))
        return 1 if failed else 0
    # The worker was killed or crashed before reporting; it could not send its own health report.
    try:
        delivered = bool(send_health(origin, instant, env))
    except Exception:
        delivered = False
    reason = "Backfill deadline exceeded" if code == DEADLINE_EXCEEDED else "Backfill failed"
    print(f"{reason}; health report {'delivered' if delivered else 'could not be delivered'}.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
