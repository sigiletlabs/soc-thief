"""Bounded, approval-gated composition of Soc Thief pipeline boundaries.

``run_window`` is dependency-injected so the complete path is testable with synthetic
records.  The CLI refuses to construct any source, model, state, or delivery object
without a private, unexpired operator approval file.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import multiprocessing
import os
import time
from dataclasses import dataclass
from datetime import datetime, time as dt_time, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Protocol

from soc_thief import breach
from soc_thief.zone import TimezoneError, check as check_zone, report_zone
from soc_thief.collector import ALLOWED_FIELDS, CollectorConfig, CollectorError, WazuhIndexerCollector, read_secret
from soc_thief.delivery import (
    ATTACHMENT_LIMIT, BASELINE_DAYS, MAX_PAGES, DeliveryError, DiscordConfig, DiscordDelivery, RenderedReport, RendererError, Report,
    ReportItem, render,
)
from soc_thief.model import JevConfig, JevTriage, ModelConfig, ModelError, OllamaTriage, triage_from_environment  # noqa: F401  (tests patch the configs here)
from soc_thief.policy import Decision, decide, preflight, tuned
from soc_thief.state import OUTBOX_PAYLOAD_LIMIT, StateError, StateStore, opaque_key
from soc_thief.tuning import Tuning, TuningError, load_tuning
from soc_thief.tuning_watch import STATE_NAME, Pager, watch



class RunnerError(RuntimeError):
    """A fixed-text, fail-closed runner failure."""


class Collector(Protocol):
    def collect(self, start: datetime, end: datetime) -> Iterable[dict[str, Any]]: ...


@dataclass(frozen=True)
class RunnerLimits:
    # Sized from measured volume: max 128.7k events/day, ~190 groups/day, ~40s collection
    # and 1.8-5.3s per model-reviewed group.  The collector page budget (500 x 1000) covers
    # max_events.
    max_events: int = 400_000
    max_groups: int = 2_000
    deadline_seconds: int = 1500

    def __post_init__(self) -> None:
        if any(type(value) is not int or not 1 <= value <= upper for value, upper in (
            (self.max_events, 1_000_000), (self.max_groups, 10_000), (self.deadline_seconds, 3600),
        )):
            raise ValueError("runner limits are invalid")


# A few rules can put a distinct path or object name in each description. One measured
# real day had 11,338 exact shapes from 251,563 events, but only 10 rule/agent/label bases with
# more than 50 ordinary description variants. Keep exact protected/critical variants and
# summarize only the ordinary variants of those high-cardinality bases.
_DESCRIPTION_VARIANT_LIMIT = 50
_RAW_GROUP_SHAPE_LIMIT = 50_000


@dataclass(frozen=True)
class RunResult:
    completed: bool
    delivered: bool
    health_failure: bool
    status: str
    caught_up: bool = False  # The window run was a missed day, not the scheduled one.


def _instant(value: object) -> datetime:
    if type(value) is not str:
        raise RunnerError("normalization failed")
    try:
        instant = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if instant.tzinfo is None or instant.utcoffset() is None:
            raise ValueError
        return instant.astimezone(timezone.utc)
    except ValueError:
        raise RunnerError("normalization failed") from None


def _group(records: Iterable[dict[str, Any]], *, start: datetime, end: datetime,
           store: StateStore | None, key: bytes, limits: RunnerLimits, expired: callable,
           exclude_committed: bool = False
           ) -> tuple[list[str], list[dict[str, object]], frozenset[int], dict[int, str]]:
    """Allowlist and deterministically aggregate records without retaining member events.

    With ``exclude_committed`` an event already in committed state stays in the ordered event
    list (replay digest and dedupe counts) but is not grouped, counted, or reviewed.

    The last value maps a group's index to its breach reason. Breach fields are read here
    and dropped; only the fixed reason leaves this function.
    """
    groups: dict[tuple[str, ...], dict[str, object]] = {}
    signals: dict[tuple[str, ...], set[str]] = {}
    brute = breach.BruteForceSuccess()
    events: list[str] = []
    seen: set[str] = set()
    for count, record in enumerate(records, 1):
        if count > limits.max_events or expired():
            raise RunnerError("collection limit exceeded")
        if type(record) is not dict or set(record) != {"source_key", "fields"}:
            raise RunnerError("normalization failed")
        source, fields = record["source_key"], record["fields"]
        if type(source) is not dict or set(source) != {"index", "id"} or type(fields) is not dict or set(fields) != set(ALLOWED_FIELDS):
            raise RunnerError("normalization failed")
        if not all(type(source[name]) is str and source[name] for name in ("index", "id")):
            raise RunnerError("normalization failed")
        instant = _instant(fields["@timestamp"])
        if not start <= instant < end:
            raise RunnerError("normalization failed")
        if type(fields["rule.level"]) is not int or not 0 <= fields["rule.level"] <= 16:
            raise RunnerError("normalization failed")
        required = ("rule.id", "rule.description", "agent.id")
        optional = ("agent.name", "decoder.name", "manager.name", "location")
        if not all(type(fields[name]) is str and fields[name] for name in required):
            raise RunnerError("normalization failed")
        if any(fields[name] is not None and (type(fields[name]) is not str or not fields[name]) for name in optional):
            raise RunnerError("normalization failed")
        if any(fields[name] is not None and (type(fields[name]) is not list
                                             or not all(type(item) is str for item in fields[name]))
               for name in ("rule.groups", "syscheck.changed_attributes")):
            raise RunnerError("normalization failed")
        if any(fields[name] is not None and (type(fields[name]) is not str or not fields[name])
               for name in ("data.srcip", "syscheck.path", "syscheck.event")):
            raise RunnerError("normalization failed")
        event = opaque_key(key, "source", source["index"], source["id"])
        # Include identities already committed in other windows.  StateStore performs global
        # dedupe while retaining this window's full ordered replay digest and assessments.
        if event in seen:
            continue
        seen.add(event)
        events.append(event)
        if exclude_committed and store.contains(event):
            continue
        # A report window runs 08:00--08:00 local time and can cross both local and UTC
        # midnight.  Its local start identity keeps a group together for that window.
        bucket = start.astimezone(report_zone()).isoformat()
        labels = {name: fields[source] for name, source in _LABELS}
        # Every presentation label is part of the identity, so each label variant (for example
        # one description per CVE) is its own group, checked by preflight individually.  Absent
        # labels become "" here only; an empty label is rejected above, so it cannot alias.
        identity = (fields["rule.id"], fields["agent.id"], *(value or "" for value in labels.values()), bucket)
        group = groups.get(identity)
        if group is None:
            if len(groups) >= _RAW_GROUP_SHAPE_LIMIT:
                raise RunnerError("group limit exceeded")
            group = {"timestamp": instant.isoformat(), "rule_id": fields["rule.id"], "rule_level": fields["rule.level"],
                     "agent_id": fields["agent.id"], "count": 1, **labels}
            groups[identity] = group
        else:
            group["count"] = int(group["count"]) + 1
            group["rule_level"] = max(int(group["rule_level"]), fields["rule.level"])
            # The earliest instant keeps the group independent of source order.
            group["timestamp"] = min(_instant(group["timestamp"]), instant).isoformat()
        found = breach.event_signals(fields)
        if found:
            signals.setdefault(identity, set()).update(found)
        brute.observe(fields, instant, identity)
    for identity in brute.flagged():
        signals.setdefault(identity, set()).add("brute_force_success")
    bases: dict[tuple[str, ...], list[tuple[tuple[str, ...], dict[str, object]]]] = {}
    for identity, group in groups.items():
        # Keep every other presentation label in the base. Only descriptions can collapse.
        base = identity[:2] + identity[3:]
        bases.setdefault(base, []).append((identity, group))
    result: list[tuple[tuple[str, ...], dict[str, object], bool]] = []
    for members in bases.values():
        protected, ordinary = [], []
        for identity, group in members:
            # A breach group is never folded into a description summary, like a protected one.
            delivered = identity in signals or preflight(group).delivery_required
            (protected if delivered else ordinary).append((identity, group))
        result.extend((identity, group, False) for identity, group in protected)
        if len(ordinary) > _DESCRIPTION_VARIANT_LIMIT:
            exemplar = min(ordinary, key=lambda item: item[0])[1]
            summary = dict(exemplar)
            summary["rule_description"] = (
                f"Multiple alert descriptions ({len(ordinary)} variants); inspect source alerts.")
            summary["count"] = sum(int(group["count"]) for _, group in ordinary)
            summary["rule_level"] = max(int(group["rule_level"]) for _, group in ordinary)
            summary["timestamp"] = min(_instant(group["timestamp"]) for _, group in ordinary).isoformat()
            identity = (exemplar["rule_id"], exemplar["agent_id"], summary["rule_description"],
                        *(exemplar[name] or "" for name, _ in _LABELS[1:]),
                        start.astimezone(report_zone()).isoformat())
            result.append((identity, summary, True))
        else:
            result.extend((identity, group, False) for identity, group in ordinary)
    result.sort(key=lambda item: item[0])
    if len(result) > limits.max_groups:
        raise RunnerError("group limit exceeded")
    return events, [group for _, group, _ in result], frozenset(
        index for index, (_, _, summarized) in enumerate(result) if summarized), {
        index: breach.name(signals[identity]) for index, (identity, _, _) in enumerate(result)
        if identity in signals}


_LABELS = (("rule_description", "rule.description"), ("agent_name", "agent.name"),
           ("decoder_name", "decoder.name"), ("manager_name", "manager.name"), ("location", "location"))


def _group_token(key: bytes, group: Mapping[str, object], window_start: datetime) -> str:
    """Opaque audit identity for one group, distinct for every label variant.

    The labels are canonical JSON (absent labels are ``null``, so they never equal a real
    string) hashed to one fixed 64-character part: opaque_key rejects empty parts and parts
    over 4096 characters, and a 4096-character description plus escaping would exceed that.
    The final part is the report window's local start identity (``SOC_THIEF_TIMEZONE``), matching grouping.
    """
    labels = json.dumps([group[name] for name, _ in _LABELS], ensure_ascii=True, separators=(",", ":"))
    return opaque_key(key, "group", group["rule_id"], group["agent_id"],
                      hashlib.sha256(labels.encode()).hexdigest(),
                      window_start.astimezone(report_zone()).isoformat())


def _case_token(key: bytes, group: Mapping[str, object]) -> str:
    """Stable rule/agent identity across windows, matching the digest baseline key."""
    return opaque_key(key, "case", group["rule_id"], group["agent_id"])


def _payload(rendered: RenderedReport) -> bytes:
    """Serialize a rendered report as the one opaque outbox row its delivery replays.

    A report is a page sequence, so the row is a JSON array. A single-object
    row written by an older single-page version still replays: see _rendered.
    """
    if type(rendered) is not RenderedReport or not 1 <= len(rendered.payloads) <= MAX_PAGES:
        raise RunnerError("rendering failed")
    try:
        # A digest carries its attachment, so its row is {"pages": [...], "attachment": text}.
        # A report without one keeps the plain array form, which older rows also use.
        body: object = list(rendered.payloads)
        if rendered.attachment is not None:
            body = {"pages": body, "attachment": rendered.attachment}
        raw = json.dumps(body, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode()
        if not 1 <= len(raw) <= OUTBOX_PAYLOAD_LIMIT:
            raise ValueError
        return raw
    except (TypeError, ValueError, UnicodeError):
        raise RunnerError("rendering failed") from None


def _rendered(raw: bytes) -> RenderedReport:
    try:
        decoded = json.loads(raw.decode("utf-8"))
        attachment = None
        if type(decoded) is dict and set(decoded) == {"pages", "attachment"}:  # Digest row.
            decoded, attachment = decoded["pages"], decoded["attachment"]
            if type(attachment) is not str or len(json.dumps(attachment)) - 2 > ATTACHMENT_LIMIT:
                raise ValueError
        payloads = [decoded] if type(decoded) is dict else decoded  # Legacy single-page row.
        if type(payloads) is not list or not 1 <= len(payloads) <= MAX_PAGES:
            raise ValueError
        for payload in payloads:
            if type(payload) is not dict or set(payload) != {"content", "allowed_mentions"} or type(payload["content"]) is not str or payload["allowed_mentions"] != {"parse": []}:
                raise ValueError
        return RenderedReport(tuple(payloads), False, 0, attachment)
    except (ValueError, UnicodeError, json.JSONDecodeError):
        raise RunnerError("pending delivery is invalid") from None


def _health_report(start: datetime, end: datetime) -> RenderedReport:
    return render(Report(start, end, (), 0, 1))


def _history(profile: object) -> dict[tuple[str, str], tuple[int, int]]:
    """Reduce a collector noise profile to (rule_id, agent_id) -> (events, days active)."""
    if type(profile) is not dict or type(profile.get("groups")) is not list:
        raise RunnerError("baseline is invalid")
    history: dict[tuple[str, str], tuple[int, int]] = {}
    for row in profile["groups"]:
        if type(row) is not dict:
            raise RunnerError("baseline is invalid")
        key, seen = (row.get("rule_id"), row.get("agent_id")), (row.get("events"), row.get("days_active"))
        if (not all(type(part) is str for part in key) or not all(type(n) is int and n >= 0 for n in seen)
                or key in history):
            raise RunnerError("baseline is invalid")
        history[key] = seen
    return history


def run_window(*, collector: Collector, model: OllamaTriage | JevTriage, delivery: DiscordDelivery,
               store: StateStore, identity_key: bytes, stream: str, start: datetime, end: datetime,
               limits: RunnerLimits = RunnerLimits(), clock: callable = time.monotonic,
               now: callable = lambda: datetime.now(timezone.utc),
               exclude_committed: bool = False, tuning: Tuning = Tuning(),
               tuning_failure: bool = False,
               baseline: Callable[[], object] | None = None,
               pager: Pager | None = None,
               observe: Callable[[dict[str, object], Decision, Any], None] | None = None) -> RunResult:
    """Run one complete window. Checkpoints advance only with a durable pending report.

    ``tuning`` mutes or downgrades only groups preflight leaves to model review; those skip the
    model and appear in the report as counts. ``tuning_failure`` (an unloadable tuning file, run
    with empty tuning) adds one health failure, which alone makes the report delivery-required.

    A delivery or acknowledgement failure leaves that report pending for retry; it never
    re-collects or advances a completed window. The entrypoint retries the oldest pending
    report in its stream before it reaches this per-window path. Failures before a safe
    rendered report attempt a fixed, content-free health report and return a fixed status.

    ``baseline`` returns the collector's noise profile for the days before the window; with
    it the report is the one-message digest. If it fails, every group is listed on the paged
    report instead and the window raises a health failure - failing towards showing more.

    ``pager`` enables the tuned-spike watch: a tuned group whose count is well above its
    baseline is paged and delivered despite tuning, and if the page fails it is delivered with a
    health failure. Without a baseline there is nothing to compare, so no watch runs.

    ``observe``, when given, is called once per group with the group, its final decision and the
    model review (or None when no model ran). It is read-only instrumentation for the demo
    snapshot; production runs pass nothing.

    ``exclude_committed`` triages only events absent from committed state (late arrivals in
    a reconciliation pass). Such a window must not be re-collected after its commit, because
    its own late arrivals would then be excluded and the replay would be inconsistent.
    """
    if (start.tzinfo is None or end.tzinfo is None or start >= end or type(stream) is not str
            or type(tuning) is not Tuning or type(tuning_failure) is not bool):
        raise ValueError("runner window is invalid")
    began = clock()
    expired = lambda: clock() - began > limits.deadline_seconds
    stream_token = opaque_key(identity_key, "stream", stream)
    try:
        # Retry a crash-surviving report before touching the source.  This makes delivery
        # retry independent of model nondeterminism and avoids a second checkpoint advance.
        pending = store.pending_delivery(stream_token, start)
        if pending is not None:
            delivery.send(_rendered(pending.payload))
            store.acknowledge_delivery(stream_token, start, pending.payload)
            store.prune_audit(now=now())
            return RunResult(True, True, False, "pending delivery acknowledged")
        events, groups, summarized, breaches = _group(collector.collect(start, end), start=start, end=end, store=store,
                                key=identity_key, limits=limits, expired=expired,
                                exclude_committed=exclude_committed)
        if expired():
            raise RunnerError("runner deadline exceeded")
        assessments: list[tuple[str, Decision, str | None]] = []
        case_rows: list[tuple[str, str, str, int, bool]] = []
        deliver: list[ReportItem] = []
        suppressed, health = 0, int(tuning_failure)
        if tuning_failure:
            tuning = Tuning()  # A failed load never contributes suppression.
        history = None
        if baseline is not None:
            try:
                history = _history(baseline())
            except Exception:
                health += 1  # No baseline: the paged report lists every group, never fewer.
        tuned_counts = {"tuned_mute": [0, 0], "tuned_low": [0, 0]}
        instant = now()
        spiking = unpaged = frozenset()
        if pager is not None and history is not None:
            spiking, unpaged = watch(groups, tuning, instant, history, pager, identity_key,
                                     lambda rule, agent: _case_token(identity_key, {"rule_id": rule, "agent_id": agent}))
        prepare = getattr(model, "prepare", None)
        preparation_failed = False
        if prepare is not None:
            try:
                prepare(groups)
            except ModelError:
                preparation_failed = True
        for group_index, group in enumerate(groups):
            if expired():
                raise RunnerError("runner deadline exceeded")
            gate = preflight(group)
            model_identity = None
            reviewed = None
            attention_probability = None
            threat_label = None
            if group_index in breaches and not gate.health_failure:
                # A breach signal is delivered as itself, never tuned and never reviewed by
                # the model. An invalid group keeps its health failure, which is louder.
                gate = decision = Decision(True, False, breaches[group_index])
            elif gate.delivery_required:
                decision = gate  # Protected groups never consult tuning.
            elif (group["rule_id"], group["agent_id"]) in spiking:
                # A tuned pair that spiked is never suppressed; an unsent page also fails health.
                lost = (group["rule_id"], group["agent_id"]) in unpaged
                decision = Decision(True, lost, "tuned_spike_unpaged" if lost else "tuned_spike")
            else:
                decision = tuned(group, tuning.action(group["rule_id"], group["agent_id"], instant))
            if decision.reason in tuned_counts:
                tuned_counts[decision.reason][0] += 1
                tuned_counts[decision.reason][1] += int(group["count"])
            elif not decision.delivery_required:
                if group_index in summarized:
                    # The exemplar is not enough context for inference. The summary is still
                    # delivered and its source events remain in the exact dedupe stream.
                    decision = Decision(True, False, "description_summary")
                else:
                    try:
                        if preparation_failed:
                            raise ModelError("model preparation failed")
                        review = model.review(group)
                        decision = decide(group, review.result)
                        reviewed = review
                        model_identity = review.model_version
                        attention_probability = review.attention_probability
                        threat_label = review.threat_label
                    except ModelError:
                        # A model result cannot change any delivery outcome, so a
                        # model boundary failure must not abort a window it could not have
                        # influenced. The old rationale - do not checkpoint a mixture of reviewed
                        # and unreviewed groups - is void, because both reach the same outcome.
                        # Fail closed for this group instead: decide() with no result delivers it
                        # and raises a health failure. This delivers strictly more, never less.
                        decision = decide(group)
            token = _group_token(identity_key, group, start)
            assessments.append((token, decision, model_identity))
            if observe is not None:
                observe(group, decision, reviewed)
            if decision.delivery_required:
                case_token = _case_token(identity_key, group)
                previous = store.case(case_token, now=instant)
                case_rows.append((case_token, group["rule_id"], group["agent_id"],
                                  group["rule_level"], not gate.delivery_required))
                deliver.append(ReportItem(group, decision, attention_probability, threat_label,
                                          case_token, previous.status if previous else "unreviewed"))
            elif decision.reason == "high_confidence_benign":
                suppressed += 1
            health += int(decision.health_failure)
        (muted_groups, muted_events), (low_groups, low_events) = tuned_counts["tuned_mute"], tuned_counts["tuned_low"]
        report = Report(start, end, tuple(deliver), suppressed, health, muted_groups=muted_groups,
                        muted_events=muted_events, low_groups=low_groups, low_events=low_events,
                        baseline=history)
        # Tuned noise alone never sends a message; delivery-required items or health failures do.
        rendered = render(report) if deliver or health else None
        # A report that carries no page for some of its groups is a health failure, so a
        # run that delivers a partial day cannot report the same status as one that delivers
        # all of it. The omission is already stated and counted on page 1.
        health += int(bool(rendered and rendered.truncated))
        pending = _payload(rendered) if rendered else None
        recorded_at = now()
        store.commit_window(stream_token, start, end, events, assessments,
                            recorded_at=recorded_at, pending_delivery=pending, cases=case_rows)
        # Audit metadata has a fixed seven-day retention policy.  Keep dedupe tokens,
        # replay hashes and checkpoints indefinitely; StateStore prunes only assessments.
        store.prune_audit(now=recorded_at)
        store.prune_cases(now=recorded_at)
        if pending is None:
            return RunResult(True, False, bool(health), "window completed; no delivery required")
        if store.delivery_acknowledged(stream_token, start):
            return RunResult(True, True, bool(health), "window replay already acknowledged")
        delivery.send(_rendered(pending))
        store.acknowledge_delivery(stream_token, start, pending)
        return RunResult(True, True, bool(health), "window completed and delivery acknowledged")
    except (RunnerError, RendererError, StateError, DeliveryError, Exception):
        # Do not disclose error details or source/model content. A delivery exception after a
        # pending commit is intentionally left pending; an operator-controlled retry can send it.
        try:
            delivery.send(_health_report(start, end))
            return RunResult(False, True, True, "window failed; health report delivered")
        except Exception:
            return RunResult(False, False, True, "window failed; health report could not be delivered")


APPROVED_ROUTE = "daily-digest"
# Thirty days, with an off-host expiry warning (soc_thief.status), replaced seven: a weekly
# manual renewal proved easy to miss, and a lapsed approval stops every run.
APPROVAL_MAX_LIFETIME = timedelta(days=30)
# A standing approval ("expires": "never") is also accepted, for operators who prefer it.
# The file must still exist with the exact shape, route and mode; removing it stops every run.
APPROVAL_PERMANENT = datetime.max.replace(tzinfo=timezone.utc)
LATENESS_MARGIN = timedelta(minutes=15)
MAX_WINDOW = timedelta(hours=25)  # A local day with a DST change is 23 or 25 hours long.
REPORT_BOUNDARY = dt_time(8)
STREAM = "daily"
RECONCILE_STREAM = "reconcile"
WORKER_GRACE_SECONDS = 60
# A scheduled daily run that finds the stream behind runs the missed windows oldest first,
# for a gap of at most this long. Longer gaps keep needing an explicit operator catch-up.
CATCH_UP_LIMIT = timedelta(days=31)
# A further window starts only while a full worker timeout plus health delivery still ends inside
# the runner unit's TimeoutStartSec (3900s), which itself ends inside backfill's 07:30-09:30 quiet
# period. A normal window takes about four minutes, so one run can recover about eight days.
CATCH_UP_START_LIMIT_SECONDS = 2100
# Added to a worker's exit code when its window was a missed day, so the parent runs the next.
CATCH_UP_CODE_OFFSET = 100
DEADLINE_EXCEEDED = 3
_ALREADY_COMPLETED = "window already completed; no collection performed"
_FAILED_DELIVERED = "window failed; health report delivered"
_FAILED_UNDELIVERED = "window failed; health report could not be delivered"
# Fixed statuses only.  Worker exit codes are 10 + 2 * index + health bit.
_STATUSES = (
    "pending delivery acknowledged",
    "window completed; no delivery required",
    "window replay already acknowledged",
    "window completed and delivery acknowledged",
    _FAILED_DELIVERED,
    _FAILED_UNDELIVERED,
    _ALREADY_COMPLETED,
)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in pairs:
        if name in result:
            raise ValueError
        result[name] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError


def approval_valid(env: Mapping[str, str], now: datetime) -> bool:
    """Accept only a private, single-line, strictly shaped approval file, dated or permanent."""
    return approval_expiry(env, now) is not None


def approval_expiry(env: Mapping[str, str], now: datetime) -> datetime | None:
    """Return a valid approval's expiry (APPROVAL_PERMANENT for "never"), or None for any
    missing, invalid or expired file."""
    try:
        path = env.get("SOC_THIEF_RUNNER_APPROVAL_FILE")
        if not path:
            return None
        value = json.loads(read_secret(Path(path)), object_pairs_hook=_unique_object,
                           parse_constant=_reject_constant)
        if (type(value) is not dict or set(value) != {"approved_route", "expires"}
                or value["approved_route"] != APPROVED_ROUTE or type(value["expires"]) is not str):
            return None
        if value["expires"] == "never":
            return APPROVAL_PERMANENT
        expires = datetime.fromisoformat(value["expires"].replace("Z", "+00:00"))
        if expires.utcoffset() == timedelta(0) and now < expires <= now + APPROVAL_MAX_LIFETIME:
            return expires
        return None
    except (CollectorError, ValueError, TypeError, json.JSONDecodeError, RecursionError):
        return None


def daily_window(now: datetime) -> tuple[datetime, datetime]:
    """Return the most recent closed 08:00-to-08:00 local day (``SOC_THIEF_TIMEZONE``) in UTC."""
    zone = report_zone()
    local = now.astimezone(zone)
    end = datetime.combine(local.date(), REPORT_BOUNDARY, tzinfo=zone)
    if end.astimezone(timezone.utc) > now - LATENESS_MARGIN:
        end = datetime.combine(local.date() - timedelta(days=1), REPORT_BOUNDARY, tzinfo=zone)
    start = datetime.combine(end.date() - timedelta(days=1), REPORT_BOUNDARY, tzinfo=zone)
    return start.astimezone(timezone.utc), end.astimezone(timezone.utc)


def reconcile_window(now: datetime) -> tuple[datetime, datetime]:
    """Return the local day before ``daily_window(now)``; it has had at least a day of lag."""
    zone = report_zone()
    end = daily_window(now)[0].astimezone(zone)
    start = datetime.combine(end.date() - timedelta(days=1), REPORT_BOUNDARY, tzinfo=zone)
    return start.astimezone(timezone.utc), end.astimezone(timezone.utc)


def catch_up_window(checkpoint: datetime, start: datetime) -> tuple[datetime, datetime] | None:
    """The oldest missed daily window after ``checkpoint``, or None when the gap is not a clean,
    bounded run of whole 08:00 local days ending at ``start``."""
    if not start - CATCH_UP_LIMIT <= checkpoint < start:
        return None
    zone = report_zone()
    local = checkpoint.astimezone(zone)
    if local.timetz().replace(tzinfo=None) != REPORT_BOUNDARY:
        return None
    end = datetime.combine(local.date() + timedelta(days=1), REPORT_BOUNDARY, tzinfo=zone).astimezone(timezone.utc)
    return (checkpoint, end) if end <= start else None


def _identity_key(env: Mapping[str, str]) -> bytes:
    value = read_secret(Path(env["SOC_THIEF_IDENTITY_KEY_FILE"]))
    if len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise ValueError("identity key is invalid")
    return bytes.fromhex(value)


def _tuning(env: Mapping[str, str]) -> tuple[Tuning, bool]:
    """Return tuning and a failure flag. A bad file never adds suppression: it applies none."""
    try:
        return load_tuning(env), False
    except TuningError:
        return Tuning(), True


def _send_page(env: Mapping[str, str]) -> Callable[[Any], None]:
    """The tuned-spike page route. Built lazily per page so a missing or invalid ntfy credential fails the
    page, not the window: the spiking group is then delivered with a health failure."""
    def send(page: Any) -> None:
        from soc_thief.fastpath import NtfyConfig, NtfyPager  # fastpath imports this module.
        NtfyPager(NtfyConfig.from_environment(env)).send(page)
    return send


def _deliver_health(delivery: Any, start: datetime, end: datetime) -> RunResult:
    try:
        delivery.send(_health_report(start, end))
        return RunResult(False, True, True, _FAILED_DELIVERED)
    except Exception:
        return RunResult(False, False, True, _FAILED_UNDELIVERED)


def _execute(start: datetime, end: datetime, env: Mapping[str, str], *, stream: str = STREAM,
             catch_up: bool = False,
             delivery_factory: Callable = lambda env: DiscordDelivery(DiscordConfig.from_environment(env)),
             collector_factory: Callable = lambda env: WazuhIndexerCollector(CollectorConfig.from_environment(env)),
             model_factory: Callable = lambda env: triage_from_environment(env),
             store_factory: Callable = StateStore,
             pager_factory: Callable = lambda env, state: Pager(_send_page(env), state / STATE_NAME)) -> RunResult:
    """Load file-backed configuration and run one approved window; never raises."""
    try:
        delivery = delivery_factory(env)
    except Exception:
        # Without a validated webhook there is no safe route; the nonzero unit result is the signal.
        return RunResult(False, False, True, _FAILED_UNDELIVERED)
    try:
        if stream not in (STREAM, RECONCILE_STREAM):
            raise ValueError
        key = _identity_key(env)
        state = env["STATE_PATH"]
        if not state:
            raise ValueError
        caught_up = False
        with store_factory(Path(state)) as store:
            token = opaque_key(key, "stream", stream)
            # A scheduled later window must never bypass an earlier durable report.  Retry the
            # oldest payload first; otherwise its minimized content could remain retained while
            # checkpoints continue advancing.  The at-least-once acknowledgement protocol is
            # unchanged (a crash after remote acceptance can still duplicate the report).
            pending = store.oldest_pending_delivery(token)
            if pending is not None:
                delivery.send(_rendered(pending.payload))
                store.acknowledge_delivery(token, pending.start, pending.payload)
                store.prune_audit(now=datetime.now(timezone.utc))
                return RunResult(True, True, False, "pending delivery acknowledged")
            # Source and model configuration are irrelevant to an already-rendered outbox
            # payload. Construct them only after the stream's oldest payload has drained.
            collector, model = collector_factory(env), model_factory(env)
            checkpoint = store.checkpoint(token)
            pending = store.pending_delivery(token, start)
            if checkpoint is not None and pending is None:
                if end <= checkpoint:
                    # Late arrivals would make a re-collection an inconsistent replay.
                    return RunResult(True, False, False, _ALREADY_COMPLETED)
                if checkpoint != start:
                    # A scheduled daily run catches up the oldest missed day itself; any
                    # other gap or overlap needs an explicit operator catch-up run.
                    missed = catch_up_window(checkpoint, start) if catch_up and stream == STREAM else None
                    if missed is None:
                        return _deliver_health(delivery, start, end)
                    (start, end), caught_up = missed, True
            if stream == RECONCILE_STREAM and pending is None:
                # Reconcile only a window the contiguous daily stream has fully committed.
                daily = opaque_key(key, "stream", STREAM)
                daily_checkpoint, daily_origin = store.checkpoint(daily), store.origin(daily)
                if (daily_checkpoint is None or daily_origin is None
                        or daily_checkpoint < end or daily_origin > start):
                    return _deliver_health(delivery, start, end)
            tuning, tuning_failure = _tuning(env)
            profile = getattr(collector, "profile", None)
            baseline = None if profile is None else (
                lambda: profile(start - timedelta(days=BASELINE_DAYS), start))
            result = run_window(collector=collector, model=model, delivery=delivery, store=store,
                                identity_key=key, stream=stream, start=start, end=end,
                                exclude_committed=stream == RECONCILE_STREAM,
                                tuning=tuning, tuning_failure=tuning_failure, baseline=baseline,
                                pager=pager_factory(env, Path(state)) if stream == STREAM else None)
            return dataclasses.replace(result, caught_up=True) if caught_up else result
    except Exception:
        return _deliver_health(delivery, start, end)


def _outcome_code(result: RunResult) -> int:
    return 10 + 2 * _STATUSES.index(result.status) + int(result.health_failure)


def _worker_code(result: RunResult) -> int:
    return _outcome_code(result) + (CATCH_UP_CODE_OFFSET if result.caught_up else 0)


def _worker(start: datetime, end: datetime, stream: str = STREAM, catch_up: bool = False) -> None:
    code = 1
    try:
        code = _worker_code(_execute(start, end, os.environ, stream=stream, catch_up=catch_up))
    except Exception:
        pass
    raise SystemExit(code)


def _run_worker(start: datetime, end: datetime, *, stream: str = STREAM, catch_up: bool = False,
                timeout: float = RunnerLimits().deadline_seconds + WORKER_GRACE_SECONDS,
                target: Callable = _worker) -> int:
    """Run in a spawned process so a stuck source, model, or webhook cannot outlive the budget."""
    # Backfill passes its own three-argument target and never catches up.
    args = (start, end, stream, True) if catch_up else (start, end, stream)
    process = multiprocessing.get_context("spawn").Process(target=target, args=args)
    try:
        process.start()
        process.join(timeout)
        if process.is_alive():
            return DEADLINE_EXCEEDED
        return process.exitcode if type(process.exitcode) is int else 1
    except Exception:
        return 1
    finally:
        if process.pid is not None:
            if process.is_alive():
                process.kill()
                process.join(5)
            if not process.is_alive():
                process.close()


def _send_health(start: datetime, end: datetime, env: Mapping[str, str]) -> bool:
    return _deliver_health(DiscordDelivery(DiscordConfig.from_environment(env)), start, end).delivered \
        if env.get("DISCORD_WEBHOOK_URL_FILE") else False


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        # argparse normally repeats untrusted argument text in its diagnostics.
        self.exit(2, "Invalid runner arguments; use --help.\n")


def _window(args: argparse.Namespace, now: datetime) -> tuple[datetime, datetime]:
    explicit = args.start is not None or args.end is not None
    if args.daily and (args.reconcile or explicit):
        raise ValueError
    if args.daily:
        return daily_window(now)
    if args.reconcile and not explicit:
        return reconcile_window(now)
    if args.start is None or args.end is None:
        raise ValueError
    start, end = datetime.fromisoformat(args.start), datetime.fromisoformat(args.end)
    if (start.utcoffset() is None or end.utcoffset() is None
            or not timedelta(0) < end - start <= MAX_WINDOW or end > now - LATENESS_MARGIN):
        raise ValueError
    start, end = start.astimezone(timezone.utc), end.astimezone(timezone.utc)
    if args.reconcile:
        # A reconcile catch-up must be exactly one daily-stream day, no newer than the automatic lag.
        zone = report_zone()
        day = start.astimezone(zone).date()
        aligned = (datetime.combine(day, REPORT_BOUNDARY, tzinfo=zone).astimezone(timezone.utc),
                   datetime.combine(day + timedelta(days=1), REPORT_BOUNDARY, tzinfo=zone).astimezone(timezone.utc))
        if (start, end) != aligned or end > reconcile_window(now)[1]:
            raise ValueError
    return start, end


def _report(code: object, start: datetime, end: datetime, env: Mapping[str, str],
            send_health: Callable) -> tuple[int, bool]:
    """Print one worker's fixed outcome. Returns the exit code and whether it caught up a day."""
    caught_up = type(code) is int and code >= CATCH_UP_CODE_OFFSET
    if caught_up:
        code -= CATCH_UP_CODE_OFFSET
    index, health = divmod(code - 10, 2) if type(code) is int and code >= 10 else (-1, 1)
    if 0 <= index < len(_STATUSES):
        status = _STATUSES[index]
        failed = bool(health) or status in (_FAILED_DELIVERED, _FAILED_UNDELIVERED)
        print(("missed day: " if caught_up else "") + status
              + ("; health review required" if health and not status.startswith("window failed") else ""))
        return (1 if failed else 0), caught_up
    # The worker was killed or crashed before reporting; it could not send its own health report.
    try:
        delivered = bool(send_health(start, end, env))
    except Exception:
        delivered = False
    reason = "Runner deadline exceeded" if code == DEADLINE_EXCEEDED else "Runner failed"
    print(f"{reason}; health report {'delivered' if delivered else 'could not be delivered'}.")
    return 1, False


def main(argv: list[str] | None = None, *, env: Mapping[str, str] | None = None,
         now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
         run_worker: Callable = _run_worker, send_health: Callable = _send_health,
         monotonic: Callable[[], float] = time.monotonic) -> int:
    parser = _Parser(description="Run one approved Soc Thief triage window.")
    parser.add_argument("--daily", action="store_true",
                        help="Most recent closed 08:00 local day (SOC_THIEF_TIMEZONE), or the oldest missed one "
                             "when the daily stream is up to 31 days behind")
    parser.add_argument("--reconcile", action="store_true",
                        help="Re-collect the day before the most recent closed day, or an explicit 08:00 "
                             "local day given by --start/--end; triage late arrivals only")
    parser.add_argument("--start", help="Timezone-aware ISO timestamp (inclusive)")
    parser.add_argument("--end", help="Timezone-aware ISO timestamp (exclusive)")
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
        start, end = _window(args, instant)
    except (ValueError, TypeError, TimezoneError):
        print("Invalid runner window.")
        return 2
    # Approval gates all egress, including health reports: nothing is constructed without it.
    if not approval_valid(env, instant):
        print("Runner approval missing, invalid, or expired; no request made.")
        return 2
    began = monotonic()
    # The clock bounds this in practice; the count bounds it if the clock does not move.
    for _ in range(CATCH_UP_LIMIT.days + 2):
        code = run_worker(start, end, stream=RECONCILE_STREAM if args.reconcile else STREAM, catch_up=args.daily)
        result, caught_up = _report(code, start, end, env, send_health)
        # A caught-up missed day means the scheduled window, or another missed day, is still due.
        # Each worker re-reads the checkpoint, so this loop needs no state of its own.
        if result or not caught_up or monotonic() - began > CATCH_UP_START_LIMIT_SECONDS:
            return result
    return result


if __name__ == "__main__":
    raise SystemExit(main())
