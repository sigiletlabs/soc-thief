"""Minimized Discord rendering and bounded webhook delivery."""

from __future__ import annotations

from soc_thief import __version__

import json
import math
import os
import re
import socket
import time
import unicodedata
from dataclasses import dataclass
from datetime import datetime
from http.client import HTTPException
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener

from soc_thief.breach import REASONS as BREACH_REASONS
from soc_thief.collector import CollectorError, read_secret
from soc_thief.policy import Decision, JEV_THREAT_LABELS

_CONTENT_LIMIT, _PAYLOAD_LIMIT = 1900, 8 * 1024
# One summary page plus bounded continuation pages. A measured real
# high-cardinality day needs 22 pages to itemize its protected/critical lines while preserving the exact-alert
# message invariant. Leave two pages of headroom; any further surplus is counted and
# raises health, never silently dropped. MAX_PAGES and _PAYLOAD_LIMIT together bound the
# outbox row state.StateStore accepts, so keep its limit coupled to this value.
MAX_PAGES, _TOP_GROUPS = 24, 10
_FULL_LIMIT, _COMPACT_LIMIT, _OMISSION_RESERVE = 700, 180, 112
_PAGE_HEAD = "**Soc Thief triage — remaining groups (page {page} of {pages})**"
# The daily digest. A group is itemised on the message when it is a failure, critical, new
# against the baseline, or spiking against it; the rest is "recurring" and collapses into one total
# plus the top rules by severity and volume. Every delivery-required group is listed in the
# attached text file. Operator-tuned groups stay counts only, as on the paged report.
BASELINE_DAYS, _SPIKE_RATIO, _SPIKE_MINIMUM, _RECURRING_LINES = 30, 3, 10, 5
_CRITICAL_EXAMPLES = 3
# Measured on the JSON-escaped form, which is never smaller than the UTF-8 file it becomes.
ATTACHMENT_LIMIT, _ATTACHMENT_LINE = 256 * 1024, 400
ATTACHMENT_NAME = "soc-thief-report.txt"
# Discord's Cloudflare front rejects urllib's default "Python-urllib/3.x" agent with 403 (error
# 1010) before the webhook is read. Fixed and content-free: names no host or operator.
_USER_AGENT = f"SocThief/{__version__}"
_WEBHOOK_PATH = re.compile(r"/api/webhooks/[0-9]{16,22}/[A-Za-z0-9._-]{20,200}\Z")
_IPV4 = re.compile(r"(?<![\w.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\w.])")
_URL = re.compile(r"https?://[^\s<>]{1,1024}", re.I)
_SECRET = re.compile(r"(?i)\b(?:password|passwd|token|secret|authorization|api[_-]?key)\s*[:=]\s*[^\s,;]+")


class RendererError(RuntimeError): pass
class DeliveryError(RuntimeError): pass


@dataclass(frozen=True)
class ReportItem:
    group: dict[str, object]
    decision: Decision
    attention_probability: float | None = None  # Jev trial: display only, never policy.
    threat_label: str | None = None  # Fixed advisory tag, never policy.
    case_token: str | None = None  # Opaque stable rule/agent review identity.
    case_status: str | None = None  # Prior human verdict; display only.


@dataclass(frozen=True)
class Report:
    start: datetime
    end: datetime
    items: tuple[ReportItem, ...]
    suppressed_count: int  # Model high-confidence benign suppression only.
    health_failure_count: int
    muted_groups: int = 0
    muted_events: int = 0
    low_groups: int = 0
    low_events: int = 0
    # (rule_id, agent_id) -> (events, days active) over BASELINE_DAYS before the window. None
    # renders the paged report instead of the digest.
    baseline: Mapping[tuple[str, str], tuple[int, int]] | None = None


@dataclass(frozen=True)
class RenderedReport:
    payloads: tuple[dict[str, object], ...]
    truncated: bool
    omitted_count: int = 0  # Delivery-required groups carried by no page at all.
    attachment: str | None = None  # The full listing, sent as a file with page 1.


def _safe_time(value: object) -> str:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise RendererError("invalid report timestamp")
    return value.isoformat(timespec="seconds")


def _safe_count(value: object) -> int:
    if type(value) is not int or not 0 <= value <= 2**63 - 1:
        raise RendererError("invalid report count")
    return value


def _plain(value: object, limit: int) -> str:
    """Validate and redact untrusted text; no markup escaping (the attachment is plain text)."""
    if type(value) is not str or not 0 < len(value) <= limit:
        raise RendererError("invalid report text")
    value = unicodedata.normalize("NFKC", value)
    if not value.strip() or any(unicodedata.category(char).startswith("C") for char in value):
        raise RendererError("invalid report text")
    value = _SECRET.sub("[redacted secret]", value)
    value = _URL.sub("[redacted URL]", value)
    return _IPV4.sub("[masked IP]", value)


def _text(value: object, limit: int) -> str:
    value = _plain(value, limit)
    return (value.replace("\\", "\\\\").replace("`", "'").replace("*", "\\*")
            .replace("_", "\\_").replace("~", "\\~").replace("|", "\\|")
            .replace("<", "‹").replace(">", "›").replace("@", "@\u200b"))


def _fields(item: object) -> dict[str, object]:
    """Validate one report item and return only escaped, size-capped safe text."""
    if type(item) is not ReportItem or type(item.group) is not dict or type(item.decision) is not Decision:
        raise RendererError("invalid report item")
    group, decision = item.group, item.decision
    score = item.attention_probability
    if score is not None and (type(score) not in (int, float) or not math.isfinite(score) or not 0 <= score <= 1):
        raise RendererError("invalid attention score")
    threat = item.threat_label
    if threat is not None and (type(threat) is not str or threat not in JEV_THREAT_LABELS or score is None):
        raise RendererError("invalid threat label")
    if ((item.case_token is None) != (item.case_status is None)
            or (item.case_token is not None and (type(item.case_token) is not str
                or re.fullmatch(r"[0-9a-f]{64}", item.case_token) is None
                or item.case_status not in {"unreviewed", "review", "routine", "uncertain"}))):
        raise RendererError("invalid case metadata")
    if not decision.delivery_required:
        raise RendererError("suppressed item in report")
    required = {"timestamp", "rule_id", "rule_level", "rule_description", "agent_id", "count"}
    optional = {"agent_name", "decoder_name", "manager_name", "location"}
    if not required <= group.keys() <= required | optional or type(group["rule_level"]) is not int or not 0 <= group["rule_level"] <= 16:
        raise RendererError("invalid report group")
    count = _safe_count(group["count"])
    if count == 0: raise RendererError("invalid report count")
    agent_id, agent_name = _text(group["agent_id"], 256), group.get("agent_name")
    if agent_name is not None: agent_name = _text(agent_name, 256)
    breach = (decision.reason.removeprefix("breach_").replace("_", " ")
              if decision.reason in BREACH_REASONS else None)
    return {"level": group["rule_level"], "count": count, "attention": score, "threat": threat,
            "case_status": item.case_status, "breach": breach,
            "timestamp": _text(group["timestamp"], 256), "rule": _text(group["rule_id"], 256),
            "description": _text(group["rule_description"], 2048),
            "identity": agent_name + " (" + agent_id + ")" if agent_name else agent_id}


def _full(fields: dict[str, object]) -> str:
    advice = f"; Jev {fields['attention']:.2f}" if fields["attention"] is not None else ""
    if fields["threat"] is not None: advice += f" [{fields['threat'].replace('_', ' ')}]"
    mark = f"**BREACH {fields['breach']}** " if fields["breach"] else ""
    text = (f"• {mark}Rule `{fields['rule']}` — severity {fields['level']}; {fields['count']} events{advice}\n"
            f"  Agent: {fields['identity']}; first: {fields['timestamp']}\n  {fields['description']}")
    return text if len(text) <= _FULL_LIMIT else text[:_FULL_LIMIT - 3] + "..."


def _compact(fields: dict[str, object]) -> str:
    """One continuation-page line. Drops only the group's first-seen timestamp."""
    advice = f" Jev {fields['attention']:.2f}" if fields["attention"] is not None else ""
    if fields["threat"] is not None: advice += f" [{fields['threat'].replace('_', ' ')}]"
    mark = f"**BREACH {fields['breach']}** " if fields["breach"] else ""
    text = f"• {mark}sev {fields['level']} `{fields['rule']}` x{fields['count']}{advice} — {fields['identity']}: {fields['description']}"
    return text if len(text) <= _COMPACT_LIMIT else text[:_COMPACT_LIMIT - 3] + "..."


def _remainder(entries: list[dict[str, object]], total: int) -> str:
    """Aggregate the groups page 1 does not show in full. Counts every one of them."""
    totals: dict[int, list[int]] = {}
    for fields in entries:
        bucket = totals.setdefault(fields["level"], [0, 0])
        bucket[0] += 1
        bucket[1] += fields["count"]
    lines = "\n".join(f"  severity {level}: {groups} groups, {events} events"
                      for level, (groups, events) in sorted(totals.items(), reverse=True))
    return f"__Remaining {len(entries)} of {total} groups by severity__\n{lines}"


def _continuations(entries: list[str]) -> tuple[list[str], int]:
    """Paginate the remaining groups into at most MAX_PAGES - 1 bounded pages.

    Returns the page bodies and the number of groups that fit on no page. A group that
    is omitted here is still counted by the page-1 aggregate and omission line, so the
    report never drops evidence without a number.
    """
    widest = len(_PAGE_HEAD.format(page=MAX_PAGES, pages=MAX_PAGES))
    pages, index = [], 0
    while index < len(entries) and len(pages) < MAX_PAGES - 1:
        lines, cursor = [], index
        while cursor < len(entries):
            line = entries[cursor]
            if widest + len("\n\n") + len("\n".join([*lines, line])) > _CONTENT_LIMIT: break
            lines.append(line)
            cursor += 1
        if not lines: break  # A single line that cannot fit: stop rather than spin.
        pages.append("\n".join(lines))
        index = cursor
    heads = len(pages) + 1
    return [_PAGE_HEAD.format(page=number + 2, pages=heads) + "\n\n" + body
            for number, body in enumerate(pages)], len(entries) - index


def render(report: Report) -> RenderedReport:
    """Render a bounded, mention-free summary page plus bounded continuation pages.

    Page 1 carries the window totals, the highest-severity groups in full, and every
    remaining group aggregated by severity. Continuation pages carry those remaining
    groups, one compact line each, ranked by severity then volume.

    Measured on a real day, a window produces 169 delivery-required groups while a
    single Discord message holds about 10, so a one-message report omitted 93% of them and
    said so only in its own text. Aggregate counts here always cover every group, and any
    group that fits on no page is counted in the omission line and sets ``truncated``,
    which the runner reports as a health failure.

    No model prose and no raw events appear on any page.
    """
    if type(report) is not Report or type(report.items) is not tuple: raise RendererError("invalid report")
    if report.baseline is not None:
        return _digest(report)
    start, end = _safe_time(report.start), _safe_time(report.end)
    suppressed, failures = _safe_count(report.suppressed_count), _safe_count(report.health_failure_count)
    header = ("**Soc Thief triage — review required**\n" f"Window: {start} to {end}\n"
              f"Delivery-required groups: {len(report.items)}; suppressed benign groups: {suppressed}; health failures: {failures}")
    muted_groups, muted_events = _safe_count(report.muted_groups), _safe_count(report.muted_events)
    low_groups, low_events = _safe_count(report.low_groups), _safe_count(report.low_events)
    if muted_groups or muted_events or low_groups or low_events:
        # Operator-tuned groups contribute counts only: no rule, agent, or tuning text.
        header += (f"\nLow priority: {low_events} events in {low_groups} groups. "
                   f"Muted: {muted_events} events in {muted_groups} groups.")
    entries = [_fields(item) for item in report.items]
    # Breach signals lead page 1 whatever their severity.
    ranked = sorted(entries, key=lambda fields: (fields["breach"] is None, -fields["level"], -fields["count"]))
    # Hold page-1 room for the widest remainder block and the omission line before choosing
    # how many groups to show in full, so pagination is decided in one pass.
    reserve = len(_remainder(ranked, len(ranked))) + _OMISSION_RESERVE + len("\n\n") * 2 if ranked else 0
    shown: list[str] = []
    for fields in ranked[:_TOP_GROUPS]:
        line = _full(fields)
        if len(header) + reserve + len("\n\n") + len("\n\n".join([*shown, line])) > _CONTENT_LIMIT: break
        shown.append(line)
    rest = ranked[len(shown):]
    pages, omitted = _continuations([_compact(fields) for fields in rest])
    if omitted:
        # "[health review]" is the established marker for a line the runner also raises as a
        # health failure, so the message and the run status never disagree.
        header += f"\n[health review] Groups omitted entirely: {omitted} (counted above, carried by no page)."
    sections = [header]
    if shown: sections.append(f"__Highest severity — {len(shown)} of {len(ranked)} groups in full__\n\n" + "\n\n".join(shown))
    if rest: sections.append(_remainder(rest, len(ranked)))
    content, truncated = "\n\n".join(sections), bool(omitted)
    if len(content) > _CONTENT_LIMIT:
        # Unreachable while the reserve holds; kept so a future format change fails loudly
        # in the safe direction rather than posting an over-long message.
        notice = "\n\n[health review] bounded message truncated."
        content, truncated = content[:_CONTENT_LIMIT - len(notice)] + notice, True
    payloads = tuple({"content": text, "allowed_mentions": {"parse": []}} for text in (content, *pages))
    for payload in payloads:
        if len(json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode()) > _PAYLOAD_LIMIT:
            raise RendererError("rendered payload exceeds limit")
    return RenderedReport(payloads, truncated, omitted)


def _baseline(value: object) -> dict[tuple[str, str], tuple[int, int]]:
    if not isinstance(value, Mapping):
        raise RendererError("invalid baseline")
    for key, seen in value.items():
        if (type(key) is not tuple or len(key) != 2 or not all(type(part) is str for part in key)
                or type(seen) is not tuple or len(seen) != 2
                or not all(type(number) is int and number >= 0 for number in seen)):
            raise RendererError("invalid baseline")
    return dict(value)


def _category(item: ReportItem, baseline: Mapping[tuple[str, str], tuple[int, int]],
              agents: frozenset[str] = frozenset()) -> str:
    """FAILED, BREACH, CRITICAL, NEW AGENT, NEW or SPIKE are flagged; the rest is recurring.

    BREACH is itemised on the message, one line per group, never summarised like CRITICAL.

    NEW AGENT is a NEW group from an agent absent from the whole baseline. Measured over 61 real
    days, both bursts of 50+ NEW groups were one newly seen agent, so the message carries one line
    per such agent instead of one per group; every group is still in the attachment.
    """
    if item.decision.health_failure:
        return "FAILED"
    if item.decision.reason in BREACH_REASONS:
        # The signal name is a fixed vocabulary, never alert text.
        return "BREACH " + item.decision.reason.removeprefix("breach_").replace("_", " ")
    if item.decision.reason == "critical_severity":
        return "CRITICAL"
    seen = baseline.get((item.group["rule_id"], item.group["agent_id"]))
    if seen is None or seen[0] == 0:
        return "NEW" if item.group["agent_id"] in agents else "NEW AGENT"
    events, days = seen
    count = item.group["count"]
    if count >= _SPIKE_MINIMUM and count > _SPIKE_RATIO * events / max(days, 1):
        return "SPIKE"
    return "recurring"


def _attachment(heading: list[str], rows: list[tuple[str, ReportItem]]) -> tuple[str, int]:
    """The full listing as plain text, bounded by ATTACHMENT_LIMIT; returns (text, rows left out)."""
    lines = [*heading, "", "category | severity | rule | events | agent | first seen | description | Jev attention score | Jev threat tag | case id | prior analyst status"]
    budget = ATTACHMENT_LIMIT - 1024  # Room for the omission line, which is never cut.
    used = sum(len(json.dumps(line + "\n")) - 2 for line in lines)
    written = 0
    for category, item in rows:
        group = item.group
        agent = _plain(group["agent_id"], 256)
        if group.get("agent_name") is not None:
            agent = _plain(group["agent_name"], 256) + " (" + agent + ")"
        score = item.attention_probability
        score_text = f" | {score:.2f}" if score is not None else " | "
        threat_text = f" | {item.threat_label}" if item.threat_label is not None else " | "
        case_text = f" | {item.case_token} | {item.case_status}" if item.case_token else ""
        advice_text = score_text + threat_text + case_text
        line = " | ".join((category, str(group["rule_level"]), _plain(group["rule_id"], 256),
                           str(group["count"]), agent, _plain(group["timestamp"], 256),
                           _plain(group["rule_description"], 2048))) + advice_text
        if len(line) > _ATTACHMENT_LINE:
            line = line[:_ATTACHMENT_LINE - len(advice_text) - 3] + "..." + advice_text
        size = len(json.dumps(line + "\n")) - 2
        if used + size > budget:
            break
        lines.append(line)
        used += size
        written += 1
    omitted = len(rows) - written
    if omitted:
        lines.append(f"[health review] {omitted} groups did not fit in this file; they are counted above.")
    return "\n".join(lines) + "\n", omitted


def _digest(report: Report) -> RenderedReport:
    """Compact daily digest: what changed up front, every group attached.

    Critical groups are counted on-screen with three examples and individually listed in the
    attachment; failed groups remain itemised on-screen. Recurring groups are counted and
    attached. Remaining flagged lines spill onto bounded pages, and anything those pages or
    the attachment cannot carry is counted and marks ``truncated``.
    """
    start, end = _safe_time(report.start), _safe_time(report.end)
    suppressed, failures = _safe_count(report.suppressed_count), _safe_count(report.health_failure_count)
    muted_groups, muted_events = _safe_count(report.muted_groups), _safe_count(report.muted_events)
    low_groups, low_events = _safe_count(report.low_groups), _safe_count(report.low_events)
    baseline = _baseline(report.baseline)
    agents = frozenset(agent for (_, agent), (events, _) in baseline.items() if events)
    entries = [(_category(item, baseline, agents), _fields(item), item) for item in report.items]
    order = lambda entry: (-entry[1]["level"], -(entry[1]["attention"] if entry[1]["attention"] is not None else -1), -entry[1]["count"])
    # Boundary failures need attention before advisory NEW/SPIKE lines, regardless of
    # severity or an uncalibrated model score. Keep their individual message lines first.
    # Breach signals come first of all: they are the reason the operator is looking.
    flagged = sorted((entry for entry in entries if entry[0] != "recurring"),
                     key=lambda entry: (not entry[0].startswith("BREACH"), entry[0] != "FAILED",
                                        *order(entry)))
    recurring = sorted((entry for entry in entries if entry[0] == "recurring"), key=order)
    critical = [entry for entry in flagged if entry[0] == "CRITICAL"]
    message_flagged = []
    critical_seen = 0
    for entry in flagged:
        if entry[0] == "CRITICAL":
            critical_seen += 1
            if critical_seen > _CRITICAL_EXAMPLES:
                continue
        message_flagged.append(entry)
    events = sum(fields["count"] for _, fields, _ in entries)
    header = ("**Soc Thief daily digest**\n" f"Window: {start} to {end}\n"
              f"{len(entries)} groups, {events} events; health failures: {failures}")
    if any(item.case_token for item in report.items):
        routine = sum(fields["case_status"] == "routine" for _, fields, _ in entries)
        header += f"\nPrior analyst routine verdict: {routine} groups (still delivered; expires after 30 days)."
    if suppressed:
        header += f"; suppressed benign groups: {suppressed}"
    if muted_groups or muted_events or low_groups or low_events:
        header += (f"\nLow priority: {low_events} events in {low_groups} groups. "
                   f"Muted: {muted_events} events in {muted_groups} groups.")
    if any(item.attention_probability is not None for item in report.items):
        header += "\nJev attention scores are uncalibrated; threat tags are unvalidated advice; ordering only, no delivery decisions."
    if critical:
        header += (f"\nCritical: {len(critical)} groups, "
                   f"{sum(fields['count'] for _, fields, _ in critical)} events; "
                   f"{min(len(critical), _CRITICAL_EXAMPLES)} examples below, every group in the attachment.")
    text, attachment_omitted = _attachment(
        [f"Soc Thief daily digest - full listing", f"Window: {start} to {end}",
         f"{len(entries)} groups, {events} events; health failures: {failures}; "
         f"muted: {muted_groups} groups; low priority: {low_groups} groups",
         f"Baseline: the {BASELINE_DAYS} days before the window. NEW = rule and agent not seen in it; "
         f"NEW AGENT = the agent itself not seen in it; "
         f"SPIKE = at least {_SPIKE_MINIMUM} events and over {_SPIKE_RATIO}x its usual daily count."],
        [(category, item) for category, _, item in (*flagged, *recurring)])
    footer = f"Every group is listed in the attached {ATTACHMENT_NAME}."
    if attachment_omitted:
        footer += f"\n[health review] {attachment_omitted} groups did not fit in the attachment."

    rules: dict[str, list] = {}
    for _, fields, _ in recurring:
        rule = rules.setdefault(fields["rule"], [fields["level"], 0, set(), fields["description"], None, None])
        rule[0], rule[1] = max(rule[0], fields["level"]), rule[1] + fields["count"]
        rule[2].add(fields["identity"])
        if fields["attention"] is not None:
            if rule[4] is None or fields["attention"] > rule[4]:
                rule[3], rule[4], rule[5] = fields["description"], fields["attention"], fields["threat"]
    scored = any(value[4] is not None for value in rules.values())
    top = sorted(rules.items(), key=(lambda item: (-(item[1][4] if item[1][4] is not None else -1), -item[1][0], -item[1][1]))
                 if scored else (lambda item: (-item[1][0], -item[1][1])))[:_RECURRING_LINES]
    recurring_lines = []
    for rule, (level, count, agents, description, score, threat) in top:
        label = f"Jev {score:.2f} • " if score is not None else ""
        if threat is not None: label = f"Jev {score:.2f} [{threat.replace('_', ' ')}] • "
        line = f"• {label}sev {level} `{rule}` x{count} on {len(agents)} agent{'s' if len(agents) != 1 else ''}: {description}"
        recurring_lines.append(line if len(line) <= _COMPACT_LIMIT else line[:_COMPACT_LIMIT - 3] + "...")
    recurring_head = (f"__Recurring — {len(recurring)} groups across {len(rules)} rules, "
                      f"{sum(fields['count'] for _, fields, _ in recurring)} events__")

    flagged_lines = []
    arrivals: dict[str, list] = {}
    for category, fields, _ in message_flagged:
        if category == "NEW AGENT":
            agent = arrivals.setdefault(fields["identity"], [fields["level"], 0, 0])
            agent[0], agent[1], agent[2] = max(agent[0], fields["level"]), agent[1] + 1, agent[2] + fields["count"]
    arrivals_shown: set[str] = set()
    for category, fields, _ in message_flagged:
        if category == "NEW AGENT":
            identity = fields["identity"]
            if identity in arrivals_shown:
                continue
            arrivals_shown.add(identity)
            level, groups, count = arrivals[identity]
            line = (f"• **NEW AGENT** {identity} — {groups} group{'s' if groups != 1 else ''}, {count} events, "
                    f"highest sev {level}; every group is in the attachment")
            flagged_lines.append(line if len(line) <= _COMPACT_LIMIT else line[:_COMPACT_LIMIT - 3] + "...")
            continue
        label = f" Jev {fields['attention']:.2f}" if fields["attention"] is not None else ""
        if fields["threat"] is not None: label += f" [{fields['threat'].replace('_', ' ')}]"
        line = f"• **{category}**{label} sev {fields['level']} `{fields['rule']}` x{fields['count']} — {fields['identity']}: {fields['description']}"
        flagged_lines.append(line if len(line) <= _COMPACT_LIMIT else line[:_COMPACT_LIMIT - 3] + "...")
    # Page 1 always keeps the header, the recurring total, the footer and room for an omission
    # line; flagged items fill what is left and the rest continue on bounded pages.
    fixed = len(header) + len(recurring_head) + len(footer) + _OMISSION_RESERVE + len("\n\n") * 4
    flagged_head = (f"__Needs a look — {len(flagged)} groups, {len(flagged_lines)} message lines__"
                    if flagged else "__Needs a look — nothing new, spiking or critical__")
    shown: list[str] = []
    for line in flagged_lines:
        if fixed + len(flagged_head) + len("\n") + len("\n".join([*shown, line])) > _CONTENT_LIMIT: break
        shown.append(line)
    pages, omitted = _continuations(flagged_lines[len(shown):])
    if len(shown) < len(flagged_lines):
        flagged_head += f" (continued on {len(pages)} more message{'s' if len(pages) != 1 else ''})" if pages else ""
    tops: list[str] = []
    base = fixed + len(flagged_head) + len("\n".join(shown)) + len("\n")
    for line in recurring_lines if len(shown) == len(flagged_lines) else []:
        if base + len("\n".join([*tops, line])) + len("\n") > _CONTENT_LIMIT: break
        tops.append(line)
    if omitted:
        header += f"\n[health review] Groups omitted from the messages: {omitted} (listed in the attachment)."
    sections = [header, "\n".join([flagged_head, *shown]) if shown else flagged_head,
                "\n".join([recurring_head, *tops]) if recurring else "__Recurring — none__", footer]
    content = "\n\n".join(sections)
    truncated = bool(omitted or attachment_omitted)
    if len(content) > _CONTENT_LIMIT:
        # Unreachable while the reserve holds; fails loudly in the safe direction.
        notice = "\n\n[health review] bounded message truncated."
        content, truncated = content[:_CONTENT_LIMIT - len(notice)] + notice, True
    payloads = tuple({"content": body, "allowed_mentions": {"parse": []}} for body in (content, *pages))
    for payload in payloads:
        if len(json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode()) > _PAYLOAD_LIMIT:
            raise RendererError("rendered payload exceeds limit")
    if len(json.dumps(text)) - 2 > ATTACHMENT_LIMIT:
        raise RendererError("rendered attachment exceeds limit")
    return RenderedReport(payloads, truncated, omitted + attachment_omitted, text)


@dataclass(frozen=True)
class DiscordConfig:
    webhook_file: Path
    timeout_seconds: int = 20
    max_attempts: int = 3
    def __post_init__(self) -> None:
        if type(self.timeout_seconds) is not int or not 1 <= self.timeout_seconds <= 60 or type(self.max_attempts) is not int or not 1 <= self.max_attempts <= 3:
            raise ValueError("invalid delivery limits")
    @classmethod
    def from_environment(cls, env: Mapping[str, str] | None = None) -> DiscordConfig:
        env = os.environ if env is None else env
        try:
            value = env["DISCORD_WEBHOOK_URL_FILE"]
            if not value: raise ValueError
            return cls(Path(value))
        except (KeyError, TypeError, ValueError):
            raise DeliveryError("Discord webhook configuration is invalid") from None
    def webhook_url(self) -> str:
        try:
            value, parsed = read_secret(self.webhook_file), None
            parsed = urlsplit(value)
            valid = (parsed.scheme == "https" and parsed.hostname in {"discord.com", "discordapp.com"} and parsed.username is None and parsed.password is None and not parsed.query and not parsed.fragment and _WEBHOOK_PATH.fullmatch(parsed.path) is not None)
        except (CollectorError, ValueError, TypeError, AttributeError): valid = False
        if not valid: raise DeliveryError("Discord webhook configuration is invalid")
        return value


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        fp.close(); raise DeliveryError("Discord redirect refused")


class DiscordDelivery:
    def __init__(self, config: DiscordConfig, opener: Any = None, sleep: Callable[[float], None] = time.sleep):
        self._config, self._opener, self._sleep = config, opener or build_opener(ProxyHandler({}), _NoRedirect(), HTTPSHandler()), sleep
    def send(self, rendered: RenderedReport) -> None:
        if type(rendered) is not RenderedReport or not rendered.payloads: raise DeliveryError("invalid rendered report")
        if rendered.attachment is not None and (type(rendered.attachment) is not str
                                                or len(json.dumps(rendered.attachment)) - 2 > ATTACHMENT_LIMIT):
            raise DeliveryError("invalid rendered report")
        url = self._config.webhook_url()
        for index, payload in enumerate(rendered.payloads):
            self._post(url, payload, attachment=rendered.attachment if index == 0 else None)
    def verify(self) -> None:
        """Send one fixed synthetic payload; invoke only after explicit approval."""
        self._post(self._config.webhook_url(), {"content": "Soc Thief delivery verification: synthetic payload only.", "allowed_mentions": {"parse": []}}, attempts=1)
    def _post(self, url: str, payload: object, attempts: int | None = None, attachment: str | None = None) -> None:
        attempts = self._config.max_attempts if attempts is None else attempts
        try:
            raw = json.dumps(payload, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode()
            if len(raw) > _PAYLOAD_LIMIT: raise ValueError
            body, kind = raw, "application/json"
            if attachment is not None:
                body, kind = _multipart(payload, attachment)
            for attempt in range(attempts):
                delay = 1 + attempt
                try:
                    request = Request(url, body, {"Content-Type": kind, "Accept": "application/json", "User-Agent": _USER_AGENT}, method="POST")
                    with self._opener.open(request, timeout=self._config.timeout_seconds) as response:
                        if getattr(response, "status", response.getcode()) in (200, 204): return
                        raise HTTPError(url, getattr(response, "status", 500), "", response.headers, None)
                except HTTPError as error:
                    # The error owns the response body and its connection; code and headers
                    # stay readable after close, and nothing here reads the body.
                    error.close()
                    if error.code not in (429, 500, 502, 503, 504) or attempt + 1 == attempts: raise
                    if error.code == 429:
                        # Discord publishes a retry delay for webhook throttling. Accept only
                        # a bounded numeric header; a long/invalid wait leaves the durable
                        # outbox pending instead of blocking a daily worker indefinitely.
                        value = error.headers.get("Retry-After") if error.headers is not None else None
                        if value is not None:
                            try:
                                delay = float(value)
                            except (TypeError, ValueError):
                                raise ValueError from None
                            if not math.isfinite(delay) or not 0 <= delay <= 30:
                                raise ValueError
                except (URLError, TimeoutError, socket.timeout, HTTPException, OSError):
                    if attempt + 1 == attempts: raise
                self._sleep(delay)
            raise ValueError
        except (HTTPError, URLError, TimeoutError, socket.timeout, HTTPException, OSError, ValueError, TypeError):
            raise DeliveryError("Discord delivery failed") from None


def _multipart(payload: object, attachment: str) -> tuple[bytes, str]:
    """Discord's webhook file upload: payload_json plus one plain-text file, no other parts."""
    if type(payload) is not dict:
        raise ValueError
    described = {**payload, "attachments": [{"id": 0, "filename": ATTACHMENT_NAME}]}
    raw = json.dumps(described, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode()
    data = attachment.encode("utf-8")
    if len(raw) > _PAYLOAD_LIMIT or len(data) > ATTACHMENT_LIMIT:
        raise ValueError
    boundary = "soc-thief-" + os.urandom(16).hex()
    if boundary.encode() in raw or boundary.encode() in data:
        raise ValueError  # 128 random bits; refuse rather than emit an ambiguous body.
    body = b"".join((
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"payload_json\"\r\n"
        "Content-Type: application/json\r\n\r\n".encode(), raw,
        f"\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"files[0]\"; "
        f"filename=\"{ATTACHMENT_NAME}\"\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n".encode(), data,
        f"\r\n--{boundary}--\r\n".encode()))
    return body, f"multipart/form-data; boundary={boundary}"
