"""Propose deterministic operator tuning entries from measured base rates.

This module does not suppress anything and does not move the delivery boundary in
``policy.py``. It only *proposes* tuning entries, shaped exactly like the operator tuning
file, for a human to review and install (or not) through the existing manual workflow
described in ``docs/TUNING.md``. ``propose`` is a pure function: no I/O, no network,
no model call. It is the caller's responsibility never to write a proposal to the live
tuning path and never to install one automatically.

Safety invariant: every row is first checked with ``soc_thief.profile.tunable``, which reuses
``policy.preflight`` unmodified. That is what keeps protected groups, level 12+ groups, and
malformed/incomplete rows out of every proposal, by construction and without reimplementing
that logic here. ``NEVER_PROPOSE`` is a second, narrower exclusion, covering classes that gate
provably misses; see its own comment.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from soc_thief.profile import tunable
from soc_thief.tuning import MAX_ENTRIES

# Measured against a real 99-day noise profile from one deployment: a
# minimum-history threshold of >=30 days of history reaches 62.3% of an expected ~120-group
# day; 45d -> 51.2%, 60d -> 49.1%, 70d -> 43.0%, 77d -> only 26.0%, 90d -> 10.7%. Coverage
# falls off well before 77 days, so 30 is the defensible default.
MIN_HISTORY_DAYS = 30

# A group must also have fired on at least this fraction of the profiled window's days, not
# merely be old enough. Absolute history alone would accept a group that was active for its
# first month and has since gone quiet, or one that has just crossed MIN_HISTORY_DAYS in
# wall-clock age on the strength of a handful of days. Both thresholds are required together.
MIN_COVERAGE = 0.5

# Level 6 and above is only ever downgraded to "low", never muted, regardless of history.
MUTE_MAX_LEVEL = 5

# Every proposal expires and must be re-earned by a fresh noise profile; nothing proposed
# here is permanent.
PROPOSAL_EXPIRY_DAYS = 30

# Rule identifiers this module never proposes, whatever their base rate.
#
# Frequency finds what is *normal*; it cannot find what is *important*, and the deterministic
# gate that should separate the two misses these classes on a word boundary:
# ``policy._PROTECTED`` matches "logon" but not logoff, "rootkit" but not rootcheck,
# "collection" but not collected, and carries no vocabulary at all for account management,
# removable devices, promiscuous mode, or agent telemetry health. Every rule below was
# measured as genuine background in a real deployment - that is
# precisely why a base-rate proposer picked it - and every one is also the shape a real
# incident takes. Agent disconnection is the clearest: a deliberately disabled agent looks
# exactly like ordinary background.
#
# This list constrains only what is proposed *automatically*. It is not a protected category:
# an operator who decides one of these is noise here can still write the entry by hand, which
# is why it lives here rather than in ``policy._PROTECTED``. Widening the protected vocabulary
# instead would have made 101 of 844 measured groups permanently untunable by anyone.
#
# **Seeded from evidence, not exhaustive.** These are the rules that carry these classes in
# one real 108-day profile. A rule in the same class that has never fired here is not listed
# and would still be proposed, so a proposal review remains a per-entry security read.
NEVER_PROPOSE = frozenset({
    "503", "504", "506",       # Wazuh agent started / disconnected / stopped: telemetry health
    "510",                     # rootcheck host-based anomaly detection
    "60109", "60110", "60111",  # Windows account enabled-or-created / changed / disabled-or-deleted
    "60137", "67023",          # Windows user logoff; non-service-account logoff
    "60227", "81101", "81102",  # new external device; USB storage attached / disconnected
    "80710",                   # auditd: device enables promiscuous mode
    "91820",                   # PowerShell recursive file collection from a filesystem search
})


@dataclass(frozen=True)
class Proposal:
    """One candidate tuning entry, not yet reviewed, not yet installed."""

    rule_id: str
    action: str
    agent_id: str | None
    expires: datetime
    note: str


def _note(days_active: int, window_days: int, events: int) -> str:
    """Build the evidence note from validated numeric fields only.

    Deliberately excludes rule descriptions, agent names, or any other free text: the note
    is discarded by ``tuning.py`` regardless, but nothing untrusted is assembled into it in
    the first place, so there is nothing to escape.
    """
    share = days_active / window_days if window_days else 0.0
    return f"baseline: active {days_active}/{window_days} days ({share:.0%}), {events} events"[:200]


def propose(rows: list[dict[str, Any]], *, end: datetime, window_days: int,
            min_history_days: int = MIN_HISTORY_DAYS,
            never_propose: frozenset[str] = NEVER_PROPOSE) -> tuple[Proposal, ...]:
    """Propose tuning entries for groups that look like this environment's background noise.

    ``rows`` are noise-profile group rows in the shape ``profile.render_report`` consumes.
    A row is proposed only if ``profile.tunable`` says "yes" (protected, level 12+, and
    incomplete/missing-description rows are excluded by that gate, not by this function),
    only if its rule is not in ``never_propose``, and only if it has both enough absolute
    history and enough coverage of the profiled window. Deferred: this does not and cannot
    detect a volume *change* on an already-established noisy rule, because the profile's
    per-day counts are discarded before this function ever sees a row (see
    docs/TUNING.md).
    """
    if type(window_days) is not int or window_days <= 0:
        raise ValueError("window_days must be a positive integer")
    if type(min_history_days) is not int or min_history_days < 0:
        raise ValueError("min_history_days must be a non-negative integer")
    if type(never_propose) is not frozenset or not all(type(r) is str for r in never_propose):
        raise ValueError("never_propose must be a frozenset of rule identifiers")
    coverage_threshold = window_days * MIN_COVERAGE
    expires = end.astimezone(timezone.utc) + timedelta(days=PROPOSAL_EXPIRY_DAYS)

    eligible = []
    for row in rows:
        if tunable(row, end) != "yes":
            continue
        # Checked after the tunable() gate so a malformed row still fails there first.
        if row["rule_id"] in never_propose:
            continue
        days_active = row["days_active"]
        if days_active < min_history_days or days_active < coverage_threshold:
            continue
        eligible.append(row)

    # Deterministic order, largest volume first, mirroring the noise profile's own ranking;
    # this decides which groups survive the MAX_ENTRIES cap, not just display order.
    eligible.sort(key=lambda r: (-r["events"], r["rule_id"], r["agent_id"]))

    proposals = []
    for row in eligible[:MAX_ENTRIES]:
        action = "mute" if row["max_level"] <= MUTE_MAX_LEVEL else "low"
        note = _note(row["days_active"], window_days, row["events"])
        proposals.append(Proposal(row["rule_id"], action, row["agent_id"], expires, note))
    return tuple(proposals)


def serialize(proposals: tuple[Proposal, ...]) -> dict[str, Any]:
    """Render proposals as a tuning-file-shaped document that ``tuning.load_tuning`` accepts."""
    entries = []
    for proposal in proposals:
        if type(proposal) is not Proposal:
            raise ValueError("proposal is malformed")
        entry: dict[str, Any] = {
            "rule_id": proposal.rule_id,
            "action": proposal.action,
            "expires": proposal.expires.isoformat(),
            "note": proposal.note,
        }
        if proposal.agent_id is not None:
            entry["agent_id"] = proposal.agent_id
        entries.append(entry)
    return {"version": 1, "entries": entries}
