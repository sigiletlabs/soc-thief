# Tuning

Tuning is how you quiet alerts you have decided are noise in your environment. It is the only way
anything is suppressed in Soc Thief, and you write every entry yourself. A model never tunes.

The workflow is the one a SOC uses for a noisy feed:

1. Profile the noise with `soc_thief.profile`.
2. Write a few tuning entries, or review the ones the proposer suggests.
3. Read the daily digests, review cases, and repeat.

## The tuning file

The runner reads the file named by `SOC_THIEF_TUNING_FILE`. In the systemd deployment it is the
`tuning` credential at `/etc/soc-thief/secrets/tuning`. Start with an empty file:

```json
{"version": 1, "entries": []}
```

An entry:

```json
{"rule_id": "591", "agent_id": "004", "action": "mute", "note": "log rotation"}
```

| Key | Required | Meaning |
| --- | --- | --- |
| `rule_id` | yes | Wazuh rule ID |
| `action` | yes | `mute` or `low` |
| `agent_id` | no | Limit the entry to one agent. Absent means every agent. |
| `expires` | no | UTC timestamp after which the entry stops applying. Absent means it never expires. |
| `note` | no | Up to 200 characters for you. Validated, then discarded: never rendered, logged, sent to a model or stored. |

An entry for a rule and agent takes precedence over a rule-only entry.

The loader rejects duplicate keys, unknown keys, non-finite numbers, duplicate `(rule_id,
agent_id)` pairs, more than 2,000 entries, files over 256 KiB, symlinks, and files readable or
writable by group or other. An unset variable means no tuning. A missing, unsafe or invalid file
means no tuning for that window plus one health failure. An error can never add suppression.

### What tuning can and cannot do

Tuning runs after preflight, and only for groups preflight would send to the model. Protected
groups, groups at level 12 or higher, breach groups, invalid groups and failed groups ignore
tuning completely.

A tuned group skips the model and is not itemised. It appears only in one count line:
`Low priority: N events in M groups. Muted: K events in J groups.` The audit reasons are
`tuned_mute` and `tuned_low`.

`mute` and `low` have the same effect today. Both keep the group out of the itemised report.
Do not treat `low` as the safer choice.

## Profiling the noise

The noise profile is a read-only aggregation. It uses no model and sends nothing.

```sh
PYTHONPATH=src python3 -m soc_thief.profile \
  --start 2026-01-01T08:00:00Z --end 2026-03-01T08:00:00Z \
  --output ~/soc-thief-private/profile.md
```

It needs the indexer `*_FILE` settings (see [COLLECTOR.md](COLLECTOR.md)), a closed window of at
most 120 days, and an output path that does not exist yet, inside a directory you own that has no
group or other write access. The report is created with mode `0600`. Standard output carries only
a fixed status with totals.

Exit codes: `0` written, `1` failure, `2` invalid arguments or output path, `3` the 180-second
deadline expired.

The report ranks `(rule_id, agent_id)` pairs by event count, with share, cumulative share, days
active, highest level, escaped labels and a `tunable` column:

- `no (protected)`: level 12 or higher, or the protected vocabulary matched;
- `no (review)`: the description is missing, mixed or invalid;
- `yes`: you may tune it.

"Top candidates" lists tunable pairs up to 80% of volume, for you to review. They are not
recommendations to mute. The report contains host names and rule text. Keep it private and delete
it when you are done.

## Proposed entries

Add `--propose-tuning` to have the profile suggest entries from measured base rates:

```sh
PYTHONPATH=src python3 -m soc_thief.profile \
  --start 2026-01-01T08:00:00Z --end 2026-04-01T08:00:00Z \
  --output ~/soc-thief-private/profile.md \
  --propose-tuning ~/soc-thief-private/proposed-tuning.json
```

The proposal file has the same shape as the tuning file. Nothing installs it. You review each
entry and copy the ones you accept into your tuning file.

How `soc_thief.baseline` chooses:

- Only rows the profile marks `tunable: yes` are considered. Protected and level 12+ groups are
  never proposed.
- A row must have been active on at least 30 days (`MIN_HISTORY_DAYS`) and on at least half the
  days in the profiled window (`MIN_COVERAGE = 0.5`). A rule that only just reached 30 days, or one
  that was busy for a month and then went quiet, fails one of the two.
- Level 5 and below is proposed as `mute`; level 6 and above as `low`.
- Every proposal has an `expires` 30 days after the window end and a `note` built only from
  numbers (days active, window days, share, events). No alert text goes into the file.
- Rules in `baseline.NEVER_PROPOSE` are never proposed, whatever their rate.

The 30-day floor is a trade-off. A longer history requirement looks safer, but on a real
multi-month profile the share of a day's groups it could cover fell steeply past 30 days. Some
groups (protected, or with unusable descriptions) can never be proposed at any threshold.

### NEVER_PROPOSE

Frequency finds what is normal. It never finds what is important. The protected vocabulary works
on word boundaries, so it catches `logon` but not "logoff", `rootkit` but not "rootcheck",
`collection` but not "collected", and has no words at all for account management, removable
devices, promiscuous mode or agent health. `baseline.NEVER_PROPOSE` lists rule IDs in those
classes so the proposer skips them:

- agent health (started, disconnected, stopped);
- rootcheck host anomalies;
- Windows account management;
- logoff;
- new external devices and USB storage;
- promiscuous mode;
- PowerShell recursive file collection.

It is not a protected category. You can still write an entry for one of these rules by hand if
you decide it is noise in your environment. The list was seeded from rules seen in one real
environment and is not complete. A rule in one of these classes that never fired there is not on
it. Review every proposal as a security decision, check what it would silence, and add a rule to
`NEVER_PROPOSE` when you find another one.

### A known blind spot

The proposer cannot see a change in volume. A rule that ran at 5 events a day for 60 days and
then jumps to 50,000 still passes both thresholds. The profile computes daily counts and then
keeps only the number of active days. Hand-written tuning has the same blind spot. The tuning
watch below covers it for entries that are already installed. When you review a proposal, look at
the profile's event totals as well as the history columns.

## The tuning watch

Entries without `expires` stay forever, so a muted rule stays muted whatever it later does. The
daily runner therefore compares every tuned (rule, agent) pair with its 30-day baseline before
tuning drops it (`src/soc_thief/tuning_watch.py`).

A pair is a finding when either is true:

- it has at least 50 events (`PAGE_MIN_EVENTS`) and at least 10 times (`PAGE_RATIO`) its usual
  daily count on active days;
- it has no baseline at all (a new agent, or a rule that never fired there) and at least 5 events
  (`NEW_MIN_EVENTS`).

These are stricter than the digest's `SPIKE` flag on purpose, because a finding pages a person.

A finding is delivered in the digest despite tuning, with the audit reason `tuned_spike`, and
paged through ntfy (`SOC_THIEF_NTFY_FILE`, the same route as the fast path). The page has a fixed
title, the tuning action, the agent ID, the count against the baseline and the opaque case ID. It
has no rule description and no host name. A pair pages at most once every 7 days but is delivered
every day it spikes. More than 10 findings in a window become one summary page. Only the daily
run pages; reconcile and backfill do not.

If ntfy is not configured, or the page fails, the group is still delivered, with audit reason
`tuned_spike_unpaged` and a health failure.

### Stale entries

```sh
PYTHONPATH=src python3 -m soc_thief.tuning_watch --output ~/soc-thief-private/stale.md
```

This profiles the last 90 days and lists tuning entries whose rule (and agent, if named) produced
no events. It prints rule ID, agent ID and action only. It never edits your tuning file. Run it
with the indexer `*_FILE` settings and `SOC_THIEF_TUNING_FILE` set.

## Case review

Each delivered (rule, agent) pair gets a stable opaque case ID in the state store. The digest
attachment shows that ID and the pair's **prior** verdict, and the message counts groups you
previously marked routine. A verdict never changes delivery: reviewed groups are still delivered.

Run the case tool as the account that owns the state directory, outside the daily run:

```sh
sudo -u soc-thief env PYTHONPATH=/opt/soc-thief/src python3 -m soc_thief.cases \
  --state /var/lib/soc-thief/state list
sudo -u soc-thief env PYTHONPATH=/opt/soc-thief/src python3 -m soc_thief.cases \
  --state /var/lib/soc-thief/state mark CASE_ID routine
```

Verdicts are `review` (needs attention), `routine` (investigated and accepted) and `uncertain`.
Check the source alert in Wazuh before you mark a case. `list` shows IDs, rule and agent IDs,
status and last-seen date, never alert content. The tool takes the same non-blocking state lock as
the runner; if it reports an error, try again after the running window finishes. For a read-only
brief on a case before you mark it, see [INVESTIGATION.md](INVESTIGATION.md).

To export candidate tuning entries from your verdicts:

```sh
sudo -u soc-thief env PYTHONPATH=/opt/soc-thief/src python3 -m soc_thief.cases \
  --state /var/lib/soc-thief/state propose \
  --output /var/lib/soc-thief/candidate-tuning.json
```

The output must be a new file. It is created with mode `0600` and the runner never loads it. It
proposes only agent-specific `low` entries for current `routine` verdicts on groups that never hit
the protected or critical gate in the retained history, and it skips `NEVER_PROPOSE` rules. Each
entry expires 30 days after export.

Case records last 90 days after the group was last seen. A `routine` verdict stops being shown or
proposed after 30 days unless you mark it again. No free-text notes are stored; keep your
investigation notes in Wazuh or your own case system.
