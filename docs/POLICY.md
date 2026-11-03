# Triage policy

This document describes how Soc Thief turns alerts into groups, which groups must be delivered,
what the model may do, and how the daily digest is built. The code is in `src/soc_thief/policy.py`,
`src/soc_thief/runner.py` and `src/soc_thief/delivery.py`.

## Input

The collector accepts only these Wazuh fields:

- `@timestamp`, `rule.id`, `rule.level`, `rule.description`, `agent.id`, `agent.name`,
  `decoder.name`, `manager.name` and `location`;
- `_index` and `_id`, used only as the deduplication key;
- `rule.groups`, `data.srcip`, `syscheck.path`, `syscheck.event` and
  `syscheck.changed_attributes`, read only by the breach signals and then dropped. They never
  enter a group, so they never reach the model, the state database or Discord.

Raw event documents, command lines, process arguments, credentials, tokens and private keys never
enter a group, prompt, log, state record or report.

## Grouping

A group key combines the rule ID, the agent ID, every label (rule description, agent name, decoder
name, manager name, location) and the report window. A group holds its earliest timestamp, its
event count, its highest rule level and the allowlisted labels. Groups are sorted by identity, so
source order does not matter.

The report window runs from 08:00 to 08:00 in the zone set by `SOC_THIEF_TIMEZONE` (an IANA
name such as `Europe/London`; the default is UTC). The window and the audit token both use the
window's start, so a window never splits at local or UTC midnight. Across a daylight-saving change
the window is 23 or 25 hours long.

Some rules put a changing value in the description, so one rule on one agent can produce many
description variants. When one rule, agent and label set has more than 50 ordinary description
variants, they become one labelled summary group with the total count, the highest level, the
earliest time and the number of variants. Protected, critical, breach and invalid variants always
stay as their own groups. A summary is delivered without model review, because no single
description represents it. Tuning still applies to it by rule and agent.

Hard limits: 50,000 raw group shapes and 2,000 groups after summarising. Going over either fails
the window closed.

## Delivery-required groups

`policy.preflight()` runs before any model call. It requires delivery when any of these is true:

- the collector, state store, model, renderer or delivery path failed;
- the group's rule level is 12 or higher;
- the normalised description matches the protected vocabulary: authentication or login terms,
  brute force, password spraying, malware, ransomware, trojan, rootkit, virus, worm, privilege,
  escalation, sudo, setuid, credential, password, collection, exfiltration, data theft, keylogging,
  and instruction-override phrases such as "ignore previous instructions" or "suppress alerts";
- the group is malformed or incomplete.

The match uses NFKC normalisation, case folding and punctuation separation. The vocabulary is
deliberately broad and favours review. It is a safety net on top of Wazuh severity, not a complete
detector for every synonym, language or obfuscation.

A group carrying a breach signal (see [DETECTION.md](DETECTION.md)) is delivered with the reason
`breach_<signal>`, before tuning or the model, and is never folded into a description summary.

## The model cannot suppress

Only an ordinary, schema-valid group that no tuning entry covers goes to the model. The model
returns a strict JSON object with exactly four keys:

| Key | Type |
| --- | --- |
| `classification` | `benign`, `suspicious` or `unknown` |
| `confidence` | a finite number from 0 to 1 |
| `rationale` | plain text, at most 512 characters |
| `analyst_action` | plain text, at most 256 characters |

Every valid answer means the group is delivered for your review. An invalid answer, a timeout or
a connection failure means the group is delivered with `invalid_model_result` and a health
failure. A model failure affects only that group; the rest of the window carries on.

An earlier version suppressed `benign` answers at confidence 0.98 or above. Measurement removed
it. On real alert groups `qwen3:4b` only ever returned 0.95 or 0.85, so the gate could never
fire, and the number did not move when the model's own verdict flipped between identical
requests at temperature 0. Lowering the threshold would suppress on a number that carries no
information. Gating on the classification alone fails the same way, because the classification
is not stable either. Removing the gate also closed a hidden risk: a model that happened to emit
0.99 would have started suppressing alerts with no calibration behind it.

Model prose is never rendered, logged or stored. The only thing kept is the model's reported
identity (for example `qwen3:4b`), on the audit row of a group that went to the model.

## False-positive categories

"False positive" is an analyst's explanation after review. It is never a policy permission. When
you review a group that turned out to be harmless, it fits one of these:

- `expected_activity`: it happened and was authorised, such as a scheduled integrity check;
- `environmental_noise`: it happened, and the rule is predictably noisy in your environment;
- `duplicate_signal`: another group already represents the same activity;
- `rule_mismatch`: the rule fired as written, but its premise does not match what happened;
- `insufficient_context`: the evidence cannot tell benign from malicious.

`insufficient_context` always stays delivery-required. The others can justify a tuning entry you
write after repeated review. The model is never allowed to send one of these as a command.
Duplicate events are removed only by exact source identity (`_index` plus `_id`). Similar text, a
repeat or a model claim never removes evidence.

## Escalation

Escalation means inclusion in your report or a page. Soc Thief never runs a response action.

- A pipeline, schema, ordering, replay, rendering, state, model or delivery failure is delivered
  with a health failure. The window is not quietly accepted.
- Critical and protected groups are delivered whatever the model says and whatever the tuning
  file says, with a fixed reason code.
- Every valid model answer, at any confidence, is delivered without being labelled a failure.
- Tuning (`mute`, `low`) is the only suppressor. It is deterministic, audited, and never applies
  to a protected or critical group. Suppression is an audit outcome. Evidence in Wazuh is never
  deleted.

You decide every investigation, containment step, rule change and tuning entry.

## The policy functions

`policy.py` is pure: no model calls, network, storage or delivery.

- `preflight(group, failures=())` runs before inference. `model_review_required` permits a model
  call; it is not permission to suppress.
- `tuned(group, action, failures=())` applies a tuning action to a group preflight would send to
  the model.
- `decide(group, model=None, failures=())` is the final gate. Calling it with no model result is
  how the runner handles a model failure.

The group contract: required `timestamp`, `rule_id`, `rule_level`, `rule_description`, `agent_id`
and `count`; optional `agent_name`, `decoder_name`, `manager_name` and `location`. Unknown fields
fail closed. The timestamp must carry a timezone, the level must be an integer from 0 to 16 and the
count a positive integer. Descriptions are capped at 2,048 characters and other text at 256. Empty
text or control characters make the group invalid.

Callers pass every known pipeline failure in `failures`. A non-empty tuple requires delivery and
sets `health_failure`. A decision carries only booleans and a fixed reason code, never input text.

## The daily digest

The renderer sorts delivery-required groups into sections, compared against a 30-day baseline:

| Section | Meaning |
| --- | --- |
| `FAILED` | A group or boundary that failed. Always itemised on the message. |
| `BREACH <signal>` | A breach signal. One line per group, always on the message. |
| `CRITICAL` | Level 12 or higher. The message shows a count and three examples. |
| `NEW AGENT` | A new group from an agent absent from the whole baseline. The message shows one line per such agent. |
| `NEW` | This rule has not fired on this agent in the baseline. |
| `SPIKE` | At least 10 events and more than 3 times its usual daily count. |
| recurring | Everything else, shown as a total. |

Every delivery-required group, including every critical group, has its own line in the attached
`soc-thief-report.txt`. The message is a summary; the attachment is complete. If the baseline query
fails, the digest falls back to listing everything and reports a health failure.

Tuned groups appear only as one count line:
`Low priority: N events in M groups. Muted: K events in J groups.` Tuned noise alone never sends a
message.

A busy day spills onto continuation messages, up to `delivery.MAX_PAGES` (24). A group that fits on
no page is counted in a `[health review]` line on page 1 and raises a health failure, so a run that
delivered part of a day never reports the same status as one that delivered all of it. Lowering
`MAX_PAGES` trades messages for omissions. `state.OUTBOX_PAYLOAD_LIMIT` must stay large enough to
hold `MAX_PAGES` pages plus the attachment, or a wide day would commit nothing; a test in
`tests/test_state.py` checks this.

## The Discord boundary

The renderer accepts only delivery-required groups and fixed accounting fields. It disables
Discord mentions, escapes formatting, masks IP addresses, URLs and obvious secret assignments, and
caps message text and payload size. Continuation lines get the same escaping and masking.

The webhook URL comes only from `DISCORD_WEBHOOK_URL_FILE` and must be an HTTPS `discord.com` or
`discordapp.com` webhook. Delivery ignores proxy environment variables, refuses redirects, accepts
only success responses and retries a bounded number of transient failures. Discord rejects
Python's default User-Agent, so Soc Thief sends a fixed `SocThief/<version>` header.

To test a webhook once, run `python -m soc_thief.delivery_verify`. It reads only
`DISCORD_WEBHOOK_URL_FILE`, sends one fixed synthetic message and prints a fixed status line.

## Late alerts, reconcile and backfill

A point-in-time snapshot does not include alerts indexed after it was taken. The daily run waits
15 minutes past the window end before collecting. The reconcile pass
(`python -m soc_thief.runner --reconcile`) collects the day before the most recent closed day
again, after the daily stream has committed it, and triages only events not already in state.
Alerts indexed after that second pass are never triaged.

The historical backfill (`python -m soc_thief.backfill --from YYYY-MM-DD`) processes at most one
day per run on its own `backfill` stream, oldest first, from the date you give up to the daily
stream's first window. The ranges never overlap, and the start date cannot change once the
backfill has begun. It uses the same grouping, policy, model and delivery as the daily run, so it
sends at most one report per historical day. It defers during two quiet periods around the daily
and reconcile runs so it never contends for the state lock.

## Retention

Wazuh is the source of record. Soc Thief stores no raw alerts. Assessment audit rows are pruned
after seven days. Deduplication tokens, replay hashes and checkpoints are kept so old events are
not processed twice. See [STATE_STORE.md](STATE_STORE.md).

## Test corpus

Tests use only synthetic fixtures in `tests/fixtures/`. The acceptance corpus covers:

- repeated low-severity groups that the model calls benign;
- each delivery-required category, which must deliver whatever the model says;
- prompt-injection text in an otherwise low-risk description;
- malformed, timed-out and unavailable model responses;
- collector, state, renderer and delivery failures;
- duplicate, out-of-order and replayed groups.

Every case expects `deliver`. A test asserts that `suppressible` never appears as a model-review
outcome. Tuning suppression is tested separately in `tests/test_tuning.py`.
