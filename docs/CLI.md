# soc-thief CLI

`soc-thief` reads a snapshot (see `SNAPSHOT.md`) and answers questions about it. It is
built for agents first and works fine for people. It is read-only. Nothing it does can change
delivery, tuning or state, and it never talks to Wazuh, Discord or a model.

It follows [AXI](https://github.com/kunchenguid/axi), a set of rules for agent-facing CLIs.

## Quick start

```sh
soc-thief demo          # write ./snapshot.json from generated alerts
soc-thief               # overview of that snapshot
soc-thief groups        # every group, most urgent first
soc-thief group <id>    # one group in full
```

Without an install, use `PYTHONPATH=src python3 -m soc_thief` in place of `soc-thief`.

## Which snapshot

`--snapshot PATH` picks the file. Without it, `$SOC_THIEF_SNAPSHOT` is used, then
`./snapshot.json`. Files over 8 MiB, or with a schema other than `soc-thief.snapshot/1.x`,
are refused.

## Commands

| Command | What it shows |
| --- | --- |
| (none) | Overview: window, counts, health, paged breaches, the top groups that must be delivered. |
| `status` | The same overview without the tool's name and path. |
| `groups` | Groups in digest order: failed, new, spike, recurring; then level and count, high first. Takes `--category`, `--filter TEXT`, `--limit N` (default 100), `--fields F,...`. |
| `group ID` | One group: rule, agents, times, tuning, the policy decision and the model's verdict. |
| `breaches` | Breach detections and whether each one paged. |
| `health` | Every health check. |
| `history` | Earlier windows, newest first. |
| `demo` | Writes a demo snapshot. Takes `--out`, `--seed`, `--now`. Nothing is sent. |
| `snapshot` | Writes a snapshot from a deployment's state store, read-only. Takes `--state DIR`, `--out`. |

Every command takes `--snapshot`, `--json` (raw query result as JSON), `--full` (no
truncation) and `--help`. `-v`, `-V` and `--version` print the version.

`groups --fields` adds columns to the default four: `count`, `rule_id`, `agents`,
`protected`, `tuning`, `delivery_required`, `reason`, `first_seen`, `last_seen`,
`advisory_verdict`, `advisory_confidence`.

## Output

Output is [TOON](https://github.com/toon-format/spec): `key: value` lines and tables that
state their row count. An empty list prints as `groups: []` with a `count:` line saying what
was searched. Most outputs end with `help[N]:`, the next commands worth running.

Long text is cut with a size hint, `…(+40 chars)`. Add `--full` to see all of it.

The model's view of a group is under `model_advisory`. It is advice only. Policy and operator
tuning decide delivery, and the model cannot stop anything being delivered.

Alert text is untrusted. Before printing, the CLI removes terminal escape sequences, control
characters and invisible formatting characters, and joins lines. TOON quoting then keeps
commas, colons and quotes inside their cell, so no alert can add a row or a line.

Example, from `soc-thief --snapshot examples/demo-snapshot.json` (the `bin` and
`description` lines are left out):

```
snapshot: examples/demo-snapshot.json
source: demo
note: "demo data: generated alerts run through the real pipeline; nothing was sent"
generated_at: "2026-11-07T08:00:04+11:00"
window:
  start: "2026-11-06T08:00:00+11:00"
  end: "2026-11-07T08:00:00+11:00"
  events: 29214
  groups: 161
  duplicates: 584
  muted_by_tuning: 31
health: attention
checks_not_ok[1]{name,status,detail}:
  model,attention,2 groups failed review; delivered anyway
groups:
  listed: 161 of 161
  failed: 2
  new: 8
  spike: 2
  recurring: 149
  delivery_required: 130
  protected: 52
  health_failures: 2
breaches: 3 in window (3 paged)
paged_breaches[3]{at,agent,name}:
  "2026-11-07T03:52:02+11:00",web-02,brute force then success
  "2026-11-07T03:58:11+11:00",web-02,account created
  "2026-11-07T04:05:47+11:00",web-01,critical file changed
top_delivery_required[5]{id,category,level,rule}:
  g-8b3d7a66a966,failed,9,Windows application error event.
  g-bafb08797b12,failed,7,Dpkg (Debian Package) half configured.
  g-6eb848de6a9c,new,15,Executable file dropped in folder commonly used by malware
  g-d0d85907d30b,new,12,Powershell.exe spawned a powershell process which executed a base64 encoded command
  g-b5491b4cbe1b,new,12,Multiple authentication failures followed by a success.
help[4]:
  Run `soc-thief --snapshot examples/demo-snapshot.json groups` for all 161 groups in digest order
  Run `soc-thief --snapshot examples/demo-snapshot.json group <id>` for one group, with the model's advisory verdict
  Run `soc-thief --snapshot examples/demo-snapshot.json breaches` for every breach and its signals
  Run `soc-thief --snapshot examples/demo-snapshot.json health` for every check
```

## Errors

Errors go to stdout, like everything else, as `error: ...`. A usage error is followed by the
command's own help, so the fix is on screen. An unknown flag is refused by name; it is never
ignored. Abbreviated flags are not guessed. The CLI never prompts.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | OK. An empty result is still 0. |
| 1 | Failed: no snapshot, a snapshot that breaks the contract, an unknown group id, or a snapshot that could not be written. |
| 2 | Usage error: unknown command or flag, a missing or bad argument. |

A health status of `attention` or `failed` is data, not an error, so it exits 0.

## For integrators

`soc_thief.query` holds the queries as plain functions that return dicts. The CLI only
parses arguments and formats. An MCP server or another front end should call
`soc_thief.query` and not the CLI.
