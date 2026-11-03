# Detection: breach signals, the fast path and measurement

The daily digest is a morning read. A breach should not wait for it. This document covers what
Soc Thief counts as a breach, how the fast path pages you, how it proves that silence means
"nothing happened", and how to measure all of it on a test host you own.

## Breach signals

`src/soc_thief/breach.py` defines six signals. They match on Wazuh rule IDs and rule groups, never
on description words, so alert text cannot trigger or dodge them.

| Signal | Matches |
| --- | --- |
| `malware` | Rootcheck 513 (Windows malware) and 521 (possible kernel-level rootkit); Defender 62113, 62122, 62123, 62126 |
| `log_cleared` | Any rule in the `logs_cleared` group (593, 18118, 60117) |
| `privileged_group_change` | Changes to Administrators, Domain Admins, Schema Admins or Enterprise Admins (60154, 60159, 60166, 60167, 18217, 18222, 18229, 18230) |
| `account_created` | 5902 (Linux user added), 60109 (Windows account enabled or created) |
| `brute_force_success` | 40112, or an `authentication_success` after an `authentication_failures` alert from the same source address on the same agent in the window |
| `critical_file_change` | A syscheck content change, addition or deletion on a fixed list: `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/gshadow`, `/etc/sudoers`, `/etc/ssh/sshd_config`, `/root/.ssh/authorized_keys`, `/etc/ld.so.preload`, `/etc/crontab`, and anything under `/etc/sudoers.d/`, `/etc/ssh/sshd_config.d/`, `/root/.ssh/` or `/etc/cron.d/` |

For `critical_file_change`, a modification counts only when size or a hash changed. Some files see
many metadata-only changes, and paging on those would page daily. An unknown event type, or a
modification where Wazuh did not say what changed, counts as a change.

Rule 521 is a known source of false positives in rootcheck. It is still a breach signal, because a
rootkit claim is exactly what must not be hidden. Expect it to page until you investigate and fix
the cause on that host.

A group with a signal is delivered with reason `breach_<signal>`. It skips tuning and the model,
is never folded into a summary, and is listed first in the digest under `BREACH`. Only the fixed
signal name leaves the process.

Two signals were considered and left out:

- Three or more MITRE tactics on one agent within a few hours. Every successful PAM login
  carries several tactics, so this fired on a large share of ordinary agent-hours. It needs a
  baseline design before it can page.
- An expected agent going silent. This needs an inventory you own. It is handled separately
  by the liveness check below.

## The fast path

`python -m soc_thief.fastpath` runs every ten minutes from `soc-thief-fastpath.timer`. Each run:

1. reads from its last checkpoint, minus a one-hour lookback, to two minutes before now, through
   the same read-only collector and grouping as the daily run;
2. keeps only groups with a breach signal;
3. pages through ntfy once per (signal, agent) per 24 hours;
4. advances its checkpoint only after every page was accepted, so a failed page is retried.

There is no model, no tuning and no Discord before the page. Tuning cannot suppress a breach and a
model cannot delay one. The daily digest still delivers every one of these groups as the audit
record.

A page carries the signal name, the Wazuh agent ID, the earliest time, the event count and the
opaque case ID. No description, host name, path or address. Pages use ntfy priority `urgent`.
More than 10 distinct pages in a run become one summary page.

After an outage, the fast path checks at most the last 24 hours. Anything older is a coverage gap,
and it sends a gap page saying so.

The fast path needs the runner approval file, like every other run. Deleting the approval stops
pages too.

Exit codes: `0` clean check; `1` a failed page (retried next run), a coverage gap, a failed
collection or a silent agent; `2` refused (no approval, or an invalid ntfy route).

State is one private file, `/var/lib/soc-thief/fastpath/fastpath.json`, holding the checkpoint
and opaque keys of recent pages.

### Follow-up investigation

Optionally, each breach page can get one follow-up page with a short automatic investigation by
the local model. It never changes, delays or withdraws the breach page. See
[INVESTIGATION.md](INVESTIGATION.md#automatic-follow-up-on-a-breach-page).

### Silent agents

A breach on an agent that has stopped reporting looks exactly like a quiet night. So each fast
path run also checks agent liveness (`soc_thief.liveness`). You keep an inventory of agents that
must report, read through `SOC_THIEF_AGENT_INVENTORY_FILE`:

```json
{"version": 1, "agents": [{"agent_id": "001", "max_silence_minutes": 180, "note": "optional"}]}
```

`agent_id` is the numeric Wazuh agent ID (3 to 8 digits). `max_silence_minutes` is 30 to 10080
(seven days). At most 500 agents, no duplicates, no other keys. Notes are validated and discarded.
Nothing generates this file for you.

"Reported" means "produced at least one alert in the indexer", because the indexer is the only
source Soc Thief reads. A quiet but healthy agent needs a gap long enough to cover its normal
rhythm; the noise profile in [TUNING.md](TUNING.md) shows it.

An agent with no alert inside its allowed silence pages `Soc Thief breach: agent_silent` with the
agent ID, the last-seen time and the allowed silence. It pages once per 24 hours, and again at once
if it recovers and then goes quiet. A missing or invalid inventory or a failed read fails the run
with a fixed journal line and no page. The status check catches that.

### The status check

`soc-thief-status.timer` runs `python -m soc_thief.status` hourly. It reads only journal lines,
never credentials or state. When everything below holds, it sends a heartbeat to a push monitor
you choose (the URL lives in a curl config file, the `status_push` credential). Your monitor alerts
you when a heartbeat is missed.

- The last daily window closed.
- If the fast path is expected: its latest outcome is `fast path checked` and at most 30 minutes
  old, its timer is active, and no `coverage gap` line appeared in the last two hours.
- If the fast path is expected: the latest `agent liveness` line is at most 30 minutes old and
  shows `0 silent`.
- A dated approval file is not within three days of expiry.

Worst case: a stopped or stalled fast path fails the next hourly check, a silent agent pages on
the first fast path run after its gap expires, and a coverage gap pages from the fast path itself.

## Measuring detection

Rules, agents and pipelines drift. The measurement harness answers one question with the same
scenarios every time: does a real breach on a test host get through Wazuh and Soc Thief?

It has two parts joined by a run log:

- `simulations/run-linux.sh` and `simulations/run-windows.ps1` perform fixed, benign,
  self-cleaning scenarios and write one JSON line per scenario with its UTC start and end.
- `python -m soc_thief.detection` reads that log and asks the indexer, read-only, what the agent
  raised in each window. It runs the alerts through the real grouping, policy and breach code and
  writes a local report. It sends nothing; "would the fast path have paged" is computed with the
  real fast-path logic.

### Before you run it

- **Use a disposable test host you own**, with a Wazuh agent already enrolled. Never a production
  host. The scripts create and delete local accounts, write to `/etc/cron.d` or the registry, and
  on Windows clear a real event log channel.
- The scripts refuse to run unless you pass the host's own hostname. That guards against typos;
  it is not an approval process.
- Linux and Windows cover different rules. See the gaps below.

### Running it

On the test host, as root or elevated:

```sh
sudo simulations/run-linux.sh --i-am-on-the-disposable-test-host "$(hostname)" --run-log run.jsonl
```

```powershell
.\simulations\run-windows.ps1 --i-am-on-the-disposable-test-host $env:COMPUTERNAME --run-log run.jsonl
```

A run takes about six minutes, with 45 seconds between scenarios so windows do not overlap. Copy
`run.jsonl` to a machine that can reach the indexer, wait the grace period (30 minutes by default;
longer for file-change scenarios if syscheck is scheduled rather than realtime), then run it with
the collector `*_FILE` settings and, optionally, `SOC_THIEF_TUNING_FILE` to measure against your
installed tuning:

```sh
PYTHONPATH=src python3 -m soc_thief.detection --run-log run.jsonl --agent-id 003
```

It writes `run.jsonl.report.json` (mode `0600`, never overwritten; `--report` picks another path)
and prints one line per scenario. `--grace-minutes` changes the wait. It refuses a window still
inside its grace period rather than score it as a miss.

Exit codes: `0` every scenario passed, `3` at least one did not, `1` the measurement itself failed
(no report written), `2` usage error.

### Verdicts

- PASS: a breach scenario produced its expected signal (so it is delivered, skips tuning and
  would page), or an alert-only scenario produced a delivered matching alert.
- MISS: no matching alert, or Wazuh raised one but Soc Thief named no expected signal. The
  `detail` field says which.
- SUPPRESSED: matching alerts were raised and your tuning muted all of them.
- NOT_RUN: the script recorded the scenario as failed or skipped. This is not a miss.

The report holds rule IDs and levels, counts, the decision reason, the breach signal, the digest
section and the fast-path signals. It holds no descriptions, host names, addresses or paths. No
model runs: a group left for model review is reported as `model_requires_review` and counted as
delivered, because the model can only deliver.

### Scenarios

Each script names its Atomic Red Team equivalents in its header; the framework itself is not used
or downloaded. Both scripts contact only `127.0.0.1`, never touch Wazuh, and clean up in an exit
trap or `finally` block. Every artefact is named `soc-thief-sim`, and the scripts refuse to start
if such an account already exists, so cleanup cannot delete someone else's.

| Scenario | Linux | Windows |
| --- | --- | --- |
| `brute_force_success` | 10 wrong-password SSH logins, then a key login, to a throwaway user over `127.0.0.1`. Needs `PasswordAuthentication yes` and, on OpenSSH 9.8 or later, `PerSourcePenalties no`. | 10 wrong network logons to `\\127.0.0.1\IPC$`, then a correct one. |
| `account_created` | `useradd`, then add to `sudo` or `wheel`. | `net user /add`, then add to Administrators. |
| `log_cleared` | Truncates only its own file under `/var/log`. | `wevtutil cl` on `Microsoft-Windows-WinRM/Operational` (change with `--log-name`). This clears a real, low-value channel. The Security log is never cleared. |
| `persistence` | A file in `/etc/cron.d` running `/bin/true`. | An HKLM `Run` value and an on-logon scheduled task running `cmd.exe /c exit`. |
| `suspicious_powershell_child` | none | PowerShell starts `cmd.exe /c whoami /priv & net user & ipconfig /all`. |
| `eicar` | The EICAR test string in `/var/tmp`. | The same in `%TEMP%`. Defender will probably block it; that still counts as the stimulus. |

Expected rule IDs and groups per scenario are in `EXPECTATIONS` in `src/soc_thief/detection.py`.

### Known gaps

- Linux `log_cleared` cannot fire. Every stock rule in the `logs_cleared` group is a Windows
  rule. A MISS here is a finding about Linux coverage.
- Linux `eicar` misses. Stock Wazuh does not scan Linux files for signatures. You need ClamAV
  or YARA integration.
- `persistence` and `suspicious_powershell_child` on Windows are alert-only. There is no breach
  signal for them, so they can be delivered but never paged.
- Matching is by rule ID or group in a narrow window, so unrelated background alerts on the
  same agent can cause a false PASS. Read the `raised` list, not only the verdict.
- Syscheck latency. File and registry changes appear only after the next scan unless the path
  is monitored in realtime.
- Windows brute force needs Wazuh to record the source address in `data.srcip`. If it does not,
  the correlation cannot work and the scenario misses. That is a real finding.
- Remote management tools. If your hosts run an RMM agent that executes PowerShell, its
  activity blurs the PowerShell scenario. Use a test host without one.

### Results so far

The Linux script has been run on a test host. `account_created` and `persistence` passed and
paged. `brute_force_success` first missed and then passed after an agent fix (below). `log_cleared`
and `eicar` missed, as the known gaps predict. The Windows script has not been run yet, and its
expected rule groups are unverified.

Wazuh agents reading journald can drop a first login. When journald creates a new per-user
journal file, the Wazuh agent's journald reader jumps to the end and skips what was just written.
A first login by a new or compromised account is exactly when that happens. This is an upstream
bug ([wazuh/wazuh#40750](https://github.com/wazuh/wazuh/issues/40750)). Until your agents run a
fixed release, set this in the agent's journald `<localfile>` block:

```xml
<only-future-events>no</only-future-events>
```

### Rerunning

Rerun after every change to Wazuh rules, tuning or Soc Thief, and compare reports. A MISS or
SUPPRESSED where there used to be a PASS is a regression.
