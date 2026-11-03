# Deployment

This guide installs Soc Thief on one Linux host with rootless Podman and the systemd units in
`deploy/systemd/`. Soc Thief is alpha software: settings and unit files may change between
releases, so read the changelog before you upgrade.

The units have been run on Ubuntu 24.04 with Podman 4.9.3 and systemd 255. Other distributions
should work if they have rootless Podman with `pasta` networking and a recent systemd, but they are
untested.

## What you need

- A Wazuh 4.x deployment and a dedicated read-only indexer user (see
  [COLLECTOR.md](COLLECTOR.md#the-read-only-indexer-user)).
- A Linux host that can reach the indexer. The units assume the indexer and Ollama are reachable on
  host loopback; see [Networking](#networking) if yours is elsewhere.
- Rootless Podman with `pasta`, and systemd.
- A Discord webhook for the daily digest, in a private channel.
- Optional: [Ollama](https://ollama.com) with `qwen3:4b` for model advice (see [MODELS.md](MODELS.md)).
- Optional: an [ntfy](https://ntfy.sh) topic for breach pages.
- Optional: a push-style uptime monitor (for example Uptime Kuma or Healthchecks) for the hourly
  heartbeat.

## The units

| Unit | Runs | Schedule | Gate file |
| --- | --- | --- | --- |
| `soc-thief.service` | `soc_thief.verify`: a bounded metadata check of indexer access | daily 08:00 | `/etc/soc-thief/enable-schedule` |
| `soc-thief-runner.service` | `soc_thief.runner --daily`: the daily digest | daily 08:20 | `/etc/soc-thief/enable-runner` |
| `soc-thief-reconcile.service` | `soc_thief.runner --reconcile`: the late-alert pass | daily 10:30 | `/etc/soc-thief/enable-reconcile` |
| `soc-thief-backfill.service` | `soc_thief.backfill`: one historical day per run | hourly | `/etc/soc-thief/enable-backfill` |
| `soc-thief-fastpath.service` | `soc_thief.fastpath`: breach pages | every 10 minutes | `/etc/soc-thief/enable-fastpath` |
| `soc-thief-status.service` | `soc_thief.status` then a heartbeat | hourly | none |
| `soc-thief-backup.service` | `deploy/bin/soc-thief-backup` | daily 08:30 | `/var/backups/soc-thief` must be a mount point |

Each container unit has a `ConditionPathExists=` gate. Without its gate file, systemd skips the run
without starting a container or touching the network. Removing the gate file is the quickest way to
stop a unit.

Every run except the verifier and status check also needs a valid approval file (see
[The approval file](#the-approval-file)).

## Timezone

Set `SOC_THIEF_TIMEZONE` to an IANA zone name such as `Europe/Berlin`. The default is `UTC`. The
report day runs from 08:00 to 08:00 in that zone, and every local time in reports and pages uses
it. An invalid name stops each run at startup.

The timer files say `UTC` in their `OnCalendar=` lines. **Change that zone to match
`SOC_THIEF_TIMEZONE`**, for example `OnCalendar=*-*-* 08:20:00 Europe/Berlin`, so the daily run
follows the local 08:00 boundary. The backfill also defers itself between 07:30 and 09:30 and
between 10:00 and 11:15 local time, so it never competes with the daily and reconcile runs.

## 1. Service account

Create an unprivileged system account with no login shell, no sudo and no Docker socket access.
Rootless Podman needs subordinate UID and GID ranges for it.

```sh
sudo useradd --system --create-home --home-dir /var/lib/soc-thief \
  --shell /usr/sbin/nologin soc-thief
sudo usermod --add-subuids 200000-265535 --add-subgids 200000-265535 soc-thief
sudo cp deploy/sysusers.d/soc-thief-status.conf /etc/sysusers.d/
sudo systemd-sysusers
```

The second account, `soc-thief-status`, runs the status check. It has no login, no home and only
journal read access.

## 2. Install the source tree

The status check and backup helper run from `/opt/soc-thief` on the host. Install the checked-out
tree there, owned by root and readable by the service accounts:

```sh
sudo install -d -m 0755 /opt/soc-thief
sudo cp -r src deploy pyproject.toml /opt/soc-thief/
sudo cp deploy/systemd/* /etc/systemd/system/
```

## 3. Build the image

Build from a commit you have reviewed, on a digest-pinned Python base image:

```sh
sudo -u soc-thief podman --root /var/lib/soc-thief/podman build \
  --build-arg PYTHON_IMAGE=docker.io/library/python:3.12-slim@sha256:<digest> \
  --build-arg SOURCE_COMMIT="$(git rev-parse HEAD)" \
  -t soc-thief:local -f Containerfile .
sudo -u soc-thief podman --root /var/lib/soc-thief/podman image inspect \
  --format '{{.Digest}}' soc-thief:local
```

Run the build from a directory the `soc-thief` account can read. The fast path uses its own Podman
store and reads this one as an additional image store, so one build serves every unit.

The final image:

- runs as a fixed non-root user (65532);
- has no shell, no package manager, no `pip`, no `su` or `login`; the build fails if any remain;
- has no setuid or setgid bit anywhere; the build fails if one remains;
- keeps Python as the runtime and the `tzdata` package for zone rules.

Every unit uses `--pull=never`. A missing image fails the run; it is never fetched at timer time.
Put the exact digest in the environment file (step 5). Tags like `latest` are not acceptable.

If your egress policy blocks the service account (it should), stop it for the build and start it
again afterwards, or build as another user and load the image into the service account's store.

## 4. Secrets

Create the secrets directory and files. Every file is a regular, root-owned file with mode `0600`.
No symlinks. systemd passes each unit only the credentials it lists, as temporary read-only copies.

```sh
sudo install -d -m 0750 /etc/soc-thief
sudo install -d -m 0700 /etc/soc-thief/secrets
```

| File in `/etc/soc-thief/secrets/` | Contents | Used by |
| --- | --- | --- |
| `wazuh_indexer_url` | `https://<indexer host>:9200` | all container units |
| `wazuh_indexer_username` | the read-only reader's username | all container units |
| `wazuh_indexer_password` | its password | all container units |
| `wazuh_indexer_ca` | the indexer's CA bundle (PEM) | all container units |
| `discord_webhook_url` | `https://discord.com/api/webhooks/<id>/<token>` | runner, reconcile, backfill |
| `identity_key` | 64 lowercase hex characters, see [STATE_STORE.md](STATE_STORE.md#opaque-identifiers) | runner, reconcile, backfill, fast path |
| `runner_approval` | see [The approval file](#the-approval-file) | runner, reconcile, backfill, fast path, status |
| `tuning` | `{"version": 1, "entries": []}` to start; see [TUNING.md](TUNING.md) | runner, reconcile, backfill |
| `ntfy` | `{"url": "https://<ntfy host>/<topic>", "token": "tk_..."}` (`token` optional) | fast path; runner via a drop-in |
| `agent_inventory` | see [DETECTION.md](DETECTION.md#silent-agents) | fast path |
| `status_push` | a curl config line: `url = "https://<monitor>/<push path>"` | status |
| `jev_key` | only for the optional Jev backend, see [MODELS.md](MODELS.md#jev-experimental) | runner via a drop-in |

The identity key must stay the same for the life of the state store. Back it up separately.

A missing credential file makes systemd fail that unit before any container starts. An invalid
tuning file applies no tuning and reports a health failure.

Never commit any of these files, and never pass their contents as flags or environment variables.

## 5. The environment file

`/etc/soc-thief/environment`, root-owned, mode `0640`, holds only non-secret values:

```
SOC_THIEF_IMAGE=localhost/soc-thief@sha256:REPLACE_WITH_VERIFIED_DIGEST
SOC_THIEF_TIMEZONE=UTC
SOC_THIEF_INDEXER_ALIAS=indexer.example.internal
SOC_THIEF_INDEXER_PORT=9200
SOC_THIEF_MODEL_PORT=11434
SOC_THIEF_BACKFILL_FROM=2026-01-01
```

| Setting | Meaning |
| --- | --- |
| `SOC_THIEF_IMAGE` | The image, pinned by `@sha256:` digest |
| `SOC_THIEF_TIMEZONE` | IANA zone for the report day; default `UTC` |
| `SOC_THIEF_INDEXER_ALIAS` | The host name in the indexer's TLS certificate |
| `SOC_THIEF_INDEXER_PORT` | The indexer port on host loopback |
| `SOC_THIEF_MODEL_PORT` | The Ollama port on host loopback |
| `SOC_THIEF_BACKFILL_FROM` | First local report date for the historical backfill. It cannot change once the backfill has started. |
| `SOC_THIEF_NTFY_ALIAS`, `SOC_THIEF_NTFY_ADDR` | Optional: a hosts entry for your ntfy server (see the fast path below) |
| `SOC_THIEF_FASTPATH_MODEL_BASE_URL` | Optional: turns on the fast path's follow-up investigation |
| `SOC_THIEF_RMM_MARKERS` | Optional: trusted remote management tools, see [INVESTIGATION.md](INVESTIGATION.md#trusted-remote-management-tools) |

## Networking

The containers use rootless Podman `pasta` networking. `-T` forwards only the listed ports from
container loopback to host loopback, and `--add-host` maps the indexer alias to container loopback,
so TLS hostname checks still see the certificate's name. The container never joins the host network
namespace. `slirp4netns` cannot reach host-loopback-only listeners, which is why `pasta` is used.

If your indexer is not on host loopback, put a small TCP forwarder on host loopback, or adapt the
units' `--network` and `--add-host` options. Test that forwarding, name resolution and TLS all work
through the unit before you rely on it.

## Egress policy

Rootless container networking alone is not an egress policy. Restrict the `soc-thief` account at
the host firewall. Allow only what you need:

- loopback (indexer and Ollama on host loopback);
- HTTPS to Discord, once you are ready to deliver;
- DNS to the resolvers the container uses (Podman gives containers the host's upstream resolvers,
  not a loopback stub);
- HTTPS to your ntfy server, if you use the fast path;
- HTTPS to a hosted model endpoint, only if you chose one.

An example nftables policy, loaded by a small oneshot unit at boot:

```
table inet soc_thief_egress {
    chain output {
        type filter hook output priority 0; policy accept;
        oif "lo" accept
        ct state established,related accept
        meta skuid 996 udp dport 53 ip daddr { 192.0.2.53 } accept
        meta skuid 996 tcp dport 53 ip daddr { 192.0.2.53 } accept
        meta skuid 996 tcp dport 443 ip daddr { 198.51.100.0/24 } accept comment "Discord"
        meta skuid 996 counter log prefix "soc-thief-drop: " level info drop comment "soc-thief: no external egress"
    }
}
```

Replace `996` with the `soc-thief` UID (`id -u soc-thief`) and the documentation addresses with
your own. Notes:

- Match the drop on `meta skuid <uid>`, not `meta skuid != <uid> accept`. Kernel-generated packets
  have no socket, so a "not this user" rule does not match them and they fall through to the drop.
- Discord is served from a shared CDN range, so an address rule is coarse. The application itself
  only accepts `discord.com` and `discordapp.com` webhook URLs.
- The drop rule does not send a reject, so a blocked destination shows up as a timeout.
- Keep the drop line exactly as shown if you want `python -m soc_thief.jev_egress` to propose a
  rule for the Jev backend; it inserts before that line.

## The approval file

Every triage run, the fast path and the status check read
`/etc/soc-thief/secrets/runner_approval`. It is a single line of JSON with exactly two keys:

```json
{"approved_route":"daily-digest","expires":"2026-02-01T00:00:00Z"}
```

`expires` is either a UTC timestamp in the future and at most 30 days away, or the string
`"never"` for a standing approval. Delete the file to stop every run, including health reports and
pages.

Without a valid approval, the run exits `2` before it builds any collector, model, state or
delivery object, and sends nothing. There is no Discord egress without approval, so the failed unit
result is the signal. The status check sees it and withholds its heartbeat. A dated approval also
fails the status check from three days before it expires.

## 6. Turn it on

Check the units, then enable step by step:

```sh
sudo systemd-analyze verify /etc/systemd/system/soc-thief*.service /etc/systemd/system/soc-thief*.timer
sudo systemctl daemon-reload
```

1. Verifier. `sudo touch /etc/soc-thief/enable-schedule`, then
   `sudo systemctl start soc-thief.service` and read
   `journalctl -u soc-thief.service`. It prints only fixed status lines. Enable
   `soc-thief.timer` once it passes.
2. Test the webhook. It sends one fixed synthetic message:

   ```sh
   sudo env PYTHONPATH=/opt/soc-thief/src \
     DISCORD_WEBHOOK_URL_FILE=/etc/soc-thief/secrets/discord_webhook_url \
     python3 -m soc_thief.delivery_verify
   ```
3. Daily runner. Create the approval file and `/etc/soc-thief/enable-runner`, run
   `sudo systemctl start soc-thief-runner.service` once, check the digest in Discord, then enable
   `soc-thief-runner.timer`.
4. Status check. Install the `status_push` credential and enable `soc-thief-status.timer`.
5. Backup. Mount an encrypted volume at `/var/backups/soc-thief` and enable
   `soc-thief-backup.timer`. The unit refuses to run unless that path is a mount point.
6. Fast path. See below.
7. Reconcile, only after the daily stream has committed some windows:
   `/etc/soc-thief/enable-reconcile` and `soc-thief-reconcile.timer`.
8. Backfill, only when you want history processed and after you have tuned the daily report for
   a week or two: `/etc/soc-thief/enable-backfill` and `soc-thief-backfill.timer`.

To roll back any step, remove its gate file and disable its timer.

## The daily runner

`python -m soc_thief.runner --daily` picks the most recent 08:00-to-08:00 local day whose end is
at least 15 minutes in the past, so late-indexed alerts have a margin. It fails closed in this
order, printing only fixed status text:

1. Invalid arguments: exit `2`, nothing built.
2. Missing or invalid approval: exit `2`, nothing built or sent.
3. A worker process loads configuration. An invalid webhook means nothing can be sent. Any other
   configuration failure (indexer, model, identity key, state) sends a content-free health report.
4. The worker is killed after the 1,500-second deadline plus 60 seconds' grace, and the parent
   tries to send a content-free health report.

Limits per window: 400,000 events, 2,000 groups, 1,500 seconds. A day near the group limit with
every group going to the model would exceed the deadline and fail closed.

Exit `0` means a completed window with no health failure.

Checkpoints. The first successful run starts the `daily` stream at its window. Earlier
history belongs to the backfill. A window already covered exits `0` without collecting again. The
oldest pending report is always retried first, before any collection.

Automatic catch-up. If the stream's checkpoint is behind, on an 08:00 boundary and at most 31
days back, a `--daily` run processes the missed days oldest first, each in its own worker, then the
scheduled day. It stops at the first failure, when it is current, or after 2,100 seconds, so the
last window still ends inside the unit's `TimeoutStartSec=3900s`. The rest follow the next day.

Manual catch-up. For a gap the automatic catch-up refuses (misaligned, overlapping or older
than 31 days), run explicit windows, oldest first, starting at the checkpoint. Use the runner
unit's own container command with `--daily` replaced by a window, for example:

```
... -m soc_thief.runner --start 2026-01-05T08:00:00+00:00 --end 2026-01-06T08:00:00+00:00
```

Each window must be at most 25 hours and closed by the lateness margin.

## The fast path

`soc-thief-fastpath.service` pages through ntfy on a breach signal; see
[DETECTION.md](DETECTION.md#the-fast-path) for what it does. To enable it:

1. Create the `ntfy` credential. The URL must be HTTPS with one path segment (the topic), no query
   and no user info; anything else refuses the run.
2. If the containers cannot resolve your ntfy host through public DNS (for example a name on a
   private network), set `SOC_THIEF_NTFY_ALIAS` and `SOC_THIEF_NTFY_ADDR` in the environment
   file. Unset, they default to `ntfy.invalid` and `127.0.0.1`, which start cleanly and page
   nowhere.
3. Allow HTTPS from the service account to the ntfy host in your egress policy.
4. Create the `agent_inventory` credential for silent-agent checks.
5. `sudo touch /etc/soc-thief/enable-fastpath` and enable `soc-thief-fastpath.timer`.
6. Make the status check require the fast path, so disabling its timer fails the check instead of
   switching the check off:

   ```ini
   # /etc/systemd/system/soc-thief-status.service.d/fastpath.conf
   [Service]
   Environment=SOC_THIEF_EXPECT_FASTPATH=1
   ```

The fast path state is `/var/lib/soc-thief/fastpath/fastpath.json`, and the container mounts only
that directory. It runs in its own Podman store, so it never contends with the daily runner's
Podman lock.

Tuning-watch pages from the daily run. To let the daily runner page when a tuned rule spikes
(see [TUNING.md](TUNING.md#the-tuning-watch)), install `deploy/systemd/soc-thief-runner-ntfy.conf`
as `/etc/systemd/system/soc-thief-runner.service.d/ntfy.conf` once the `ntfy` file and egress
exist. Without it, a spiking tuned group is still delivered, with a health failure.

### Follow-up investigation

To have each breach page followed by a short local investigation (see
[INVESTIGATION.md](INVESTIGATION.md)), add one line to the environment file:

```
SOC_THIEF_FASTPATH_MODEL_BASE_URL=http://127.0.0.1:11434
```

Use the same port as `SOC_THIEF_MODEL_PORT`. The unit already forwards it. No new credential or
egress rule is needed. Remove the line to turn it off.

Briefs go to `/var/lib/soc-thief/fastpath/investigations/`, mode `0700`, files `0600`, at most
32 KiB each, newest 50 kept.

## The status check

`soc-thief-status.service` runs on the host, not in a container, as `soc-thief-status`. It reads
journal lines through `systemctl` and `journalctl`, never credentials, state or reports. If
everything is healthy it runs `curl --config` with the `status_push` credential to send the
heartbeat. Point that at a push monitor that alerts you when a heartbeat is missed.

## Reconcile, backfill and the priority lock

Reconcile and backfill reuse the runner's hardening line for line (a test enforces it), the same
credentials and the same approval file.

Daily and reconcile always take priority over backfill, including manual starts and catch-up after
downtime. Each priority unit first runs the fixed privileged command
`systemctl stop soc-thief-backfill.service`, then holds `/run/soc-thief/priority.lock` around its
Podman process. Backfill takes the same lock with `flock --nonblock` and exits before doing anything
if a priority run holds it. The backfill unit has no way to stop daily or reconcile. A stopped
backfill window stays uncommitted and is retried by a later run.

All four container units that share `RuntimeDirectory=soc-thief` set
`RuntimeDirectoryPreserve=yes`. Without it, systemd deletes `/run/soc-thief` when any one of them
stops, even while another is running. That unlinks the lock file a running unit holds, so the next
`flock` takes a fresh "exclusive" lock at once, and it deletes the running container's Podman
runroot. Keep the setting on any new unit that shares the directory. The application's own state
lock is under `/var/lib/soc-thief/state/` and is not affected.

Reconcile catch-up. After a missed reconcile day, every later run reports the gap until you
run the missing days by hand, one day per run, oldest first:

```
... -m soc_thief.runner --reconcile --start <ISO> --end <ISO>
```

Each window must be exactly one local report day, already committed by the daily stream.

Backfill pace. Each run first retries a pending backfill report, then processes at most one
historical day, and prints `backfill complete; no collection performed` when done. It sends up to
one report per historical day, so a long history means many Discord messages. A dated approval must
be renewed during the backfill.

### Checking the privileged stop on your host

The priority scheme depends on two systemd behaviours: that a `+` prefix runs an `ExecStartPre`
with full privileges in a `User=soc-thief` unit, and that the stop finishes before `ExecStart`
takes the lock. You can check both with two throwaway units that touch nothing of Soc Thief's.
Run from `/`:

```sh
# A holder running as soc-thief, holding a scratch lock for five minutes.
sudo systemd-run --unit=st-lockprobe-holder --working-directory=/ \
  --property=User=soc-thief \
  /usr/bin/flock --exclusive /tmp/st-lockprobe.lock /bin/sleep 300
systemctl is-active st-lockprobe-holder.service      # expect: active

# A priority unit shaped like the runner: privileged stop, then a blocking flock.
time sudo systemd-run --unit=st-lockprobe-priority --working-directory=/ --wait \
  --property=User=soc-thief \
  --property='ExecStartPre=+/usr/bin/systemctl stop st-lockprobe-holder.service' \
  /usr/bin/flock --exclusive /tmp/st-lockprobe.lock /bin/true

systemctl is-active st-lockprobe-holder.service      # expect: inactive
sudo systemctl reset-failed st-lockprobe-holder.service st-lockprobe-priority.service 2>/dev/null
sudo rm -f /tmp/st-lockprobe.lock
```

Pass: the priority unit returns in well under a second and the holder is inactive. Fail: it waits
about five minutes and then succeeds, which means the `+` did not elevate and it simply outwaited
the holder. That failure matters. `TimeoutStartSec` covers `ExecStartPre` and `ExecStart`
together, so a daily run that waits out a long backfill can be killed by systemd before it reaches
the code that sends a health report: a silently missed day.

## Hardening

The container runs read-only, as a non-root user, with every capability dropped,
`--security-opt=no-new-privileges`, a 16 MB `noexec` `/tmp`, no host network and no Docker socket.
It sees only its state volume and its credentials.

The systemd units add `PrivateTmp`, `PrivateDevices` (with `/dev/net/tun` allowed back in for
`pasta`), `ProtectSystem=strict`, `ProtectHome`, `ProtectKernelModules`, `ProtectControlGroups`,
`ProtectClock`, `ProtectProc=invisible`, `ProcSubset=pid`, `RestrictSUIDSGID`, `LockPersonality`,
`MemoryDenyWriteExecute`, `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK`,
`SystemCallArchitectures=native` and `UMask=0077`.

Absent on purpose. Rootless Podman cannot start under three common settings, so the container
units leave them out. This was measured by trying each setting in turn through the real unit,
after killing Podman's rootless pause process (as after a reboot):

| Setting | Why it is absent |
| --- | --- |
| `NoNewPrivileges=yes` | Blocks the setuid `newuidmap` helper Podman needs to set up the user namespace. The container itself still runs with `no-new-privileges`. |
| `ProtectKernelTunables=yes` | Overmounts parts of `/proc`, so the kernel refuses the container its own `/proc` mount. |
| `ProtectHostname=yes` | Same `/proc` problem. |

`RestrictNamespaces` and a restrictive `SystemCallFilter` are also not set, because Podman must
create user and mount namespaces. Test them against your storage driver before adding them.
`AF_NETLINK` is needed for container network setup. `ProtectSystem=strict` works only together with
`PrivateTmp=yes`. A test in `tests/test_deployment.py` records these choices.

The status and backup units do not run Podman, so they use the full set, including
`NoNewPrivileges` and the kernel protections.

## Monitoring and backup

Use the journal identifiers (`soc-thief`, `soc-thief-runner`, `soc-thief-reconcile`,
`soc-thief-backfill`, `soc-thief-fastpath`, `soc-thief-status`, `soc-thief-backup`) for
status-only monitoring. Treat any non-zero unit result, missed timer run or backup failure as a
health problem. Do not turn on debug logging or capture container output that could include alert
fields.

The backup helper uses SQLite's backup API, validates the copy, prints only a fixed result and
keeps seven days of `state-*.sqlite3` files. To restore, copy a backup into an isolated `0700`
directory, check it with `PRAGMA quick_check`, stop the units, then replace the state file. Keep
the failed copy for investigation. Encryption, off-host copies and key custody are up to you.

## Problems found on a first real deployment

The synthetic test suite passed, and each of these still broke every run on a real host. They are
fixed in the code and units, but worth knowing if you adapt the deployment:

1. Discord rejects Python's default User-Agent with a 403 before it reads the webhook. Soc
   Thief sends a fixed `SocThief/<version>` agent.
2. systemd credentials look different inside a rootless container. `LoadCredential` creates
   root-owned files with an ACL that shows as `0440`, and host root appears as the overflow UID
   65534. The secret reader accepts group read and the overflow owner only on a read-only mount.
3. No DNS. The container uses the host's upstream resolvers, which the egress policy blocked.
4. Unit hardening that rootless Podman cannot start under; see the table above.
5. An alert with no `rule.description` failed a whole window. A missing description now
   becomes `[rule description missing]`.
6. The first run after a rebuild failed. Rootless Podman's ID-mapped copy of a new image must
   restore setuid bits, which `RestrictSUIDSGID=yes` forbids. The image now has none.
7. Socketless kernel packets fell through a `skuid !=` accept rule into the drop. Scope the
   drop to the service UID instead.
