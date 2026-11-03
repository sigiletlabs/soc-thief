#!/usr/bin/env bash
# Soc Thief detection measurement: fixed, benign attack simulations for a DISPOSABLE Linux test host.
#
# Run as root, ON the test host only, after the operator has approved the run (docs/DETECTION.md):
#   sudo ./run-linux.sh --i-am-on-the-disposable-test-host "$(hostname)" [--run-log FILE]
#
# Built-in tools only (bash, useradd, ssh to 127.0.0.1, cron). Nothing is downloaded and no
# address other than 127.0.0.1 is contacted. Wazuh is never touched. Every artefact carries the
# name `soc-thief-sim` and is removed by the EXIT trap, including after a failure.
#
# Equivalent Atomic Red Team tests (named only; the framework is not used or downloaded):
#   brute_force_success  T1110.001 (password guessing) then T1078.003 (valid local account)
#   account_created      T1136.001-1 (create local account), T1098 / T1078 (add to sudo/wheel)
#   log_cleared          T1070.002-1/-2 (clear system logs) - see the note on that scenario
#   persistence          T1053.003-2 (cron job) written under /etc/cron.d so syscheck sees it
#   eicar                T1204.002 / AV test file (EICAR test string)
# There is no Linux "suspicious PowerShell child" scenario.
#
# Scenarios the operator should know about before approving:
#   - brute_force_success needs sshd on 127.0.0.1 with PasswordAuthentication yes. The script
#     checks this and records the scenario as failed, rather than guessing.
#   - log_cleared CANNOT be made to fire Wazuh's log-cleared rules without destroying a real
#     log: the rules that carry the `logs_cleared` group (593, 18118, 60117) are all Windows
#     rules. This script truncates only its own test file, which Wazuh does not read, so it is
#     expected to MISS. That MISS is a finding (no Linux coverage), not a script fault.
#   - persistence writes to /etc/cron.d, which src/soc_thief/breach.py treats as a critical
#     path. Wazuh syscheck may only report it on its next scan (default every 12 hours) unless
#     /etc/cron.d is monitored in realtime; run the measurement after that delay.

set -u -o pipefail

NAME="soc-thief-sim"
BF_USER="soc-thief-sim-bf"
WORK="$(mktemp -d "${TMPDIR:-/var/tmp}/soc-thief-sim.XXXXXX")"
RUN_ID="sim-$(date -u +%Y%m%dT%H%M%SZ)"
RUN_LOG="./soc-thief-sim-run-${RUN_ID}.jsonl"
PAUSE=45   # seconds between scenarios so alert windows do not overlap
CRON_FILE="/etc/cron.d/${NAME}"
LOG_FILE="/var/log/${NAME}.log"
EICAR_FILE="/var/tmp/${NAME}-eicar.com"

host_ok=""
while [ $# -gt 0 ]; do
  case "$1" in
    --i-am-on-the-disposable-test-host) host_ok="${2:-}"; shift 2 ;;
    --run-log) RUN_LOG="${2:-}"; shift 2 ;;
    *) echo "unknown argument" >&2; exit 2 ;;
  esac
done

# Hostname guard: refuse unless the operator typed this machine's own hostname.
if [ -z "$host_ok" ] || [ "$host_ok" != "$(hostname)" ]; then
  echo "refusing: pass --i-am-on-the-disposable-test-host <this host's hostname>" >&2
  exit 2
fi
if [ "$(id -u)" -ne 0 ]; then
  echo "refusing: must run as root on the test host" >&2
  exit 2
fi
if [ -e "$RUN_LOG" ]; then
  echo "refusing: run log already exists" >&2
  exit 2
fi
if id "$NAME" >/dev/null 2>&1 || id "$BF_USER" >/dev/null 2>&1; then
  echo "refusing: a ${NAME} account already exists; the cleanup would delete it" >&2
  exit 2
fi
umask 077
: > "$RUN_LOG"

cleanup() {
  userdel -r "$NAME" >/dev/null 2>&1
  userdel -r "$BF_USER" >/dev/null 2>&1
  rm -f "$CRON_FILE" "$LOG_FILE" "$EICAR_FILE"
  rm -rf "$WORK"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

now() { date -u +%Y-%m-%dT%H:%M:%SZ; }

# run_scenario ID FUNCTION: runs FUNCTION, writes one JSON line (id, UTC start/end, status).
run_scenario() {
  local id="$1" fn="$2" start end status="ok"
  start="$(now)"
  "$fn" || status="failed"
  end="$(now)"
  printf '{"run":"%s","platform":"linux","scenario":"%s","start":"%s","end":"%s","status":"%s"}\n' \
    "$RUN_ID" "$id" "$start" "$end" "$status" >> "$RUN_LOG"
  sleep "$PAUSE"
}

# --- brute_force_success: wrong passwords over ssh to 127.0.0.1, then a key login. ----------
# Setup (user creation) happens before the first window starts so it does not read as the
# account_created scenario; its deletion happens after the last window, in cleanup.
setup_bf_user() {
  useradd -m -s /bin/bash "$BF_USER" || return 1
  echo "${BF_USER}:$(head -c 24 /dev/urandom | base64 | tr -d '/+=')" | chpasswd || return 1
  ssh-keygen -q -t ed25519 -N "" -f "$WORK/key" || return 1
  install -d -m 700 -o "$BF_USER" -g "$BF_USER" "/home/${BF_USER}/.ssh" || return 1
  install -m 600 -o "$BF_USER" -g "$BF_USER" "$WORK/key.pub" "/home/${BF_USER}/.ssh/authorized_keys" || return 1
}

scenario_brute_force_success() {
  local pw_auth penalties i
  pw_auth="$(sshd -T 2>/dev/null | awk '$1=="passwordauthentication"{print $2}')"
  [ "$pw_auth" = "yes" ] || { echo "sshd PasswordAuthentication is not yes; scenario failed" >&2; return 1; }
  # OpenSSH >= 9.8 drops connections from a source after repeated failures, which refuses the
  # final key login. The test host must set "PerSourcePenalties no"; older sshd has no such setting and prints nothing here.
  penalties="$(sshd -T 2>/dev/null | awk '$1=="persourcepenalties"{print $2}')"
  [ -z "$penalties" ] || [ "$penalties" = "no" ] || {
    echo "sshd PerSourcePenalties is on; set it to no on the test host; scenario failed" >&2; return 1; }
  printf '#!/bin/sh\necho wrong-password-sim\n' > "$WORK/askpass"
  chmod 700 "$WORK/askpass"
  local common=(-o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o LogLevel=ERROR)
  for i in $(seq 1 10); do   # Wazuh's brute-force rules count repeated failures from one source.
    SSH_ASKPASS="$WORK/askpass" SSH_ASKPASS_REQUIRE=force DISPLAY=none setsid \
      ssh "${common[@]}" -o PubkeyAuthentication=no -o PreferredAuthentications=password \
      -o NumberOfPasswordPrompts=1 "${BF_USER}@127.0.0.1" true </dev/null >/dev/null 2>&1
  done
  ssh "${common[@]}" -o PasswordAuthentication=no -o IdentitiesOnly=yes -i "$WORK/key" \
    "${BF_USER}@127.0.0.1" true </dev/null >/dev/null 2>&1
}

# --- account_created: create an admin account, then delete it. -------------------------------
scenario_account_created() {
  local group=sudo
  getent group wheel >/dev/null && group=wheel
  useradd -m -s /bin/bash -G "$group" "$NAME" || return 1
  sleep 5
  userdel -r "$NAME"
}

# --- log_cleared: truncate this script's own file only; see the header note. ------------------
scenario_log_cleared() {
  printf 'soc-thief-sim line 1\nsoc-thief-sim line 2\n' > "$LOG_FILE" || return 1
  : > "$LOG_FILE"   # The "clear". Real logs are never touched.
  rm -f "$LOG_FILE"
}

# --- persistence: a cron.d entry that does nothing, created then removed. ---------------------
scenario_persistence() {
  printf '# soc-thief-sim: harmless persistence simulation\n*/30 * * * * root /bin/true\n' > "$CRON_FILE" || return 1
  chmod 644 "$CRON_FILE"
  sleep 30
  rm -f "$CRON_FILE"
}

# --- eicar: the standard AV test string, built from pieces so this file is not itself flagged. -
scenario_eicar() {
  local a='X5O!P%@AP[4\PZX54(P^)7CC)7}$' b='EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
  printf '%s%s' "$a" "$b" > "$EICAR_FILE" || return 1
  sleep 30
  rm -f "$EICAR_FILE"
}

setup_ok=1
setup_bf_user || setup_ok=0
sleep "$PAUSE"   # let the setup alerts fall outside the first window

if [ "$setup_ok" -eq 1 ]; then
  run_scenario brute_force_success scenario_brute_force_success
else
  printf '{"run":"%s","platform":"linux","scenario":"brute_force_success","start":"%s","end":"%s","status":"skipped"}\n' \
    "$RUN_ID" "$(now)" "$(now)" >> "$RUN_LOG"
fi
run_scenario account_created scenario_account_created
run_scenario log_cleared scenario_log_cleared
run_scenario persistence scenario_persistence
run_scenario eicar scenario_eicar

echo "run log: $RUN_LOG"
