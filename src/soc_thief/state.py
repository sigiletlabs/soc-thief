"""Private metadata-only SQLite state with atomic, replay-checked window commits.

Call only after a complete collection window has passed validation. This module
does not certify a source snapshot or provide a delivery outbox.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
from typing import Iterable

from soc_thief.breach import REASONS as BREACH_REASONS
from soc_thief.policy import Decision


class StateError(RuntimeError):
    """Abort progress and require delivery of a health failure."""


# A pending report is one JSON array of Discord payloads (the daily report
# can be multi-page), or for a digest an object holding that array plus the digest's attachment. Bounds
# delivery.MAX_PAGES payloads at delivery._PAYLOAD_LIMIT each, plus delivery.ATTACHMENT_LIMIT and
# a little framing; tests/test_state.py asserts this stays at or above what the renderer can produce.
OUTBOX_PAYLOAD_LIMIT = 24 * 8 * 1024 + 256 * 1024 + 4 * 1024

_TOKEN = re.compile(r"[0-9a-f]{64}\Z")
_MODEL_IDENTITY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/+-]{0,255}\Z")
_REASONS = {
    "pipeline_failure": (True, True),
    "invalid_group": (True, True),
    "critical_severity": (True, False),
    "protected_indicator": (True, False),
    "invalid_model_result": (True, True),
    "high_confidence_benign": (False, False),
    "model_requires_review": (True, False),
    "description_summary": (True, False),
    "tuned_mute": (False, False),
    "tuned_low": (False, False),
    **{reason: (True, False) for reason in BREACH_REASONS},
    "tuned_spike": (True, False),
    "tuned_spike_unpaged": (True, True),
}


def opaque_key(key: bytes, namespace: str, *parts: str) -> str:
    """HMAC identity components; keep the stable 32-byte secret outside SQLite.

    Different namespaces separate source, group and stream identities. Inputs
    remain local and are never emitted in exceptions or persisted by this helper.
    """
    if (type(key) is not bytes or len(key) != 32 or namespace not in ("source", "group", "stream", "case", "page", "watch")
            or not parts or len(parts) > 16
            or any(type(p) is not str or not 0 < len(p) <= 4096 for p in parts)):
        raise StateError("invalid identity input")
    try:
        raw = json.dumps([namespace, *parts], ensure_ascii=True, separators=(",", ":")).encode()
        return hmac.new(key, raw, hashlib.sha256).hexdigest()
    except (ValueError, UnicodeError):
        raise StateError("invalid identity input") from None


def _token(value: object) -> str:
    if type(value) is not str or not _TOKEN.fullmatch(value):
        raise StateError("invalid opaque identifier")
    return value


def _time(value: datetime) -> str:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise StateError("invalid state timestamp")
    try:
        return value.astimezone(timezone.utc).isoformat(timespec="microseconds")
    except (ValueError, OverflowError):
        raise StateError("invalid state timestamp") from None


@dataclass(frozen=True)
class CommitResult:
    new_events: int
    duplicate_events: int
    replayed: bool


@dataclass(frozen=True)
class PendingDelivery:
    """A rendered, minimized report awaiting a webhook acknowledgement.

    Payloads are retained only while pending so a crash between send and acknowledgement
    can be retried without rebuilding a window or retaining collector input. An
    acknowledgement retains only its digest for exact-replay safety.
    """
    stream: str
    start: datetime
    payload: bytes


@dataclass(frozen=True)
class Case:
    token: str
    rule_id: str
    agent_id: str
    max_level: int
    tunable: bool
    status: str
    first_seen: datetime
    last_seen: datetime
    reviewed_at: datetime | None


CASE_RETENTION_DAYS = 90
ROUTINE_VALID_DAYS = 30
_CASE_STATUSES = frozenset({"review", "routine", "uncertain"})


def _private_file(path: Path) -> int:
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or info.st_mode & 0o077 or info.st_nlink != 1):
        os.close(fd)
        raise StateError("unsafe state file")
    return fd


class StateStore:
    """Single-process-owner store in a trusted, user-owned 0700 directory.

    One nonblocking lifetime lock serializes cooperating readers and writers.
    Directory ancestors must be operator-controlled. The caller must close the
    store before forking; inheriting an open store into a child is unsupported.
    """

    def __init__(self, directory: Path):
        self._db = None
        self._lock = None
        try:
            directory = Path(directory)
            directory.mkdir(mode=0o700, parents=False, exist_ok=True)
            info = directory.lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                    or info.st_mode & 0o077):
                raise StateError("unsafe state directory")
            self._lock = _private_file(directory / "state.lock")
            fcntl.flock(self._lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            path = directory / "state.sqlite3"
            fd = _private_file(path)
            os.close(fd)
            # Validate possible crash-recovery sidecars before SQLite opens them.
            for suffix in ("-journal", "-wal", "-shm"):
                sidecar = Path(str(path) + suffix)
                if os.path.lexists(sidecar):
                    fd = _private_file(sidecar)
                    os.close(fd)
            self._db = sqlite3.connect(path, timeout=0, isolation_level=None)
            self._db.execute("PRAGMA trusted_schema=OFF")
            self._db.execute("PRAGMA synchronous=FULL")
            self._db.execute("PRAGMA journal_mode=DELETE")
            self._db.execute("PRAGMA secure_delete=ON")
            version = self._db.execute("PRAGMA user_version").fetchone()[0]
            if version not in (0, 1, 2, 3, 4):
                raise StateError("unsupported state schema")
            if version == 0:
                if self._db.execute("SELECT count(*) FROM sqlite_master").fetchone()[0]:
                    raise StateError("unrecognized state schema")
                self._db.executescript("""
                    BEGIN IMMEDIATE;
                    CREATE TABLE checkpoints (stream TEXT PRIMARY KEY, end TEXT NOT NULL);
                    CREATE TABLE events (token TEXT PRIMARY KEY) WITHOUT ROWID;
                    CREATE TABLE windows (
                        stream TEXT NOT NULL, start TEXT NOT NULL, end TEXT NOT NULL,
                        digest TEXT NOT NULL, added INTEGER NOT NULL, duplicates INTEGER NOT NULL,
                        PRIMARY KEY (stream, start)
                    ) WITHOUT ROWID;
                    CREATE TABLE audit (
                        stream TEXT NOT NULL, start TEXT NOT NULL, ordinal INTEGER NOT NULL,
                        group_token TEXT NOT NULL, delivery INTEGER NOT NULL,
                        health INTEGER NOT NULL, reason TEXT NOT NULL, recorded TEXT NOT NULL,
                        PRIMARY KEY (stream, start, ordinal)
                    ) WITHOUT ROWID;
                    CREATE INDEX audit_retention ON audit(recorded);
                    PRAGMA user_version=1;
                    COMMIT;
                """)
                version = 1
            if version == 1:
                self._db.executescript("""
                    BEGIN IMMEDIATE;
                    CREATE TABLE outbox (
                        stream TEXT NOT NULL, start TEXT NOT NULL, payload BLOB,
                        digest TEXT NOT NULL, PRIMARY KEY (stream, start)
                    ) WITHOUT ROWID;
                    PRAGMA user_version=2;
                    COMMIT;
                """)
                version = 2
            if version == 2:
                self._db.executescript("""
                    BEGIN IMMEDIATE;
                    ALTER TABLE audit ADD COLUMN model_identity TEXT;
                    PRAGMA user_version=3;
                    COMMIT;
                """)
                version = 3
            if version == 3:
                self._db.executescript("""
                    BEGIN IMMEDIATE;
                    CREATE TABLE cases (
                        token TEXT PRIMARY KEY, rule_id TEXT NOT NULL, agent_id TEXT NOT NULL,
                        max_level INTEGER NOT NULL, tunable INTEGER NOT NULL,
                        status TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
                        reviewed_at TEXT
                    ) WITHOUT ROWID;
                    CREATE INDEX cases_retention ON cases(last_seen);
                    PRAGMA user_version=4;
                    COMMIT;
                """)
            if self._db.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
                raise StateError("state integrity check failed")
        except Exception:
            self.close()
            raise StateError("state store could not be opened safely") from None

    def close(self) -> None:
        try:
            if self._db is not None:
                self._db.close()
        finally:
            self._db = None
            if self._lock is not None:
                os.close(self._lock)
                self._lock = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def checkpoint(self, stream: str) -> datetime | None:
        try:
            row = self._db.execute("SELECT end FROM checkpoints WHERE stream=?", (_token(stream),)).fetchone()
            return datetime.fromisoformat(row[0]) if row else None
        except Exception:
            raise StateError("state checkpoint read failed") from None

    def origin(self, stream: str) -> datetime | None:
        """Start of a stream's earliest committed window, or None before its first commit."""
        try:
            row = self._db.execute("SELECT min(start) FROM windows WHERE stream=?", (_token(stream),)).fetchone()
            return datetime.fromisoformat(row[0]) if row[0] is not None else None
        except Exception:
            raise StateError("state origin read failed") from None

    def contains(self, event: str) -> bool:
        """Check committed dedupe state while this store's lifetime lock is held."""
        try:
            return self._db.execute("SELECT 1 FROM events WHERE token=?", (_token(event),)).fetchone() is not None
        except Exception:
            raise StateError("state deduplication read failed") from None

    def case(self, token: str, *, now: datetime) -> Case | None:
        """Read metadata only; a stale routine verdict is shown as unreviewed."""
        try:
            row = self._db.execute("SELECT * FROM cases WHERE token=?", (_token(token),)).fetchone()
            if row is None:
                return None
            reviewed = datetime.fromisoformat(row[8]) if row[8] else None
            status = row[5]
            if status == "routine" and (reviewed is None or now.astimezone(timezone.utc) - reviewed >= timedelta(days=ROUTINE_VALID_DAYS)):
                status = "unreviewed"
            return Case(row[0], row[1], row[2], row[3], bool(row[4]), status,
                        datetime.fromisoformat(row[6]), datetime.fromisoformat(row[7]), reviewed)
        except Exception:
            raise StateError("case read failed") from None

    def cases(self, *, now: datetime, limit: int = 2000) -> tuple[Case, ...]:
        """List recent cases without alert descriptions or model output."""
        try:
            if type(limit) is not int or not 1 <= limit <= 2000:
                raise ValueError
            tokens = self._db.execute("SELECT token FROM cases ORDER BY last_seen DESC LIMIT ?", (limit,)).fetchall()
            return tuple(self.case(row[0], now=now) for row in tokens)
        except Exception:
            raise StateError("case list failed") from None

    def routine_cases(self, *, now: datetime) -> tuple[Case, ...]:
        """All still-current routine verdicts for bounded candidate export."""
        try:
            cutoff = _time(now - timedelta(days=ROUTINE_VALID_DAYS))
            tokens = self._db.execute("""SELECT token FROM cases WHERE status='routine'
                AND reviewed_at>? ORDER BY reviewed_at DESC""", (cutoff,)).fetchall()
            return tuple(self.case(row[0], now=now) for row in tokens)
        except Exception:
            raise StateError("routine case read failed") from None

    def mark_case(self, token: str, status: str, *, now: datetime) -> None:
        """An operator verdict changes case metadata, never delivery policy or tuning."""
        try:
            token, stamp = _token(token), _time(now)
            if type(status) is not str or status not in _CASE_STATUSES:
                raise ValueError
            self._db.execute("BEGIN IMMEDIATE")
            changed = self._db.execute("UPDATE cases SET status=?, reviewed_at=? WHERE token=?",
                                       (status, stamp, token)).rowcount
            if changed != 1:
                raise ValueError
            self._db.execute("COMMIT")
        except Exception:
            if self._db is not None and self._db.in_transaction:
                self._db.execute("ROLLBACK")
            raise StateError("case verdict failed") from None

    def commit_window(
        self, stream: str, start: datetime, end: datetime, events: Iterable[str],
        decisions: Iterable[tuple], *, recorded_at: datetime,
        pending_delivery: bytes | None = None,
        cases: Iterable[tuple[str, str, str, int, bool]] = (),
    ) -> CommitResult:
        """Atomically dedupe, record final decisions, and advance one stream.

        Ordered input must replay exactly. A new window must start at the prior
        checkpoint. Independent historical/daily streams may overlap; event
        identity is global. Iteration, validation and disk failures roll back.
        Callers must bound iterables and enforce the runner's wall-clock budget.
        """
        try:
            stream, start, end = _token(stream), _time(start), _time(end)
            recorded = _time(recorded_at)
            if start >= end or recorded < end:
                raise StateError("invalid state window")
            if pending_delivery is not None and (type(pending_delivery) is not bytes
                                                or not 1 <= len(pending_delivery) <= OUTBOX_PAYLOAD_LIMIT):
                raise StateError("invalid pending delivery")
            self._db.execute("BEGIN IMMEDIATE")
            prior = self._db.execute(
                "SELECT end,digest,added,duplicates FROM windows WHERE stream=? AND start=?",
                (stream, start),
            ).fetchone()
            checkpoint = self._db.execute("SELECT end FROM checkpoints WHERE stream=?", (stream,)).fetchone()
            if prior is None and checkpoint is not None and checkpoint[0] != start:
                raise StateError("noncontiguous state window")
            digest = hashlib.sha256()
            added = duplicates = 0
            for token in events:
                token = _token(token)
                digest.update(b"event:" + token.encode() + b"\n")
                if prior is None:
                    changed = self._db.execute("INSERT OR IGNORE INTO events VALUES (?)", (token,)).rowcount
                    added += changed
                    duplicates += 1 - changed
            digest.update(b"decisions\n")
            decision_count = 0
            for ordinal, assessment in enumerate(decisions):
                decision_count += 1
                if type(assessment) not in (tuple, list) or len(assessment) not in (2, 3):
                    raise StateError("invalid audit decision")
                group, decision = assessment[:2]
                model_identity = assessment[2] if len(assessment) == 3 else None
                group = _token(group)
                if (type(decision) is not Decision or type(decision.delivery_required) is not bool
                        or type(decision.health_failure) is not bool or type(decision.reason) is not str
                        or decision.reason not in _REASONS
                        or (decision.delivery_required, decision.health_failure) != _REASONS[decision.reason]):
                    raise StateError("invalid audit decision")
                if (model_identity is not None
                        and (type(model_identity) is not str
                             or _MODEL_IDENTITY.fullmatch(model_identity) is None)):
                    raise StateError("invalid audit decision")
                if (model_identity is not None
                        and decision.reason not in {"high_confidence_benign", "model_requires_review",
                                                   "invalid_model_result"}):
                    raise StateError("invalid audit decision")
                values = (group, int(decision.delivery_required), int(decision.health_failure), decision.reason)
                digest.update(json.dumps(values, separators=(",", ":")).encode() + b"\n")
                if prior is None:
                    self._db.execute("""INSERT INTO audit
                        (stream,start,ordinal,group_token,delivery,health,reason,recorded,model_identity)
                        VALUES (?,?,?,?,?,?,?,?,?)""",
                                     (stream, start, ordinal, *values, recorded, model_identity))
            if added and not decision_count:
                raise StateError("new events require an audit decision")
            case_rows = list(cases)
            if len(case_rows) > decision_count:
                raise StateError("invalid case records")
            if case_rows:
                digest.update(b"cases\n")
            for item in case_rows:
                if (type(item) is not tuple or len(item) != 5 or type(item[1]) is not str
                        or type(item[2]) is not str or not 0 < len(item[1]) <= 64
                        or not 0 < len(item[2]) <= 64 or type(item[3]) is not int
                        or not 0 <= item[3] <= 16 or type(item[4]) is not bool):
                    raise StateError("invalid case records")
                token = _token(item[0])
                digest.update(json.dumps((token, *item[1:]), separators=(",", ":")).encode() + b"\n")
                if prior is None:
                    self._db.execute("""INSERT INTO cases
                        (token,rule_id,agent_id,max_level,tunable,status,first_seen,last_seen,reviewed_at)
                        VALUES (?,?,?,?,?,'unreviewed',?,?,NULL)
                        ON CONFLICT(token) DO UPDATE SET
                        max_level=max(cases.max_level,excluded.max_level),
                        tunable=min(cases.tunable,excluded.tunable),last_seen=excluded.last_seen""",
                        (token, item[1], item[2], item[3], int(item[4]), recorded, recorded))
            if prior is not None:
                if prior[:2] != (end, digest.hexdigest()):
                    raise StateError("inconsistent window replay")
                existing = self._db.execute("SELECT digest FROM outbox WHERE stream=? AND start=?",
                                            (stream, start)).fetchone()
                supplied = hashlib.sha256(pending_delivery).hexdigest() if pending_delivery else None
                if (existing is None) != (pending_delivery is None) or (existing and existing[0] != supplied):
                    raise StateError("inconsistent pending delivery replay")
                result = CommitResult(prior[2], prior[3], True)
            else:
                self._db.execute("INSERT INTO windows VALUES (?,?,?,?,?,?)",
                                 (stream, start, end, digest.hexdigest(), added, duplicates))
                self._db.execute("INSERT INTO checkpoints VALUES (?,?) ON CONFLICT(stream) DO UPDATE SET end=excluded.end",
                                 (stream, end))
                if pending_delivery is not None:
                    self._db.execute("INSERT INTO outbox VALUES (?,?,?,?)", (stream, start, pending_delivery,
                                     hashlib.sha256(pending_delivery).hexdigest()))
                result = CommitResult(added, duplicates, False)
            self._db.execute("COMMIT")
            return result
        except BaseException as exc:
            if self._db is not None and self._db.in_transaction:
                try:
                    self._db.execute("ROLLBACK")
                except sqlite3.Error:
                    self.close()
            if not isinstance(exc, Exception):
                raise
            raise StateError("state window commit failed") from None

    def pending_delivery(self, stream: str, start: datetime) -> PendingDelivery | None:
        """Return one private pending payload. Do not log or render it again."""
        try:
            stream, start = _token(stream), _time(start)
            row = self._db.execute("SELECT payload FROM outbox WHERE stream=? AND start=?", (stream, start)).fetchone()
            return PendingDelivery(stream, datetime.fromisoformat(start), bytes(row[0])) if row and row[0] is not None else None
        except Exception:
            raise StateError("pending delivery read failed") from None

    def oldest_pending_delivery(self, stream: str) -> PendingDelivery | None:
        """Return the oldest unacknowledged payload for a stream, if any.

        Schedulers must retry this before advancing to a newer source window, so an
        accepted commit cannot leave a minimized report retained indefinitely.
        """
        try:
            stream = _token(stream)
            row = self._db.execute(
                "SELECT start,payload FROM outbox WHERE stream=? AND payload IS NOT NULL ORDER BY start LIMIT 1",
                (stream,),
            ).fetchone()
            return PendingDelivery(stream, datetime.fromisoformat(row[0]), bytes(row[1])) if row else None
        except Exception:
            raise StateError("pending delivery read failed") from None

    def delivery_acknowledged(self, stream: str, start: datetime) -> bool:
        """Whether a matching report was acknowledged; no payload is returned."""
        try:
            stream, start = _token(stream), _time(start)
            row = self._db.execute("SELECT payload FROM outbox WHERE stream=? AND start=?", (stream, start)).fetchone()
            return row is not None and row[0] is None
        except Exception:
            raise StateError("delivery acknowledgement read failed") from None

    def acknowledge_delivery(self, stream: str, start: datetime, payload: bytes) -> None:
        """Discard the exact payload after a successful acknowledgement, retaining its digest."""
        try:
            stream, start = _token(stream), _time(start)
            if type(payload) is not bytes or not 1 <= len(payload) <= OUTBOX_PAYLOAD_LIMIT:
                raise ValueError
            self._db.execute("BEGIN IMMEDIATE")
            earlier = self._db.execute(
                "SELECT 1 FROM outbox WHERE stream=? AND payload IS NOT NULL AND start < ? LIMIT 1",
                (stream, start),
            ).fetchone()
            if earlier is not None:
                raise ValueError
            row = self._db.execute("SELECT digest FROM outbox WHERE stream=? AND start=?", (stream, start)).fetchone()
            if row is None or not hmac.compare_digest(row[0], hashlib.sha256(payload).hexdigest()):
                raise ValueError
            self._db.execute("UPDATE outbox SET payload=NULL WHERE stream=? AND start=?", (stream, start))
            self._db.execute("COMMIT")
        except Exception:
            if self._db is not None and self._db.in_transaction:
                self._db.execute("ROLLBACK")
            raise StateError("delivery acknowledgement failed") from None

    def prune_audit(self, *, now: datetime) -> int:
        """Remove assessment audit older than seven days; retain dedupe/checkpoints.

        These are policy assessments, not pending delivery records. No raw alert
        store exists here. Actual delivery acknowledgements need their own outbox.
        """
        try:
            cutoff = _time(now - timedelta(days=7))
            return self._db.execute("DELETE FROM audit WHERE recorded < ?", (cutoff,)).rowcount
        except Exception:
            raise StateError("audit retention failed") from None

    def prune_cases(self, *, now: datetime) -> int:
        """Discard case metadata 90 days after its last appearance."""
        try:
            cutoff = _time(now - timedelta(days=CASE_RETENTION_DAYS))
            return self._db.execute("DELETE FROM cases WHERE last_seen < ?", (cutoff,)).rowcount
        except Exception:
            raise StateError("case retention failed") from None
