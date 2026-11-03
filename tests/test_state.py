"""Synthetic transaction, recovery and metadata isolation checks."""

from contextlib import closing
from datetime import datetime, timedelta, timezone
import multiprocessing
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest

from soc_thief.policy import Decision
from soc_thief.delivery import ATTACHMENT_LIMIT, MAX_PAGES, _PAYLOAD_LIMIT
from soc_thief.state import OUTBOX_PAYLOAD_LIMIT, StateError, StateStore, opaque_key


START = datetime(2026, 1, 1, tzinfo=timezone.utc)
END = START + timedelta(hours=1)
STREAM = "a" * 64
EVENT = "b" * 64
GROUP = "c" * 64
DECISION = Decision(True, False, "model_requires_review")


def crash_mid_transaction(path):
    with StateStore(Path(path)) as store:
        def events():
            yield EVENT
            os._exit(23)
        store.commit_window(STREAM, START, END, events(), [(GROUP, DECISION)], recorded_at=END)


class OutboxLimitTests(unittest.TestCase):
    def test_outbox_accepts_the_widest_report_the_renderer_can_produce(self):
        # A pending report is one JSON array of up to MAX_PAGES payloads. If the
        # renderer can outgrow the outbox, a wide day commits nothing and fails the window.
        # A digest row also carries its attachment, JSON-escaped, plus framing.
        self.assertGreaterEqual(OUTBOX_PAYLOAD_LIMIT, MAX_PAGES * _PAYLOAD_LIMIT + ATTACHMENT_LIMIT + 1024)


class StateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "state"

    def commit(self, store, events=(EVENT,), decisions=((GROUP, DECISION),), **kwargs):
        return store.commit_window(kwargs.get("stream", STREAM), kwargs.get("start", START),
                                   kwargs.get("end", END), events, decisions,
                                   recorded_at=kwargs.get("recorded_at", END),
                                   pending_delivery=kwargs.get("pending_delivery"))

    def count(self, table):
        with closing(sqlite3.connect(self.path / "state.sqlite3")) as db:
            return db.execute("SELECT count(*) FROM " + table).fetchone()[0]

    def test_commit_reopen_replay_and_global_dedupe(self):
        with StateStore(self.path) as store:
            self.assertIsNone(store.checkpoint(STREAM))
            self.assertFalse(store.contains(EVENT))
            result = self.commit(store, events=(EVENT, EVENT))
            self.assertEqual((result.new_events, result.duplicate_events), (1, 1))
            self.assertTrue(store.contains(EVENT))
        with StateStore(self.path) as store:
            self.assertEqual(store.checkpoint(STREAM), END)
            self.assertTrue(self.commit(store, events=(EVENT, EVENT)).replayed)
            result = self.commit(store, stream="d" * 64)
            self.assertEqual((result.new_events, result.duplicate_events), (0, 1))
        self.assertEqual(self.count("events"), 1)
        self.assertEqual(self.count("audit"), 2)

    def test_empty_window_and_contiguous_progress(self):
        with StateStore(self.path) as store:
            self.commit(store, events=(), decisions=())
            self.commit(store, start=END, end=END + timedelta(hours=1),
                        recorded_at=END + timedelta(hours=1))
            self.assertEqual(store.checkpoint(STREAM), END + timedelta(hours=1))

    def test_origin_is_first_committed_window_start_per_stream(self):
        with StateStore(self.path) as store:
            self.assertIsNone(store.origin(STREAM))
            self.commit(store, events=(), decisions=())
            self.commit(store, start=END, end=END + timedelta(hours=1), events=(), decisions=(),
                        recorded_at=END + timedelta(hours=1))
            self.assertEqual(store.origin(STREAM), START)
            self.assertIsNone(store.origin("d" * 64))
            with self.assertRaises(StateError):
                store.origin("not-a-token")

    def test_case_verdict_expires_and_never_changes_window_replay(self):
        case_id = "d" * 64
        with StateStore(self.path) as store:
            store.commit_window(STREAM, START, END, (EVENT,), ((GROUP, DECISION),),
                                recorded_at=END, cases=((case_id, "100", "001", 3, True),))
            store.mark_case(case_id, "routine", now=END)
            self.assertEqual(store.case(case_id, now=END).status, "routine")
            self.assertEqual(store.case(case_id, now=END + timedelta(days=30)).status, "unreviewed")
            self.assertTrue(store.commit_window(STREAM, START, END, (EVENT,), ((GROUP, DECISION),),
                                                recorded_at=END, cases=((case_id, "100", "001", 3, True),)).replayed)
            with self.assertRaises(StateError):
                store.commit_window(STREAM, START, END, (EVENT,), ((GROUP, DECISION),),
                                    recorded_at=END, cases=((case_id, "100", "001", 3, False),))
            self.assertEqual(store.case(case_id, now=END).status, "routine")
            with self.assertRaises(StateError):
                store.mark_case("e" * 64, "routine", now=END)
            with self.assertRaises(StateError):
                store.mark_case(case_id, "mute", now=END)
            self.assertEqual(store.prune_cases(now=END + timedelta(days=91)), 1)
            self.assertIsNone(store.case(case_id, now=END + timedelta(days=91)))

    def test_case_commit_failure_rolls_back_window(self):
        with StateStore(self.path) as store:
            with self.assertRaises(StateError):
                store.commit_window(STREAM, START, END, (EVENT,), ((GROUP, DECISION),),
                                    recorded_at=END, cases=(("bad", "100", "001", 3, True),))
            self.assertIsNone(store.checkpoint(STREAM))
            self.assertEqual(store.cases(now=END), ())

    def test_gap_overlap_and_inconsistent_replay_fail_without_mutation(self):
        with StateStore(self.path) as store:
            self.commit(store)
            for start, end in ((START - timedelta(hours=1), START),
                               (START + timedelta(minutes=1), END),
                               (END + timedelta(hours=1), END + timedelta(hours=2)),
                               (START, END + timedelta(hours=1))):
                with self.assertRaises(StateError):
                    self.commit(store, start=start, end=end, recorded_at=end)
            with self.assertRaises(StateError):
                self.commit(store, events=("e" * 64,))
            with self.assertRaises(StateError):
                self.commit(store, decisions=((GROUP, Decision(False, False, "high_confidence_benign")),))
            self.assertEqual(store.checkpoint(STREAM), END)
        self.assertEqual(self.count("events"), 1)
        self.assertEqual(self.count("audit"), 1)

    def test_iterator_failure_rolls_back_everything_and_hides_details(self):
        def failed():
            yield EVENT
            raise RuntimeError("synthetic sensitive marker")
        with StateStore(self.path) as store:
            with self.assertRaises(StateError) as caught:
                self.commit(store, events=failed())
            self.assertNotIn("sensitive", str(caught.exception))
            self.assertTrue(caught.exception.__suppress_context__)
            self.assertIsNone(store.checkpoint(STREAM))
            self.assertFalse(store.contains(EVENT))
            self.assertEqual(self.commit(store).new_events, 1)

    def test_audit_iteration_failure_rolls_back_events_and_audit(self):
        def failed():
            yield GROUP, DECISION
            raise ValueError("synthetic error")
        with StateStore(self.path) as store:
            with self.assertRaises(StateError):
                self.commit(store, decisions=failed())
            self.assertFalse(store.contains(EVENT))
        for table in ("audit", "events", "windows", "checkpoints"):
            self.assertEqual(self.count(table), 0)

    def test_sqlite_write_failure_does_not_advance_checkpoint(self):
        with StateStore(self.path) as store:
            store._db.execute("PRAGMA query_only=ON")
            with self.assertRaises(StateError):
                self.commit(store)
            store._db.execute("PRAGMA query_only=OFF")
            self.assertIsNone(store.checkpoint(STREAM))
            self.assertEqual(self.commit(store).new_events, 1)

    def test_process_crash_recovers_uncommitted_state_and_releases_lock(self):
        process = multiprocessing.get_context("spawn").Process(
            target=crash_mid_transaction, args=(str(self.path),))
        process.start()
        process.join(10)
        if process.is_alive():
            process.kill()
            process.join(2)
            self.fail("synthetic crash worker exceeded deadline")
        self.assertEqual(process.exitcode, 23)
        with StateStore(self.path) as store:
            self.assertIsNone(store.checkpoint(STREAM))
            self.assertFalse(store.contains(EVENT))
            self.assertEqual(self.commit(store).new_events, 1)

    def test_second_owner_is_rejected_then_can_reopen(self):
        with StateStore(self.path):
            with self.assertRaises(StateError):
                StateStore(self.path)
        with StateStore(self.path) as store:
            self.commit(store)

    def test_retention_boundary_preserves_dedupe_and_replay(self):
        with StateStore(self.path) as store:
            self.commit(store)
            self.assertEqual(store.prune_audit(now=END + timedelta(days=7)), 0)
            self.assertEqual(store.prune_audit(now=END + timedelta(days=7, microseconds=1)), 1)
            self.assertTrue(store.contains(EVENT))
            self.assertTrue(self.commit(store).replayed)
            self.assertEqual(store.checkpoint(STREAM), END)
        self.assertEqual(self.count("audit"), 0)

    def test_pending_delivery_is_atomic_retryable_and_acknowledged_without_payload_retention(self):
        payload = b'{"content":"synthetic minimized report","allowed_mentions":{"parse":[]}}'
        with StateStore(self.path) as store:
            self.commit(store, pending_delivery=payload)
            pending = store.pending_delivery(STREAM, START)
            self.assertIsNotNone(pending)
            self.assertEqual(pending.payload, payload)
            with self.assertRaises(StateError):
                store.acknowledge_delivery(STREAM, START, b"different")
            store.acknowledge_delivery(STREAM, START, payload)
            self.assertIsNone(store.pending_delivery(STREAM, START))
            self.assertTrue(store.delivery_acknowledged(STREAM, START))
            self.assertTrue(self.commit(store, pending_delivery=payload).replayed)
        self.assertNotIn(payload, (self.path / "state.sqlite3").read_bytes())

    def test_oldest_pending_delivery_is_selected_per_stream(self):
        payload = b'{"content":"synthetic minimized report","allowed_mentions":{"parse":[]}}'
        later = END + timedelta(days=1)
        other = opaque_key(b"k" * 32, "stream", "other")
        with StateStore(self.path) as store:
            self.commit(store, pending_delivery=payload)
            store.commit_window(STREAM, END, later, [], [], recorded_at=later, pending_delivery=payload)
            store.commit_window(other, START, END, [], [], recorded_at=END, pending_delivery=payload)
            pending = store.oldest_pending_delivery(STREAM)
            self.assertIsNotNone(pending)
            self.assertEqual((pending.stream, pending.start, pending.payload), (STREAM, START, payload))
            store.acknowledge_delivery(STREAM, START, payload)
            self.assertEqual(store.oldest_pending_delivery(STREAM).start, END)
            self.assertIsNone(store.oldest_pending_delivery(opaque_key(b"k" * 32, "stream", "missing")))

    def test_newer_pending_delivery_cannot_be_acknowledged_before_the_oldest(self):
        payload = b'{"content":"synthetic minimized report","allowed_mentions":{"parse":[]}}'
        later = END + timedelta(days=1)
        with StateStore(self.path) as store:
            self.commit(store, pending_delivery=payload)
            store.commit_window(STREAM, END, later, [], [], recorded_at=later, pending_delivery=payload)
            with self.assertRaises(StateError):
                store.acknowledge_delivery(STREAM, END, payload)
            self.assertEqual(store.oldest_pending_delivery(STREAM).start, START)
            self.assertIsNotNone(store.pending_delivery(STREAM, END))

    def test_files_private_and_raw_identity_never_persisted(self):
        source = "synthetic-sensitive-source-identity"
        event = opaque_key(b"k" * 32, "source", "synthetic-index", source)
        with StateStore(self.path) as store:
            self.commit(store, events=(event,))
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o700)
        for file in self.path.iterdir():
            self.assertEqual(file.stat().st_mode & 0o777, 0o600)
            self.assertNotIn(source.encode(), file.read_bytes())

    def test_unsafe_directory_file_and_sidecar_rejected(self):
        self.path.mkdir(mode=0o755)
        with self.assertRaises(StateError):
            StateStore(self.path)
        self.path.chmod(0o700)
        db = self.path / "state.sqlite3"
        db.touch(mode=0o644)
        with self.assertRaises(StateError):
            StateStore(self.path)
        db.unlink()
        target = Path(self.temp.name) / "target"
        target.touch(mode=0o600)
        db.symlink_to(target)
        with self.assertRaises(StateError):
            StateStore(self.path)
        db.unlink()
        journal = self.path / "state.sqlite3-journal"
        journal.symlink_to(target)
        with self.assertRaises(StateError):
            StateStore(self.path)
        journal.unlink()
        db.unlink()
        os.link(target, db)
        with self.assertRaises(StateError):
            StateStore(self.path)

    def test_corrupt_or_unknown_schema_fails_closed(self):
        with StateStore(self.path):
            pass
        with closing(sqlite3.connect(self.path / "state.sqlite3")) as db:
            db.execute("PRAGMA user_version=999")
        with self.assertRaises(StateError):
            StateStore(self.path)

    def test_schema_migrates_to_model_identity_audit_without_losing_rows(self):
        with StateStore(self.path) as store:
            self.commit(store)
        # Reconstruct the prior schema with one retained audit row, then reopen through
        # the public constructor to exercise the version-2 migration.
        with closing(sqlite3.connect(self.path / "state.sqlite3")) as db:
            db.execute("ALTER TABLE audit DROP COLUMN model_identity")
            db.execute("DROP TABLE cases")
            db.execute("PRAGMA user_version=2")
        with StateStore(self.path):
            pass
        with closing(sqlite3.connect(self.path / "state.sqlite3")) as db:
            self.assertEqual(db.execute("PRAGMA user_version").fetchone(), (4,))
            columns = {row[1] for row in db.execute("PRAGMA table_info(audit)")}
            self.assertIn("model_identity", columns)
            self.assertEqual(db.execute("SELECT reason,model_identity FROM audit").fetchone(),
                             ("model_requires_review", None))

    def test_model_identity_is_audited_only_for_model_reviewed_decisions(self):
        with StateStore(self.path) as store:
            self.commit(store, decisions=((GROUP, DECISION, "qwen3:4b"),))
        with closing(sqlite3.connect(self.path / "state.sqlite3")) as db:
            self.assertEqual(db.execute("SELECT model_identity FROM audit").fetchone(), ("qwen3:4b",))
        for index, identity in enumerate(("", " qwen3:4b", "qwen3:4b\nleak",
                                          "qwen3:4b?token=value", "x" * 257)):
            other = Path(self.temp.name) / ("invalid-" + str(index))
            with self.subTest(identity=identity):
                with StateStore(other) as store:
                    with self.assertRaises(StateError):
                        store.commit_window(STREAM, START, END, (EVENT,),
                                            ((GROUP, DECISION, identity),), recorded_at=END)
        (self.path / "state.sqlite3").write_bytes(b"synthetic corruption")
        with self.assertRaises(StateError):
            StateStore(self.path)

    def test_invalid_input_and_preflight_decisions_fail_closed(self):
        with StateStore(self.path) as store:
            for events, decisions in [
                (("raw identifier",), ((GROUP, DECISION),)),
                ((EVENT,), ()),
                ((EVENT,), ((GROUP, Decision(False, False, "model_review_required")),)),
                ((EVENT,), ((GROUP, Decision(False, True, "pipeline_failure")),)),
                ((EVENT,), ((GROUP, Decision(True, False, "pipeline_failure")),)),
                ((EVENT,), ((GROUP, Decision(True, False, "untrusted text")),)),
            ]:
                with self.assertRaises(StateError):
                    self.commit(store, events=events, decisions=decisions)
                self.assertIsNone(store.checkpoint(STREAM))
            for start, end in ((START.replace(tzinfo=None), END), (END, START), (START, START)):
                with self.assertRaises(StateError):
                    self.commit(store, start=start, end=end)
        self.assertEqual(self.count("events"), 0)

    def test_tuned_reason_codes_are_accepted_only_with_non_delivery_flags(self):
        with StateStore(self.path) as store:
            for reason in ("tuned_mute", "tuned_low"):
                for flags in ((True, False), (False, True), (True, True)):
                    with self.subTest(reason=reason, flags=flags), self.assertRaises(StateError):
                        self.commit(store, decisions=((GROUP, Decision(*flags, reason)),))
                    self.assertIsNone(store.checkpoint(STREAM))
            self.commit(store, decisions=((GROUP, Decision(False, False, "tuned_mute")),
                                          ("d" * 64, Decision(False, False, "tuned_low"))))
            self.assertEqual(store.checkpoint(STREAM), END)
        with closing(sqlite3.connect(self.path / "state.sqlite3")) as db:
            self.assertEqual(db.execute("SELECT reason,delivery,health FROM audit ORDER BY ordinal").fetchall(),
                             [("tuned_mute", 0, 0), ("tuned_low", 0, 0)])

    def test_hmac_namespace_and_component_boundaries(self):
        key = b"k" * 32
        self.assertNotEqual(opaque_key(key, "source", "ab", "c"), opaque_key(key, "source", "a", "bc"))
        self.assertNotEqual(opaque_key(key, "source", "a"), opaque_key(key, "group", "a"))
        self.assertEqual(opaque_key(key, "source", "a"), opaque_key(key, "source", "a"))
        with self.assertRaises(StateError):
            opaque_key(b"short", "source", "a")

    def test_checkpoint_write_failure_rolls_back_prior_writes(self):
        with StateStore(self.path) as store:
            store._db.execute("""CREATE TEMP TRIGGER reject_checkpoint BEFORE INSERT ON checkpoints
                              BEGIN SELECT RAISE(ABORT, 'synthetic storage failure'); END""")
            with self.assertRaises(StateError):
                self.commit(store)
            self.assertIsNone(store.checkpoint(STREAM))
            self.assertFalse(store.contains(EVENT))
        for table in ("events", "audit", "windows", "checkpoints"):
            self.assertEqual(self.count(table), 0)

    def test_interrupt_rolls_back_and_remains_interrupt(self):
        def interrupted():
            yield EVENT
            raise KeyboardInterrupt
        with StateStore(self.path) as store:
            with self.assertRaises(KeyboardInterrupt):
                self.commit(store, events=interrupted())
            self.assertIsNone(store.checkpoint(STREAM))
            self.assertFalse(store.contains(EVENT))

    def test_equivalent_timezone_window_replays(self):
        with StateStore(self.path) as store:
            self.commit(store)
            offset = timezone(timedelta(hours=11))
            self.assertTrue(self.commit(store, start=START.astimezone(offset),
                                        end=END.astimezone(offset)).replayed)


if __name__ == "__main__":
    unittest.main()
