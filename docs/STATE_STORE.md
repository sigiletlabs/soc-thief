# State store

`soc_thief.state.StateStore` is a local SQLite database of metadata. It records which events were
already processed, what was decided about each group, where each stream has reached, any report
still waiting to be delivered, and case verdicts. It never stores raw alerts, alert labels, model
prose or source cursor values.

## Opaque identifiers

`opaque_key(key, namespace, *parts)` derives HMAC-SHA256 identifiers from a 32-byte secret and
structured parts. The namespaces are `source` (index plus document ID), `group` (the grouping
components), `stream` (an intake stream), `case`, `page` and `watch`.

The secret is the identity key, read from `SOC_THIEF_IDENTITY_KEY_FILE`: one line of 64 lowercase
hex characters. Generate it once:

```sh
python3 -c 'import secrets; print(secrets.token_hex(32))' > identity_key
chmod 600 identity_key
```

Keep it out of SQLite, Git and logs, and back it up separately from the database. Changing it on
an existing store changes every identity, which breaks deduplication. That is not supported.

## Files and locking

Pass a directory to `StateStore(Path(...))`. Its parent must already exist and be trusted. The
directory is created `0700` if absent; an existing one must belong to the current user with no
group or other permissions. The database and lock files are `0600`. Symlinks, hard links,
non-regular files, wrong owners and loose permissions are rejected, including on SQLite's recovery
side files.

A non-blocking advisory lock is held for the store's whole lifetime, including reads, so a second
process fails immediately. Use the store as a context manager and close it before forking. This is
a local-filesystem lock; do not put the store on a network filesystem. SQLite runs with full
synchronous rollback-journal transactions and secure delete, and checks integrity on open. An
unknown schema version fails closed.

## Committing a window

`contains(event_token)` checks whether an event was already committed. The caller also
deduplicates within the current window before grouping.

`commit_window(stream, start, end, events, decisions, recorded_at=...)` takes ordered opaque event
tokens and `(group_token, Decision)` or `(group_token, Decision, model_identity)` assessments. Rules:

- The window must be non-empty, timezone-aware, and closed by `recorded_at`.
- The first window of a stream starts wherever the caller chooses. Each later window must start
  exactly at that stream's checkpoint. A gap or overlap is refused.
- Streams (`daily`, `reconcile`, `backfill`) share event deduplication.
- An empty window may advance with no decisions. New events require at least one final decision.
  Preflight-only decisions and inconsistent reason and flag combinations are refused.

Event insertion, the decision audit, replay metadata, the pending report and the checkpoint commit
in one transaction. Any error rolls back all of them. `StateError` has fixed text and means "send a
health report".

If a commit's acknowledgement is lost, reopening and replaying the same inputs is safe. A replay
must match the stream, start, end and ordered content exactly; changed input fails closed. An exact
replay returns the original counts with `replayed=True` and writes nothing new. The replay digest
contains no source text.

The checkpoint marks the end of an ingestion window. It is not a search cursor and not proof of
delivery. Commit only after the collector has fully validated the window. The store cannot prove a
snapshot was complete or rebuild groups from opaque keys; those are the runner's job.
`origin(stream)` returns a stream's first committed start; reconcile and backfill anchor to the
`daily` stream's origin.

## The pending report outbox

When a window needs delivery, the runner stores the rendered, minimised report in the same
transaction as the checkpoint. A delivery failure therefore can never advance a window without
leaving a report to retry. A pending report is the full page sequence plus the digest attachment,
bounded by `state.OUTBOX_PAYLOAD_LIMIT`. It is protected by the same file checks and must never be
logged or reused as a source of report text.

- `oldest_pending_delivery(stream)` returns the oldest unacknowledged report. The daily, reconcile
  and backfill entry points retry it before building any collector or model, so a newer window can
  never strand an older report.
- `acknowledge_delivery` accepts only the exact payload that was sent, securely removes it and
  keeps its SHA-256 digest, so a replay cannot send it twice.
- The store refuses to acknowledge a later report while an earlier one in the same stream is still
  pending.

This is at-least-once delivery. A crash after Discord accepts a message but before the local
acknowledgement can produce a duplicate message.

## Retention

The assessment audit holds a group token, a fixed decision code, delivery and health flags, the
window, the recording time and an optional model identity (1 to 256 characters from letters,
digits and `._:/+-`). Protected, critical, breach and tuned groups have no model identity because
no model ran. `prune_audit(now=...)` deletes rows older than seven days using SQLite secure delete.
The runner calls it after every committed window and every acknowledged report; a pruning failure
is a state failure.

Deduplication tokens, replay hashes and checkpoints are kept indefinitely so old events are never
processed twice. Plan for slow growth. Case records last 90 days after a group was last seen.

Back up the database with the supplied helper (`deploy/bin/soc-thief-backup`), which uses SQLite's
backup API, validates the copy and keeps seven days. Backups need their own encryption and
retention.

## Schema versions

The schema version is stored in `PRAGMA user_version`. Opening an older store migrates it forward
inside one transaction; existing rows are kept. A store newer than the code understands fails
closed. Migrations never rewrite a window's replay digest.

## Tests

`PYTHONPATH=src python3 -m unittest discover -q` includes synthetic tests for transactions,
cross-stream deduplication, exact replay, gap and overlap refusal, write and iterator failures,
rollback, interruption, crash recovery, the ownership lock, retention boundaries, private-file
checks, schema and corruption handling, and identifier isolation.
