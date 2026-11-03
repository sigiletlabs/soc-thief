# Collector

The collector (`src/soc_thief/collector.py`) reads one bounded window of alerts from the Wazuh
indexer, read-only. It does not store records, call the model, send reports or delete anything.
It was built and tested against Wazuh 4.14 (OpenSearch-based indexer).

## Settings

`CollectorConfig.from_environment()` reads four file-path settings:

| Setting | File contents |
| --- | --- |
| `WAZUH_INDEXER_URL_FILE` | The indexer HTTPS origin, for example `https://indexer.example.internal:9200`, with no path, query, fragment or credentials |
| `WAZUH_INDEXER_USERNAME_FILE` | The dedicated read-only indexer username |
| `WAZUH_INDEXER_PASSWORD_FILE` | Its password |
| `WAZUH_INDEXER_CA_FILE` | Optional PEM CA bundle. Without it, system trust is used. |

Keep these files in a private directory outside Git, mode `0700`. Each file must be a regular file
owned by you or root, with no group or other permissions (`0600`, or `0400` on a read-only mount).
A final symlink is rejected. One UTF-8 value per file; a trailing newline is fine, embedded control
characters are not. Spaces in a password are kept. Never put credentials in environment variables
or command-line flags, and never turn off certificate or hostname checks.

The index pattern is fixed at `wazuh-alerts-*`. The origin you supply is the only destination.
Redirects and proxy environment variables are ignored, and there is no endpoint discovery. Your
host egress policy should still restrict the service account to that destination.

## The read-only indexer user

Create a dedicated internal indexer user for Soc Thief. Do not reuse an administrator, dashboard,
Filebeat or manager identity. Map it directly to one custom role:

- cluster permission `cluster_composite_ops_ro`;
- index pattern `wazuh-alerts-*`;
- index action group `read`, plus `indices:admin/mappings/get` if your version lists it
  separately;
- point-in-time actions, for example `indices:data/read/point_in_time/create` and
  `indices:data/read/point_in_time/delete` (some versions evaluate delete as a cluster permission);
- no write, delete, index-management, security-management or tenant-write permission.

An empty backend-role list is fine when the user is mapped directly.

Check the result from the user's side: `_count` on `wazuh-alerts-*` should succeed, while
`_cat/indices`, any write, and `cluster:monitor/state` should be refused. Never widen the role to
make collection pass.

The `own_index` default. OpenSearch ships a static `own_index` role that grants
`cluster_composite_ops` and `indices_all` on an index named after the user. Many installs map it to
`Users: *`, so your Soc Thief user inherits it like everyone else. The custom role is read-only,
but the user's total permissions are not strictly minimal while that mapping exists. Removing the
wildcard is a cluster-wide change that affects every user, so plan it separately if you decide to.

Also confirm the custom role has no tenant permissions and no document-level security, field-level
security or field masking that would make collection silently incomplete.

References:
[Wazuh RBAC](https://documentation.wazuh.com/current/user-manual/user-administration/rbac.html),
[OpenSearch users and roles](https://docs.opensearch.org/latest/security/access-control/users-roles/),
[default action groups](https://docs.opensearch.org/latest/security/access-control/default-action-groups/),
[static roles](https://github.com/opensearch-project/security/blob/main/src/main/resources/static_config/static_roles.yml).

## How a window is collected

- Windows carry a timezone, include the start and exclude the end.
- Requests select only allowlisted source fields and turn off partial search results.
- Results are ordered by timestamp, then index, then document ID. Index plus document ID is the
  source identity, even when two indices hold the same document ID.
- Every response must report no timeout, no failed shards, a complete hit envelope and an exact
  total. Missing fields, a changing total, an event outside the window, inconsistent counts, a bad
  cursor or a cursor that does not advance all fail the collection. Each page is validated before
  any of its records is used.
- Required event fields are timestamp, rule ID, rule level and agent ID. A missing
  `rule.description` becomes the fixed text `[rule description missing]`. Wrong types, empty values
  and oversized values are refused.
- Defaults: 500 records per page, at most 1,000 pages per window, an 8 MiB response cap, a
  20-second server timeout and a 30-second socket timeout. Running out of pages is an error, never
  a finished window. The runner adds its own wall-clock deadline.
- Network errors and HTTP 429, 502, 503 and 504 are retried up to three attempts with 1 and 2
  second back-off. Other errors fail at once. Error messages never include the endpoint,
  credentials, response body or alert content.

## Point-in-time snapshots

`collect()` always reads through one OpenSearch point in time (PIT), so a window is internally
consistent.

The PIT context limit. A PIT takes one search context per shard. Wazuh writes one index per
day, so a pattern that covers months of history can need hundreds of contexts. The indexer's
`search.max_open_pit_context` setting defaults to 300. Past that, PIT creation fails with HTTP 429
`rejected_execution_exception`, and Soc Thief reports a generic `indexer search failed`. If you see
that error, suspect this limit first.

Soc Thief avoids the limit for daily work: it opens only the daily indices the window touches, one
`wazuh-alerts-*-YYYY.MM.DD` term per UTC date. A one-day window touches two dates, so two indices.
The noise profile's 120-day search can still need more. If it does, raise the setting as an
administrator:

```sh
curl --cacert root-ca.pem -u admin -X PUT "https://indexer.example.internal:9200/_cluster/settings" \
  -H 'Content-Type: application/json' \
  -d '{"persistent": {"search.max_open_pit_context": 2000}}'
```

A `persistent` setting lives in the indexer's data volume. Recreating the stack without its
volumes resets it.

**Never allow partial PIT creation.** With partial creation allowed, the same request succeeds
with some shards missing: a snapshot that silently drops alerts and still looks healthy. Soc Thief
sends `allow_partial_pit_creation=false`, which turns that loss into a visible failure.

The requests:

- Create: `POST /<pattern>/_search/point_in_time?keep_alive=2m&allow_partial_pit_creation=false&allow_no_indices=false&ignore_unavailable=false`.
  The pattern is the comma-joined list of daily terms, never a version-specific prefix such as
  `wazuh-alerts-4.x-`, so a Wazuh upgrade cannot quietly stop matching. A window spanning more
  than 31 UTC dates is refused before any request. The response must hold a non-empty `pit_id`
  of at most 64 KiB and complete `_shards`.
- Search: `POST /_search?allow_partial_search_results=false` with `pit: {id, keep_alive: "2m"}`.
  A retried page repeats the identical request before anything is used, so no record appears
  twice. A response `pit_id` must equal the created one.
- Release: `DELETE /_search/point_in_time`, once, in a `finally` block. If the window otherwise
  succeeded, a failed release is an error. If collection had already failed, release errors are
  suppressed so they never hide the first failure.

The snapshot's exact total must stay the same on every page and equal the number of records
returned.

A day with no index is an error. `allow_no_indices=false` and `ignore_unavailable=false` mean
a requested date with no backing index fails the whole window. Either the data aged out of
retention or the pipeline was down that day. Neither should look like a quiet night.

Every returned event's `_index` must end in one of the window's own UTC dates. Narrowing by index
is safe only because Wazuh puts each alert in the index for its own UTC date; this check enforces
that per event.

## What a snapshot cannot prove

A PIT makes one window consistent. It does not make it final. An alert indexed after the snapshot,
with a timestamp inside an already processed window, is missed. The runner waits 15 minutes past
the window end, and the reconcile pass collects each committed day again about a day later,
triaging only events not already in state. Alerts indexed after reconcile are never triaged.

`CollectorError` means "deliver a health report". The caller must abort the window and must not
advance its checkpoint. Allowlisted records may still hold sensitive labels such as host names.
They are local input, never directly safe for a prompt, a log or a report.

## Noise profile aggregation

`WazuhIndexerCollector.profile()` backs `python -m soc_thief.profile`. It uses search permission
only, with no PIT: a `size: 0` composite aggregation over `rule.id` and `agent.id` (250 per page,
at most 40 pages), with the maximum rule level, a daily `date_histogram` and the most frequent
`rule.description` and `agent.name`. It requests no documents. The window must be closed and at
most 120 days. Incomplete shards, timeouts, returned hits, unexpected shapes, daily counts that do
not add up or a changing total all fail with fixed text. Events with no `rule.id` or `agent.id`
fail the profile instead of vanishing. Labels are untrusted.

## Agent liveness aggregation

`WazuhIndexerCollector.agent_last_seen()` backs the fast path's silent-agent check. It reads the
latest `@timestamp` per listed agent with one `terms` aggregation over the daily indices, requests
no documents, and refuses before any request unless it lists 1 to 500 numeric agent IDs and a
window of at most seven days. See [DETECTION.md](DETECTION.md#silent-agents).

## Verifying access

Synthetic checks need no network:

```sh
PYTHONPATH=src python3 -m unittest discover -q
```

To check TLS, authentication and pagination against your indexer, set the four `*_FILE`
variables and pick a recent closed window of at most one hour with at least two alerts:

```sh
PYTHONPATH=src python3 -m soc_thief.verify \
  --start 2026-01-01T00:00:00Z --end 2026-01-01T00:15:00Z
```

It makes at most two requests with `size: 1` and `_source: false`, one attempt each. It never
fetches alert content and never prints document IDs. A separate worker enforces a 75-second
deadline. Exit codes: `0` pagination verified, `1` failure, `2` inconclusive (fewer than two
records), `3` deadline expired.

Add `--snapshot` to run the same two pages inside one PIT and release it. Success shows the user
can create, search and release a PIT. Neither mode proves least privilege, and neither probes
for write access. Use the dedicated reader, never an administrator.

Upstream references: OpenSearch
[pagination](https://docs.opensearch.org/latest/search-plugins/searching-data/paginate/) and
[search API](https://docs.opensearch.org/latest/api-reference/search-apis/search/).
