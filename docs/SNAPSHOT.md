# Snapshot format

The console (`soc-thief-console tui` and `soc-thief-console web`) never talks to Wazuh,
Discord or the model. It reads one JSON file, the snapshot, and shows it.

Python writes the snapshot:

- `python -m soc_thief.demo --out snapshot.json` runs the real grouping, policy and digest
  code over generated alerts. No network, no credentials.
- `python -m soc_thief.snapshot --out snapshot.json` reads a real deployment's state
  read-only and writes what it can see.
- `python -m soc_thief.attacks --snapshot snapshot.json --geoip FILE --home AU` adds the
  globe view's attack shots to an existing snapshot. See [Attacks](#attacks) below.

The console re-reads the file when it changes, so a timer that rewrites it gives a live view.

## Rules

- UTF-8 JSON, one object, at most 8 MiB. The console refuses anything bigger.
- Every string is untrusted. It came from alert fields. The console escapes it and caps
  its length; the web view sets text, never HTML.
- Times are RFC 3339 with an offset.
- Unknown fields are ignored, so the format can grow. A different major `schema` value is
  refused.
- No credentials, webhook URLs, raw events or full command lines ever go in a snapshot.

## Shape

```json
{
  "schema": "soc-thief.snapshot/1.1",
  "generated_at": "2026-11-07T08:00:04+11:00",
  "source": "demo",
  "timezone": "Australia/Sydney",
  "window": {
    "start": "2026-11-06T08:00:00+11:00",
    "end": "2026-11-07T08:00:00+11:00",
    "events": 48213,
    "groups": 214,
    "duplicates": 913,
    "muted_by_tuning": 61
  },
  "health": {
    "status": "ok",
    "checks": [
      {"name": "collector", "status": "ok", "detail": "48213 events in 3 indices"},
      {"name": "model", "status": "attention", "detail": "2 groups timed out; delivered anyway"}
    ]
  },
  "groups": [
    {
      "id": "c-7f3a91",
      "rule_id": "5712",
      "rule_description": "sshd: brute force trying to get access to the system",
      "level": 10,
      "count": 812,
      "agents": ["web-01", "web-02"],
      "first_seen": "2026-11-06T22:14:09+11:00",
      "last_seen": "2026-11-07T03:51:40+11:00",
      "category": "spike",
      "protected": true,
      "tuning": "none",
      "decision": {"delivery_required": true, "health_failure": false, "reason": "protected_indicator"},
      "model": {"name": "qwen3:4b", "verdict": "investigate", "confidence": 0.82,
                "tags": ["authentication", "brute-force"], "summary": "Repeated SSH failures from one source."},
      "breach_signals": []
    }
  ],
  "breaches": [
    {"name": "brute force then success", "signals": ["auth_failure_burst", "auth_success"],
     "agent": "web-01", "at": "2026-11-07T03:52:02+11:00", "paged": true}
  ],
  "timeline": [
    {"start": "2026-11-06T08:00:00+11:00", "events": 1830, "delivery_required": 12}
  ],
  "history": [
    {"start": "2026-11-05T08:00:00+11:00", "end": "2026-11-06T08:00:00+11:00",
     "events": 51022, "groups": 198, "delivered": true, "health_failure": false}
  ],
  "attacks": {
    "home": "AU",
    "start": "2026-11-06T08:00:00+11:00",
    "end": "2026-11-07T08:00:00+11:00",
    "no_source": 31877,
    "dropped": 0,
    "shots": [
      {"t": 3912.4, "country": "CN", "level": 5, "kind": "tuned", "label": "sshd: authentication failed."},
      {"t": 71522.0, "country": "RU", "level": 12, "kind": "breach", "label": "brute force then success"}
    ]
  }
}
```

### Field notes

- `schema`: `soc-thief.snapshot/1`. A minor version (`/1.2`) only adds optional fields, so
  readers accept any `/1.N`.
- `window.events` and `window.duplicates` count events. `window.groups` and
  `window.muted_by_tuning` count groups.
- `groups` lists every group in the window, up to 5000. If there are more, it keeps the
  delivery-required ones first and `window.groups` stays the true total, so a reader can show
  "5000 of 11204".
- `groups[].model.confidence` is between 0 and 1.
- `source`: `demo` or `state`. The console shows a DEMO banner for `demo`.
- `health.status` and each check's `status`: `ok`, `attention` or `failed`.
- `groups[].category`: `failed` (the model or a boundary failed for this group), `new`,
  `spike` (well above its 30-day baseline) or `recurring`. Same order as the digest.
- `groups[].tuning`: `none`, `low` or `mute`. Tuning is the only thing that can stop a group
  being delivered, and `protected` groups can never be tuned away.
- `groups[].model` is `null` when no model ran. The model only advises. It can never change
  `decision.delivery_required` to `false`.
- `timeline` is hourly buckets across the window, oldest first.
- `history` is earlier windows, newest first, at most 30.
- `decision.reason` is the policy's own reason code, such as `protected_indicator`,
  `model_requires_review` or `invalid_model_result`.
- `model` is also `null` for protected groups, because the model is never asked about them.
- A real-state snapshot (`source: "state"`) shows much less. The state store keeps opaque
  tokens and outcomes, not alert text. So `rule_id` and `rule_description` are empty, `level`
  and `count` are 0, `agents` is empty, `model` is `null`, `category` is only `failed` or
  `recurring`, and `breaches` and `timeline` are empty. `history` and `health` are complete.
- The rendered digest is not part of the snapshot. `python -m soc_thief.demo --digest-out FILE`
  writes it separately.

## Attacks

`attacks` is optional and was added in schema 1.1. The console's globe view (`5 GLOBE`)
replays it as arcs flying from each source country to `home`. Without it, the view says how
to get it.

- `python -m soc_thief.demo` makes shots from a seeded generator, because the demo's
  addresses are documentation ranges and have no country. The demo's breaches are added as
  `breach` shots at their real times.
- `python -m soc_thief.attacks` reads the snapshot's own window through the read-only
  collector, with the same `WAZUH_INDEXER_*_FILE` settings as the runner, and looks up each
  alert's `data.srcip` in an offline [DB-IP Lite](https://db-ip.com/db/lite.php) country CSV
  (plain or `.gz`). It makes no other network request. `SOC_THIEF_TUNING_FILE`, if set, marks
  tuned shots.

Fields:

- `home`: the two-letter ISO 3166-1 code the arcs land on.
- `start` and `end`: the window the shots cover, the same as `window`.
- `shots[].t`: seconds after `start`. Shots are oldest first.
- `shots[].country`: a two-letter code, or `LAN` for an address that is not public (private,
  loopback, link-local, carrier-grade NAT or documentation ranges).
- `shots[].kind`: `tuned` (tuning matched), `reported` or `breach` (a breach signal, even if
  tuned, as in policy). The console draws an unknown kind as `reported`.
- `shots[].label`: the rule description, at most 48 characters, with addresses and secrets
  masked.
- `no_source`: alerts with no source address, or one the GeoIP file does not know. They are
  counted, not listed.
- `dropped`: shots over the cap of 20,000. Breach shots are kept first, then reported, then
  tuned.

A shot never carries an IP address, host name or agent name. Like the rest of the snapshot,
the globe cannot change what is delivered.
