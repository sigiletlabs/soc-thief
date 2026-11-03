# soc-thief-console

A read-only viewer for Soc Thief. It has two modes: a terminal UI and a local web page.

It reads one JSON file, the snapshot, and shows it. The format is in
[`docs/SNAPSHOT.md`](../docs/SNAPSHOT.md). The console never talks to Wazuh, Discord
or any model, and it makes no outbound network connections. It checks the file every
two seconds and redraws when it changes.

## Build

You need Rust 1.88 or later.

```sh
cd console
cargo build --release
```

The binary is `target/release/soc-thief-console`.

## Run against the demo

```sh
# Terminal UI
soc-thief-console tui --snapshot fixtures/demo.json

# Web page at http://127.0.0.1:8787/
soc-thief-console web --snapshot fixtures/demo.json
```

`--snapshot` defaults to `./snapshot.json`. `--listen` defaults to `127.0.0.1:8787`.
The web mode refuses any address that is not loopback.

To make a snapshot from the Python side, see `docs/SNAPSHOT.md`.

## Keys (terminal UI)

| Key | Action |
| --- | --- |
| `q` | quit |
| `Tab`, `1`-`4` | switch view: overview, groups, health, history |
| `j` / `k` or arrows | move |
| `Enter` | open the selected group |
| `Esc` | back, or clear the filters |
| `/` | filter groups by text |
| `c` | cycle the category filter |
| `r` | reload the file now |

In the web page, `1`-`4` switch views and `/` jumps to the filter.

## What it shows

- **Overview**: the window, counts, health, an hourly chart of events with
  delivery-required counts below it, and breaches. Paged breaches are marked loudly.
- **Groups**: every group in digest order (failed, new, spike, recurring, then level
  and count). The detail view shows why a group was delivered, whether it is protected,
  its tuning, and the model's advice. The model only advises. It cannot suppress a group.
- **Health**: each check and its status.
- **History**: earlier windows.

## Safety

Alert text is attacker-controlled. The console treats every string in the snapshot
as untrusted.

- Files over 8 MiB and unknown major schema versions are refused.
- Control characters, terminal escape sequences and bidi overrides are stripped, and
  every string is length-capped, before anything is drawn.
- The web page is three embedded files with no inline script or style and nothing
  fetched from elsewhere. It renders with `textContent`, never `innerHTML`.
- Responses carry a strict Content-Security-Policy, `nosniff`, `no-referrer` and
  `no-store`. Requests whose `Host` header does not match the loopback listener are
  refused, which blocks DNS rebinding. Only `GET` is served.
- If the file goes missing or turns invalid, the last good snapshot stays on screen
  marked STALE.

## Checks

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```
