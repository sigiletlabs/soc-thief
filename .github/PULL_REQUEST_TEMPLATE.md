## What this changes

## Why

## Checks

- [ ] `PYTHONPATH=src python3 -m unittest discover -q` passes
- [ ] `cargo test` and `cargo clippy -- -D warnings` pass in `console/` (if you touched it)
- [ ] No real alerts, host names, IP addresses (use 192.0.2.x, 198.51.100.x or 203.0.113.x), tokens or webhook URLs in code, tests or this description
- [ ] A model still can't hide an alert, and protected alerts still can't be tuned away
