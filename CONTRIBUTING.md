# Contributing

Contributions are welcome. Soc Thief is alpha software (0.1.0-alpha.2), so interfaces, settings and
file formats may still change. That also means there is plenty to do.

## Proposing a change

- **Open an issue first** for anything that touches policy, the invariants below, what data leaves
  the host, or the deployment's security settings. Agreeing on the approach before code saves both
  of us time.
- Small fixes, tests and docs can go straight to a pull request.
- Keep a pull request to one change, and say in its description why you made it.

## Good first contributions

- A new breach rule in `src/soc_thief/breach.py`, matched on Wazuh rule IDs or groups, with
  tests in `tests/test_breach.py` and, if you can, a scenario for `simulations/`.
- A model backend in `src/soc_thief/model.py` that keeps the strict schema and the
  fail-closed behaviour. See [docs/MODELS.md](docs/MODELS.md).
- Console views in `console/`.
- Docs: anything in `docs/` that was unclear when you set Soc Thief up.

## Development setup

The engine needs Python 3.12 or later and one runtime dependency, `tzdata`.

```sh
pip install tzdata
PYTHONPATH=src python3 -m unittest discover -q
python3 -m compileall -q src tests
git diff --check
```

The tests need no network, no Wazuh and no model.

The console is Rust, in `console/`:

```sh
cd console
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
```

CI runs all of these on every pull request, plus a secret scan.

Before you push, you can run `scripts/check-public`, which runs gitleaks and trufflehog if they are
installed. To run it on every push: `git config core.hooksPath .githooks`.

## Test data rules

Never put any of these in code, tests, fixtures, issues or pull requests:

- production alerts or Wazuh exports, even "anonymised" ones;
- real host names, user names or agent names;
- real IP addresses. Use RFC 5737 documentation ranges: `192.0.2.0/24`, `198.51.100.0/24`,
  `203.0.113.0/24`;
- tokens, passwords, keys or webhook URLs, real or realistic-looking;
- model prompts built from production data.

Write synthetic fixtures by hand. If a bug only shows with real data, describe its shape (field
names, lengths, characters) instead of pasting it.

## Invariants a pull request must not break

1. A model result can never suppress an alert. `policy.decide()` has no non-delivering branch. Do
   not add a confidence gate; the suite is built to fail if you do.
2. The tuning file is the only suppressor, and it never applies to protected, critical, breach,
   invalid or failed groups.
3. Every failure (source, model, state, renderer, delivery) produces a delivery-required report
   and a health failure. A model failure fails closed for that group only.
4. Wazuh access stays read-only.
5. Secrets are read only through `*_FILE` paths. Never as flags, never printed, never logged.
6. The model and Discord receive only allowlisted, minimised fields. Command lines, raw events,
   credentials and private keys never leave the collector.
7. Alert text and model output are untrusted: escape it, cap it, validate it against a schema.
8. `delivery.MAX_PAGES` and `state.OUTBOX_PAYLOAD_LIMIT` stay coupled; a test checks it.
9. The systemd hardening options that are absent on purpose stay absent unless you have tested
   rootless Podman under them through the real unit. See
   [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md#hardening).

If a change needs one of these to move, open an issue and make the case there first.

## Tests that prove something

A test written alongside the code it checks tends to agree with that code, bugs included. Before
you call a new test evidence, break the code it covers and confirm the test fails.

## Licence

Soc Thief is licensed under Apache-2.0. By contributing you agree that your contribution is
licensed under the same terms.
