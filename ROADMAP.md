# Roadmap

Soc Thief is alpha. This is where it's heading. Nothing here has a date. If you want to work on
something, open an issue first so we can agree the shape.

The goal is a SOC that runs itself overnight, stays quiet when nothing is wrong, and wakes you
up when something is. Every step keeps the same rule: a model can raise how urgent something is,
but it can't lower it or hide it. That only changes if measured accuracy supports it and you
choose to allow it.

## Next

**One Rust binary.** Port the Python engine (collector, policy, digest, fast path, state
store), the CLI and the MCP server to Rust, alongside the console that's already in Rust. One static binary is simpler to
install, simpler to sandbox and simpler to audit. The Python test suite is the spec. It moves
across with the code so the behaviour stays the same.

**Agents that can act, with a human in the loop.** The alpha ships a read-only `soc-thief`
CLI and MCP server, so an AI agent can already read windows, groups, breaches and health. Next:

- Cover cases and investigation briefs as well as the snapshot.
- Add a small set of actions, such as recording a verdict on a case or proposing a tuning
  entry. Each one needs a human to approve it before it takes effect.
- No tool will let an agent mute, suppress or hide an alert. Tuning stays a file a person
  installs.
- Port both to Rust with the engine.

**Measure accuracy.** Build a labelled set of alert groups and score each model backend
against it. That number decides whether a model gets more say, and which backend is the
default.

## Later

- Route authentication alerts by individual event rather than by group, so one real login
  inside a noisy group isn't averaged away.
- Test whether giving the model redacted command lines makes its confidence more useful.
- More breach definitions, with simulations for each.
- Container image and release binaries published from CI.
- More delivery targets beside Discord and ntfy.

## Done in 0.1.0-alpha.1

See [CHANGELOG.md](CHANGELOG.md).
