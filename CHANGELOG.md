# Changelog

Soc Thief is alpha software. Settings, file formats and command names may change between
releases. Breaking changes are listed here.

## 0.1.0-alpha.1 (2026-11-07)

First public release.

- Read-only Wazuh indexer collector with snapshot pagination.
- Grouping, de-duplication and a deterministic delivery policy. A model can advise but can
  never hide an alert. Your tuning file is the only thing that can, and it can't touch
  protected alerts.
- Daily Discord digest with new, spiking and failed groups up front and everything else in an
  attached file.
- Fast path that checks for breaches every few minutes and pages through ntfy.
- Bring your own model: local Ollama or any OpenAI-compatible server, hosted APIs such as
  OpenRouter, or the experimental Jev backend through TypeSafe's own API, OpenRouter or Vercel's
  AI Gateway. Remote models need an explicit opt-in.
- `soc-thief-console`: a terminal UI and a local web dashboard.
- A read-only `soc-thief` CLI for people and AI agents. It follows the AXI conventions and
  prints TOON. A read-only MCP server exposes the same commands as tools.
- Demo mode that runs the real pipeline over generated alerts, so you can try it without Wazuh.
- Hardened systemd and rootless Podman units.
