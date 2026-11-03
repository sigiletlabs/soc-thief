# Threat model

## Assets

- The Wazuh indexer read credential and the Discord webhook URL.
- Alert content, which describes your hosts, users and activity.
- The state store and the integrity of reports.
- Your ability to see an urgent alert in time.

## Threats

1. Prompt injection in Wazuh alert fields manipulates triage or report content.
2. A model error hides a real incident.
3. Sensitive event fields leak to Discord, logs or an external model endpoint.
4. A compromised runtime reaches the host, a container socket or unrelated networks.
5. Duplicate or replayed events cause alert fatigue and hide a real escalation.
6. A source, delivery or scheduling failure looks like a quiet night.
7. A breach happens on an agent that has stopped reporting.

## Mitigations

1. Alert text is data. Prompts are fixed, the group goes in its own message, answers must match a
   strict JSON schema, and instruction-override phrases are in the protected vocabulary, which
   forces delivery. Model prose is never rendered.
2. The model cannot suppress. Delivery is decided by fixed policy; only your tuning file
   suppresses, and never for protected, critical or breach groups.
3. Field allowlists at collection, masking and escaping before Discord, capped sizes, and
   pseudonymisation before any hosted model. Logs carry fixed status text only.
4. Rootless Podman, a read-only non-root container with no capabilities, no host network, no
   container socket, and a host egress policy scoped to the service account.
5. Deduplication by exact source identity, bounded windows, transactional checkpoints and an
   idempotent outbox.
6. Every failure produces a health report. An hourly status check sends a heartbeat only when the
   last runs were healthy, so a missing heartbeat alerts you out of band.
7. The fast path checks an agent inventory you maintain and pages when an expected agent goes
   silent.

See [ARCHITECTURE.md](../ARCHITECTURE.md) for the trust boundaries.
