# Security policy

## Supported versions

Soc Thief is alpha software. Only the `main` branch receives security fixes.

## Reporting a vulnerability

Report privately through GitHub's private vulnerability reporting: open the
[Security tab of sigiletlabs/soc-thief](https://github.com/sigiletlabs/soc-thief/security) and
choose "Report a vulnerability". Please do not open a public issue for a security problem.

Include what you found, how to reproduce it, and what an attacker could do with it. Do not include
real alerts, host names, IP addresses, credentials or webhook URLs from your own systems; use
synthetic values and RFC 5737 addresses (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).

## In scope

- Any way to make a model answer, alert text or input file suppress, hide or delay an alert.
- Any way for a tuning entry to suppress a protected, critical or breach group.
- A failure that produces silence instead of a health report.
- Prompt injection that changes report content, delivery or paging.
- Leaks of credentials, webhook URLs or unmasked alert fields to Discord, ntfy, logs, a model
  endpoint or the state store.
- Writes to Wazuh, or reads beyond the documented allowlisted fields.
- Weaknesses in the container image, the systemd units or the documented egress policy.
- Server-side request forgery or redirect handling in any outbound client.

Out of scope: vulnerabilities in Wazuh, OpenSearch, Ollama, Discord, ntfy or Podman themselves
(report those upstream), and deployments that ignore the documented hardening.

## Security design

- A model cannot suppress. Model output is advice. Fixed policy decides delivery, and every
  valid or invalid model answer leads to delivery.
- Only your tuning file suppresses, and never for protected, critical or breach groups.
- Fail closed. Collection, model, state and delivery failures all produce a health report;
  an hourly heartbeat catches runs that could not report.
- Least privilege. A read-only Wazuh indexer user, a non-root read-only container with no
  capabilities, and a host egress policy for the service account.
- Secrets only from files. Credentials are read through `*_FILE` paths, never flags or plain
  environment variables, and alert text is allowlisted, masked and escaped before it leaves.

Details: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and
[docs/threat-models/initial.md](docs/threat-models/initial.md).
