# ADR 0001: Policy-bounded AI triage

## Status

Accepted. Strengthened later: the model can no longer suppress anything (see Consequences).

## Context

A small local model can read alert summaries and say which look routine. Wazuh alerts are
untrusted text, models make mistakes, and a missed breach costs far more than an extra line in a
report.

## Decision

Use a model behind a narrow, structured interface. A deterministic policy engine decides whether
a group is delivered. The model returns only a validated classification, confidence, rationale and
recommended analyst action. It cannot run tools, change state outside its audit record, choose its
own network destination, or decide anything about protected classes.

## Consequences

- A malformed or unavailable model leads to delivery with a health failure.
- The state store keeps enough non-sensitive metadata to audit why each group was delivered,
  grouped or suppressed.
- The first version let the model suppress `benign` results at very high confidence. Measurement
  showed the model's confidence carried no information, so that gate was removed. The model is now
  advisory only, and your tuning file is the only suppressor. See
  [POLICY.md](../POLICY.md#the-model-cannot-suppress).
