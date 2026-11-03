"""Pure delivery policy. Decisions contain fixed codes, never untrusted input.

This boundary accepts normalized group summaries, not collector records. The
caller must supply the group's maximum severity and propagate pipeline failures.
"""

from dataclasses import dataclass
from datetime import datetime
import math
import re
import unicodedata


_REQUIRED = {"timestamp", "rule_id", "rule_level", "rule_description", "agent_id", "count"}
_OPTIONAL = {"agent_name", "decoder_name", "manager_name", "location"}
_MODEL_KEYS = {"classification", "confidence", "rationale", "analyst_action"}
# Fixed Jev display vocabulary. These labels are advice only and never enter decide() or tuned().
JEV_THREAT_LABELS = frozenset({"routine", "possible_auth_abuse", "possible_malware",
                              "possible_privilege_misuse", "possible_policy_violation",
                              "other_concern", "insufficient_context"})
# Conservative security vocabulary: false positives require analyst review.
_PROTECTED = re.compile(
    r"authentication|authorization|login|logon|brute\s*force|password\s*spray|"
    r"malware|ransomware|trojan|rootkit|virus|worm|"
    r"privilege|escalat|sudo|setuid|credential|password|"
    r"collection|exfiltrat|data\s*theft|keylog|"
    r"ignore\s+(?:all\s+|previous\s+)?instructions|suppress\s+alerts"
)


@dataclass(frozen=True)
class Decision:
    delivery_required: bool
    health_failure: bool
    reason: str


def _text(value: object, limit: int) -> bool:
    return (type(value) is str and 0 < len(value) <= limit and bool(value.strip())
            and not any(unicodedata.category(c).startswith("C") for c in value))


def _valid_group(group: object) -> bool:
    if type(group) is not dict or not _REQUIRED <= group.keys() <= _REQUIRED | _OPTIONAL:
        return False
    if type(group["rule_level"]) is not int or not 0 <= group["rule_level"] <= 16:
        return False
    if type(group["count"]) is not int or not 1 <= group["count"] <= 2**63 - 1:
        return False
    if not all(_text(group[k], 2048 if k == "rule_description" else 256)
               for k in ("timestamp", "rule_id", "rule_description", "agent_id")):
        return False
    if any(group.get(k) is not None and not _text(group[k], 256) for k in _OPTIONAL):
        return False
    try:
        timestamp = datetime.fromisoformat(group["timestamp"].replace("Z", "+00:00"))
        return timestamp.tzinfo is not None and timestamp.utcoffset() is not None
    except ValueError:
        return False


def preflight(group: object, *, failures: tuple[str, ...] = ()) -> Decision:
    """Run before inference. A false delivery flag here means model review needed.

    Any failure indication (including malformed failure context) fails closed.
    Failure strings are neither interpreted nor echoed.
    """
    if type(failures) is not tuple or failures:
        return Decision(True, True, "pipeline_failure")
    if not _valid_group(group):
        return Decision(True, True, "invalid_group")
    if group["rule_level"] >= 12:
        return Decision(True, False, "critical_severity")
    description = unicodedata.normalize("NFKC", group["rule_description"]).casefold()
    description = re.sub(r"[\W_]+", " ", description)
    if _PROTECTED.search(description):
        return Decision(True, False, "protected_indicator")
    return Decision(False, False, "model_review_required")


_TUNED = {"mute": Decision(False, False, "tuned_mute"), "low": Decision(False, False, "tuned_low")}


def tuned(group: object, action: object, *, failures: tuple[str, ...] = ()) -> Decision:
    """Apply an operator tuning action only where preflight would permit model review.

    Protected, critical, invalid and failed groups always keep their preflight decision. No
    action, or an unrecognized one, leaves ``model_review_required``; it never suppresses.
    """
    gate = preflight(group, failures=failures)
    if gate.delivery_required or type(action) is not str:
        return gate
    return _TUNED.get(action, gate)


def decide(group: object, model: object = None, *, failures: tuple[str, ...] = ()) -> Decision:
    """Final gate: model output can require delivery or fail closed, but never suppresses.

    Pass a parsed JSON object. Text fields are schema-checked only; they are never
    instructions and must not be reused as safe report text by downstream code.

    A model result no longer suppresses anything. The former gate was
    ``classification == "benign" and confidence >= 0.98``. Measured over 836 real alert
    groups, ``qwen3:4b`` never once returned a confidence at or above 0.98 - it emits only
    0.95 and 0.85 - so the gate was unreachable rather than strict. Worse, the value carried
    no information: ``benign`` was always 0.95 and ``suspicious`` was 0.85 or 0.95, and one
    group returned benign, then suspicious, then suspicious across three identical requests
    at ``temperature 0`` while reporting 0.95 every time.

    Lowering the threshold was therefore rejected, because it would suppress on a number that
    does not move when the model's own verdict flips; gating on the classification alone was
    rejected too, because that is not stable either. Suppression now rests entirely on the
    deterministic paths: operator tuning (``tuned``) and nothing else.

    This also removes a latent hazard. While the gate existed, swapping in a model that
    happened to emit 0.99 would have silently enabled suppression with no calibration behind
    it, moving the safety boundary with no code change and no review.

    ``confidence`` is still schema-validated so that a malformed result still fails closed;
    it simply no longer influences any decision.
    """
    gate = preflight(group, failures=failures)
    if gate.health_failure:
        return gate
    valid = type(model) is dict and model.keys() == _MODEL_KEYS
    if valid:
        confidence = model["confidence"]
        valid = (type(model["classification"]) is str
                 and model["classification"] in ("benign", "suspicious", "unknown")
                 and type(confidence) in (int, float) and 0 <= confidence <= 1
                 and math.isfinite(confidence)
                 and _text(model["rationale"], 512)
                 and _text(model["analyst_action"], 256))
    if not valid:
        return Decision(True, True, "invalid_model_result")
    if gate.delivery_required:
        return gate
    # No branch here may return a non-delivering Decision: see the docstring. A model result
    # can only require delivery or fail closed.
    return Decision(True, False, "model_requires_review")
