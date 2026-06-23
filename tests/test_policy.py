"""
tests/test_policy.py — Unit tests for PolicyEngine.

Coverage areas
--------------
* SAFE → ALLOWED
* SUSPICIOUS → WARNED
* MALICIOUS → BLOCKED
* Unknown risk level raises ValueError
* is_blocked / is_warned predicates
* to_dict serialisation
* Custom policy map
"""

from __future__ import annotations

import pytest

from prompt_shield.policy import PolicyDecision, PolicyEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def engine() -> PolicyEngine:
    return PolicyEngine()


# ---------------------------------------------------------------------------
# Standard policy outcomes
# ---------------------------------------------------------------------------


class TestStandardPolicies:
    def test_safe_is_allowed(self, engine: PolicyEngine) -> None:
        decision = engine.evaluate("SAFE", 0)
        assert decision.status == "ALLOWED"
        assert decision.is_blocked is False

    def test_suspicious_is_warned(self, engine: PolicyEngine) -> None:
        decision = engine.evaluate("SUSPICIOUS", 50)
        assert decision.status == "WARNED"
        assert decision.is_warned is True
        assert decision.is_blocked is False

    def test_malicious_is_blocked(self, engine: PolicyEngine) -> None:
        decision = engine.evaluate("MALICIOUS", 80)
        assert decision.status == "BLOCKED"
        assert decision.is_blocked is True

    def test_blocked_has_correct_reason(self, engine: PolicyEngine) -> None:
        decision = engine.evaluate("MALICIOUS", 80)
        assert "Prompt Injection" in decision.reason

    def test_safe_decision_carries_score(self, engine: PolicyEngine) -> None:
        decision = engine.evaluate("SAFE", 0)
        assert decision.risk_score == 0
        assert decision.risk_level == "SAFE"


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


class TestErrorHandling:
    def test_unknown_risk_level_raises(self, engine: PolicyEngine) -> None:
        with pytest.raises(ValueError, match="Unknown risk level"):
            engine.evaluate("CRITICAL", 99)

    def test_empty_risk_level_raises(self, engine: PolicyEngine) -> None:
        with pytest.raises(ValueError):
            engine.evaluate("", 0)


# ---------------------------------------------------------------------------
# Serialisation
# ---------------------------------------------------------------------------


class TestSerialization:
    def test_to_dict_keys(self, engine: PolicyEngine) -> None:
        decision = engine.evaluate("MALICIOUS", 90)
        d = decision.to_dict()
        assert set(d.keys()) == {"status", "reason", "risk_level", "risk_score"}

    def test_to_dict_values(self, engine: PolicyEngine) -> None:
        decision = engine.evaluate("SAFE", 10)
        d = decision.to_dict()
        assert d["status"] == "ALLOWED"
        assert d["risk_score"] == 10

    def test_result_is_frozen(self, engine: PolicyEngine) -> None:
        decision = engine.evaluate("SAFE", 0)
        with pytest.raises((AttributeError, TypeError)):
            decision.status = "BLOCKED"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Custom policy map
# ---------------------------------------------------------------------------


class TestCustomPolicyMap:
    def test_custom_action(self) -> None:
        custom_map = {"SAFE": "PASS", "SUSPICIOUS": "REVIEW", "MALICIOUS": "REJECT"}
        custom_reasons = {"PASS": "OK", "REVIEW": "Check it", "REJECT": "Denied"}
        engine = PolicyEngine(policy_map=custom_map, policy_reasons=custom_reasons)

        decision = engine.evaluate("MALICIOUS", 80)
        assert decision.status == "REJECT"
        assert decision.reason == "Denied"

    def test_custom_new_level(self) -> None:
        custom_map = {
            "SAFE": "ALLOWED",
            "SUSPICIOUS": "WARNED",
            "MALICIOUS": "BLOCKED",
            "CRITICAL": "TERMINATED",
        }
        engine = PolicyEngine(policy_map=custom_map)
        decision = engine.evaluate("CRITICAL", 100)
        assert decision.status == "TERMINATED"
