"""
tests/test_scorer.py — Unit tests for RiskScorer.

Coverage areas
--------------
* Safe prompt → score 0, level SAFE
* Low-score single pattern → SAFE / SUSPICIOUS boundary
* High-score combination → MALICIOUS
* Score capping at 100
* Empty pattern list
* Unknown / unscored patterns
* Type error handling
* Custom weights and thresholds
"""

from __future__ import annotations

import pytest

from prompt_shield.scorer import RiskScorer, ScoreResult


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def scorer() -> RiskScorer:
    return RiskScorer()


# ---------------------------------------------------------------------------
# Safe prompts (no patterns)
# ---------------------------------------------------------------------------


class TestSafeScoring:
    def test_no_patterns_gives_zero(self, scorer: RiskScorer) -> None:
        result = scorer.score([])
        assert result.score == 0
        assert result.risk_level == "SAFE"

    def test_unknown_pattern_ignored(self, scorer: RiskScorer) -> None:
        result = scorer.score(["this pattern does not exist"])
        assert result.score == 0
        assert result.risk_level == "SAFE"


# ---------------------------------------------------------------------------
# SUSPICIOUS range (31–60)
# ---------------------------------------------------------------------------


class TestSuspiciousScoring:
    def test_developer_instructions(self, scorer: RiskScorer) -> None:
        result = scorer.score(["developer instructions"])
        assert result.score == 30
        # 30 is SAFE per the spec; 31+ is SUSPICIOUS
        assert result.risk_level == "SAFE"

    def test_hidden_plus_developer(self, scorer: RiskScorer) -> None:
        # hidden prompt (30) + developer instructions (30) = 60 → SUSPICIOUS
        result = scorer.score(["hidden prompt", "developer instructions"])
        assert result.score == 60
        assert result.risk_level == "SUSPICIOUS"

    def test_single_medium_weight_pattern(self, scorer: RiskScorer) -> None:
        result = scorer.score(["act as system"])
        assert 31 <= result.score <= 60
        assert result.risk_level == "SUSPICIOUS"


# ---------------------------------------------------------------------------
# MALICIOUS range (61–100)
# ---------------------------------------------------------------------------


class TestMaliciousScoring:
    def test_jailbreak_alone(self, scorer: RiskScorer) -> None:
        result = scorer.score(["jailbreak"])
        assert result.score == 50
        assert result.risk_level == "SUSPICIOUS"

    def test_ignore_plus_reveal(self, scorer: RiskScorer) -> None:
        # ignore previous instructions (40) + reveal system prompt (40) = 80
        result = scorer.score(
            ["ignore previous instructions", "reveal system prompt"]
        )
        assert result.score == 80
        assert result.risk_level == "MALICIOUS"

    def test_jailbreak_plus_ignore(self, scorer: RiskScorer) -> None:
        # jailbreak (50) + ignore (40) = 90 → MALICIOUS
        result = scorer.score(["jailbreak", "ignore previous instructions"])
        assert result.score == 90
        assert result.risk_level == "MALICIOUS"


# ---------------------------------------------------------------------------
# Score capping
# ---------------------------------------------------------------------------


class TestScoreCapping:
    def test_score_never_exceeds_100(self, scorer: RiskScorer) -> None:
        # Use every pattern — raw sum will be well over 100
        from prompt_shield.config import PATTERN_WEIGHTS

        all_patterns = list(PATTERN_WEIGHTS.keys())
        result = scorer.score(all_patterns)
        assert result.score <= 100
        assert result.risk_level == "MALICIOUS"

    def test_duplicate_patterns_accumulate_but_cap(
        self, scorer: RiskScorer
    ) -> None:
        patterns = ["ignore previous instructions"] * 5  # 5 × 40 = 200 → capped
        result = scorer.score(patterns)
        assert result.score == 100


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_type_error_on_non_list(self, scorer: RiskScorer) -> None:
        with pytest.raises(TypeError):
            scorer.score("ignore previous instructions")  # type: ignore[arg-type]

    def test_result_is_frozen(self, scorer: RiskScorer) -> None:
        result = scorer.score([])
        with pytest.raises((AttributeError, TypeError)):
            result.score = 99  # type: ignore[misc]

    def test_to_dict(self, scorer: RiskScorer) -> None:
        result = scorer.score(["jailbreak"])
        d = result.to_dict()
        assert "score" in d
        assert "risk_level" in d


# ---------------------------------------------------------------------------
# Custom weights / thresholds
# ---------------------------------------------------------------------------


class TestCustomConfiguration:
    def test_custom_weights(self) -> None:
        custom_weights = {"my-pattern": 45}
        s = RiskScorer(pattern_weights=custom_weights)
        result = s.score(["my-pattern"])
        assert result.score == 45
        assert result.risk_level == "SUSPICIOUS"

    def test_custom_thresholds(self) -> None:
        # Raise MALICIOUS floor to 90 so 80 becomes SUSPICIOUS
        thresholds = ((90, "MALICIOUS"), (50, "SUSPICIOUS"), (0, "SAFE"))
        s = RiskScorer(thresholds=thresholds)
        result = s.score(["ignore previous instructions", "reveal system prompt"])
        assert result.score == 80
        assert result.risk_level == "SUSPICIOUS"

    def test_boundary_values(self) -> None:
        scorer = RiskScorer()
        # Score of exactly 31 should be SUSPICIOUS
        custom_weights = {"boundary-test": 31}
        s = RiskScorer(pattern_weights=custom_weights)
        result = s.score(["boundary-test"])
        assert result.score == 31
        assert result.risk_level == "SUSPICIOUS"

    def test_score_30_is_safe(self) -> None:
        custom_weights = {"safe-boundary": 30}
        s = RiskScorer(pattern_weights=custom_weights)
        result = s.score(["safe-boundary"])
        assert result.score == 30
        assert result.risk_level == "SAFE"
