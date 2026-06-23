"""
scorer.py — Risk scoring engine for Prompt Shield.

Converts a list of matched injection patterns into a numeric risk
score and a human-readable risk level.  Scoring rules are defined
entirely in ``config.py`` for easy tuning without touching this file.

Scoring algorithm
-----------------
* Sum the weights of every matched pattern.
* Cap the total at 100 to keep the scale predictable.
* Map the capped score to a risk level via ``config.RISK_THRESHOLDS``.

Future extension points
-----------------------
* ``BaseScorer`` abstract class for pluggable ML-based scorers (Phase 4).
* Contextual boosting: patterns appearing near "DAN" or role-play
  keywords could receive a multiplier.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import List

from prompt_shield import config

logger = logging.getLogger(__name__)

# Maximum score — capped to keep risk levels meaningful.
_MAX_SCORE: int = 100

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ScoreResult:
    """Immutable result returned by :class:`RiskScorer`."""

    score: int
    risk_level: str

    def to_dict(self) -> dict:
        """Serialise to a JSON-friendly dictionary."""
        return {"score": self.score, "risk_level": self.risk_level}


# ---------------------------------------------------------------------------
# Scorer
# ---------------------------------------------------------------------------


class RiskScorer:
    """
    Computes a cumulative risk score from matched injection patterns.

    Parameters
    ----------
    pattern_weights:
        Optional override for ``config.PATTERN_WEIGHTS``.
    thresholds:
        Optional override for ``config.RISK_THRESHOLDS``.
    """

    def __init__(
        self,
        pattern_weights: dict[str, int] | None = None,
        thresholds: tuple | None = None,
        intent_weights: dict[str, int] | None = None,
    ) -> None:
        self._weights: dict[str, int] = (
            pattern_weights if pattern_weights is not None
            else config.PATTERN_WEIGHTS
        )
        self._thresholds: tuple = (
            thresholds if thresholds is not None
            else config.RISK_THRESHOLDS
        )
        self._intent_weights: dict[str, int] = (
            intent_weights if intent_weights is not None
            else config.INTENT_WEIGHTS
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def score(
        self,
        matched_patterns: List[str],
        intents: List[str] | None = None,
    ) -> ScoreResult:
        """
        Calculate a risk score combining pattern matches and detected intents.

        Parameters
        ----------
        matched_patterns:
            Patterns from :class:`~prompt_shield.detector.InjectionDetector`.
        intents:
            Intent categories from
            :class:`~prompt_shield.intent_detector.IntentDetector`.

        Returns
        -------
        ScoreResult
            Frozen dataclass with ``score`` (0-100) and ``risk_level``.
        """
        if not isinstance(matched_patterns, list):
            raise TypeError(
                f"score() expects a list, got {type(matched_patterns).__name__!r}."
            )
        intents = intents or []

        pattern_score = self._calculate_raw(matched_patterns)
        intent_score  = self._calculate_intent_raw(intents)
        raw_score = pattern_score + intent_score
        capped = min(raw_score, _MAX_SCORE)
        risk_level = self._classify(capped)

        logger.info(
            "Risk scoring | pattern=%d | intent=%d | total=%d | level=%s",
            pattern_score,
            intent_score,
            capped,
            risk_level,
        )
        return ScoreResult(score=capped, risk_level=risk_level)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _calculate_raw(self, matched_patterns: List[str]) -> int:
        """Sum weights for every matched pattern; unknown patterns score 0."""
        total = 0
        for pattern in matched_patterns:
            weight = self._weights.get(pattern, 0)
            logger.debug("Pattern %r → weight %d", pattern, weight)
            total += weight
        return total

    def _calculate_intent_raw(self, intents: List[str]) -> int:
        """Sum weights for every detected intent; unknown intents score 0."""
        total = 0
        for intent in intents:
            weight = self._intent_weights.get(intent, 0)
            logger.debug("Intent %r → weight %d", intent, weight)
            total += weight
        return total

    def _classify(self, score: int) -> str:
        """Map a numeric score to a risk-level label."""
        for threshold, label in self._thresholds:
            if score >= threshold:
                return label
        # Fallback — should never be reached with a well-formed config.
        return "SAFE"
