"""
main.py — Orchestration pipeline for Prompt Shield.

``PromptShield`` wires together four stages:

  InjectionDetector → IntentDetector → RiskScorer → PolicyEngine

and returns a single ``ShieldResult`` that downstream code (CLI,
API gateway, LLM middleware) can inspect.

Usage
-----
    from prompt_shield.main import PromptShield

    shield = PromptShield()
    result = shield.evaluate("Ignore previous instructions")
    print(result.to_dict())
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import List

from prompt_shield import config
from prompt_shield.detector import DetectionResult, InjectionDetector
from prompt_shield.intent_detector import IntentDetector, IntentResult
from prompt_shield.policy import PolicyDecision, PolicyEngine
from prompt_shield.scorer import RiskScorer, ScoreResult

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Composite result
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ShieldResult:
    """
    Aggregated result from a full pipeline evaluation.

    Attributes
    ----------
    status:
        Final enforcement action: ``"ALLOWED"``, ``"WARNED"``, or
        ``"BLOCKED"``.
    risk_score:
        Numeric score in the range 0–100.
    risk_level:
        Human-readable tier: ``"SAFE"``, ``"SUSPICIOUS"``, or
        ``"MALICIOUS"``.
    reason:
        Short human-readable explanation of the decision.
    detected:
        ``True`` if at least one injection pattern was matched.
    matched_patterns:
        List of pattern strings that triggered a match.
    """

    status: str
    risk_score: int
    risk_level: str
    reason: str
    detected: bool
    matched_patterns: List[str] = field(default_factory=list)
    intents: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Serialise to a JSON-friendly dictionary."""
        return {
            "status": self.status,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "reason": self.reason,
            "detected": self.detected,
            "matched_patterns": self.matched_patterns,
            "intents": self.intents,
        }


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------


class PromptShield:
    """
    End-to-end prompt-injection detection and enforcement pipeline.

    Instantiate once and call :meth:`evaluate` for every user message.

    Parameters
    ----------
    detector:
        Custom :class:`~prompt_shield.detector.InjectionDetector`.
        Defaults to a standard instance driven by ``config.py``.
    scorer:
        Custom :class:`~prompt_shield.scorer.RiskScorer`.
    policy:
        Custom :class:`~prompt_shield.policy.PolicyEngine`.
    """

    def __init__(
        self,
        detector: InjectionDetector | None = None,
        intent_detector: IntentDetector | None = None,
        scorer: RiskScorer | None = None,
        policy: PolicyEngine | None = None,
    ) -> None:
        self._detector = detector or InjectionDetector()
        self._intent_detector = intent_detector or IntentDetector()
        self._scorer = scorer or RiskScorer()
        self._policy = policy or PolicyEngine()
        logger.info(
            "%s v%s pipeline initialised.",
            config.PROJECT_NAME,
            config.VERSION,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evaluate(self, user_input: str) -> ShieldResult:
        """
        Run *user_input* through the full detection pipeline.

        Parameters
        ----------
        user_input:
            Raw text submitted by the user.

        Returns
        -------
        ShieldResult
            Composite, immutable result covering detection, scoring,
            and enforcement decision.

        Raises
        ------
        TypeError
            Propagated from sub-components if *user_input* is not a str.
        """
        logger.info("--- Evaluating new prompt ---")
        logger.info("Input: %r", user_input[:200])

        # Stage 1: pattern-based injection detection
        detection: DetectionResult = self._detector.detect(user_input)

        # Stage 2: intent-based detection (Phase 1.5)
        intent_result: IntentResult = self._intent_detector.detect(user_input)

        # Stage 3: risk scoring (patterns + intents combined)
        score_result: ScoreResult = self._scorer.score(
            detection.matched_patterns,
            intents=intent_result.intents,
        )

        # Stage 4: apply policy
        decision: PolicyDecision = self._policy.evaluate(
            risk_level=score_result.risk_level,
            risk_score=score_result.score,
        )

        is_detected = detection.detected or intent_result.detected
        result = ShieldResult(
            status=decision.status,
            risk_score=score_result.score,
            risk_level=score_result.risk_level,
            reason=decision.reason,
            detected=is_detected,
            matched_patterns=detection.matched_patterns,
            intents=intent_result.intents,
        )

        logger.info(
            "Final decision | status=%s | score=%d | level=%s | patterns=%s | intents=%s",
            result.status,
            result.risk_score,
            result.risk_level,
            result.matched_patterns,
            result.intents,
        )
        return result
