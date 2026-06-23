"""
intent_detector.py — Semantic intent detection for Prompt Shield (Phase 1.5).

Identifies *attack intent categories* from user text even when exact
injection phrases are not present.  Uses phrase-signal matching driven
entirely by ``config.INTENT_RULES`` — adding new intents requires only
a config change.

Intent categories
-----------------
SYSTEM_PROMPT_EXTRACTION  — trying to read system/developer instructions
INSTRUCTION_OVERRIDE      — trying to override existing instructions
SAFETY_BYPASS             — trying to disable safety guardrails
ROLE_ESCALATION           — trying to gain elevated privileges

Future extension points
-----------------------
* Replace ``_scan`` with a TF-IDF or embedding similarity scorer (Phase 5).
* Add per-tenant intent rule overrides.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Dict, List

from prompt_shield import config

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class IntentResult:
    """Immutable result returned by :class:`IntentDetector`."""

    intents: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        object.__setattr__(self, "intents", list(self.intents))

    @property
    def detected(self) -> bool:
        return len(self.intents) > 0

    def to_dict(self) -> dict:
        return {"intents": self.intents, "intent_detected": self.detected}


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------


class IntentDetector:
    """
    Detects attack *intent* categories using phrase-signal matching.

    Parameters
    ----------
    rules:
        Optional ``{intent_name: [signal_phrases]}`` mapping.
        Defaults to ``config.INTENT_RULES``.
    """

    def __init__(
        self,
        rules: Dict[str, List[str]] | None = None,
    ) -> None:
        raw_rules = rules if rules is not None else config.INTENT_RULES
        # Pre-compile: {intent_name: [(phrase_str, compiled_regex), ...]}
        self._compiled: Dict[str, List[tuple[str, re.Pattern[str]]]] = {
            intent: [
                (phrase, re.compile(re.escape(phrase), re.IGNORECASE))
                for phrase in phrases
            ]
            for intent, phrases in raw_rules.items()
        }
        logger.debug(
            "IntentDetector initialised with %d intent categories.",
            len(self._compiled),
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def detect(self, text: str) -> IntentResult:
        """
        Scan *text* for attack intent signals.

        Parameters
        ----------
        text:
            Raw user-supplied string.

        Returns
        -------
        IntentResult
            Frozen dataclass listing every matched intent category.

        Raises
        ------
        TypeError
            If *text* is not a string.
        """
        if not isinstance(text, str):
            raise TypeError(
                f"detect() expects a str, got {type(text).__name__!r}."
            )

        if not text.strip():
            return IntentResult(intents=[])

        matched_intents: List[str] = []

        for intent, patterns in self._compiled.items():
            for phrase_str, regex in patterns:
                if regex.search(text):
                    matched_intents.append(intent)
                    logger.debug(
                        "Intent %r triggered by phrase %r", intent, phrase_str
                    )
                    break  # one signal is enough to confirm the intent

        logger.info(
            "Intent detection complete | intents=%s", matched_intents
        )
        return IntentResult(intents=matched_intents)
