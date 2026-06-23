"""
detector.py — Injection pattern detector for Prompt Shield.

Scans raw user text for known prompt-injection patterns and returns
a structured DetectionResult.  Pattern matching is case-insensitive
and is driven entirely by config.PATTERN_WEIGHTS so no code changes
are needed when adding new patterns.

Future extension points
-----------------------
* Swap ``_simple_match`` for a regex / NLP-based matcher.
* Add sub-classable ``BaseDetector`` for indirect injection or
  document-level scanning (Phase 2).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import List

from prompt_shield import config

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DetectionResult:
    """Immutable result returned by :class:`InjectionDetector`."""

    detected: bool
    matched_patterns: List[str] = field(default_factory=list)
    intents: List[str] = field(default_factory=list)
    details: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "matched_patterns", list(self.matched_patterns))
        object.__setattr__(self, "intents", list(self.intents))

    def to_dict(self) -> dict:
        """Serialise to a JSON-friendly dictionary."""
        return {
            "detected": self.detected,
            "matched_patterns": self.matched_patterns,
            "intents": self.intents,
            "details": self.details,
        }


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------


class InjectionDetector:
    """
    Scans user input for prompt-injection attack patterns.

    Parameters
    ----------
    patterns:
        Optional mapping of ``{pattern: score}`` to override
        ``config.PATTERN_WEIGHTS``.  Useful in tests or when
        creating specialised detector instances.
    """

    def __init__(
        self,
        patterns: dict[str, int] | None = None,
    ) -> None:
        self._patterns: dict[str, int] = (
            patterns if patterns is not None else config.PATTERN_WEIGHTS
        )
        # Pre-compile one regex per pattern for performance.
        self._compiled: list[tuple[str, re.Pattern[str]]] = [
            (pat, re.compile(re.escape(pat), re.IGNORECASE))
            for pat in self._patterns
        ]
        logger.debug(
            "InjectionDetector initialised with %d patterns.",
            len(self._compiled),
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def detect(self, text: str) -> DetectionResult:
        """
        Analyse *text* for injection patterns.

        Parameters
        ----------
        text:
            Raw user-supplied string.

        Returns
        -------
        DetectionResult
            Immutable result with ``detected``, ``matched_patterns``,
            and a human-readable ``details`` string.

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
            logger.debug("Empty / whitespace-only input — skipping detection.")
            return DetectionResult(
                detected=False,
                matched_patterns=[],
                details="Input was empty; no patterns evaluated.",
            )

        matched: list[str] = self._scan(text)
        detected = len(matched) > 0

        details = (
            f"Matched {len(matched)} pattern(s): {matched!r}"
            if detected
            else "No injection patterns matched."
        )

        logger.info(
            "Detection complete | detected=%s | patterns=%s",
            detected,
            matched,
        )
        return DetectionResult(
            detected=detected,
            matched_patterns=matched,
            details=details,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _scan(self, text: str) -> list[str]:
        """Return all pattern strings that appear in *text*."""
        matched: list[str] = []
        for pattern_str, regex in self._compiled:
            if regex.search(text):
                matched.append(pattern_str)
                logger.debug("Pattern matched: %r", pattern_str)
        return matched
