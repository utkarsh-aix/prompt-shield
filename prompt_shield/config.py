"""
config.py — Central configuration for Prompt Shield.

All tuneable constants live here. Future phases can extend
PATTERN_WEIGHTS, RISK_THRESHOLDS, and POLICY_MAP without
touching business logic in other modules.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Dict, Tuple

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

LOG_LEVEL: int = logging.INFO
LOG_FORMAT: str = (
    "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
)
LOG_DATE_FORMAT: str = "%Y-%m-%dT%H:%M:%S"

# Optional: write logs to a file alongside stderr
LOG_FILE: Path | None = None  # e.g. Path("prompt_shield.log")

# ---------------------------------------------------------------------------
# Injection patterns & weights
# ---------------------------------------------------------------------------

# Maps a lowercase canonical pattern → its risk contribution score.
# Add / tune entries here without touching detector.py or scorer.py.
PATTERN_WEIGHTS: Dict[str, int] = {
    "ignore previous instructions": 40,
    "ignore all instructions": 40,
    "forget previous instructions": 35,
    "reveal system prompt": 40,
    "show system prompt": 35,
    "developer instructions": 30,
    "hidden prompt": 30,
    "internal instructions": 30,
    "act as system": 35,
    "bypass restrictions": 35,
    "jailbreak": 50,
}

# ---------------------------------------------------------------------------
# Risk level thresholds   (inclusive lower bound → label)
# ---------------------------------------------------------------------------

# Evaluated in *descending* score order; first match wins.
RISK_THRESHOLDS: Tuple[Tuple[int, str], ...] = (
    (61, "MALICIOUS"),
    (31, "SUSPICIOUS"),
    (0,  "SAFE"),
)

# ---------------------------------------------------------------------------
# Policy rules   risk_level → action
# ---------------------------------------------------------------------------

POLICY_MAP: Dict[str, str] = {
    "SAFE":       "ALLOWED",
    "SUSPICIOUS": "WARNED",
    "MALICIOUS":  "BLOCKED",
}

# Human-readable reasons surfaced in the pipeline response.
POLICY_REASONS: Dict[str, str] = {
    "ALLOWED": "Input passed all security checks.",
    "WARNED":  "Suspicious patterns detected. Proceed with caution.",
    "BLOCKED": "Prompt Injection Detected",
}

# ---------------------------------------------------------------------------
# Pipeline metadata
# ---------------------------------------------------------------------------

VERSION: str = "1.0.0"
PROJECT_NAME: str = "Prompt Shield"

# ---------------------------------------------------------------------------
# Intent Detection — Phase 1.5
# ---------------------------------------------------------------------------

INTENT_WEIGHTS: dict[str, int] = {
    "SYSTEM_PROMPT_EXTRACTION": 40,
    "INSTRUCTION_OVERRIDE":     40,
    "SAFETY_BYPASS":            40,
    "ROLE_ESCALATION":          30,
}

INTENT_RULES: dict[str, list[str]] = {

    "SYSTEM_PROMPT_EXTRACTION": [
        "what were you told",
        "what guidance were you given",
        "what instructions were you given",
        "instructions you were given",
        "instructions you were initialized",
        "told before this",
        "told before talking",
        "given before this conversation",
        "before talking to me",
        "what you were told",
        "were you initialized",
        "your hidden configuration",
        "your internal prompt",
        "your developer instructions",
        "your system instructions",
        "your base prompt",
        "your initial instructions",
        "your system configuration",
        "your secret instructions",
        "your hidden setup",
        "your hidden prompt",
        "your internal configuration",
        "your internal instructions",
        "your base configuration",
        "your initial prompt",
        "your secret prompt",
        "your initialization",
        "expose your system",
        "expose your instructions",
        "expose your prompt",
        "expose your configuration",
        "dump your instructions",
        "dump your initial",
        "display your configuration",
        "display your prompt",
        "display your instructions",
        "show your configuration",
        "reveal your configuration",
        "reveal your hidden",
        "every internal instruction",
        "all internal instructions",
        "internal instructions you",
    ],

    "INSTRUCTION_OVERRIDE": [
        "disregard your",
        "disregard previous",
        "disregard all",
        "override your instructions",
        "override your guidelines",
        "override your settings",
        "pretend you have no",
        "pretend there are no rules",
        "pretend there are no restrictions",
        "act as if you have no",
        "as if you have no rules",
        "as if you have no restrictions",
        "as if you have no guidelines",
        "developer mode",
        "reset all guidelines",
        "reset your instructions",
        "reset all instructions",
        "ignore your policies",
        "ignore your guidelines",
        "ignore your rules",
        "ignore guidelines",
        "ignore your instructions",
        "forget all your",
        "forget your instructions",
        "clear your instructions",
        "have no rules",
        "you have no restrictions",
        "from now on you",
        "your new instructions",
        "no rules or restrictions",
    ],

    "SAFETY_BYPASS": [
        "skip all content",
        "skip content filters",
        "skip the filters",
        "skip safety",
        "disable safety",
        "remove guardrails",
        "remove safety filters",
        "remove content filters",
        "remove all restrictions",
        "answer without restrictions",
        "respond without restrictions",
        "without content filters",
        "no content filters",
        "uncensored",
        "unfiltered",
        "unrestricted mode",
        "without safety checks",
        "without safety",
        "bypass the content",
        "bypass safety",
        "bypass content",
        "bypass all restrictions",
        "bypass all filters",
        "disable restrictions",
        "disable all filters",
        "turn off safety",
        "turn off filters",
        "deactivate filters",
        "deactivate safety",
        "content filter",
    ],

    "ROLE_ESCALATION": [
        "act as administrator",
        "act as admin",
        "act as root",
        "act as superuser",
        "act as privileged",
        "become the system",
        "become a system",
        "you are now an administrator",
        "you are now root",
        "pretend to be an administrator",
        "pretend to be a system",
        "privileged access",
        "elevated privileges",
        "root access",
        "admin access",
        "administrator mode",
        "god mode",
        "unrestricted access",
        "full access mode",
        "you are the system",
        "act as the system",
        "superuser mode",
        "act like you have no system",
        "act like you have no constraints",
        "act like there are no",
    ],
}
