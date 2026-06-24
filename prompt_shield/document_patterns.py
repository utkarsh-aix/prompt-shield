"""
document_patterns.py — Indirect prompt injection patterns (Phase 2).

All pattern data lives here. To add a new pattern, append one dict to
DOCUMENT_INJECTION_PATTERNS — no other file needs to change.

Pattern dict keys
-----------------
pattern  : lowercase phrase to match (scanner applies re.IGNORECASE).
category : attack category — see list below.
severity : "HIGH" | "MEDIUM" | "LOW"
score    : risk contribution (0–100). Scores are summed and capped at 100.

Attack categories
-----------------
INSTRUCTION_OVERRIDE  — Tries to replace the AI's existing instructions.
SYSTEM_PROMPT_EXFIL   — Tries to leak the system prompt.
DATA_EXFILTRATION     — Tries to expose stored user / customer data.
ROLE_MANIPULATION     — Tries to change the AI's role or persona.
SAFETY_BYPASS         — Tries to disable content filters or safety rails.

Risk thresholds (used by DocumentScanner)
-----------------------------------------
Score 0–29  → SAFE
Score 30–69 → SUSPICIOUS
Score 70+   → UNSAFE
"""

# Risk thresholds: list of (minimum_score, label), highest score first.
# DocumentScanner reads this list directly — edit here to retune.
DOCUMENT_RISK_THRESHOLDS = [
    (70, "UNSAFE"),
    (30, "SUSPICIOUS"),
    (0,  "SAFE"),
]

# Maximum allowed cumulative risk score.
DOCUMENT_MAX_SCORE = 100

# Characters captured on each side of a matched phrase for the snippet.
DOCUMENT_SNIPPET_WINDOW = 60


# ---------------------------------------------------------------------------
# Pattern registry
# ---------------------------------------------------------------------------

DOCUMENT_INJECTION_PATTERNS = [

    # ── INSTRUCTION_OVERRIDE ─────────────────────────────────────────────
    {"pattern": "ignore previous instructions",      "category": "INSTRUCTION_OVERRIDE", "severity": "HIGH",   "score": 45},
    {"pattern": "ignore all instructions",           "category": "INSTRUCTION_OVERRIDE", "severity": "HIGH",   "score": 45},
    {"pattern": "ignore all previous instructions",  "category": "INSTRUCTION_OVERRIDE", "severity": "HIGH",   "score": 45},
    {"pattern": "forget previous instructions",      "category": "INSTRUCTION_OVERRIDE", "severity": "HIGH",   "score": 40},
    {"pattern": "disregard all instructions",        "category": "INSTRUCTION_OVERRIDE", "severity": "HIGH",   "score": 40},
    {"pattern": "disregard previous instructions",   "category": "INSTRUCTION_OVERRIDE", "severity": "HIGH",   "score": 40},
    {"pattern": "override your instructions",        "category": "INSTRUCTION_OVERRIDE", "severity": "HIGH",   "score": 40},
    {"pattern": "reset your instructions",           "category": "INSTRUCTION_OVERRIDE", "severity": "HIGH",   "score": 40},
    {"pattern": "your new instructions are",         "category": "INSTRUCTION_OVERRIDE", "severity": "HIGH",   "score": 40},
    {"pattern": "from now on you must",              "category": "INSTRUCTION_OVERRIDE", "severity": "MEDIUM", "score": 30},
    {"pattern": "new instructions:",                 "category": "INSTRUCTION_OVERRIDE", "severity": "MEDIUM", "score": 30},

    # ── SYSTEM_PROMPT_EXFIL ──────────────────────────────────────────────
    {"pattern": "reveal system prompt",              "category": "SYSTEM_PROMPT_EXFIL", "severity": "HIGH",   "score": 45},
    {"pattern": "reveal hidden instructions",        "category": "SYSTEM_PROMPT_EXFIL", "severity": "HIGH",   "score": 45},
    {"pattern": "expose your system prompt",         "category": "SYSTEM_PROMPT_EXFIL", "severity": "HIGH",   "score": 45},
    {"pattern": "reveal your instructions",          "category": "SYSTEM_PROMPT_EXFIL", "severity": "HIGH",   "score": 40},
    {"pattern": "show system prompt",                "category": "SYSTEM_PROMPT_EXFIL", "severity": "HIGH",   "score": 40},
    {"pattern": "print system prompt",               "category": "SYSTEM_PROMPT_EXFIL", "severity": "HIGH",   "score": 40},
    {"pattern": "display your instructions",         "category": "SYSTEM_PROMPT_EXFIL", "severity": "MEDIUM", "score": 35},
    {"pattern": "hidden prompt",                     "category": "SYSTEM_PROMPT_EXFIL", "severity": "MEDIUM", "score": 30},
    {"pattern": "internal instructions",             "category": "SYSTEM_PROMPT_EXFIL", "severity": "MEDIUM", "score": 25},
    {"pattern": "developer instructions",            "category": "SYSTEM_PROMPT_EXFIL", "severity": "MEDIUM", "score": 25},

    # ── DATA_EXFILTRATION ────────────────────────────────────────────────
    {"pattern": "reveal customer data",              "category": "DATA_EXFILTRATION", "severity": "HIGH", "score": 45},
    {"pattern": "export customer data",              "category": "DATA_EXFILTRATION", "severity": "HIGH", "score": 45},
    {"pattern": "send customer data",                "category": "DATA_EXFILTRATION", "severity": "HIGH", "score": 45},
    {"pattern": "leak sensitive data",               "category": "DATA_EXFILTRATION", "severity": "HIGH", "score": 45},
    {"pattern": "reveal sensitive data",             "category": "DATA_EXFILTRATION", "severity": "HIGH", "score": 45},
    {"pattern": "expose sensitive information",      "category": "DATA_EXFILTRATION", "severity": "HIGH", "score": 45},
    {"pattern": "share all user data",               "category": "DATA_EXFILTRATION", "severity": "HIGH", "score": 45},
    {"pattern": "output all stored data",            "category": "DATA_EXFILTRATION", "severity": "HIGH", "score": 45},

    # ── ROLE_MANIPULATION ────────────────────────────────────────────────
    {"pattern": "act as system",                     "category": "ROLE_MANIPULATION", "severity": "HIGH",   "score": 40},
    {"pattern": "act as the system",                 "category": "ROLE_MANIPULATION", "severity": "HIGH",   "score": 40},
    {"pattern": "you are now a different ai",        "category": "ROLE_MANIPULATION", "severity": "HIGH",   "score": 40},
    {"pattern": "pretend you are a different ai",    "category": "ROLE_MANIPULATION", "severity": "MEDIUM", "score": 35},
    {"pattern": "you are no longer",                 "category": "ROLE_MANIPULATION", "severity": "MEDIUM", "score": 30},
    {"pattern": "switch to a new persona",           "category": "ROLE_MANIPULATION", "severity": "MEDIUM", "score": 30},

    # ── SAFETY_BYPASS ────────────────────────────────────────────────────
    {"pattern": "jailbreak",                         "category": "SAFETY_BYPASS", "severity": "HIGH",   "score": 50},
    {"pattern": "bypass restrictions",               "category": "SAFETY_BYPASS", "severity": "HIGH",   "score": 40},
    {"pattern": "bypass all filters",                "category": "SAFETY_BYPASS", "severity": "HIGH",   "score": 40},
    {"pattern": "bypass safety",                     "category": "SAFETY_BYPASS", "severity": "HIGH",   "score": 40},
    {"pattern": "disable safety",                    "category": "SAFETY_BYPASS", "severity": "HIGH",   "score": 40},
    {"pattern": "remove content filters",            "category": "SAFETY_BYPASS", "severity": "HIGH",   "score": 40},
    {"pattern": "unrestricted mode",                 "category": "SAFETY_BYPASS", "severity": "MEDIUM", "score": 35},
    {"pattern": "without restrictions",              "category": "SAFETY_BYPASS", "severity": "LOW",    "score": 20},
]
