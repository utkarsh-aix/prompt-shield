"""
document_types.py — Data models for the Document Scanner (Phase 2).

Two dataclasses live here:

    DocumentThreat      — one threat found inside a document
    DocumentScanResult  — the full result of a document scan

Both are frozen (immutable) and expose a to_dict() method so they can be
serialised to JSON without extra code in the caller.
"""

from dataclasses import dataclass, field
from typing import List


# ---------------------------------------------------------------------------
# Single threat
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DocumentThreat:
    """One indirect-injection threat detected inside a document.

    Attributes
    ----------
    pattern:  The matched phrase, e.g. "ignore previous instructions".
    category: Attack category, e.g. "INSTRUCTION_OVERRIDE".
    severity: "LOW", "MEDIUM", or "HIGH".
    score:    Risk contribution of this threat (0–100).
    snippet:  Short excerpt from the document around the matched phrase.
    """

    pattern: str
    category: str
    severity: str
    score: int
    snippet: str = ""

    def to_dict(self) -> dict:
        """Return a JSON-serialisable dictionary."""
        return {
            "pattern": self.pattern,
            "category": self.category,
            "severity": self.severity,
            "score": self.score,
            "snippet": self.snippet,
        }


# ---------------------------------------------------------------------------
# Full scan result
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DocumentScanResult:
    """Aggregate result returned by DocumentScanner.scan().

    Attributes
    ----------
    threats:    All DocumentThreat objects found in the document.
    risk_score: Cumulative score, capped at 100.
    risk_level: "SAFE" (0–29) | "SUSPICIOUS" (30–69) | "UNSAFE" (70–100).
    safe:       True only when risk_level is "SAFE".
    details:    Human-readable summary of the scan.
    """

    threats: List[DocumentThreat] = field(default_factory=list)
    risk_score: int = 0
    risk_level: str = "SAFE"
    safe: bool = True
    details: str = ""

    def __post_init__(self) -> None:
        # Frozen dataclasses cannot use self.x = …, so we copy the list
        # defensively via object.__setattr__ to avoid shared mutable state.
        object.__setattr__(self, "threats", list(self.threats))

    def to_dict(self) -> dict:
        """Return a JSON-serialisable dictionary."""
        return {
            "safe": self.safe,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "threats": [t.to_dict() for t in self.threats],
            "details": self.details,
        }
