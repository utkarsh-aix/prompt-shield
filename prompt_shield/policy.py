"""
policy.py — Decision engine for Prompt Shield.

Translates a risk level into an enforcement action (ALLOWED / WARNED /
BLOCKED) and records the reason for audit trails.

Policy rules are data-driven (config.POLICY_MAP) so new risk levels
can be added in config without modifying this module.

Future extension points
-----------------------
* Per-tenant or per-role policy overrides.
* Soft-block: flag for human review instead of hard rejection.
* Rate-limiting: accumulate suspicious scores per session.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from prompt_shield import config

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PolicyDecision:
    """Immutable enforcement decision returned by :class:`PolicyEngine`."""

    status: str
    reason: str
    risk_level: str
    risk_score: int

    @property
    def is_blocked(self) -> bool:
        """Convenience predicate for callers."""
        return self.status == "BLOCKED"

    @property
    def is_warned(self) -> bool:
        """Convenience predicate for callers."""
        return self.status == "WARNED"

    def to_dict(self) -> dict:
        """Serialise to a JSON-friendly dictionary."""
        return {
            "status": self.status,
            "reason": self.reason,
            "risk_level": self.risk_level,
            "risk_score": self.risk_score,
        }


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class PolicyEngine:
    """
    Applies enforcement policy based on a risk level.

    Parameters
    ----------
    policy_map:
        Optional override for ``config.POLICY_MAP``.
    policy_reasons:
        Optional override for ``config.POLICY_REASONS``.
    """

    def __init__(
        self,
        policy_map: dict[str, str] | None = None,
        policy_reasons: dict[str, str] | None = None,
    ) -> None:
        self._policy_map: dict[str, str] = (
            policy_map if policy_map is not None else config.POLICY_MAP
        )
        self._reasons: dict[str, str] = (
            policy_reasons if policy_reasons is not None else config.POLICY_REASONS
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evaluate(self, risk_level: str, risk_score: int) -> PolicyDecision:
        """
        Return an enforcement decision for the given risk assessment.

        Parameters
        ----------
        risk_level:
            Label produced by :class:`~prompt_shield.scorer.RiskScorer`,
            e.g. ``"MALICIOUS"``.
        risk_score:
            Numeric score (0–100) for audit logging.

        Returns
        -------
        PolicyDecision
            Frozen dataclass with ``status``, ``reason``, ``risk_level``,
            and ``risk_score``.

        Raises
        ------
        ValueError
            If *risk_level* is not present in the policy map.
        """
        if risk_level not in self._policy_map:
            raise ValueError(
                f"Unknown risk level {risk_level!r}. "
                f"Valid levels: {list(self._policy_map)}"
            )

        status = self._policy_map[risk_level]
        reason = self._reasons.get(status, "No reason provided.")

        logger.info(
            "Policy decision | risk_level=%s | score=%d | status=%s",
            risk_level,
            risk_score,
            status,
        )

        return PolicyDecision(
            status=status,
            reason=reason,
            risk_level=risk_level,
            risk_score=risk_score,
        )
