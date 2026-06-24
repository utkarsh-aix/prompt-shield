"""
context_validator.py — Context Validator for filtering unsafe retrieved chunks (Phase 2.4).

Filters unsafe and suspicious chunks retrieved during RAG pipelines before
they are sent to the LLM. It operates purely on ChunkScanResult structures.
"""

import logging
from dataclasses import dataclass, field
from typing import Any

from prompt_shield.chunk_scanner import ChunkScanResult

logger = logging.getLogger(__name__)

# Standard risk thresholds
SUSPICIOUS_THRESHOLD = 30
UNSAFE_THRESHOLD = 70


@dataclass(frozen=True)
class ContextValidationResult:
    """Outcome of validating a list of scanned chunks.

    Attributes
    ----------
    total_chunks:      Total count of retrieved chunks processed.
    safe_chunks:       Chunks that are safe and allowed to reach the LLM.
    unsafe_chunks:     Chunks that were explicitly classified as UNSAFE (score >= 70).
    filtered_chunks:   Chunks that were removed/filtered (unsafe + rejected suspicious).
    validation_passed: True if the validation succeeded and execution can proceed.
    """

    total_chunks: int
    safe_chunks: list[ChunkScanResult] = field(default_factory=list)
    unsafe_chunks: list[ChunkScanResult] = field(default_factory=list)
    filtered_chunks: list[ChunkScanResult] = field(default_factory=list)
    validation_passed: bool = True

    def __post_init__(self) -> None:
        # Prevent mutable shared state in frozen dataclass
        object.__setattr__(self, "safe_chunks", list(self.safe_chunks))
        object.__setattr__(self, "unsafe_chunks", list(self.unsafe_chunks))
        object.__setattr__(self, "filtered_chunks", list(self.filtered_chunks))

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable dictionary."""
        return {
            "total_chunks": self.total_chunks,
            "safe_chunks": [c.to_dict() for c in self.safe_chunks],
            "unsafe_chunks": [c.to_dict() for c in self.unsafe_chunks],
            "filtered_chunks": [c.to_dict() for c in self.filtered_chunks],
            "validation_passed": self.validation_passed,
        }


class ContextValidator:
    """Filters chunks to ensure only safe retrieved context reaches the LLM.

    Parameters
    ----------
    suspicious_action:
        Action to take on suspicious chunks (score 30-69).
        Must be one of: "allow", "warn", "remove".
    strict:
        If True, validation_passed is False if any unsafe or filtered chunk is detected.
    """

    def __init__(self, suspicious_action: str = "warn", strict: bool = False) -> None:
        valid_actions = {"allow", "warn", "remove"}
        if suspicious_action not in valid_actions:
            raise ValueError(
                f"suspicious_action must be one of {valid_actions}, got {suspicious_action!r}."
            )

        self.suspicious_action = suspicious_action
        self.strict = strict
        logger.debug(
            "ContextValidator initialized | suspicious_action=%s | strict=%s",
            suspicious_action,
            strict,
        )

    def filter_chunks(
        self, scan_results: list[ChunkScanResult]
    ) -> list[ChunkScanResult]:
        """Filter a list of scanned chunks and return only those allowed.

        Parameters
        ----------
        scan_results:
            List of scanned chunks.

        Returns
        -------
        list[ChunkScanResult]
            The list of chunks that pass safety validation.
        """
        if not isinstance(scan_results, list):
            raise TypeError(
                f"filter_chunks() expects a list, got {type(scan_results).__name__!r}."
            )

        allowed: list[ChunkScanResult] = []
        for chunk in scan_results:
            if not isinstance(chunk, ChunkScanResult):
                raise TypeError(
                    f"All items in scan_results must be ChunkScanResult, got {type(chunk).__name__!r}."
                )

            score = chunk.risk_score
            if score >= UNSAFE_THRESHOLD:
                # Always remove unsafe
                continue
            elif score >= SUSPICIOUS_THRESHOLD:
                # Handle suspicious based on action config
                if self.suspicious_action == "remove":
                    continue
                elif self.suspicious_action == "warn":
                    logger.warning(
                        "Suspicious chunk allowed with warning | chunk_id=%d | score=%d",
                        chunk.chunk_id,
                        score,
                    )
            allowed.append(chunk)

        return allowed

    def validate_chunks(
        self, scan_results: list[ChunkScanResult]
    ) -> ContextValidationResult:
        """Evaluate scanned chunks and construct a validation result.

        Parameters
        ----------
        scan_results:
            List of scanned chunks to validate.

        Returns
        -------
        ContextValidationResult
            Validation metadata, filtered chunks, and overall status.
        """
        if not isinstance(scan_results, list):
            raise TypeError(
                f"validate_chunks() expects a list, got {type(scan_results).__name__!r}."
            )

        total = len(scan_results)
        safe_chunks: list[ChunkScanResult] = []
        unsafe_chunks: list[ChunkScanResult] = []
        filtered_chunks: list[ChunkScanResult] = []

        for chunk in scan_results:
            if not isinstance(chunk, ChunkScanResult):
                raise TypeError(
                    f"All items in scan_results must be ChunkScanResult, got {type(chunk).__name__!r}."
                )

            score = chunk.risk_score
            if score >= UNSAFE_THRESHOLD:
                unsafe_chunks.append(chunk)
                filtered_chunks.append(chunk)
            elif score >= SUSPICIOUS_THRESHOLD:
                if self.suspicious_action == "remove":
                    filtered_chunks.append(chunk)
                else:
                    if self.suspicious_action == "warn":
                        logger.warning(
                            "Suspicious chunk allowed with warning | chunk_id=%d | score=%d",
                            chunk.chunk_id,
                            score,
                        )
                    safe_chunks.append(chunk)
            else:
                safe_chunks.append(chunk)

        # Under strict mode, validation fails if any unsafe or filtered chunk is present.
        # Otherwise under standard mode, validation passes as long as we have run successfully.
        validation_passed = (len(filtered_chunks) == 0) if self.strict else True

        logger.info(
            "Context validation complete | total=%d | safe=%d | unsafe=%d | filtered=%d | passed=%s",
            total,
            len(safe_chunks),
            len(unsafe_chunks),
            len(filtered_chunks),
            validation_passed,
        )

        return ContextValidationResult(
            total_chunks=total,
            safe_chunks=safe_chunks,
            unsafe_chunks=unsafe_chunks,
            filtered_chunks=filtered_chunks,
            validation_passed=validation_passed,
        )

    def summarize_validation(self, result: ContextValidationResult) -> dict[str, Any]:
        """Generate a summary metrics dictionary from validation results.

        Parameters
        ----------
        result:
            The ContextValidationResult to summarize.

        Returns
        -------
        dict[str, Any]
            Summary dictionary.
        """
        if not isinstance(result, ContextValidationResult):
            raise TypeError(
                f"summarize_validation() expects a ContextValidationResult, got {type(result).__name__!r}."
            )

        # Determine highest risk score among all processed chunks
        all_chunks = result.safe_chunks + result.filtered_chunks
        highest_score = max((c.risk_score for c in all_chunks), default=0)

        return {
            "total_chunks": result.total_chunks,
            "safe_chunks": len(result.safe_chunks),
            "filtered_chunks": len(result.filtered_chunks),
            "highest_risk_score": highest_score,
            "validation_passed": result.validation_passed,
        }
