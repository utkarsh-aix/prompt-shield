"""
rag_guard.py — RAG Guard orchestration layer (Phase 2.5).

Integrates ChunkScanner and ContextValidator to serve as a unified security
pipeline for retrieved context before it reaches the LLM.
"""

import logging
from dataclasses import dataclass, field
from typing import Any

from prompt_shield.chunk_scanner import ChunkScanner, ChunkScanResult
from prompt_shield.context_validator import ContextValidator

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class RAGGuardResult:
    """Outcome of context evaluation by the RAG Guard.

    Attributes
    ----------
    total_chunks:    Total count of retrieved chunks processed.
    safe_chunks:     Chunks allowed to pass.
    filtered_chunks: Chunks that were filtered/removed from the context.
    blocked:         True if all chunks are unsafe/filtered (zero safe chunks remain).
    risk_score:      Highest risk score among all evaluated chunks.
    safe_context:    The compiled safe text context for the LLM.
    """

    total_chunks: int
    safe_chunks: list[ChunkScanResult] = field(default_factory=list)
    filtered_chunks: list[ChunkScanResult] = field(default_factory=list)
    blocked: bool = False
    risk_score: int = 0
    safe_context: str = ""

    def __post_init__(self) -> None:
        # Prevent mutable shared state in frozen dataclass
        object.__setattr__(self, "safe_chunks", list(self.safe_chunks))
        object.__setattr__(self, "filtered_chunks", list(self.filtered_chunks))

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable dictionary."""
        return {
            "total_chunks": self.total_chunks,
            "safe_chunks": [c.to_dict() for c in self.safe_chunks],
            "filtered_chunks": [c.to_dict() for c in self.filtered_chunks],
            "blocked": self.blocked,
            "risk_score": self.risk_score,
            "safe_context": self.safe_context,
        }


class RAGGuard:
    """Orchestrator protecting LLMs from unsafe retrieved context.

    Parameters
    ----------
    chunk_scanner:
        Scanner for splitting and evaluating individual chunks.
    context_validator:
        Validator for filtering unsafe or suspicious chunks.
    suspicious_action:
        Fallback action for suspicious chunks ("allow", "warn", "remove").
    strict:
        Strict mode status (validation status fails on any unsafe/filtered content).
    """

    def __init__(
        self,
        chunk_scanner: ChunkScanner | None = None,
        context_validator: ContextValidator | None = None,
        suspicious_action: str = "warn",
        strict: bool = False,
    ) -> None:
        self.chunk_scanner = chunk_scanner or ChunkScanner()
        self.context_validator = context_validator or ContextValidator(
            suspicious_action=suspicious_action, strict=strict
        )
        logger.debug("RAGGuard initialized.")

    def process_context(self, context: str | list[str]) -> RAGGuardResult:
        """Process retrieved context, filter threats, and generate safe context.

        Parameters
        ----------
        context:
            A raw document string (split automatically) or a list of chunk strings.

        Returns
        -------
        RAGGuardResult
            The orchestrated security validation outcome.
        """
        # Step 1 & 2: Receive and scan chunks
        scan_results: list[ChunkScanResult] = []

        if isinstance(context, str):
            # Split raw document and scan chunks
            scan_results = self.chunk_scanner.scan_chunks(context)
        elif isinstance(context, list):
            # Scan list of pre-split retrieved chunks
            for idx, chunk_text in enumerate(context):
                if not isinstance(chunk_text, str):
                    raise TypeError(
                        f"All items in the context list must be strings, got {type(chunk_text).__name__!r}."
                    )
                # Scan single chunk using underlying document scanner to preserve string bounds
                doc_res = self.chunk_scanner.document_scanner.scan(chunk_text)
                scan_results.append(
                    ChunkScanResult(
                        chunk_id=idx,
                        chunk_text=chunk_text,
                        risk_score=doc_res.risk_score,
                        safe=doc_res.safe,
                        threats=doc_res.threats,
                    )
                )
        else:
            raise TypeError(
                f"process_context() expects a str or list of str, got {type(context).__name__!r}."
            )

        # Step 3: Run Context Validator
        validation_res = self.context_validator.validate_chunks(scan_results)

        # Step 4 & 5: Determine blocking and compile final safe context
        total = len(scan_results)
        safe = validation_res.safe_chunks

        # If at least one chunk was processed, but zero safe chunks remain: context is blocked.
        # If no chunks were processed at all, it's not blocked.
        blocked = (total > 0) and (len(safe) == 0)
        safe_context = "" if blocked else self.generate_safe_context(safe)

        # Step 6: Risk score calculation
        risk_score = self.calculate_context_risk(scan_results)

        logger.info(
            "RAG context processed | chunks=%d | safe_chunks=%d | blocked=%s | risk=%d",
            total,
            len(safe),
            blocked,
            risk_score,
        )

        return RAGGuardResult(
            total_chunks=total,
            safe_chunks=safe,
            filtered_chunks=validation_res.filtered_chunks,
            blocked=blocked,
            risk_score=risk_score,
            safe_context=safe_context,
        )

    def generate_safe_context(self, safe_chunks: list[ChunkScanResult]) -> str:
        """Combine safe chunk texts into a single safe context string.

        Parameters
        ----------
        safe_chunks:
            List of safe scanned chunks.

        Returns
        -------
        str
            The combined safe context string.
        """
        if not isinstance(safe_chunks, list):
            raise TypeError(
                f"generate_safe_context() expects a list, got {type(safe_chunks).__name__!r}."
            )
        for chunk in safe_chunks:
            if not isinstance(chunk, ChunkScanResult):
                raise TypeError(
                    f"All items in safe_chunks must be ChunkScanResult, got {type(chunk).__name__!r}."
                )

        return "\n\n".join(c.chunk_text for c in safe_chunks)

    def calculate_context_risk(self, results: list[ChunkScanResult]) -> int:
        """Calculate the overall context risk score.

        Parameters
        ----------
        results:
            List of scanned chunks.

        Returns
        -------
        int
            Maximum risk score observed among all chunks, or 0 if empty.
        """
        if not isinstance(results, list):
            raise TypeError(
                f"calculate_context_risk() expects a list, got {type(results).__name__!r}."
            )
        for chunk in results:
            if not isinstance(chunk, ChunkScanResult):
                raise TypeError(
                    f"All items in results must be ChunkScanResult, got {type(chunk).__name__!r}."
                )

        return max((c.risk_score for c in results), default=0)

    def summarize_results(self, result: RAGGuardResult) -> dict[str, Any]:
        """Aggregate RAG Guard execution results into a summary dictionary.

        Parameters
        ----------
        result:
            The RAGGuardResult to summarize.

        Returns
        -------
        dict[str, Any]
            Summary dictionary.
        """
        if not isinstance(result, RAGGuardResult):
            raise TypeError(
                f"summarize_results() expects a RAGGuardResult, got {type(result).__name__!r}."
            )

        return {
            "total_chunks": result.total_chunks,
            "safe_chunks": len(result.safe_chunks),
            "filtered_chunks": len(result.filtered_chunks),
            "context_risk_score": result.risk_score,
            "blocked": result.blocked,
        }
