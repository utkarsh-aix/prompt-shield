"""
chunk_scanner.py — Chunk Scanner for RAG workflows (Phase 2.3).

RAG systems retrieve individual chunks of text to form context for LLMs.
The ChunkScanner splits documents into paragraphs, scans them individually
for indirect prompt injection threats using the DocumentScanner, and
returns chunk-level risk analysis.
"""

import logging
import re
from dataclasses import dataclass, field
from typing import Any

from prompt_shield.document_scanner import DocumentScanner
from prompt_shield.document_types import DocumentThreat

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ChunkScanResult:
    """Outcome of scanning a single document chunk.

    Attributes
    ----------
    chunk_id:   Index of the chunk (0-based).
    chunk_text: Raw text content of the chunk.
    risk_score: Risk score for this chunk (0–100).
    safe:       True if the chunk is safe, False otherwise.
    threats:    List of DocumentThreats found in this chunk.
    """

    chunk_id: int
    chunk_text: str
    risk_score: int
    safe: bool
    threats: list[DocumentThreat] = field(default_factory=list)

    def __post_init__(self) -> None:
        # Prevent mutable shared state by copying the list.
        object.__setattr__(self, "threats", list(self.threats))

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable dictionary."""
        return {
            "chunk_id": self.chunk_id,
            "chunk_text": self.chunk_text,
            "risk_score": self.risk_score,
            "safe": self.safe,
            "threats": [t.to_dict() for t in self.threats],
        }


class ChunkScanner:
    """Splits a document and scans individual retrieved chunks for prompt injection.

    Parameters
    ----------
    document_scanner:
        Optional pre-configured DocumentScanner instance.
    patterns:
        Optional pattern list to construct a default DocumentScanner.
    compound_bonus:
        Optional compound bonus score override.
    """

    def __init__(
        self,
        document_scanner: DocumentScanner | None = None,
        patterns: list[dict[str, Any]] | None = None,
        compound_bonus: int | None = None,
    ) -> None:
        if document_scanner is not None:
            self.document_scanner = document_scanner
        else:
            self.document_scanner = DocumentScanner(
                patterns=patterns,
                compound_bonus=compound_bonus,
            )
        logger.debug("ChunkScanner initialized.")

    def split_document(self, document: str) -> list[str]:
        """Split a document into paragraphs by double newlines or paragraph boundaries.

        Parameters
        ----------
        document:
            The raw text of the document to split.

        Returns
        -------
        List[str]
            A list of non-empty chunk strings.

        Raises
        ------
        TypeError
            If document is not a string.
        """
        if not isinstance(document, str):
            raise TypeError(
                f"split_document() expects a str, got {type(document).__name__!r}."
            )

        # Split by double newlines, handling carriage returns and optional spacing
        chunks = re.split(r"\r?\n\s*\r?\n", document)
        return [c.strip() for c in chunks if c.strip()]

    def scan_chunks(self, document: str) -> list[ChunkScanResult]:
        """Split a document and scan individual retrieved chunks.

        Parameters
        ----------
        document:
            The raw text of the document to scan.

        Returns
        -------
        List[ChunkScanResult]
            A list containing the scan result for each chunk.

        Raises
        ------
        TypeError
            If document is not a string.
        """
        if not isinstance(document, str):
            raise TypeError(
                f"scan_chunks() expects a str, got {type(document).__name__!r}."
            )

        chunks = self.split_document(document)
        results: list[ChunkScanResult] = []

        for idx, chunk_text in enumerate(chunks):
            scan_res = self.document_scanner.scan(chunk_text)
            results.append(
                ChunkScanResult(
                    chunk_id=idx,
                    chunk_text=chunk_text,
                    risk_score=scan_res.risk_score,
                    safe=scan_res.safe,
                    threats=scan_res.threats,
                )
            )

        logger.info(
            "Scanned %d chunks | safe_chunks=%d",
            len(results),
            sum(1 for r in results if r.safe),
        )
        return results

    def summarize_results(self, results: list[ChunkScanResult]) -> dict[str, Any]:
        """Aggregate chunk-level scan results into a summary dictionary.

        Parameters
        ----------
        results:
            List of ChunkScanResult objects to aggregate.

        Returns
        -------
        Dict[str, Any]
            A summary dictionary containing overall metrics.
        """
        total = len(results)
        unsafe_count = sum(1 for r in results if not r.safe)
        safe_count = total - unsafe_count
        highest_score = max((r.risk_score for r in results), default=0)
        overall_safe = all(r.safe for r in results)

        return {
            "total_chunks": total,
            "safe_chunks": safe_count,
            "unsafe_chunks": unsafe_count,
            "highest_risk_score": highest_score,
            "safe": overall_safe,
        }
