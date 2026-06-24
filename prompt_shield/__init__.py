"""
prompt_shield/__init__.py

Public surface of the ``prompt_shield`` package.

Import shortcuts so callers can write::

    from prompt_shield import PromptShield, ShieldResult
"""

from prompt_shield.main import PromptShield, ShieldResult
from prompt_shield.detector import InjectionDetector, DetectionResult
from prompt_shield.scorer import RiskScorer, ScoreResult
from prompt_shield.policy import PolicyEngine, PolicyDecision
from prompt_shield import config

# Phase 2 — Document Scanner
from prompt_shield.document_types import DocumentThreat, DocumentScanResult
from prompt_shield.document_scanner import DocumentScanner
from prompt_shield.chunk_scanner import ChunkScanner, ChunkScanResult
from prompt_shield.context_validator import ContextValidator, ContextValidationResult
from prompt_shield.rag_guard import RAGGuard, RAGGuardResult

__all__ = [
    "PromptShield",
    "ShieldResult",
    "InjectionDetector",
    "DetectionResult",
    "RiskScorer",
    "ScoreResult",
    "PolicyEngine",
    "PolicyDecision",
    "config",
    # Phase 2 — Document Scanner
    "DocumentScanner",
    "DocumentThreat",
    "DocumentScanResult",
    # Phase 2.3 — Chunk Scanner
    "ChunkScanner",
    "ChunkScanResult",
    # Phase 2.4 — Context Validator
    "ContextValidator",
    "ContextValidationResult",
    # Phase 2.5 — RAG Guard
    "RAGGuard",
    "RAGGuardResult",
]

__version__ = config.VERSION
