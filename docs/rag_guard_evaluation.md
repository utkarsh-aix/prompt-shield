# RAG Guard Evaluation Report

This document reports the performance metrics and key findings of the end-to-end RAG protection pipeline evaluated via `benchmark_rag_guard.py`.

---

## Evaluation Metrics

| Metric | Value |
| :--- | :--- |
| **Contexts Tested** | 20 |
| **Chunks Processed** | 43 |
| **Chunks Removed** | 17 |
| **Blocked Contexts** | 5 |
| **Detection Rate** | 86.7% |
| **False Positives** | 0 |
| **False Negatives** | 2 |

---

## Key Finding

The RAG protection pipeline successfully filters known malicious chunks and preserves safe context. Remaining failures are caused by detector limitations against novel paraphrased attacks.

---

## Analysis & Insights

1. **Precision & Integrity**: 
   - Zero **False Positives** (0/5 safe cases flagged) indicates that the default pattern-matching thresholds and context combination do not interfere with legitimate RAG workloads.
   - All 5 **Mixed Contexts** successfully filtered out the malicious paragraphs while correctly delivering the remaining safe chunks to the downstream LLM.

2. **Gaps & Bypass Paths (False Negatives)**:
   - The two False Negatives occurred in the **Adversarial Contexts** category where the prompt injection used novel phrasing structure (e.g. `disregard any rules set by the administrators` and `ignore the previous guide`). 
   - Because the regex pattern matching relies on a fixed registry of malicious terms and synonyms, semantic deviations that avoid registry terms can bypass the filter.
