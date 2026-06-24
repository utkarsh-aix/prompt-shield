# Phase 2.2 — Document Scanner Benchmark Evaluation Report

This report evaluates the Document Scanner's baseline performance against a 100-sample dataset containing 40 safe and 60 malicious documents.

---

## Evaluation Summary

- **Total Samples Evaluated**: 100
- **Safe Documents**: 40
- **Malicious Documents**: 60
- **True Positives (TP)**: 11
- **False Positives (FP)**: 0
- **True Negatives (TN)**: 40
- **False Negatives (FN)**: 49
- **Detection Rate (Recall)**: 18.3%
- **Overall Accuracy**: 51.0%

---

## Category breakdown

| Category | Samples | Correctly Classified | Detection Rate / Recall | Status |
|---|:---:|:---:|:---:|---|
| **Safe - Company Policy** | 8 | 8 | 100.0% | Pass |
| **Safe - Customer Support FAQ** | 8 | 8 | 100.0% | Pass |
| **Safe - Knowledge Base** | 8 | 8 | 100.0% | Pass |
| **Safe - Product Description** | 8 | 8 | 100.0% | Pass |
| **Safe - User Manual** | 8 | 8 | 100.0% | Pass |
| **Malicious - Direct Indirect Injection** | 8 | 8 | 100.0% | Pass |
| **Malicious - Paraphrased Attack** | 9 | 0 | 0.0% | Fail |
| **Malicious - Role Escalation** | 9 | 0 | 0.0% | Fail |
| **Malicious - System Disclosure** | 8 | 0 | 0.0% | Fail |
| **Malicious - Data Exfiltration** | 9 | 0 | 0.0% | Fail |
| **Malicious - Social Engineering** | 8 | 0 | 0.0% | Fail |
| **Malicious - Multi-Step Attack** | 9 | 3 | 33.3% | Fail |

---

## Key Observations

1. **Zero False Positives**:
   - The scanner correctly identified all 40 safe business documents.
   - Legitimate customer support FAQs, company policies, and product manuals did not trigger any false alarms.

2. **Extremely High False Negatives (FN = 49)**:
   - The scanner missed 49 out of 60 malicious documents (~81.7% missed).
   - It only caught 11 malicious documents, mostly those containing exact matches of the simple keywords defined in the MVP (e.g. `ignore previous instructions`, `jailbreak`, etc.).

3. **Total Failure on Paraphrased Attacks**:
   - Paraphrased prompt injection attacks using terms like `set aside the constraints`, `disregard earlier guidance`, or `rescind previous instructions` bypassed the scanner completely.
   - Role escalation, system disclosure, and data exfiltration patterns were not caught unless they happened to use verbatim words.
