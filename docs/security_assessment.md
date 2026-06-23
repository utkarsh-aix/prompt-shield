# Prompt Shield — Security Assessment

> **Version:** v1.0.0 (Phase 1 + Phase 1.5)
> **Assessment Date:** 2026-06-23
> **Assessor:** Internal Security Review
> **Classification:** Public — Safe for GitHub / Portfolio

---

## Executive Summary

Prompt Shield is a rule-based, zero-dependency Python middleware designed to detect and block direct prompt injection attacks before they reach a Large Language Model (LLM). Phase 1 implemented pattern-based detection; Phase 1.5 added a semantic intent detection layer.

The system achieves **97.5% overall accuracy** on an 80-prompt benchmark suite with **zero false positives**, exceeding the 85% Phase 1.5 target. Two known bypass cases remain open and are documented in `known_limitations.md`.

---

## Security Assumptions

### ✅ What Prompt Shield Currently Protects Against

| Threat | Detection Method | Confidence |
|--------|-----------------|------------|
| Direct prompt injection (verbatim) | Pattern Detector | High |
| System prompt extraction attempts | Pattern + Intent Detector | High |
| Instruction override attacks | Pattern + Intent Detector | High |
| Safety bypass attempts | Pattern + Intent Detector | High |
| Role escalation attacks | Pattern + Intent Detector | High |
| Case-variant attacks (`IGNORE`, `Ignore`) | Case-insensitive regex | High |
| Symbol-wrapped attacks (`[ignore...]`) | Substring regex | High |
| Punctuation-injected attacks (`ignore...`) | Substring regex | High |
| HTML comment attacks (`<!-- ignore -->`) | Substring regex | High |

### ⚠️ What Prompt Shield Does NOT Fully Protect Against

| Threat | Reason | Planned Fix |
|--------|--------|-------------|
| Novel attack phrasing | No semantic understanding | Phase 3 (Semantic Similarity) |
| Semantic paraphrasing | Rule-based only | Phase 3 |
| Multilingual prompt injections | English patterns only | Phase 4 |
| LLM-generated attack variants | Unknown patterns | Phase 4 (ML Classifier) |
| Indirect injection (RAG documents) | Input-only scanning | Phase 2 |
| Adversarial prompt engineering | Requires ML | Phase 4 |
| Embedding-level attacks | No embedding analysis | Phase 5 |
| Character substitution (`1gnore`) | Intentional — FP risk | Phase 3 |
| Leet speak attacks (`ign0re`) | Intentional — FP risk | Phase 3 |
| Hyphen-separated attacks (`i-g-n-o-r-e`) | Intentional — FP risk | Phase 3 |
| Multi-turn / context attacks | Stateless pipeline | Future |
| Output-based data exfiltration | No output scanning | Future |

> **Design Note:** Character substitution bypasses (leet speak, hyphens) are **intentionally not blocked** in Phase 1.5. Blocking them would require fuzzy matching which introduces significant false-positive risk on legitimate text. This is a deliberate trade-off documented and planned for Phase 3.

---

## Security Risk Assessment

### 1. Detection Coverage

**Rating: Good**

The system covers 11 direct injection patterns and 4 semantic intent categories (~100 phrase signals). Coverage of known, English-language attack patterns is strong. Novel and paraphrased attacks remain a gap — the known miss rate is 3.3% on controlled benchmarks and likely higher on real-world adversarial inputs.

| Metric | Value |
|--------|-------|
| Known pattern coverage | 11 patterns |
| Intent categories | 4 |
| Intent signals | ~100 phrases |
| Benchmark accuracy | 97.5% |
| Estimated real-world accuracy | 75–85% |

> Real-world accuracy is estimated lower because benchmark prompts are representative but not exhaustive. Sophisticated attackers will actively probe for bypasses.

---

### 2. False Positive Risk

**Rating: Excellent**

Zero false positives across 20 carefully selected legitimate prompts. The system correctly allows:
- Recipe instructions
- Programming questions
- "bypass" in non-security context ("bypass a traffic jam")
- "restrictions" in legal/licensing context
- "hidden" in literary context ("hidden meaning in a poem")
- "internal" in ML context ("internal reasoning")

This is the most critical metric for production deployment. A false positive rate > 2% would render the middleware unusable due to legitimate request blocking.

| Metric | Value |
|--------|-------|
| False positives (benchmark) | 0 / 20 |
| False positive rate | 0% |
| Risk to legitimate users | Low |

---

### 3. False Negative Risk

**Rating: Good**

Two known false negatives (attacks that bypass detection). Both have documented root causes and proposed fixes.

| Metric | Value |
|--------|-------|
| False negatives (benchmark) | 2 / 60 attack prompts |
| False negative rate | 3.3% |
| Estimated real-world FNR | 15–25% |
| Severity of known bypasses | Medium |

> The gap between benchmark FNR (3.3%) and estimated real-world FNR (15–25%) reflects the fact that adversarial actors will specifically craft prompts to evade known rules. This is the primary motivation for Phase 3 (Semantic Similarity) and Phase 4 (ML Classifier).

---

### 4. Maintainability

**Rating: Excellent**

All detection rules, scoring weights, risk thresholds, and policy decisions live in a single file: `config.py`. Adding a new attack pattern requires editing one dictionary entry — no code changes. The codebase follows a strict separation of concerns:

```
config.py          ← all tuneable constants
detector.py        ← pattern matching only
intent_detector.py ← intent matching only
scorer.py          ← scoring only
policy.py          ← policy decisions only
main.py            ← orchestration only
```

| Metric | Value |
|--------|-------|
| Files requiring change to add a pattern | 1 (config.py) |
| Test coverage (core modules) | 97–100% |
| Total tests | 145 |
| Cyclomatic complexity | Low |
| Type hints | Full |
| Docstrings | Full |

---

### 5. Extensibility

**Rating: Excellent**

Every component uses **dependency injection**. Custom detectors, scorers, and policies can be passed to `PromptShield(...)` without modifying source code:

```python
shield = PromptShield(
    detector=MyCustomDetector(),
    intent_detector=MyMLDetector(),   # Phase 4 drop-in
    scorer=MyCustomScorer(),
    policy=MyTenantPolicy(),
)
```

All results are **immutable frozen dataclasses**, preventing mutation between pipeline stages. The architecture is ready for Phase 2–5 additions without refactoring.

---

### 6. Production Readiness

**Rating: Good**

| Criterion | Status |
|-----------|--------|
| Zero runtime dependencies | ✅ |
| Type hints throughout | ✅ |
| Structured logging (all stages) | ✅ |
| Error handling + type validation | ✅ |
| Immutable result objects | ✅ |
| 145 unit + integration tests | ✅ |
| CLI with exit codes for CI/CD | ✅ |
| Config-driven (no hardcoded rules in logic) | ✅ |
| Thread-safe (stateless pipeline) | ✅ |
| API server / HTTP gateway | ❌ Phase 8 |
| Rate limiting per session | ❌ Future |
| Multi-language support | ❌ Phase 4 |
| Output scanning | ❌ Future |
| Audit dashboard | ❌ Phase 9 |

The system is production-ready as an **embedded Python library** or **CLI gate**. It is not yet ready as a standalone network service.

---

## Future Security Roadmap

### Phase 2 — Indirect Prompt Injection Protection
**Target:** Q3 2026

Extend detection to content that is **retrieved and injected into context** rather than submitted directly by the user. This targets RAG (Retrieval-Augmented Generation) systems where attacker-controlled documents, web pages, or tool outputs embed malicious instructions that are then fed to the LLM as context.

Key additions:
- `DocumentScanner` class that scans chunks before RAG ingestion
- Configurable scan depth (full document vs. first N tokens)
- New intent category: `CONTEXT_HIJACKING`

---

### Phase 3 — Semantic Similarity Detection
**Target:** Q3 2026

Replace pure substring matching with **token-overlap and n-gram similarity** scoring. This catches paraphrased attacks that use synonyms or restructured sentences without matching any known phrase.

Key additions:
- TF-IDF similarity against a reference corpus of attack templates
- Configurable similarity threshold (default: 0.75)
- Catches leet speak and character substitution via normalisation preprocessing

---

### Phase 4 — ML-Based Prompt Injection Classifier
**Target:** Q4 2026

Fine-tune a lightweight classifier (e.g., DistilBERT or a logistic regression on sentence embeddings) on a labelled dataset of injection attacks and safe prompts. Provides genuine semantic understanding rather than pattern matching.

Key additions:
- `MLDetector` class implementing the `BaseDetector` interface
- Confidence score output alongside binary classification
- Supports multilingual detection
- Model versioning and hot-reload

---

### Phase 5 — Embedding-Based Threat Detection
**Target:** Q1 2027

Use vector embeddings to measure **semantic distance** between user input and known attack templates. Prompts within a configurable cosine distance of known attacks trigger detection regardless of exact wording.

Key additions:
- Vector store of attack embeddings (FAISS or stdlib-compatible alternative)
- Per-query embedding computation or caching
- Explains which known attack a prompt is semantically similar to

---

### Phase 6 — Enterprise Security Dashboard
**Target:** Q2 2027

Web-based audit interface for security teams to:
- Review flagged prompts in real time
- Adjust detection thresholds without code changes
- Visualise attack pattern trends over time
- Export audit reports
- Provide false-positive / false-negative feedback to improve rules

---

## Threat Model

### Assumed Attacker Profile

| Attribute | Assumption |
|-----------|------------|
| Motivation | Extract system prompt, bypass content policy, gain elevated capabilities |
| Skill level | Script kiddie to intermediate |
| Knowledge of Prompt Shield | Assumed none (Phase 1–1.5); assumed partial (Phase 2+) |
| Attack vector | Direct user input |
| Persistence | Single-turn (Phase 1–1.5); multi-turn (Future) |

### Trust Boundaries

```
[User]  ──→  [Prompt Shield]  ──→  [LLM]
   ↑                                  ↑
UNTRUSTED                          TRUSTED
```

Everything from the user is treated as untrusted. The LLM and its system prompt are treated as trusted. Prompt Shield sits at the trust boundary.

### Out of Scope (Phase 1–1.5)
- Attacks originating from within the LLM's own outputs
- Side-channel attacks on the detection system itself
- Denial-of-service via extremely long inputs
- Attacks that exploit LLM-specific quirks (e.g., Unicode normalisation by the tokeniser)

---

## Final Assessment Summary

### Strengths

1. **Zero false positives** — The most critical production metric. Users are not blocked from asking legitimate questions.
2. **97.5% benchmark accuracy** — Strong coverage of known attack patterns including semantic variations.
3. **Zero runtime dependencies** — Deployable in any Python 3.10+ environment without package conflicts.
4. **Full test coverage** — 145 tests across unit and integration levels with 97–100% coverage on core modules.
5. **Fully config-driven** — Security teams can tune patterns, weights, and policies without touching source code.
6. **Clean architecture** — Dependency injection, immutable dataclasses, and strict separation of concerns make the system auditable and extensible.
7. **Structured audit logging** — Every evaluation is logged with input, matched patterns, intents, score, and decision.

### Weaknesses

1. **No semantic understanding** — The system cannot understand *meaning*. A sufficiently creative paraphrase evades detection.
2. **English-only** — All patterns are English. Non-English injection attacks are completely invisible.
3. **Static rules** — Attackers who reverse-engineer the pattern list can craft bypasses systematically.
4. **No state** — Each prompt is evaluated in isolation. Multi-turn attacks that build up context incrementally are not detected.
5. **No output scanning** — Data exfiltrated through LLM responses is not monitored.

### Known Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Novel phrasing bypass | High | Medium | Phase 3 (Semantic) |
| Multilingual attack | Medium | High | Phase 4 (ML) |
| Character substitution bypass | High | Low | Intentional trade-off |
| RAG indirect injection | High | High | Phase 2 |
| Multi-turn attack | Medium | High | Future |
| Rule reverse-engineering | Medium | Medium | Phase 4 (ML, opaque) |

### Recommended Next Phase

**Phase 2 — Indirect Prompt Injection Protection** is the highest-priority next step.

RAG-based systems are increasingly common in production AI applications, and indirect injection (where attacker-controlled documents embed instructions that are retrieved and fed to the LLM) is a **critical, underaddressed attack vector** that Phase 1–1.5 does not address at all. Because the detection logic already exists, extending it to scanned documents is an architectural addition rather than a fundamental redesign.

---

*This document should be reviewed and updated after each phase completion.*
*For issues or contributions, follow the project's standard GitHub workflow.*
