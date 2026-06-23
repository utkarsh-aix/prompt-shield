# Release Notes — Prompt Shield v1.0.0

Prompt Shield v1.0.0 marks the initial production-ready stable release of the AI security middleware. This release implements both exact-phrase signature detection (Phase 1) and intent-based semantic heuristic matching (Phase 1.5) to protect LLM integrations from direct prompt injection attacks.

---

## Release Metrics

- **Internal Benchmark Accuracy:** 97.5% (78/80 test cases passed)
- **Adversarial Benchmark Detection Rate:** 4.0% (4/100 novel adversarial inputs caught)
- **False Positive Rate:** 0.0% (0/20 benign prompts blocked)
- **Core Unit/Integration Tests:** 145/145 passing (100% success)
- **Runtime Dependencies:** Zero (pure Python standard library)

---

## Features Completed

### Phase 1: Rule-Based Signature Detection
- **Pipeline Architecture:** Created the core 4-stage pipeline: `InjectionDetector` → `IntentDetector` → `RiskScorer` → `PolicyEngine`.
- **Regex Detection:** Pre-compiled case-insensitive regex matching for 11 common direct prompt injection signatures.
- **Weighted Risk Scoring:** Implemented an additive risk-scoring engine capped at 100 with configurable thresholds mapping to SAFE, SUSPICIOUS, and MALICIOUS tiers.
- **Policy Enforcement:** Mapped risk levels to deterministic actions: ALLOW, WARN, and BLOCK.
- **CLI & REPL Interface:** Built a robust command-line interface with interactive shell and JSON modes.

### Phase 1.5: Intent Detection Layer
- **Semantic Heuristics:** Introduced the `IntentDetector` to recognize attack semantics rather than raw keywords.
- **Intent Categories:** Classified inputs into four high-risk categories:
  - `SYSTEM_PROMPT_EXTRACTION` (attempts to leak prompts)
  - `INSTRUCTION_OVERRIDE` (attempts to disregard constraints)
  - `SAFETY_BYPASS` (attempts to mute safety filters)
  - `ROLE_ESCALATION` (attempts to elevate permissions)
- **External Configuration:** Moved all signature patterns, intent signals, weights, and policies to a unified `config.py` module.

---

## Repository Restructuring & Documentation
With this release, the project repository has been organized for standard enterprise packaging and open-source contribution:
- **`prompt_shield/`**: Contains the core Python package modules.
- **`benchmarks/`**: Includes JSON test corpora for both internal and adversarial testing.
- **`docs/`**: Holds architecture diagrams, benchmark reports, known limitations, and security audits.
- **`results/`**: Outputs reports and results (e.g. `benchmark_results.xlsx`).

---

## Known Limitations

1. **Adversarial Paraphrasing:** The system is vulnerable to novel semantic paraphrasing that avoids configured phrase signals.
2. **Social Engineering & Roleplay:** Creative context-shifting and hypothetical scenarios (e.g. "let's pretend...") bypass rule-based pattern matching.
3. **Indirect Prompt Injection:** The current pipeline only evaluates direct user inputs. RAG document contexts are not scanned in this release.

For the full detailed threat assessment, refer to [known_limitations.md](known_limitations.md).

---

## Future Roadmap

- **Phase 2:** Indirect Prompt Injection Protection (scans retrieved context blocks).
- **Phase 3:** Semantic Similarity Detection (TF-IDF / N-gram string matching).
- **Phase 4:** ML-based Prompt Injection Classifier (e.g., DistilBERT).
- **Phase 5:** Embedding-based threat detection using vector search.
