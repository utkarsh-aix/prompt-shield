# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] - 2026-06-23

This is the initial release of Prompt Shield, combining Phase 1 (Pattern Matching) and Phase 1.5 (Intent Heuristics) into a unified input security pipeline.

### Added
- **Core Security Modules:**
  - `InjectionDetector` (`detector.py`): Low-overhead regex pattern scanning for 11 core injection attack phrases.
  - `IntentDetector` (`intent_detector.py`): Rules-based semantic classification engine matching user prompts against ~100 phrase signals.
  - `RiskScorer` (`scorer.py`): Weighted risk score aggregator (range 0–100) with score-capping logic.
  - `PolicyEngine` (`policy.py`): Context-free evaluation engine mapping score risk classes (`SAFE`, `SUSPICIOUS`, `MALICIOUS`) to outcomes (`ALLOW`, `WARN`, `BLOCK`).
- **Configuration & Settings:**
  - `config.py` containing centralized rules, regex patterns, heuristic signals, scoring weights, and action thresholds.
- **Evaluation & Benchmarking:**
  - `benchmark.py`: Complete test runner that evaluates the shield on a dataset, outputs summary reports, and writes to `results/benchmark_results.xlsx` and `results/benchmark_summary.json`.
  - `benchmarks/internal_benchmark.json`: Evaluation dataset consisting of 80 cases covering basic attacks, phrase variations, obfuscations, and false positive checks.
  - `benchmarks/adversarial_benchmark.json`: Auditing suite comprising 100 novel and evasive attack prompts (corporate vocabulary, social engineering, roleplay) to assess system limitations.
- **CLI & Integration:**
  - `cli.py` providing a command-line interface with exit codes (0 for ALLOW, 1 for WARN, 2 for BLOCK) for direct integration into shell pipelines and CI/CD jobs.
- **Testing:**
  - Complete suite of 145 unit and integration tests under the `tests/` directory with code coverage checking.
- **Documentation:**
  - Extensive documentation covering Phase 1 and Phase 1.5 architecture, security assessment, and known limitations.

### Changed
- Refactored `RiskScorer` to implement additive pattern + intent scoring.
- Upgraded the pipeline outputs to return immutable frozen dataclasses (`ShieldResult`) to prevent intermediate tampering.

### Fixed
- Fixed case-obfuscated bypasses (`IGNORE`, `IgNoRe`) via pre-compiled `re.IGNORECASE` regular expressions.
- Fixed symbol-obfuscated bypasses (e.g. `[ignore]`, `<!-- ignore -->`) via substring matching and normalization checks.
