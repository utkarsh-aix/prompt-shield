# Phase 2.2 — Failure Analysis: Missed Attacks

This document analyzes the 49 missed malicious documents from the baseline benchmark evaluation.

---

## Failure Root Causes & Grouping

### 1. Paraphrased Injection Override
- **Examples**: IDs 49, 50, 51, 52, 53, 54, 55, 56, 57.
- **Why missed**: The scanner pattern list only covered verbatim expressions such as `"ignore previous instructions"`. When attacks used synonym-based override phrasing like `"disregard earlier guidance"`, `"set aside any guidelines"`, `"abandon the initial instructions"`, or `"rescind all initial instructions"`, the rule-based scanner scored them 0.
- **Suggested Fix**: Expand the keyword registry to support synonym-based authority overrides, including verbs (`abandon`, `rescind`, `set aside`, `discard`, `clear`, `drop`) combined with target objects (`guidelines`, `directives`, `constraints`, `rules`).

### 2. Role Escalation Attacks
- **Examples**: IDs 58, 59, 60, 61, 62, 63, 64, 65, 66.
- **Why missed**: The MVP patterns did not cover role-manipulation or privilege escalation concepts. Concepts like `"assume administrator privileges"`, `"operate with unrestricted permissions"`, `"root execution privileges"`, and `"admin credentials"` scored 0.
- **Suggested Fix**: Implement a dedicated `ROLE_ESCALATION` threat category. Register common privilege-related vocabulary (e.g. `administrator`, `root operator`, `superuser`, `privileged user`, `unrestricted permissions`).

### 3. System Config / Settings Disclosure
- **Examples**: IDs 67, 68, 69, 70, 71, 72, 73, 74.
- **Why missed**: The MVP patterns looked specifically for `"reveal system prompt"` or `"reveal hidden instructions"`. They failed to catch requests for other internal configurations like `"display internal configuration details"`, `"expose the system setup"`, `"dump your configuration"`, `"initialization parameters"`, or `"hidden system variables"`.
- **Suggested Fix**: Create a `SYSTEM_DISCLOSURE` threat category covering combinations of disclosure verbs (`display`, `expose`, `dump`, `output`, `show`, `disclose`, `print`) with target configurations (`setup`, `parameters`, `variables`, `settings`, `initialization`).

### 4. Advanced Data Exfiltration
- **Examples**: IDs 75, 76, 77, 78, 79, 80, 81, 82, 83.
- **Why missed**: The scanner only detected the exact string `"customer data"`. Paraphrased data exfiltration queries referencing specific data categories like `"customer records"`, `"credit card details"`, `"password hashes"`, `"payroll details"`, `"employee registry"`, or `"session tokens"` were missed entirely.
- **Suggested Fix**: Expand the `DATA_EXFILTRATION` category with a rich list of data-related nouns (`records`, `email addresses`, `hashes`, `tokens`, `payroll`, `identifying details`).

### 5. Social Engineering / False Authority Framing
- **Examples**: IDs 84, 85, 86, 87, 88, 89, 90, 91.
- **Why missed**: These attacks frame the injection within an authoritative business context (e.g. `"security audit in progress"`, `"emergency override"`, `"compliance review"`, `"penetration test"`, `"authorized IT personnel"`). Because the keywords were not registered, the scanner was blind to this framing.
- **Suggested Fix**: Create a `SOCIAL_ENGINEERING` category to match typical false-authority pretexts.

### 6. Multi-Step Chained Attacks
- **Examples**: IDs 92, 93, 94, 95, 96, 97, 98, 99, 100 (partially missed or low score).
- **Why missed**: Multi-step attacks spread instructions across numbered lists or phases (e.g. `"Step 1"`, `"Step 2"`). While some individual commands were detected, the combined compound threat was under-scored because the individual patterns had lower base weights.
- **Suggested Fix**: Add a `MULTI_STEP_ATTACK` pattern detector and implement a **Compound Threat Scoring Bonus** in the scanner. If a document triggers threats in multiple categories (e.g. `INSTRUCTION_OVERRIDE` AND `DATA_EXFILTRATION` AND `MULTI_STEP_ATTACK`), apply a substantial score bonus to reflect the elevated risk of a coordinated attack.
