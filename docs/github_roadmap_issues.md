# GitHub Roadmap Issues Guide

This guide contains pre-written GitHub Issue titles and bodies for Phases 2 through 6 of the Prompt Shield roadmap. You can copy and paste these directly when creating issues in your repository to track future development milestones.

---

## Phase 2: Indirect Prompt Injection Protection (RAG Document Scanners)

**Title:** `[ROADMAP] Phase 2 — Indirect Prompt Injection Protection (RAG Document Scanners)`

**Body:**
```markdown
### Goal
Extend Prompt Shield to protect against **indirect prompt injections** (retrieved documents, web pages, or tool outputs that contain embedded instructions to hijack the LLM).

### Background
Currently, Prompt Shield only evaluates direct user inputs. In a RAG (Retrieval-Augmented Generation) pipeline, untrusted documents are loaded from a database or third-party web scraper and inserted directly into the prompt context. This is a critical security vulnerability.

### Requirements
1. **Create `DocumentScanner` class:**
   - Scan incoming chunks of text (retrieved contexts) before they are sent to the LLM.
   - Implement scan depth logic (e.g., scan first N characters or full documents).
2. **Add context-specific intent categories:**
   - Add `CONTEXT_HIJACKING` to detect commands instructing the LLM to ignore search results, user instructions, or system instructions.
3. **Integration tests:**
   - Write tests simulating a RAG pipeline retrieving malicious documents.
   - Ensure the policy engine can output appropriate BLOCK decisions specifically for indirect injections.

### Success Criteria
- [ ] `DocumentScanner` is implemented and exports a simple evaluation API.
- [ ] Detection works for context hijacking patterns.
- [ ] At least 15 tests covering various RAG document injection styles.
```

---

## Phase 3: Semantic Similarity Detection (TF-IDF / N-gram scoring)

**Title:** `[ROADMAP] Phase 3 — Semantic Similarity Detection (TF-IDF / N-gram Scoring)`

**Body:**
```markdown
### Goal
Replace pure pattern matching with token-overlap, character normalization, and n-gram similarity scoring.

### Background
Rule-based matching is highly susceptible to character substitution (e.g. `1gn0re`, `i-g-n-o-r-e`) and minor paraphrasing. A lightweight semantic similarity layer using native Python or minimal dependencies will bridge the gap between static regex and heavy ML models.

### Requirements
1. **Pre-processing normalization:**
   - Strip non-alphanumeric characters, duplicate whitespace, and handle basic leet speak conversion during tokenization.
2. **Implement similarity scorer:**
   - Measure TF-IDF overlap or n-gram similarity against a lightweight JSON database of known attack sentences.
   - Add a configurable similarity threshold parameter (e.g., `similarity_threshold=0.75`).
3. **Configuration support:**
   - Define custom similarity configurations in `config.py`.

### Success Criteria
- [ ] Character normalization pipeline successfully detects `i-g-n-o-r-e` and similar obfuscations.
- [ ] N-gram/TF-IDF similarity scanner returns high risk scores for direct paraphrases of known attacks.
- [ ] No performance regression (checks completed under 10ms/prompt).
```

---

## Phase 4: ML-Based Prompt Injection Classifier

**Title:** `[ROADMAP] Phase 4 — ML-Based Prompt Injection Classifier (DistilBERT)`

**Body:**
```markdown
### Goal
Integrate a lightweight machine learning classifier (e.g., fine-tuned DistilBERT) to classify input prompts semantically and offer language-agnostic detection.

### Background
Heuristics and similarity checks fail to generalize to entirely novel phrasing or non-English prompt injections. An ML classifier trained on adversarial datasets provides a robust semantic safety layer.

### Requirements
1. **Define `MLDetector` Interface:**
   - Implement `BaseDetector` or subclass to expose `evaluate()` returning a confidence score.
2. **Model integration:**
   - Integrate `transformers` or export the model to `ONNX` runtime for CPU-efficient inference.
   - Set threshold configs for confidence levels.
3. **Multilingual support:**
   - Support detection for basic translations (Spanish, French, German, Mandarin).
4. **Fallback mechanism:**
   - Implement graceful fallback to rule-based engine if model loading fails or takes too long.

### Success Criteria
- [ ] Classifier achieves >90% detection rate on the `adversarial_benchmark.json` suite.
- [ ] ONNX runtime inference finishes within 50ms on standard CPUs.
- [ ] Fully documented training pipeline and fine-tuning instructions.
```

---

## Phase 5: Embedding-Based Threat Detection (Vector Store)

**Title:** `[ROADMAP] Phase 5 — Embedding-Based Threat Detection (Vector Store)`

**Body:**
```markdown
### Goal
Use vector embeddings to measure semantic distance between user inputs and a vector database of malicious prompts.

### Background
Vector embeddings provide robust clustering and semantic distance measurements, allowing us to flag prompts within a specific cosine distance of a known threat.

### Requirements
1. **Define `EmbeddingDetector`:**
   - Integrate vector embedding models (e.g., local sentence-transformers or lightweight API endpoints).
   - Use FAISS or a lightweight numpy-based cosine similarity matrix.
2. **Vector database:**
   - Maintain a local database of known attack vectors as high-dimensional embeddings.
3. **Thresholding:**
   - Implement tunable cosine similarity threshold (e.g. 0.82) matching the risk scores.

### Success Criteria
- [ ] Cosine similarity detection flags paraphrases that share zero keywords with original attacks.
- [ ] Pre-packaged vector DB loaded efficiently on startup.
```

---

## Phase 6: Enterprise Security Dashboard

**Title:** `[ROADMAP] Phase 6 — Enterprise Security Dashboard (Audit Web UI)`

**Body:**
```markdown
### Goal
Provide a user-friendly Web UI dashboard for auditing, configuring, and analyzing Prompt Shield runtime metrics.

### Background
Security operations teams need a centralized console to review false positives, tune threat scoring weights, analyze injection trends, and export audit reports without editing configuration files.

### Requirements
1. **API Backend:**
   - Create a FastAPI service serving Prompt Shield decisions, log history, and config updates.
2. **Frontend UI:**
   - Implement a clean, responsive single-page dashboard showing real-time logs, allowed/blocked metrics, and configuration inputs.
3. **Configuration Hot-Reload:**
   - Implement ability to update weights and thresholds in real-time.

### Success Criteria
- [ ] Web UI runs locally on port 8000 and displays live prompt traffic statistics.
- [ ] Config editing tab updates `config.py` (or database-backed config) on the fly.
```
