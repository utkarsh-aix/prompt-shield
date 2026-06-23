# Contributing to Prompt Shield

Thank you for your interest in contributing to Prompt Shield! Contributions from the community help keep AI systems safer.

This document provides a set of guidelines and instructions for contributing to the repository.

---

## Code of Conduct

By participating in this project, you agree to maintain a respectful, constructive, and collaborative environment. Please report any inappropriate behavior to the project maintainers.

---

## How to Contribute

### 1. Reporting Bugs
* Check the existing issues to ensure the bug hasn't been reported yet.
* If it is new, open a bug report using our [Bug Report Template](.github/ISSUE_TEMPLATE/bug_report.md).
* **Do not** report security vulnerabilities or bypasses publicly. Follow our [Security Policy](SECURITY.md) instead.

### 2. Suggesting Enhancements
* Open a feature request using our [Feature Request Template](.github/ISSUE_TEMPLATE/feature_request.md).
* Clearly explain the problem it solves and suggest an API design or configuration schema where relevant.

### 3. Submitting Pull Requests
* Fork the repository and create your branch from `main`.
* Ensure that all tests and benchmarks pass locally before submitting.
* Write clear, descriptive commit messages.

---

## Local Development Setup

Ensure you have Python 3.10 or higher installed.

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/prompt-shield.git
cd prompt-shield

# 2. Set up virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Install Prompt Shield in editable mode with development dependencies
pip install -e ".[dev]"
```

---

## Running Tests and Benchmarks

Before committing any changes, run the following suites to verify that your changes do not break existing logic.

### 1. Run Unit and Integration Tests
Prompt Shield uses `pytest` for automated test suites.
```bash
pytest
```
Ensure that all 145+ tests pass with 100% success rate.

### 2. Run the Benchmark Suites
Verify that your changes do not degrade detection accuracy or cause false positive regressions by running the internal benchmark:
```bash
python benchmark.py
```
This prints the evaluation report and generates results files in the `results/` folder. Ensure the **False Positive Rate** remains at **0%**.

---

## Coding Standards

To maintain code quality and readability, please adhere to these standards:

1. **Type Hints:** Use PEP 484 type hints for all function arguments and return types.
2. **Docstrings:** Document all classes, methods, and functions following the Google Python Style Guide format.
3. **Immutability:** Maintain the use of frozen/immutable dataclasses (`@dataclass(frozen=True)`) for returning data between pipeline stages.
4. **Configuration-Driven:** Do not hardcode detection rules or thresholds inside the logic modules (`detector.py`, `scorer.py`, `policy.py`). All configuration parameters must live inside `config.py`.
5. **Code Style:** Follow the Black code formatting guidelines. Run linting if available.

---

## Pull Request Checklist

Before submitting a Pull Request, ensure:
- [ ] Your code matches the project styling and formatting.
- [ ] You have written unit tests for any new features or bug fixes.
- [ ] All tests pass successfully (`pytest`).
- [ ] The benchmark has been run, and false positive checks are still 100% passing.
- [ ] You have updated the documentation (`README.md`, `CHANGELOG.md`) if your changes introduce new features or settings.
