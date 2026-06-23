# Security Policy

This document details the security policy for **Prompt Shield**, including supported versions and how to report vulnerabilities.

---

## Supported Versions

Only the latest release version of Prompt Shield receives active security updates and vulnerability patches.

| Version | Supported |
|---|---|
| **v1.0.x** | ✅ Yes (Active) |
| **< v1.0.0** | ❌ No |

---

## Reporting a Vulnerability

### ⚠️ DO NOT Open a Public Issue for Security Bugs

If you identify a security vulnerability (such as a bypass vector, denial-of-service, or remote code execution vector), please **do not** open a public bug report or pull request. Public disclosure makes systems running Prompt Shield vulnerable to attacks.

### Disclosure Process

Please report all security vulnerabilities confidentially:

1. **Email Your Report:** Send an email to `security@promptshield.dev` (or the repository administrator's contact).
2. **Include Key Information:** To help us evaluate and patch the issue quickly, please include:
   - A clear description of the vulnerability or bypass vector.
   - The exact prompt payload or code snippet used to trigger the behavior.
   - The impact of the vulnerability (e.g., system prompt extraction, policy bypass).
   - Your environment setup (OS, Python version).
3. **Response SLA:**
   - **Acknowledgment:** We will acknowledge receipt of your email within 48 hours.
   - **Triage:** We will investigate and provide a status update within 5 days.
   - **Fix/Patch:** We aim to release a patch for verified vulnerabilities within 14 business days.
   - **Advisory:** We will coordinate a public advisory release alongside the patch release.

---

## Scope of Security Audits

The following areas are considered in-scope for security evaluations:
- Bypasses that allow instruction overrides without triggering high risk scores (>60) on default configurations.
- Execution errors or CPU crashes (DoS) caused by standard input prompts.

The following are out-of-scope:
- Obfuscations that fall under "Known Limitations" (such as character-separated words or foreign languages in v1.0.0). These are actively being addressed in the upcoming roadmap phases (Phase 3 & Phase 4).
