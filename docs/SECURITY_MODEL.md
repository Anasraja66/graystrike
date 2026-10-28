# APT Agents CI/CD Security & Safety Model

This document outlines the safety architecture, permission model, and isolation controls implemented in the APT Agents GitHub Actions integration.

---

## 1. Machine-to-Machine Authentication & Least Privilege
- **No Human Password Storage:** Workflows never store or transmit human passwords or interactive login sessions.
- **One-Way SHA-256 Hashing:** The server only stores `SHA256(raw_api_key)`. Secret tokens (`apt_live_...`) are returned exactly once upon generation.
- **Project Scoping:** API Keys can be constrained to individual projects or organizations with explicit capability scopes (`ci:scan`, `findings:read`).
- **Immediate Revocation:** Any compromised API key can be deactivated immediately via `DELETE /api/v1/ci/keys/{key_id}` without resetting user accounts.

---

## 2. Scope & Safety Enforcement (Anti-SSRF Architecture)
When testing pull requests, attackers often attempt to supply malicious targets in PR descriptions or branch configurations to probe internal clouds or corporate networks.

APT Agents prevents this with strict, multi-layered scope verification:
1. **Forbidden Target Blacklist:**
   - Cloud metadata IPs (`169.254.169.254`)
   - Loopback / Localhost (`127.0.0.1`, `localhost`, `0.0.0.0`)
   - Link-local and private network ranges
2. **Domain Matching Constraint:**
   - Any `target_url` provided in a PR must strictly match the project's base hostname or an authorized subdomain (`*.project.com`). Any other URL is rejected with HTTP `400 Scope Violation`.
3. **DNS Rebinding & Hostname Resolution Verification:**
   - Target hostnames are resolved and IP addresses verified before requests are dispatched.

---

## 3. Secret Redaction Filter
Automated PR comments and GitHub Step Summaries must never leak production credentials or sensitive session tokens.

APT Agents implements an automated regex-based redaction engine on all CI output:
- **JWT Tokens:** Masked to `[REDACTED_JWT]`
- **Bearer Tokens:** Masked to `Bearer [REDACTED_TOKEN]`
- **Passwords & Secret Keys:** Masked to `[REDACTED]`
- **Session & CSRF Cookies:** Masked to `cookie: [REDACTED_COOKIE]`

---

## 4. Non-Destructive Heuristic Auditing
CI/CD automated scans execute safe, non-destructive security probes:
- Injections use benign canary tags (`apt_retest_safe_...`) rather than data-destructive drop/update statements.
- Rate limits (RPS) and request quotas protect preview environments from resource exhaustion or denial-of-service.
