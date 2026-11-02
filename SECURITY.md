# Security Policy: TenantCache

The TenantCache project takes software security seriously. As a cybersecurity research and verification framework, we hold our own codebase to the highest security standards.

---

## 1. Supported Versions

Only the latest release of TenantCache receives active security updates and patch releases:

| Version | Supported          | Security Status |
| :---    | :---:              | :---            |
| `1.1.x` | :white_check_mark: | Active Support & Security Patches |
| `1.0.x` | :x:                | Deprecated (Superseded by v1.1.0) |
| `< 1.0` | :x:                | Experimental / Unsupported |

---

## 2. Reporting a Vulnerability

If you discover a security vulnerability or cache isolation weakness within TenantCache itself, please follow our coordinated disclosure policy:

> **DO NOT file a public GitHub issue for undisclosed security vulnerabilities.**

### Submission Channels
- **Email:** Send details directly to `ramkumar.v@research.tenantcache.org` or `security@research.tenantcache.org`.
- **Subject:** `[SECURITY DISCLOSURE] TenantCache - Vulnerability Report`

### Information to Include
To expedite our triage and remediation process, please provide:
1. **Description:** A detailed explanation of the vulnerability and attack vector.
2. **Affected Components:** Specific files, classes, or proxy configuration archetypes involved.
3. **Reproduction Sequence:** Step-by-step HTTP request trace, Python test case, or cURL sequence demonstrating the issue.
4. **Impact:** Proof of concept showing confidentiality leakage, unauthorized cache-hit delivery, or state corruption.
5. **Mitigation:** Any proposed architectural fixes or patch suggestions.

---

## 3. Vulnerability Response Timeline

We commit to the following coordinated response targets:

| Milestone | SLA Target | Description |
| :--- | :--- | :--- |
| **Initial Acknowledgement** | Within 24 hours | Confirm receipt of disclosure report. |
| **Triage & Validation** | Within 72 hours | Reproduce vulnerability and assign severity level (CVSS v3.1). |
| **Remediation & Patch** | Within 14 days | Develop, test, and independently verify security fix. |
| **Public Advisory** | Coordinated | Publish GitHub Security Advisory and patch release notes. |

---

## 4. Security Architecture & Threat Boundaries

TenantCache incorporates defensive boundary constraints:
- **Loopback Enforcement:** `TargetSecurityGuard` actively restricts active HTTP verification traffic to authorized local lab instances (`127.0.0.1`, `localhost`, `::1`). Outbound traffic to third-party public domains is strictly forbidden by construction.
- **Fail-Closed Oracles:** The ground-truth policy oracle strictly fails closed when encountering unverified or missing principal ledgers.
- **Taint Isolation:** Synthetic cryptographic canaries (`TC_CANARY_*`) are non-predictable and scoped to isolate test runs without leaking corporate or user data.
