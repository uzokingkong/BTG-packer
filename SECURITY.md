# Security Policy

## Supported Versions
Security updates and fixes are only applied to the `main` branch and the latest tagged release.

## Reporting a Vulnerability
Please do **not** open a public issue for security vulnerabilities. Instead, report them privately directly to the maintainer via:

* **Email:** uzokingkong@gmail.com
* **Discord:** snake0071

**When reporting, please include:**
* Affected version / commit hash / `build_id` (from `.btgmanifest`)
* Input PE (or minimized reproducer) and exact CLI flags used
* A brief description of the impact (e.g., deterministic-build breakage, anti-tamper bypass)

## Design Notes for Researchers
* **Scope:** The framework's goal is anti-tamper, anti-dump, and anti-static-analysis. Confidentiality of the protected payload against a local attacker with full privileges is not guaranteed. 
* **Deterministic Builds:** The `--seed` flag must always produce byte-identical output. Any deviation that introduces independent entropy is considered a bug and should be reported.
