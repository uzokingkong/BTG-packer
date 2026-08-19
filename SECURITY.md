# Security Policy

## Supported versions

BTG Packer is a research/beta protection framework. Security fixes are applied to
the current `main` branch and the latest tagged release.

## Reporting a vulnerability

Do **not** open a public issue for a security vulnerability. Instead, report it
privately to the maintainers.

- **Where:** contact the repository maintainers via a private channel (email or
  private issue). If no contact is published, open a GitHub issue with the
  `security` label and mark it private if your GitHub plan supports it.
- **What to include:**
  - affected version / commit hash / `build_id` from the `.btgmanifest`
  - input PE (or a minimized reproducer) and the exact CLI flags used
  - expected vs. observed behaviour
  - impact assessment (e.g. runtime code execution, key material disclosure,
    deterministic-build breakage, anti-tamper bypass)

## Response expectations

- Acknowledgment within 48 hours.
- Triage and impact assessment within 5 business days.
- Fix + advisory for confirmed high-impact issues within 30 days.

## Security-relevant design notes (for researchers)

- The packed binary ships a client-recoverable key material (seed) — per the
  limits of any client-side protector, confidentiality of the protected
  plaintext is *not* guaranteed against a determined local attacker. The
  protection goal is anti-tamper / anti-dump / anti-static-analysis, not
  confidentiality.
- Integrity is currently CRC32 + a keyed-MAC layer; the streaming at-rest cipher
  is BTG-C1 / RC4 / ChaCha20 (RFC 8439) selectable via `--crypto-mode`. A
  ChaCha20-Poly1305 AEAD runtime path (tag verification in the boot stub) is the
  planned Phase D hardening.
- Deterministic builds (`--seed`) must produce byte-identical output; any build
  path that introduces independent entropy is a bug (see
  `src/vm/mod.rs::build_vm_module_mba` P3-1 note). Please report such cases as
  security issues too.
- Anti-debug / attestation failures hard-fail (UD2 or seed corruption). This is
  by design for the current research profile but is planned to become a
  profile-controlled risk signal for production use.