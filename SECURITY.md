# Security Policy

## Status

**IDENSEC is early-stage software and has not been independently reviewed.**
Version 0.x. The security model is documented in
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md), and what it does *not* cover is
documented with equal prominence in
[`docs/LIMITATIONS.md`](docs/LIMITATIONS.md). Read both before deploying it
anywhere that matters.

## Reporting a vulnerability

Report privately through GitHub's **Report a vulnerability** flow on
<https://github.com/jaisurya93945/idensec/security/advisories>. Please do not
open a public issue for an unfixed bypass.

Useful reports include a reproduction — ideally a failing test in the style of
`tests/test_adversarial.py`, which is the fastest possible path from report to
fix, since every fix lands with a regression test anyway.

We will acknowledge receipt, confirm or dispute the finding with reasoning, and
credit you unless you prefer otherwise. We do not currently offer a bounty and
will not pretend otherwise.

## What counts as a vulnerability

**In scope** — any input, under the adversary model in the threat model, that
causes the monitor to `ALLOW` a tool call whose authority-bearing argument is
not positively attributable to an authorised source. Specifically:

- A laundering technique that produces an *attributed* verdict for an
  attacker-chosen value.
- A handle that resolves when it should not, or a kind confusion that admits a
  value into the wrong parameter.
- A composition that inherits authority from a legitimate prefix.
- Extraction gaps that leave a common authority-bearing value unsealed.
- Anything that makes a decision non-deterministic.
- Audit chain manipulation that still verifies.

**Also in scope, and genuinely wanted:** a false *denial* that breaks an
obviously legitimate workflow. Utility failures are the least-measured part of
this project ([`docs/LIMITATIONS.md`](docs/LIMITATIONS.md) §2) and reports are
more valuable to us than they are annoying.

**Out of scope** — the documented limitations. These are known, written down,
and tested as known gaps rather than hidden:

- Negation blindness and the intent gap (U01, U02).
- Paraphrased confidential content escaping quotation-based tracking (P02).
- Authority carried in prose rather than identifiers (U05).
- Aggregate harm across individually authorised calls (U04).
- Denial-feedback leakage within the budget (P01).
- Anything arising from a violated integrator assumption (A1–A5): mislabelled
  sources, mis-declared contracts, content bypassing `observe()`, or executing
  the unresolved arguments instead of the resolved ones.

If you think one of these is worse than we have described, that *is* a report
worth making. The categorisation is a judgement, and judgements can be wrong.

## Supported versions

Pre-1.0: only `main` is supported. There are no backports.

## Our own practice

- Every commit is cryptographically signed and verified against a pinned key
  before push: `python3 tools/verify_commits.py`.
- Zero required runtime dependencies. The library imports nothing outside the
  standard library, and the signature verifier deliberately does not either.
- Every fix for a bypass lands together with a regression test in
  `tests/test_adversarial.py`.
- Security-relevant defaults are restrictive, and a change that relaxes one is
  treated as a breaking change.
