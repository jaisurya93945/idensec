# Contributing

## The short version

```bash
git clone https://github.com/jaisurya93945/idensec && cd idensec
python3 -m pip install -e ".[dev]"
pytest && ruff check . && mypy && python3 tools/verify_commits.py
```

All four must pass. There is no CI dependency to install for the library itself —
it has no runtime dependencies and that is deliberate.

---

## What this project wants

**Attacks.** The most valuable contribution is a test that breaks the monitor. A
failing case in `tests/test_adversarial.py` is worth more than a feature, and it
is the fastest path from a report to a fix.

**Contracts.** Tool contracts for real MCP servers and APIs. These are data, not
code, and they are the part of the project that compounds with contributions.

**Evidence.** Measurements against the gaps listed in
[`docs/LIMITATIONS.md`](docs/LIMITATIONS.md) — utility under enforcement,
extraction coverage, contract derivation accuracy. If you have model API access,
you can answer questions we cannot.

**Honest negative results.** A benchmark that shows the approach costs too much
utility is a contribution, not a problem. See
[`docs/RESEARCH.md`](docs/RESEARCH.md) for how findings are recorded.

---

## Rules that are not negotiable

1. **No model in the decision path.** Not for provenance, not for role
   assignment, not "just as a fallback". This is ADR-0003 and it is the property
   the whole design is built to preserve.
2. **No runtime dependencies in `idensec/`.** A security component in the data
   path should not drag a dependency tree behind it.
3. **Fail closed.** Undeclared parameter → `AUTHORITY`. Unknown tool → assume it
   writes, egresses and is irreversible. Unattributed → deny. A change that
   relaxes a default is a breaking change and needs an ADR.
4. **Determinism.** A verdict is a pure function of session state, contracts,
   policy and call. No clock, no randomness outside handle minting, no I/O.
   `tests/test_determinism.py` enforces this.
5. **Documentation matches implementation.** If a change makes a document wrong,
   the change fixes the document. This applies with particular force to
   `LIMITATIONS.md` and `THREAT_MODEL.md`, whose value is entirely in being
   accurate about what does not work.

---

## Making a change

**Every security fix ships with a regression test** in
`tests/test_adversarial.py`, named for the technique, with the attacker's
capability stated in the docstring.

**Architectural decisions get an ADR** in
[`docs/DESIGN_DECISIONS.md`](docs/DESIGN_DECISIONS.md): problem, alternatives
genuinely considered, evidence, decision, what was rejected, what it costs.
Decisions to *remove* or *not build* get the same treatment — knowing what not
to build is most of the work.

**Milestones get a review entry** in [`docs/REVIEW.md`](docs/REVIEW.md),
answering what was learned, which assumption was wrong, what should be removed,
and whether the project should still exist. If an entry reads as comfortable, it
was written badly.

**Research findings go in the ledger** with an explicit confidence tag: `FACT`,
`INFERENCE`, `HYPOTHESIS`, `EXPERIMENT`, `RESULT`. Nothing is promoted to `FACT`
without a source or an experiment. Do not present inference as fact, and do not
soften an uncomfortable result.

**Claims need evidence.** No "industry-leading", no "unhackable", no
"enterprise-ready". If a number is not measured, say it is not measured. If a
comparison is not verified, label it unverified.

---

## Commits

- Signed. `git config gpg.format ssh`, `git config user.signingkey <your key>`,
  `git config commit.gpgsign true`, and add your public key to
  `.github/allowed_signers` in the commit that first uses it — signed by an
  existing maintainer.
- Verified before push: `python3 tools/verify_commits.py origin/main..HEAD`.
- Meaningful. A change with a reason, a message that explains *why* rather than
  restating the diff, and neither a dozen micro-commits nor one commit
  containing everything.
- Conventional prefixes: `feat:`, `fix:`, `security:`, `test:`, `docs:`,
  `research:`, `benchmark:`, `chore:`.

## Code style

`ruff` and `mypy --strict` are the arbiters; both must be clean. Beyond that:
full type annotations, and comments that explain why a thing is the way it is
rather than what the line does. The security-relevant subtleties in this
codebase — why attribution is existential, why `UNATTRIBUTED` is denied, why tool
descriptions sit at the bottom of the lattice — are exactly the things a future
reader will otherwise "simplify" away.
