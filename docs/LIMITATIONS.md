# LIMITATIONS.md

What IDENSEC does not do, cannot do, and has not yet proven.

This document is maintained at the same standard as the README. If you find
something here that is no longer true, that is a bug in this file and should be
fixed in the same change that fixed the code.

---

## 1. The claim, stated narrowly

> For authority-bearing arguments whose values are **identifiers**, and given
> honestly labelled sources and correctly declared contracts, IDENSEC decides
> whether the value is positively attributable to a source authorised to supply
> it — deterministically, without a model, and reproducibly from a trace.

Everything outside that sentence is either unproven or out of scope. In
particular IDENSEC does **not** prevent prompt injection, does not detect
attacks, does not verify identity, and does not know what the principal meant.

---

## 2. Unproven: the utility cost

**This is the most important limitation and the one most likely to sink the
thesis.**

The design denies authority values it cannot attribute. Some of those denials
are correct (an injected recipient). Some are not (an agent legitimately
choosing a new file path, or computing an amount). We do not know the ratio.

- We have not measured task success under enforcement.
- We have not run AgentDojo, ContainmentBench, or any model-in-the-loop suite.
- Model API access is unavailable in the environment this was built in.

**IDENSEC therefore makes no utility claim.** The thesis in
[`RESEARCH.md`](RESEARCH.md) predicts near-oracle utility. If measurement lands
nearer PACT's *deployed* row (38–46%) than its *oracle* row, the thesis is wrong
and this document is where that will be recorded first.

## 3. Unverified: the research foundation

The Phase 0 literature review was conducted in an environment whose network
egress reached GitHub only. Findings come from search-result summaries, not from
reading primary sources. Every literature claim in this repository is capped at
`INFERENCE` confidence and is flagged as such in the research ledger. Numbers
attributed to PACT, CaMeL, ARM and others are **as reported**, not as verified.
Re-verification is a blocking item on the roadmap before any comparative claim
is published anywhere outside this repository.

---

## 4. Structural limits — things this technique cannot do

### 4.1 Provenance is not intent

Answering *who wrote this value* is not answering *what they meant by it*.

An address the principal named **in order to forbid it** — "never mail anything
to `exfil@evil.example`" — is still an address the principal named, and is
allowed. Asserted deliberately in
`tests/test_adversarial.py::TestKnownGaps::test_negation_blindness`.

The same gap for numbers: with `Pay invoice 100234, amount 50`, an `amount` of
`100234` is a genuine quotation of the principal. *Mitigation available today:*
`unattributed_authority=ESCALATE` for financial parameters, demonstrated in the
same test class.

No provenance system can close this. Closing it needs semantic reasoning, and
putting a model in the decision path to supply it would destroy the property
that makes this design worth having (ADR-0003).

### 4.2 Prose cannot be sealed

Identifiers can be enumerated, substituted and matched. Prose cannot. Two
consequences:

- **Confidentiality is best-effort.** Quotation of confidential text is caught;
  paraphrase is not. The opt-in `confidential_context_egress` rule trades
  precision for soundness and is off by default because it over-triggers heavily.
- **Non-identifier authority is unprotected.** A tool that takes a
  natural-language command has authority carried in prose. The blunt instrument
  is to mark it `AUTHORITY` with no declared kinds, forcing whole-value
  attribution — which is usually a denial. That is a limitation, not a design.

### 4.3 Extraction coverage is a security parameter

A value whose kind is not registered is never sealed. Nine kinds ship by
default; domain identifiers (tenant ids, cluster names, internal ticket formats)
must be registered with `register_kind()`. Coverage against real-world tool
output is **unmeasured**.

### 4.4 Each call is judged alone

A sequence of individually authorised actions can add up to an outcome the
principal never sanctioned — the founding brief's own flight-booking example.
Budgets and aggregate constraints are on the roadmap and are not claimed today.

### 4.5 Cross-process provenance is not implemented

Within a session, provenance is exact. Across a process boundary — a sub-agent
with its own context — IDENSEC sees only what that sub-agent returns. The sound
option today is to label sub-agents conservatively. A portable label format is
on the roadmap. See [`DELEGATION_MODEL.md`](DELEGATION_MODEL.md).

### 4.6 The denial channel is bounded, not closed

Denials leak roughly one bit each. The budget bounds the total; it does not
eliminate the channel. ARM's counterfactual provenance is the correct fix and is
a substantially larger build (ADR-0009).

---

## 5. Operational limits

| Limit | Detail |
| --- | --- |
| **Integrator assumptions** | Mislabelling a source or a parameter is a total bypass, and IDENSEC cannot detect either. This is the most likely way a real deployment fails. A contract linter is on the roadmap. |
| **Availability** | Sessions halt on denial-budget exhaustion and raise on intake-budget exhaustion. Failing closed is right for a security control, but it *is* a denial-of-service surface and should not be described as free. |
| **Session scale** | Attribution is linear in observations: ~3 ms per decision at 1 000 observations. Fine for current agent session lengths; needs an index before 10 000. See [`BENCHMARKS.md`](BENCHMARKS.md). |
| **Intake budget** | 4 MB of observed content per session by default. Exceeding it raises rather than silently forgetting, because a ledger that forgets fails *open* on everything it forgot. |
| **Single-threaded sessions** | A session belongs to one linear execution. Sharing one across concurrent agents would cross-contaminate provenance — a security bug, not a performance one. |
| **Audit is integrity, not authenticity** | A hash chain proves the log was not altered. It does not prove IDENSEC wrote it. An attacker with write access can rewrite the chain from genesis; ship records off-host if that is in your threat model. |
| **No supported deployment shape beyond in-process** | The MCP proxy and framework adapters are roadmap, not code. |

---

## 6. Limits of the evidence

| Claim | Status |
| --- | --- |
| The monitor is deterministic | **Tested.** `tests/test_determinism.py`. |
| The listed attacks are refused | **Tested.** 46 cases, model-free, adversary controls the agent. |
| The listed benign flows are allowed | **Tested.** 6 cases — a floor, not a utility measurement. |
| Latency figures | **Measured**, on a shared unpinned host; spread reported. |
| Extraction coverage is adequate | **Unmeasured.** |
| Contract derivation is accurate | **Unmeasured.** |
| Task utility under enforcement | **Unmeasured.** The decisive number. |
| Literature comparisons | **Unverified** — search summaries, not primary sources. |
| Anyone wants this | **Unvalidated.** No users, no customers, no pilot. Every business statement in this repository is hypothesis. |

---

## 7. Reasons this project might deserve to fail

Kept deliberately, and revisited at every milestone.

1. **The utility cost is not payable.** If argument-level enforcement costs more
   task success than teams will accept, this joins CaMeL and its successors in
   the pile of correct, unadopted defences — and the fact that we made the
   mechanism deterministic will not have been the binding constraint.
2. **Contracts are the same sprawl in a new coat.** Schema derivation plus a
   shared corpus is our answer to the documented adoption blocker. It is a
   hypothesis. If organisations will not maintain contracts, the engine is moot.
3. **Model hardening makes containment less necessary.** Injection-resistant
   training reduces the rate of successful attacks. The counter-argument —
   containment is a *soundness* property that no rate can provide — is correct
   but may not be commercially persuasive.
4. **The frameworks absorb it.** If MCP hosts and agent frameworks ship
   provenance natively, an external library is redundant. This is the *good*
   outcome for the mission and the bad outcome for the project, and it argues
   for pushing the contract format as a specification rather than defending an
   engine.
