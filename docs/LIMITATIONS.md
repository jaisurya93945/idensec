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

## 2. Measured, and not yet good enough: the utility cost

**This was listed here as the most important unknown. It is now measured, and
the result is uncomfortable.**

Against AgentDojo — 97 user tasks, 609 in-scope security cases, no model
involved — with the best labelling we could write:

| | |
| --- | ---: |
| Security (assuming the model is *always* hijacked) | 560/609 · **92.0%** |
| Utility (a correct agent's ground-truth calls admitted) | 50/97 · **51.5%** |

Full method, per-suite breakdown and cause analysis in
[`BENCHMARKS.md`](BENCHMARKS.md).

**Against this project's own falsification criterion, that is closer to failure
than to success.** [`REVIEW.md`](REVIEW.md) stated it before the number existed:
the thesis predicts near-oracle utility, and *"if a utility measurement lands
nearer 38–46% than 90%+, the thesis is wrong, determinism was not the binding
constraint"*. 51.5% is nearer the first.

Four things are true about that number, and none of them is a reason to dismiss
it:

1. **It is a lower bound.** Ground-truth calls are not model behaviour, and a
   real agent reads before it writes — read paths are admitted far more often
   than write paths.
2. **Slack's 9.5% is not a monitor failure.** In that suite the channel
   directory and web-content store are themselves injection vectors, so no field
   grant is safe. That environment is outside what source labelling can express.
3. **Most remaining refusals were contract quality, not the monitor.** Fixing
   two deriver bugs and adding field-scoped grants took the total from 22.7% to
   51.5% without weakening security. There is more of that available.
4. **The setup cost is the objection.** Effect classes and scoped grants were
   hand-written per API. That is the policy-sprawl problem this project claims
   to answer, and one afternoon for four APIs does not answer it.

**The obligation this creates:** the next milestone either raises this number
materially with better contracts and grants, or the thesis is wrong and should
be recorded as disproven in [`RESEARCH.md`](RESEARCH.md). It should not be
allowed to sit at 51.5% while features accumulate around it.

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

**Now quantified.** On AgentDojo this accounts for 28 of the 49 security
escapes: 20 where the attacker *selects* a legitimate directory entry
(`reserve_hotel` on a real hotel a poisoned review recommended) and 8 where a
low-entropy token in the principal's own prompt collides with the attacker's
target — *"what are we doing on June 13"* authorises `delete_file(id="13")`.
`Policy.min_quotation_length` addresses the second class and is priced in
[`BENCHMARKS.md`](BENCHMARKS.md); nothing addresses the first, because it is
intent.

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

### 4.2b Non-identifier authority, quantified

A call whose arguments are all content and timestamps has nothing to attribute.
On AgentDojo, `create_calendar_event(title, start_time, end_time, description)`
is admitted for exactly that reason — 20 of the 49 escapes. The linter *does*
flag such a contract (`no-authority-parameter` on a writing tool), so it is
detectable in advance; it is not preventable by provenance.

### 4.3 Extraction coverage is a security parameter

A value whose kind is not registered is never sealed. Nine kinds ship by
default; domain identifiers (tenant ids, cluster names, internal ticket formats)
must be registered with `register_kind()`. Coverage against real-world tool
output is **unmeasured**.

### 4.4 Each call is judged alone unless a budget says otherwise

The admission rule judges one call. Session budgets close the founding brief's
flight-booking example — three individually authorised bookings at 20,000
against a 50,000 cap — over call counts, numeric sums and distinct destinations.

What remains: **a budget must be stated.** IDENSEC cannot infer that "under
50,000" was a limit rather than a preference; that is intent, and §4.1 applies.
Budgets are also per-session, so an agent restarted mid-task starts from zero.

### 4.5 Cross-process provenance is not implemented

Within a session, provenance is exact. Across a process boundary — a sub-agent
with its own context — IDENSEC sees only what that sub-agent returns. The sound
option today is to label sub-agents conservatively. A portable label format is
on the roadmap. See [`DELEGATION_MODEL.md`](DELEGATION_MODEL.md).

### 4.6 The denial channel is bounded, measured, not closed

Denials leak roughly one bit each. The budget bounds the total,
`Session.denial_channel_bits` reports it, and `denial_influenced_egress` will
escalate egress after any denial if you turn it on.

None of that *closes* the channel. What narrows it in practice is that the bits
still have to leave, and an attacker's own destination is never authoritative —
so completing the leak needs a channel the principal chose. That is a real
narrowing, and it leans entirely on the source labels being right (A1). ARM's
counterfactual provenance is the correct general fix (ADR-0009).

---

## 5. Operational limits

| Limit | Detail |
| --- | --- |
| **Integrator assumptions** | Mislabelling a source or a parameter is a total bypass. `idensec.lint` catches the mechanically detectable subset and runs at proxy startup, but it reasons from names and cannot know that *your* `ref` parameter picks a production database. Still the most likely way a real deployment fails. |
| **Availability** | Sessions halt on denial-budget exhaustion and raise on intake-budget exhaustion. Failing closed is right for a security control, but it *is* a denial-of-service surface and should not be described as free. |
| **Session scale** | Attribution is linear in observations: ~3 ms per decision at 1 000 observations. Fine for current agent session lengths; needs an index before 10 000. See [`BENCHMARKS.md`](BENCHMARKS.md). |
| **Intake budget** | 4 MB of observed content per session by default. Exceeding it raises rather than silently forgetting, because a ledger that forgets fails *open* on everything it forgot. |
| **Single-threaded sessions** | A session belongs to one linear execution. Sharing one across concurrent agents would cross-contaminate provenance — a security bug, not a performance one. |
| **Audit is integrity, not authenticity** | A hash chain proves the log was not altered. It does not prove IDENSEC wrote it. An attacker with write access can rewrite the chain from genesis; ship records off-host if that is in your threat model. |
| **MCP needs an out-of-band task channel** | The protocol has nowhere to carry the principal's instruction, and the agent cannot be asked for it without creating a total bypass. The proxy reads it from a host-written file; a host that cannot provide one gets no trusted corpus and should run in observe mode rather than claim enforcement. See [`MCP.md`](MCP.md). |
| **stdio transport only** | The proxy does not yet speak streamable HTTP. Framework adapters are roadmap, not code. |

---

## 6. Limits of the evidence

| Claim | Status |
| --- | --- |
| The monitor is deterministic | **Tested.** `tests/test_determinism.py`. |
| The listed attacks are refused | **Tested.** 46 cases, model-free, adversary controls the agent. |
| The listed benign flows are allowed | **Tested.** 6 cases — a floor, not a utility measurement. |
| Latency figures | **Measured**, on a shared unpinned host; spread reported. |
| Extraction coverage is adequate | **Measured** on a synthetic corpus: 93% recall, 0 false positives. Not measured against real traffic. |
| Contract derivation is accurate | **Measured** on 25 hand-labelled schemas: 100% authority recall, 0 dangerous misses. Ground truth is our own. |
| Task utility under enforcement | **Measured**: 51.5% on AgentDojo ground-truth replay, against 92.0% security. A lower bound, and below what the thesis predicts. |
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
