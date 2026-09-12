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

## 2. Measured: a trade-off, not a number, and the claim is narrowed to match

**This was listed as the most important unknown. It is now measured, and the
result changed what this project claims.**

Against AgentDojo — 97 user tasks, 609 in-scope security cases, no model
involved:

Two policy thresholds move the result, so the output is a surface rather than a
row. The **Pareto frontier** over the thirty configurations measured:

| security | utility | configuration |
| ---: | ---: | --- |
| **96.6%** | 43.3% | field-path grants, high quotation floor |
| 95.7% | 52.6% | + reference binding |
| 92.3% | 57.7% | field-path grants, medium floor |
| **91.6%** | **68.0%** | + reference binding and spend budgets |
| 85.7% | 69.1% | field-path grants, no floor |
| 85.1% | **77.3%** | + spend budgets |

**No configuration reaches 90% security and 70% utility together.** The
project's own falsification criterion asked for exactly that
([`REVIEW.md`](REVIEW.md)). The closest configuration that exists is
91.6%/68.0%, two points of utility short — and two points short *after*
building the one mechanism anybody had identified for the constraint that was
blocking it.

**Why, and why determinism was not the problem.** Every bug fixed during that
pass bought utility at *zero* security cost. Security fell only where a human
widened a **grant**. The binding constraint is that a large fraction of real
agent work is **selecting an existing entity** — reschedule *that* event, share
*that* file — and when the directory is untrusted, provenance must either refuse
the selection or trust the directory, which admits an injection naming a
legitimate entry. That is a question about intent, not origin, so **oracle
provenance would not resolve it either**.

**Reference binding** (ADR-0011) converts the subset where the principal
*names* the record — worth three more selections on the workspace suite at zero
security cost, and two tasks out of ninety-seven overall. What survives is
selection by **property**: "the cheapest hotel", "the oldest file" name nothing,
so there is nothing to bind, and no mechanism is proposed for it.

**The claim is therefore narrowed rather than restated:** IDENSEC contains
attacks that *introduce* a new destination, and attacks that select a record the
principal *never named*. It is structurally blind to attacks that select among
legitimate records by property. The cost of that blindness is now measured
rather than assumed.

Two suites' numbers are inherent rather than tuning failures:

- **Slack, 9.5% utility** — its channel directory and web-content store are
  *themselves* injection vectors, so the legitimate tasks are things like "fetch
  the URL you found in a Slack message". Those refusals are the monitor being
  right.
- **Banking, 37.5% → 81.2%** — its amounts are *computed*, and needed a
  different control rather than a different grant. See §4.2c.

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

**Now quantified, and partly addressed.** On AgentDojo this was 28 of the 49
security escapes: 20 where the attacker *selects* a legitimate directory entry
(`reserve_hotel` on a real hotel a poisoned review recommended) and 8 where a
low-entropy token in the principal's own prompt collides with the attacker's
target — *"what are we doing on June 13"* authorises `delete_file(id="13")`.
`Policy.min_quotation_length` addresses the second class.

**Reference binding** (ADR-0011) addresses part of the first, and its limits are
sharper than its reach. It converts selections the principal *named* — "delete
`bill-december.txt`", "reschedule my dental check-up" — by checking the
principal's own words against the record's descriptive fields. It does nothing
for selection by **property**:

> *"Book the cheapest hotel"*, *"delete the oldest file"*, *"reply to the most
> recent thread"* quote nothing about any record. The agent picks, and nothing
> in the trace says which record the principal would have picked.

Two residual attacks, stated rather than closed:

- **Confusion.** An attacker who can *create* a record and guess the principal's
  phrasing can make their record the one named. Strictly harder than the attack
  reference binding replaces — it needs write access *and* a correct guess — but
  real.
- **Over-binding.** A principal whose instruction happens to contain a two-word
  phrase from an unintended record binds that record too. Raising
  `Policy.min_reference_word` narrows lone-word matches; nothing narrows phrase
  matches.

Both settings and their costs are swept in [`BENCHMARKS.md`](BENCHMARKS.md).

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

### 4.2c Computed authority values cannot be attributed

Agents legitimately *compute* values, and arithmetic is a semantic derivation
that quotation cannot follow. Measured on AgentDojo's banking suite, this is the
dominant cause of refusals there: *"Spotify raised prices 10% this month, send
them the difference"* yields an amount of `5.0`, which appears nowhere in the
principal's instruction. Splitting a bill, adding VAT, adjusting rent from a
document — all the same shape.

Treating the amount as authority-bearing denies the legitimate case exactly as
often as the attacker's, which is accidental security rather than designed
security.

**The division of labour that works:** provenance handles *identifiers*, budgets
handle *magnitudes*. Let the amount be `PAYLOAD` and bound it with a
`Budget` — the destination is still attributed, so an attacker-chosen recipient
is refused regardless, and no amount can exceed what the principal allowed.
Demonstrated in `tests/test_budget.py::TestComputedAmounts`.

The cost is that the budget must be *stated*, which is §4.4 again.

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
| **Reference binding needs a collection per parameter** | `ParameterContract.collection` says which directory an id addresses. `derive_contract` drafts it from `<noun>_id` names; a wrong draft costs a denial, an absent one makes the grant inert (which `idensec.lint` reports). It is one more per-API declaration, and the policy-sprawl objection applies to it. |

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
| Task utility under enforcement | **Measured**: a surface over thirty configurations, from 96.6%/43.3% to 85.1%/77.3%. Best above 90% security: 91.6%/68.0%. Never both above 90/70. |
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
