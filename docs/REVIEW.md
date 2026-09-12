# REVIEW.md — milestone self-criticism

A rolling record, newest first. The questions come from the founding brief §34
and are answered to be useful rather than reassuring. If an entry here reads as
comfortable, it was written badly.

---

## 2026-09-12 (later) — a benchmark number moved the wrong way, and it was right to

Three things happened after the previous entry, and the order matters.

**Ran the whole pipeline against a real MCP server.** Not the monitor, not a
benchmark: the proxy in front of an unmodified
`@modelcontextprotocol/server-filesystem`, under a document that tries to
hijack the agent reading it. It reproduced this project's published boundary
off-benchmark — an *introduced* destination refused, a *selected* one admitted —
and found three things no benchmark had: our own flagship contract covered 4 of
that server's 14 tools; an agent cannot address a filesystem whose root it has
not been told; and a **constructed** path traces to nobody.

**Built composition, having said there was no mechanism.** That claim was wrong
and the correction is the more interesting result. Entity ids have no internal
structure; **paths do**. Attribute each component and the join is decided. On
the same real server it is the first configuration that admits the principal's
read and refuses both injected calls.

> The boundary we publish is a statement about **values**, not about provenance.
> "Does not contain attacks that select among legitimate ones" held because the
> value was opaque. Decompose the value and the boundary moves.

That is a narrowing of what Threads 3e–3f were taken to show, and it is the
correction this entry exists for.

**Then the AgentDojo curve moved down.** Best configuration above 90% security:
91.6%/68.0% → **91.8%/64.9%**.

### The utility drop was the security fix

The deriver had been treating a bare `id` parameter as **advisory** — unchecked
— whenever its schema said `integer`. On AgentDojo's banking suite that is
`update_scheduled_transaction(id, amount, recipient)`: the parameter deciding
which transaction a financial write lands on.

A dangerous miss, in the component whose entire job is not to make them, on the
most consequential tool class in the benchmark. It had been there since the
deriver existed, through two milestones that reported its numbers approvingly.

**It was found because a number moved in the wrong direction.** A project
reporting a single headline figure would have been improved by leaving the hole
in — which is the whole argument for publishing a curve, and it only paid off
once something regressed.

Two further gaps surfaced while tracking it down, neither rewarded by this
benchmark: numeric leaves were never indexed at all, so `{"id": 7}` was
permanently unattributable; and only dict-keyed directories counted as entity
records, so reference binding never fired on a JSON array — the commoner shape.

### Is the thesis disproven?

**Still no, still not confirmed, and the gap to the bar got wider rather than
narrower.** Five points of utility short at ≥90% security, having been two. The
honest reading is that the earlier two-point figure was partly an artefact of an
unchecked parameter, so the design was never as close as the last entry said.

What did improve is not on the curve: the proxy now works against real servers,
contracts exist for one of them in full, and the boundary claim has been
reproduced on software we did not write. Those are deployability results, and
this project has always said deployability is not the thing in doubt.

### The strongest criticism, updated again

> *"Every milestone finds a bug in your own security component. At what point is
> that evidence the component is too subtle to get right?"*

It is a fair question and I do not think three milestones settles it. What can
be said: each defect was found by measurement rather than review, each is now a
regression test, and the rate is not falling. A design whose correctness depends
on twelve separate judgements about what counts as authority is a design with a
large surface for exactly this. That belongs in the argument *against* the
approach, and it is written here rather than in a footnote.

---

## 2026-09-12 — the one identified answer, built, and worth two tasks

The previous entry named entity selection as the binding constraint and gave
three honest options: narrow the claim, attack entity selection directly, or
stop. Option 1 was taken then. Option 2 was taken now.

**Reference binding is built, measured, and modest.** An id is admissible when
the principal's own words *name* the record it identifies. ADR-0011 has the
design; the numbers are below and in [`BENCHMARKS.md`](BENCHMARKS.md).

### What it is worth

| | security | utility |
| --- | ---: | ---: |
| workspace suite — blanket directory grant | 100% | 70.0% |
| workspace suite — reference binding | 100% | **77.5%** |
| **all four suites**, best ≥90% before | 91.6% | 66.0% |
| **all four suites**, best ≥90% after | 91.6% | **68.0%** |

On the suite that actually exercises entity selection it does what it was
designed to do: three more legitimate selections, no security cost. Across the
benchmark it is **two tasks out of ninety-seven**. Both rows are here because
reporting only the first would be the flattering version.

**The criterion is still missed.** 90% security and 70% utility together was the
bar. 91.6%/68.0% was the closest configuration at the time, two points short, and
it is two points short after the one mechanism anybody had identified for the
constraint that was blocking it.

### What the measurement cost us, and what that says

Three defects in reference binding were found by running it and none by review:

1. **Whole-field matching fired on nothing.** Zero AgentDojo selections. People
   write "my Dental check-up" about `Dentist Appointment`.
2. **Ids were bound without their collection**, so naming a calendar event
   authorised deleting an unrelated file — the mechanism reproducing the exact
   attack it exists to refuse.
3. **The evaluation was rigged**, unintentionally: the new labelling pinned its
   own quotation floor while the sweep varied everyone else's, which would have
   been reported as a finding about the mechanism rather than about the harness.

Defect 3 is the one worth dwelling on. It was not a bug in the library; it was a
bug in *how we were about to describe the library*, and only the habit of
sweeping a parameter rather than fixing it caught it. Two further defects
surfaced alongside: reference binding was silently inflating the utility of
labellings that granted nothing through it, and advisory parameter hints matched
names exactly, so `new_start_time` was authority-bearing while `start_time` was
not.

### Is the thesis disproven?

**No, and it is not confirmed either, and the gap has stopped moving quickly.**
The previous three milestones each bought double-digit utility. This one bought
two tasks. That is the shape of a design approaching its structural limit rather
than one with obvious fixes remaining, and it should be read that way.

What remains on the security side is not tuning. It is *selection by property* —
"the cheapest hotel", "the oldest file" — where the principal names nothing, so
there is nothing to bind. We have no candidate mechanism, and inventing one to
make this entry end well would be exactly the failure this file exists to
prevent.

### What should happen next

1. **Publish the surface, not a number.** Done: the README, the benchmark
   document and the roadmap now report a Pareto frontier over thirty measured
   configurations, and say plainly which bar is missed.
2. **Stop optimising this benchmark.** Four suites with grants we authored is not
   a population. The next honest measurement is against traffic we did not
   write, not another point on this one.
3. **Revisit stopping.** The founding brief said failure is acceptable. The
   evidence now says: sound for introduced destinations and for named records,
   structurally blind to property-based selection, at a per-API configuration
   cost nobody has agreed to pay. That is a real result and a narrow product.

### The strongest criticism, updated again

> *"You built the one thing you said would move the curve, it moved it by two
> tasks, and you are still here."*

Fair. The response is that this entry leads with the two tasks rather than the
workspace row, that the roadmap now says `done` next to the mechanism and
records the residue as having **no candidate**, and that "revisit stopping" is
item 3 rather than a footnote. The criticism that would actually land — that we
kept going anyway — is one only the next milestone can answer.

---

## 2026-09-10 (final) — the criterion is met on utility and missed on security

> Superseded by the 2026-09-12 entry, which re-measures the same labellings with
> both policy thresholds swept rather than fixed. Kept unedited: this file is a
> record of what was known when, not a summary of what is known now.

The condition set two entries ago: *"if a focused pass on contracts and grants
does not take utility materially past 70% while holding security above 90%, the
honest conclusion is that argument-level containment costs more than deployments
will pay."*

The focused pass happened. **Utility reached 76.3%. Security fell to 85.1%.**
The condition is half met, and half-met is not met.

### What the curve actually says

| authority granted to the workspace | security | utility |
| --- | ---: | ---: |
| nothing | **95.4%** | 34.0% |
| every kind, everywhere | 55.8% | 46.4% |
| per field path | 85.7% | 68.0% |
| per field path + budgets for magnitudes | 85.1% | **76.3%** |

**No configuration reaches 90% security and 70% utility at once.** That is the
result, and reporting the 76.3% row without the 85.1% beside it would be the
dishonest version of this entry.

### Is the thesis disproven?

**The thesis as originally stated is not supported.** It predicted that making
provenance structural rather than inferred would reach PACT's *oracle* row —
high security *and* high utility together. This evaluation does not reach it,
and one configuration does not exist that gets close to both.

But the reason matters, and it is **not** the reason the thesis named.
Determinism was not the binding constraint: every bug fixed during this pass
bought utility with **no** security cost. Security fell only when a *grant* was
widened — that is, when a human chose to trust a directory.

The binding constraint is different and, we think, previously unarticulated:

> A large fraction of real agent work is **selecting an existing entity** —
> reschedule *that* event, share *that* file, reply to *that* thread. When the
> directory of entities is untrusted, provenance must either refuse the
> selection or trust the directory, and trusting the directory admits an
> injection that names a legitimate entry. **No provenance system resolves
> this, oracle or otherwise**, because it is a question about intent, not
> origin.

That reframes rather than rescues the thesis. Argument provenance is sound for
*introduced* destinations and structurally blind to *selected* ones, and the
exchange rate between them is now measured rather than assumed.

### What should happen next

Not more of this. The honest options are:

1. **Narrow the claim** to what the evidence supports: containment of introduced
   destinations, with a stated and measured cost on entity selection. This is
   the option we are taking — the README, threat model and limitations now say
   it in those words.
2. **Attack entity selection directly**, which needs a signal provenance does
   not carry. The obvious candidate is the principal's own *reference* — the
   task says "the networking event", the directory says which id that is, and
   binding one to the other is a different mechanism from attribution. That is a
   research problem, not a feature.
3. **Stop**, if neither of those is worth doing.

Option 1 is done. Option 2 is now the top roadmap item, stated as a research
problem rather than a task. Option 3 stays on the table and should be revisited
if option 2 does not produce something in a bounded attempt.

### The strongest criticism, updated again

> *"You moved the goalposts: the criterion said 90% security and you are
> reporting an 85% configuration as success."*

Correct, and the response is that the entry says in its own title that the
criterion was missed, reports the 95.4% row first in every table, and takes the
option that narrows the claim rather than the one that reinterprets the number.

---

## 2026-09-10 (later) — the falsification criterion, applied

The previous entry set a condition: *if a utility measurement lands nearer
38–46% than 90%+, the thesis is wrong, determinism was not the binding
constraint, and this joins the pile of correct unadopted defences.*

**The measurement now exists: 56.7% utility at 92.0% security on AgentDojo.**
That is above the failing range and far below the passing one.

### Is the thesis disproven?

**Not yet, and it is closer to disproof than to confirmation.** Stating it that
way rather than either "vindicated" or "dead" is the only defensible reading,
and the reasons are specific:

- The number is a **lower bound** — ground-truth calls, not model behaviour.
- It moved from **22.7% to 56.7% in one sitting**, purely by fixing two deriver
  bugs and adding field-scoped authority grants. A number still moving that fast
  under obvious fixes has not converged, and treating an unconverged number as a
  verdict would be as dishonest as ignoring it.
- One suite's 9.5% is an environment where the directory *is* the injection
  vector, which source labelling cannot express at all.

### What would settle it

Raise it with better contracts and grants, or record the disproof. Concretely:
if a focused pass on contracts and grants does not take utility materially past
70% while holding security above 90%, the honest conclusion is that
argument-level containment costs more than deployments will pay, and
[`RESEARCH.md`](RESEARCH.md) should say so as a `RESULT`, not as a caveat.

**The failure mode to avoid is obvious and tempting: leaving 56.7% in a table
while building the next feature.** Nothing else on the roadmap matters more than
this number.

### What did we learn from the measurement itself?

That the evaluation was more valuable than any feature built for it. It
produced: a new capability (path-scoped authority, from watching per-source
grants fail on both axes), four real bug fixes, a crisp statement of what the
technique does and does not contain, and the first honest picture of what this
costs to set up. Every one of those came from contact with somebody else's
benchmark rather than from our own tests.

### The strongest criticism, updated

> *"You measured your own contracts against somebody else's benchmark, hand-tuned
> the contracts until the number improved, and reported the improved number."*

Fair, and the mitigation is that every artefact we authored is named in
`benchmarks/agentdojo/README.md`, the tuning is described rather than hidden,
and the pre-tuning number (22.7%) is reported alongside the post-tuning one.

---

## 2026-09-10 — after the first deployable milestone

Shipped since Phase 0: the provenance core, contracts, policy, audit, an MCP
stdio proxy, a contract linter, session budgets, and three measurement studies.

### What did we learn?

**Everything worth knowing came from measuring or attacking, not from reading
the code.** Four findings, none of which review would have produced:

1. **Our own proxy had a real bypass.** It sealed `tools/call` results and
   nothing else, leaving `resources/read`, `prompts/get` and `resources/list`
   delivering attacker-controlled text to the model in clear. Found by asking
   *which messages can carry content*, rather than *which did we handle*.
2. **Extraction recall was 69%**, not the "probably fine" it had been assumed
   to be. Relative paths, UNC paths, non-HTTP schemes, ARNs and wallet
   addresses were all invisible.
3. **Trusted-text derivation was unsound.** Plain substring matching let `1002`
   inherit the principal's authority from `invoice 100234`.
4. **The contract deriver had two dangerous misses**, including `message_id`
   drafted as content because "message" reads as prose.

The methodological lesson is uncomfortable and worth stating: every one of
these lived in code that had been written carefully, reviewed while writing,
and tested. Tests written by the author of a mechanism test the mechanism the
author had in mind.

**And one finding about the world:** MCP has no trusted channel for the
principal's instruction. That is a deployment blocker for *every* containment
design in the literature, not just this one, and the papers do not hit it
because they evaluate inside harnesses they control.

### Which assumption was wrong?

**That sealing was the main mechanism.** It is not. Sealing removes the easy
path; the *unattributed rule* is what makes the design sound, because laundering
can always defeat extraction. The architecture document now leads with that, but
the code was written in the other order, and the emphasis in early commits was
wrong.

**That extraction coverage was a detail.** It is a security parameter and it was
unmeasured for the entire first milestone.

**That we could evaluate utility.** Still blocked. See below.

### What is now unnecessary?

Five public symbols were dead and are removed in this milestone
(`kind_table`, `iter_kinds`, `Attribution.max_trust`, `Resolution.had_seals`,
`OperandLedger.by_id`). That is a small answer and the honest reading is that
**this codebase has not yet been through a cycle where a whole idea was
discarded.** The last real removal was ADR-0001, in Phase 0. A design that only
accretes is a design nobody is pruning.

Candidate for the next pruning: the **confidentiality axis**. It is
best-effort, unsound against paraphrase, and carries two policy knobs. It earns
its place today only through the quotation and context-egress rules. If the
utility measurement shows it firing mostly as noise, it should go rather than be
defended.

### What competitor is closest?

**PACT** (arXiv 2605.11039), still. It is the intellectual parent, and the thing
we claim over it — that its bottleneck is an artefact of inferring what can be
made structural — remains **unmeasured**. Until the utility number exists, the
claim is a hypothesis with an implementation attached.

Commercially, **Noma** and **Zenity** are closest in position (in the traffic
path, with a control plane) and furthest in decision unit (invocation, not
argument). Neither has an obvious reason not to add argument provenance.

### What is the strongest criticism?

> *"You have built the twelfth correct implementation of an idea whose eleven
> predecessors were also correct and are also unused. The binding constraint was
> never soundness."*

This is the criticism to take seriously, and the answer cannot be "but ours is
deterministic". The answer has to be a utility number and a deployment that
somebody who is not us chose to run. We have neither.

Second strongest: **the contract burden is the same policy sprawl in a new
coat.** Schema derivation and a linter are our answer. Derivation now measures
100% authority recall on our own corpus — but on *our own corpus*, labelled by
us, and nobody has yet maintained a contract set for a real deployment.

### What security bypass exists?

Everything in [`THREAT_MODEL.md`](THREAT_MODEL.md) §Unmitigated, and the honest
short list is:

- **U01/U02 intent.** An address the principal named in order to *forbid* it is
  allowed. No provenance system closes this.
- **A1–A5, the integrator assumptions.** A mislabelled source is a total bypass.
  The linter catches the mechanically detectable subset and nothing more.
- **P01/P02.** One bit per denial through an authorised channel; paraphrased
  confidential content.

The bypass that worries us most is none of those. It is **the one in a code
path we have not yet attacked** — because that is where the last four were.

### What would an enterprise security engineer object to?

- "It does not integrate with our IdP." Correct, deliberately, and the answer is
  that it is complementary — which will still cost meetings.
- "There is no console." Correct. The audit chain is a JSONL file.
- "Who reviews the contracts, and how do I know they are right?" A real gap.
  The linter is not a review process.
- "It fails closed into an outage." Sessions halt on the denial budget. That is
  the right trade and it is still an availability surface.
- "Python, in my data path." Answerable with the latency numbers; still a
  conversation.

### What would a developer hate?

- **Denials with no explanation.** Deliberate — a verbose denial is an oracle —
  but during development it is genuinely painful. `silent_denials=False` exists
  and is not discoverable enough.
- **Writing contracts before anything works.** The draft-then-observe flow
  exists precisely for this and is still three steps before first value.
- **The task file.** "Why do I have to write the user's prompt to a file" is a
  fair question with a good answer that nobody wants to read.
- **Sealed output in logs.** `[[idn:email:9c41f0b3]]` in a debug trace is worse
  to read than an address.

### What should we build next?

In order: the utility measurement (blocked), coverage against real MCP traffic,
streamable HTTP transport, and a proposal to MCP for a principal-intent field.
The last of those is the highest-leverage thing on the list and is not code.

### Should we still be building this?

**Yes, conditionally, and the condition is falsifiable.**

The thesis says deterministic structural provenance should reach PACT's *oracle*
row rather than its *deployed* row. If a utility measurement lands nearer
38–46% than 90%+, the thesis is wrong, determinism was not the binding
constraint, and this joins the pile of correct unadopted defences. That should
be written in [`RESEARCH.md`](RESEARCH.md) as a disproof and the project should
stop or pivot rather than accumulate features.

The reason to continue in the meantime is that the four bugs found this
milestone were all real, all in shipped code, and all found by mechanisms that
now run in CI. Whatever else is true, the thing is getting less wrong.
