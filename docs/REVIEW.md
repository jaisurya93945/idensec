# REVIEW.md — milestone self-criticism

A rolling record, newest first. The questions come from the founding brief §34
and are answered to be useful rather than reassuring. If an entry here reads as
comfortable, it was written badly.

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
