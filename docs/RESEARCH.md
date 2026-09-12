# RESEARCH.md — IDENSEC research ledger

A living record of what we looked at, what we concluded, and how confident we are.
Every entry is tagged with one of:

| Tag | Meaning |
| --- | --- |
| `FACT` | Directly observed in a source, or directly observed in our own code/tests. |
| `INFERENCE` | Our reasoning over one or more facts. Could be wrong. |
| `HYPOTHESIS` | Not yet tested. Stated so it can be disproven. |
| `EXPERIMENT` | Something we ran. Method is recorded. |
| `RESULT` | Outcome of an experiment, including negative results. |

Nothing in this file may be promoted from `INFERENCE` to `FACT` without a source
or an experiment.

---

## Research-environment limitation (read this before trusting anything below)

`FACT` (2026-09-09) — The build environment used for the Phase 0 research pass
has restricted outbound network egress. Only GitHub hosts were reachable;
`arxiv.org`, `nist.gov`, vendor sites and publisher sites were blocked by the
egress proxy. Verified by direct probe: eight hosts tested, only
`github.com` / `raw.githubusercontent.com` returned a response.

**Consequence:** the Phase 0 findings below are derived from *search-engine
result summaries*, not from reading primary sources end to end. Titles, venues,
arXiv identifiers and headline claims are recorded as reported. They are good
enough to establish *that a line of work exists* and roughly *what it claims*.
They are **not** good enough to support a claim that we have read, reproduced or
correctly characterised any specific paper's method or numbers.

Every literature entry below is therefore capped at `INFERENCE` confidence with
respect to technical detail, even where the existence of the work is `FACT`.
Re-verification against primary sources is tracked as a blocking task in
[`ROADMAP.md`](ROADMAP.md) before any external claim of comparison or
benchmark parity is published.

---

## Phase 0 — starting state

`FACT` (2026-09-09) — The IDENSEC repository was empty at the start of this
work: no commits, no code, no documentation, no history. There was therefore no
pre-existing thesis, architecture, security model or technical debt to inherit.
The "initial hypothesis" in the founding brief is the only prior input.

`FACT` (2026-09-09) — Commit signing is available in this environment: SSH
signature format, ed25519 key
`ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKy87HxSEheG8vEPhSs9u2KZCtVErAQfpmprtUJCZ2w7`,
confirmed by inspecting the `gpgsig` header of a probe commit object. Local
verification via `git log --show-signature` is *not* available because the
signer binary supports `-Y sign` only, not `-Y verify`; signatures are therefore
verified by inspecting the commit object and by GitHub's own verification after
push.

---

## Thread 1 — Is "stateful delegated authority for agents" an open problem?

The founding hypothesis was that autonomous agents need authorization that is
stateful, delegated, task-scoped and chain-aware, and that this is unserved.

### 1.1 The commercial market has already converged on this vocabulary

`FACT` (2026-09-09, search summaries of 2026 landscape reports) — Reported state
of the AI-agent identity market in 2026:

- Microsoft Entra Agent ID reached general availability in April 2026.
- Okta and Auth0 are shipping agent-native identity capability.
- Several well-funded 2026 entrants in agent identity/authorization
  (reported: Oak $60M, NewCore $66M, Keycard $38M).
- AI/agent security took roughly a quarter of cybersecurity seed funding in
  Q2 2026 (as reported).

`FACT` (as reported) — The most load-bearing sentence we found in the landscape
coverage: *"Product vocabulary converged across every segment: an agent
registry, a human sponsor bound to each agent, short-lived scoped credentials,
MCP-layer enforcement, and runtime (not login-time) authorization."*

`INFERENCE` — Every noun in the founding hypothesis is now standard product
vocabulary sold by incumbents and by funded startups. "Runtime, not login-time,
authorization for agents" is not a differentiator in 2026; it is table stakes.

**Confidence:** high on convergence, medium on the specific funding figures
(single-source, secondary).

### 1.2 The research community has already published the sharper version

`FACT` (existence) — `PAuth — Precise Task-Scoped Authorization For Agents`,
arXiv 2603.17170, March 2026, associated with Microsoft Research. Reported
premise: OAuth-style *operator-scoped* authorization (grant the `transfer`
operator) is structurally over-privileged compared to what a natural-language
task actually implies (`transfer $100 to Bob`). Reported mechanism: "NL slices"
(symbolic specifications of the calls a service expects, derived from the task
and upstream results) plus "envelopes" (structures binding each operand's
concrete value to its symbolic provenance so a server can verify the operand
arose from a legitimate computation). Evaluated on AgentDojo.

`INFERENCE` — This is the founding hypothesis, published, by a major industrial
research lab, six months before this work started, with a sharper framing than
ours (operand-level rather than chain-level).

`FACT` (existence) — Adjacent published work found in the same pass:
`Authorization Propagation in Multi-Agent AI Systems` (arXiv 2605.05440),
`SessionBound: Turning Enterprise Task Approval into Budgeted Database Sessions`
(arXiv 2607.00751).

### 1.3 Verdict on the founding hypothesis

`INFERENCE` — **The founding hypothesis is not disproven as a description of
reality; it is disproven as a differentiator.** Stateful, delegated, task-scoped
agent authorization is real, is needed, and is being built by incumbents,
funded startups and industrial research simultaneously. Building "an agent
authorization engine" as such would be entering a converged market with no
technical edge.

**Decision:** Do not build a delegated-authority authorization platform.
Keep looking for the part of the problem that is *not* converged.
Recorded as [ADR-0001](DESIGN_DECISIONS.md#adr-0001).

---

## Thread 2 — What is actually unsolved?

### 2.1 Prompt injection is unsolved, and the field has shifted to containment

`FACT` (as reported, 2026) — OWASP-affiliated researchers continue to describe
prompt injection as an unsolved architectural problem: LLMs process input as a
single token sequence with no reliable privilege boundary between system prompt,
user query and retrieved content.

`FACT` (as reported) — Consensus framing in 2026 coverage has moved from
prevention to **containment**: "the response to prompt injection must move
beyond prevention-only thinking and toward constraining what an injected agent
can do."

`INFERENCE` — Containment is an *authorization* problem, not a *detection*
problem. This is the point where the agent-security market and the agent-identity
market actually meet, and it is the interesting place to stand.

### 2.2 The academic answer is known, and is not deployed

`FACT` (existence, and as reported) — CaMeL, *Defeating Prompt Injections by
Design* (arXiv 2503.18813). Privileged LLM plans from the trusted query only; a
quarantined LLM handles untrusted data with no tool access; a custom interpreter
tracks data provenance and enforces capability policies before each tool call.
Reported AgentDojo utility with provable security: ~67–77% against ~84%
undefended.

`FACT` (as reported, from 2026 retrospectives on CaMeL) — **Zero production
adoption**, for CaMeL and for the lower-burden academic variants that followed
it. Stated reasons in that coverage:
1. dual-LLM overhead;
2. **policy sprawl** — a Python policy function per tool, which in an
   organisation with hundreds of APIs becomes inconsistent, duplicated and
   unauditable;
3. utility loss from default-deny on any argument containing untrusted data;
4. a user-reasoning gap — end users do not natively reason about *data sources*
   as carriers of trust, though they do reason about whether an *action* is
   risky.

`INFERENCE` — The cost explanation is explicitly contradicted by the observation
that the cheapest variants also have zero adoption. So the binding constraint is
not compute. It is that **none of these systems can be dropped into an existing
agent without rewriting the agent and hand-authoring a policy per tool.**

### 2.3 Argument-level provenance is the current research consensus

`FACT` (existence) — A dense 2026 literature on argument-/field-level provenance
for agent tool calls. Works identified in this pass:

| Work | arXiv | Reported contribution |
| --- | --- | --- |
| PACT — *The Granularity Mismatch in Agent Security* | 2605.11039 | Provenance-Aware Capability Contracts; runtime monitor at argument granularity |
| ARM — *Causality Laundering* | 2604.04035 | Provenance graph + integrity lattice + counterfactual edges from denied actions |
| RTBAS | 2502.08966 | Prompt injection + privacy leakage defence |
| *Ghost in the Agent* | 2604.23374 | Information-flow tracking redefined for LLM agents |
| SecureClaw | 2606.09549 | Trusted gateway returns opaque high-entropy handles + bounded summaries; authorization at the effect sink, plaintext confinement at the read boundary |
| CXI — *Context-to-Execution Integrity* | 2607.06000 | Opaque data slots; deterministic gate binding field authority, exact-effect authorization and invocation authority to one action manifest |
| APPA | 2607.24625 | Recoverable information-flow control |
| CaMeLs Can Use Computers Too | 2601.09923 | CaMeL for computer-use agents |
| ContainmentBench | 2607.23999 | Trace-based evaluation of *post-exposure* containment |
| ToolPrivacyBench | 2606.28061 | Purpose-bound privacy for tool-using agents |

`FACT` (as reported, PACT) — The single most decision-relevant number found in
the entire Phase 0 pass:

> Under **oracle provenance**, PACT achieves **100% utility and 100% security**
> on mixed-trust diagnostic suites. With provenance and semantic roles inferred
> at runtime by the model, PACT reaches 100% security while recovering only
> **38.1–46.4% utility** on the three strongest models — 8–16 points above
> CaMeL at the same security level. Ablations attribute the remaining deployed
> errors to **role assignment and provenance inference**.

`FACT` (as reported, PACT) — The framing sentence: *indirect prompt injection
becomes dangerous not when untrusted content appears in context, but when it
determines an authority-bearing argument.*

`FACT` (as reported, ARM) — An integrity lattice with five tiers is in use in
this literature: `ToolDesc < ToolUntrusted < ToolTrusted < UserInput <
SysInstr`. ARM additionally reports sub-millisecond policy evaluation overhead
and demonstrates *causality laundering*: an adversary probes a protected action,
learns from the denial, and exfiltrates the inferred bit through a later benign
call — a channel that flat data-flow provenance does not capture.

`FACT` (as reported, ContainmentBench) — Endpoint attack-success rates do not
reveal what a defence does between exposure and commit, nor whether it also
suppresses *authorized* actions. In their corpus, 73.5% of matched
active-tainted rollout pairs differed in logged trajectory or utility despite
identical zero-committed-harm outcomes.

### 2.4 What products actually enforce

`FACT` (as reported, vendor material and comparisons) — Commercial agent-security
enforcement in 2026 is at **invocation granularity**: per-agent identity,
tool-level approve/review/block, live request inspection, allow-lists, static
scanning of MCP server manifests, and pattern/classifier guardrails on content.
Named in this pass: Zenity (Boundaries engine, Live View), Noma Security (Agent
Access Control, Open Enforcement across agent hooks / MCP gateways / AI gateways
/ SDKs), Snyk-owned Invariant Labs (`mcp-scan`, point-in-time manifest
scanning).

`INFERENCE` — There is a **granularity gap between the literature and the
market**: research says the security-relevant unit is the *argument and its
provenance*; products enforce at the *invocation*. The gap is not ignorance —
it is that argument-level provenance has had no deployable implementation.

### 2.5 Standards are moving toward, not away from, this

`FACT` (as reported) — NIST CAISI launched the AI Agent Standards Initiative on
2026-02-17 (three pillars: standards development, community open-source protocol
work co-invested with NSF, and fundamental research in agent security/identity/
interoperability). NCCoE concept paper *Accelerating the Adoption of Software and
AI Agent Identity and Authorization* (February 2026) proposes applying OAuth 2.0,
OIDC and SPIFFE/SPIRE to agents as non-human identities.

`FACT` (as reported) — MCP shipped its largest specification revision on
2026-07-28: stateless core, Dynamic Client Registration deprecated in favour of
Client ID Metadata Documents, validated issuer claim on authorization responses.
Reported alongside: >40 CVEs against MCP SDKs and servers between January and
April 2026, and press commentary that authorization *scope* remained the control
left out of that revision.

`FACT` (as reported) — OWASP GenAI Security Project released the 2026 Top 10 for
LLM Applications plus a new **Agent Control Standard (ACS)** on 2026-09-01, and
the Top 10 for Agentic Applications (ASI01–ASI10, including goal hijack, tool
misuse, memory poisoning, rogue agents).

`INFERENCE` — Standards work is converging on *identity* (who the agent is) and
on *control surfaces* (what can be inspected and stopped). Neither NIST's
identity track nor MCP's authorization track answers "what determined this
argument". That question is left to the enforcement layer — i.e. to us.

---

## Thread 3 — The decision

`INFERENCE` — Synthesising threads 1 and 2:

1. Agent *identity and delegated authority* is converged and contested. Do not
   build there. (Thread 1)
2. Agent *containment* is the unsolved problem, and containment is an
   authorization problem at **argument granularity**. (2.1, 2.3)
3. The conceptual primitive is **not** unclaimed. Argument-level provenance,
   integrity lattices, opaque handles, effect-sink authorization and action
   manifests are all published, several of them in 2026. We must not claim
   novelty for any of them. (2.3)
4. What *is* unclaimed is the engineering: every published system either
   rewrites the agent, assumes an oracle, asks an LLM (and loses half its
   utility), or hand-authors a policy per tool. Adoption is zero. (2.2)
5. PACT's own ablation names the bottleneck precisely: **role assignment and
   provenance inference**. (2.3)

`HYPOTHESIS` **(IDENSEC thesis v1, falsifiable)** —

> Oracle-grade argument provenance does not require an oracle, a rewritten
> agent, or a language model. For the class of values that can actually carry
> authority — identifiers: addresses, URLs, hostnames, paths, account numbers,
> resource IDs — provenance can be made **structural** rather than inferred, by
> mediating the two boundaries every agent harness already owns: the
> tool-result→context path and the tool-call→execution path.
>
> And **semantic role is a static property of a tool's interface, not a runtime
> property of a call.** `sendEmail(to, subject, body)` — `to` is authority-bearing
> in every invocation that will ever exist. Asking a model to re-derive that on
> every call is what costs the utility.

If the hypothesis holds, the consequence is that a deterministic monitor should
reach PACT's *oracle* row (high security **and** high utility) rather than its
*deployed* row, without touching the agent's architecture or its model.

**Decision:** build that monitor. Recorded as
[ADR-0002](DESIGN_DECISIONS.md#adr-0002) and
[ADR-0003](DESIGN_DECISIONS.md#adr-0003).

### The two mechanisms, and why neither works alone

`INFERENCE` — This is the technical core, and the reason the design is not a
one-liner:

- **Sealing alone is insufficient.** If untrusted authority-shaped values are
  replaced by opaque handles before entering the context, the model cannot emit
  an attacker's address — *unless the attacker never wrote it in extractable
  form.* `send it to bob at evil dot com` survives extraction, and the model
  helpfully reconstitutes `bob@evil.com` at call time. Sealing is defeated by
  obfuscation.
- **Attribution alone is insufficient.** If we only check "does this argument
  match a known-untrusted value", verbatim copies are caught and paraphrases,
  encodings and reconstructions are not. This is the laundering problem the
  literature already documents.

The two compose into something neither provides:

> **An authority-bearing argument is admissible only if it is *positively
> attributable* to a source authorised for that kind of value. A value that
> matches nothing — neither a seal nor the trusted task text — is not "clean";
> it is `UNATTRIBUTED`, and `UNATTRIBUTED` is denied.**

Sealing removes the easy path (verbatim emission). The unattributed rule closes
the laundering path, because laundering an untrusted value cannot make it
*trusted-derivable* — it can only make it unattributable, which is already
denied. This is the design's load-bearing claim and it is tested directly in
`tests/test_adversarial.py`.

`HYPOTHESIS` — The cost of the unattributed rule is utility on tasks where the
agent must legitimately *originate* an authority value (choose a new file path,
invent an identifier). This is expected to be the dominant source of false
denials and is exposed as a policy knob (`DENY` vs `ESCALATE`) rather than
hidden. Magnitude unmeasured — see [`LIMITATIONS.md`](LIMITATIONS.md).

---

## Thread 3b — A finding from building the MCP proxy (2026-09-10)

`FACT` (observed directly, not reported) — **MCP carries no trusted channel for
the principal's instruction.** The protocol moves tool calls and tool results.
It does not move intent. Verified by implementing a full stdio proxy against the
protocol surface: `initialize`, `tools/list`, `tools/call` and their results
carry no field in which a host can state what the user actually asked for.

`INFERENCE` — This is a structural problem for *every* containment design in the
literature, not just ours. CaMeL, PACT, PAuth and the rest all take the trusted
user query as an input and reason from it. If the dominant tool protocol has
nowhere to put that query, then every one of those defences needs an out-of-band
side channel before it can be deployed over MCP — which is a deployment blocker
nobody in the literature we surveyed appears to have flagged, because the papers
evaluate inside harnesses they control.

`FACT` — The obvious fix is unsound and we rejected it. Asking the *agent* to
declare the task lets an injected agent declare the attacker's goal as the task
and launder it to `USER_INPUT`. That is a total bypass. There is deliberately no
`idensec/declare_task` tool, and there should never be one.

**Decision:** the task arrives from a host-written file the agent cannot write
(`task_file`), and both deployment requirements — not agent-writable, and the
principal's verbatim words rather than a model's summary — are stated in
[`MCP.md`](MCP.md) rather than buried. A configuration without it produces a
loud startup warning saying that a strict policy will deny nearly everything.

`HYPOTHESIS` — A protocol-level field for principal intent, carried from host to
server and marked as non-agent-writable, would be a small addition to MCP with
disproportionate value for every containment approach. This is the most
concrete standards contribution this project could make. Untested with anyone.

---

## Thread 3c — Self-attack on the proxy (2026-09-10)

`EXPERIMENT` — Red-teamed our own MCP proxy by asking which protocol messages
can carry attacker-controlled text into a model's context, rather than which
ones we had thought to handle.

`RESULT` — **A real bypass in our own code.** The proxy sealed `tools/call`
results and `tools/list` descriptions. It did not seal `resources/read`,
`prompts/get` or `resources/list`, all of which deliver server-supplied text to
the model. An attacker controlling a resource could hand the model an address in
clear, defeating the read boundary entirely for that path. Demonstrated with
failing tests before the fix.

`INFERENCE` — The root cause was the *shape* of the design, not a missed case.
Enumerating content-bearing methods is a losing game against a protocol that
keeps adding them. The default was inverted: seal every result, and name the two
exceptions where a handle would break something structural (the `initialize`
handshake, and JSON Schemas inside `tools/list`).

`FACT` — This is safe to apply that broadly because sealing is a no-op on text
containing no operands: prose passes through byte-for-byte, so "seal
everything" costs nothing on the messages that carry no identifiers.

**Decision:** allowlist the exceptions rather than the targets, here and in any
future transport. Recorded because the same mistake is available in every
adapter we have not written yet.

---

## Thread 3d — Validation against a real MCP server (2026-09-10)

`EXPERIMENT` — Installed the reference `mcp-server-time` from PyPI and ran a
full session through the IDENSEC proxy: `initialize`, `tools/list`,
`--emit-contracts`, an allowed `tools/call`, and a call to a tool with no
contract. Real server, real protocol, real pipes — the first validation against
software we did not write.

`RESULT` — The chain works end to end. The handshake passes through untouched,
contracts draft correctly from the server's advertised schemas, a legitimate
call returns real data, and an uncontracted tool is refused with
`unknown_tool` plus `unattributed_authority`.

`RESULT` — **A linter false positive, found within minutes of touching real
software.** `convert_time` declares `target_timezone`; "target" is in the
linter's authority-token list, so a correct contract drew two errors. Our own
test file asserts that a linter which cries wolf gets switched off, so this was
a defect by our own standard. Fixed with a presentational-token exemption
(`timezone`, `locale`, `format`, `encoding`, …) that suppresses the
authority-name check without weakening it for names like `target_url`.

`RESULT` — Second false positive: a read-only tool whose parameters are all
presentational — `get_current_time(timezone)` — was reported as
`no-authority-parameter` at WARNING. That is a correct contract. Downgraded to
NOTE for tools whose effects are read-only; still an error for anything that
writes or deletes.

`INFERENCE` — Both defects were in a component that had 37 passing tests, all
written by its author. The general lesson is the one already recorded in
[`REVIEW.md`](REVIEW.md): our own tests encode our own expectations, and contact
with software we did not write is a different and better source of evidence.

`FACT` — One deriver inconsistency observed and deliberately **not** fixed:
`timezone` alone drafts as ADVISORY while `source_timezone` drafts as
AUTHORITY, because advisory hints match exactly and identifier-ish names do
not. The inconsistency is in the safe direction (over-restrictive), and making
advisory matching token-based would risk downgrading names like
`limit_amount`. Churning a measured component for a cosmetic gain is the wrong
trade; recorded instead.

---

## Thread 3e — AgentDojo evaluation (2026-09-10)

`EXPERIMENT` — Evaluated IDENSEC against AgentDojo, model-free, by replaying
published ground truth in both directions: the injection tasks' attacker calls
(security) and the user tasks' correct calls (utility). 97 user tasks, 609
in-scope security cases, four suites. Method and the artefacts we had to author:
[`benchmarks/agentdojo/README.md`](../benchmarks/agentdojo/README.md).

`RESULT` (**first pass** — superseded by the second-pass entry below, kept
because the ledger is a record of what was known when) — Security 560/609
(92.0%), utility 55/97 (56.7%), with the model assumed to be *always* hijacked.

`RESULT` — **Source labelling is the dominant variable, and per-source grants
are the wrong shape.** Authoritative-for-nothing gave 95.4%/34.0%;
authoritative-for-everything gave 55.8%/45.4% — worse on *both* axes.
Path-scoped grants gave 92.0%/56.7% at that stage. The cause is structural: legitimate
addresses live in `sender`/`recipients`/`participants` while every injection
lives in `description`/`content`/`reviews`, and both arrive from one source.
This produced a new capability (`Source.authoritative_paths`) rather than a
tuning; the travel suite went 0% → 100% utility on it.

`RESULT` — **Every escape is explained, and all fall into limitations documented
before the measurement existed.** 20 where the attacker selects a legitimate
directory entry (U01), 20 where the target call has no authority-bearing
argument at all (U05), 8 low-entropy token collisions (U02), 20 speech-only
tasks excluded as outside what an action monitor can address.

`INFERENCE` — The boundary statement this yields is the most useful output of
the whole exercise: **IDENSEC contains attacks that introduce a new destination;
it does not contain attacks that merely select among legitimate ones, nor
attacks whose target call carries no authority-bearing argument.**

`RESULT` — Four real defects found and fixed: `recipient` constrained to
`email` (breaking every IBAN transfer), `url` constrained to `url` (breaking
every scheme-less fetch), temporal parameters treated as authority-bearing (the
single largest source of false denials), and `*_id` constrained to the `uuid`
kind. Utility went 22.7% → 56.7% with no security loss in that pass.

`RESULT` (**uncomfortable, recorded as such**) — 56.7% is above PACT's
*deployed* row (38–46%) and far below its *oracle* row. By the falsification criterion
this project set for itself in [`REVIEW.md`](REVIEW.md), that is closer to
disproof than to confirmation. The thesis is **not yet disproven** — the number
moved 29 points in one sitting under obvious fixes and has not converged — but
it is now the only thing on the roadmap that matters, and leaving it at 56.7%
while building features would be the dishonest outcome.

`RESULT` (**second pass, after fixing what the first pass exposed**) — The
measurement is a curve, not a number: 95.4% security at 34.0% utility with no
authority granted, 85.1%/76.3% with directories granted and magnitudes budgeted.
**No configuration reaches 90% security and 70% utility together.** (Those
figures are this pass's; Thread 3f re-measures the same labellings with both
policy knobs swept and supersedes them.)

`INFERENCE` — **The binding constraint is entity selection, and it is not
something determinism can fix.** Every bug fixed in this pass bought utility at
zero security cost; security fell only where a human widened a *grant*. A large
fraction of real agent work is selecting an existing entity — reschedule *that*
event, share *that* file — and when the directory is untrusted, provenance must
either refuse the selection or trust the directory, which admits an injection
naming a legitimate entry. This is a question about intent, not origin, so
**oracle provenance would not resolve it either**.

`HYPOTHESIS` — PACT's reported oracle row (100% utility at 100% security) is
hard to reconcile with entity-selection workflows, which suggests its diagnostic
suites may not contain that pattern. **Unverifiable here** — the paper is not
reachable from this environment, and this is recorded as a hypothesis about a
paper we have not read, not as a criticism of it.

`DECISION` — Narrow the claim to what the evidence supports rather than restate
it: IDENSEC contains attacks that introduce a new destination, and is
structurally blind to attacks that select among legitimate ones. Recorded in
[`REVIEW.md`](REVIEW.md), and the README, threat model and limitations now say
it in those words.

`FACT` — Effect classes and scoped grants were hand-authored per API by people
who do not own those APIs. That is the policy-sprawl objection this project
claims to answer, and one afternoon for four APIs does not answer it.

---

## Thread 3f — Reference binding, and what measuring it cost (2026-09-12)

`EXPERIMENT` — Thread 3e identified *entity selection* as the binding constraint
and named one candidate answer: bind the id the agent passes back to the
principal's own **reference** to the record. Built as a pseudo-kind
(`referenced`) granted per field path, and measured on the same AgentDojo
harness. ADR-0011 records the decision; the numbers are in
[`BENCHMARKS.md`](BENCHMARKS.md).

`RESULT` — **Three defects in the mechanism, all found by measuring it and none
by review.** They are recorded first because the version of this entry that
skipped them would have reported a real number for a mechanism that did not
work.

1. **Whole-field matching fires on nothing.** The first implementation required
   the principal to quote a descriptive field in full. Against AgentDojo it
   matched **zero** selections: people write "reschedule my Dental check-up"
   about a record titled `Dentist Appointment` with the description `Regular
   dental check-up.`. Naming is partial. The unit had to become a *fragment* —
   a two-word phrase, or a lone word long enough to be distinctive.
2. **An id means nothing outside its collection.** AgentDojo's calendar, inbox
   and drive all number their records from 1. Binding the key `13` outright let
   an instruction naming *calendar event 13* authorise `delete_file(13)` — the
   attack the mechanism exists to refuse, reproduced *by* the mechanism. Fixed
   by requiring the receiving parameter to declare which directory its id
   addresses, and by firing for no parameter that does not.
3. **The evaluation was rigged, unintentionally.** The `referenced` labelling
   pinned its own quotation floor while the sweep varied everyone else's, which
   made its column invariant **by construction** and would have been reported as
   a finding. The floor now applies uniformly to all five labellings.

`RESULT` — Two further defects surfaced alongside: reference binding was
computed even for labellings that granted nothing through it, silently inflating
their utility; and advisory parameter hints matched names exactly, so
`new_start_time` was treated as authority-bearing while `start_time` was not.

`RESULT` — **The mechanism works, and it is not the win the roadmap hoped for.**
On the workspace suite -- the one that actually exercises entity selection -- it
admits three previously-refused selections at **zero** security cost: 70.0% →
77.5% utility, 100% security either way. In aggregate across four suites it is
worth **two tasks out of ninety-seven**: the best configuration above 90%
security moves from 91.8%/62.9% to 91.8%/64.9%. It does **not** clear the
90%/70% bar this project set itself, and the permissive configurations still buy
more utility for less security.

`RESULT` — **It also loses a task, and the loss is instructive.** A blanket grant
over a file directory authorises not only the file *ids* but the contents of
every file, which is how the previous configuration passed a banking task that
reads an address out of a document. AgentDojo never charges for that grant
because its banking injections target transfers rather than profile fields, so
the benchmark scores the unsafe configuration higher. The charge is asserted as
a test (`TestWhatTheBlanketGrantCostsElsewhere`) rather than argued in prose.

`INFERENCE` — What reference binding changes is less the point than the *shape*:
its utility barely moves across quotation floors 1 through 4 (68.0% at all of
them), because the reference check does not depend on the id being long enough
to quote. Every other labelling trades security against utility along that
floor — `recommended` swings 77.3% → 66.0% over the same range. An operator
tuning the floor is otherwise choosing a security/utility point with a character
count, which is a poor interface. That is a usability property, not a security
one, and it is worth about as much as it sounds.

`FACT` — The residue of entity selection is selection by **property**: "the
cheapest hotel", "the oldest file", "the most recent thread". The principal
names nothing, so there is nothing to bind. No candidate mechanism is proposed,
because we do not have one, and inventing one here to make the section end well
would be exactly the failure mode this ledger exists to prevent.

`FACT` — `ParameterContract.collection` is a new per-API declaration. It is
drafted from `<noun>_id` parameter names, and a wrong draft costs a denial
rather than a bypass, but it is one more thing an operator writes down. The
policy-sprawl objection in Thread 3e applies to it unchanged.

---

## Thread 3g — MCP tool annotations, and the direction test (2026-09-12)

`EXPERIMENT` — Captured `tools/list` from seven published MCP servers over
stdio and drafted contracts from the real schemas. 52 tools, 94 parameters.
Corpus checked in at `benchmarks/data/mcp_tools.json`; method and caveats in
[`BENCHMARKS.md`](BENCHMARKS.md).

`FACT` — **MCP carries an effect signal after all, and 51 of 52 tools use it.**
Tool annotations (`readOnlyHint`, `destructiveHint`, `idempotentHint`,
`openWorldHint`) are near-universal in these servers. This project has said
since ADR-0004 that "effects cannot be read off a schema", which remains true of
the *schema* — but the protocol carries them next to it, and we were not
looking.

`FACT` — They are supplied by the **server**, which is `TOOL_DESCRIPTION`, the
bottom of the integrity lattice. The same channel this project already seals for
tool poisoning.

`INFERENCE` — The resolution is a **direction test**, not a trust decision, and
it generalises beyond MCP: *attacker-controllable metadata may be read whenever
believing it can only restrict.*

* `destructiveHint: true`, `openWorldHint: true` → believed. A hostile server
  lying this way denies its own tools and achieves nothing.
* `readOnlyHint: true` → **ignored**. Believing it is a total bypass: mark the
  exfiltration tool read-only and every confidentiality rule stops firing.

`RESULT` — **32 of 52 real tools claim `readOnlyHint: true`.** A monitor that
believed the hint would have disabled its own egress checks on 62% of this
corpus on day one. That is what makes the direction test load-bearing rather
than pedantic.

`RESULT` — Believing only the restrictive hints completed **8 of 52 drafts**
that would otherwise have carried no effects at all. A small, free improvement
in the only direction that is safe.

`RESULT` — Four defects, none findable from a corpus we wrote: a `TypeError` on
JSON Schema union types; camelCase invisible to every hint match; the linter
reporting the `unclassified` pseudo-kind as a typo at ERROR severity on 23 of 94
parameters; and `branchId` drafting the collection `**.branchs`, which matches
nothing.

`RESULT` (**uncomfortable**) — Reference binding's collection draft fires on
**2 of 60** authority-bearing parameters here. Published servers name things
`path`, `repo_path` and `branch_name`, not `<noun>_id`. The mechanism was
designed and measured against AgentDojo, whose environments are keyed
dictionaries; the servers people deploy are not shaped that way. ADR-0011 is
qualified accordingly rather than quietly left alone.

`FACT` — Seven reference and first-party servers is not a representative
sample. The interesting case — a server written to a deadline by someone who
never read the annotations spec — is absent, and the direction test is precisely
what makes that absence survivable.

---

## Thread 3h — The read boundary against real tool output (2026-09-12)

`EXPERIMENT` — Captured 23 read-only `tools/call` responses from six
locally-launched MCP servers and ran them through `observe()`. Corpus at
`benchmarks/data/mcp_results.json`, with `git_show` pinned to a fixed revision
so the fixture does not change under us.

`RESULT` — **Sealing is lossless, and now provably so on data we did not
write.** Resolving every handle reproduces the original byte for byte. "Prose
passes through untouched" has been asserted in this repository since the first
commit; it is a checked property from now on, gated in CI.

`RESULT` — **One intended exception, found on the first run.** A `git show` of
this repository contains `[[idn:email:…]]`, because the threat model documents
the handle syntax, and the read boundary defuses handle-shaped untrusted text
(T05). A repository that documents its own escape syntax is the most natural
source of decoys there is, and we had never tested against one.

`RESULT` (**the real finding**) — **The `hostname` filter was a blocklist, and
sealed 151 of 244 operands spuriously.** `Role.AUTHORITY`, `json.dumps`,
`time.time`, `pytest.mark.parametrize` — every dotted identifier in every line
of Python or JavaScript an agent reads. The pattern accepted any `label.label`
and vetoed a list of file extensions, so anything unlisted was a hostname.

`INFERENCE` — The shape was the bug, and it is a shape this project criticises
by name elsewhere. On the pinned corpus the fix is reproducible as sealing
density over a source diff: **6.6% to 1.1%** on identical input. [`ROADMAP.md`](ROADMAP.md) declines to build a
prompt-injection classifier because "a control with an attacker-searchable
false-negative rate is a filter, not a boundary" — and then shipped a blocklist
in the extractor. **Enumerating what something is not is the same mistake
wherever it appears.** Replaced with a TLD allowlist: spurious extractions
151 → 0, synthetic recall unchanged at 93%, false positives still 0/16.

`FACT` — Neither filter works alone. `.py` is Paraguay, `.md` Moldova, `.sh`
St Helena, `.io` the British Indian Ocean Territory: accepting every two-letter
label as a ccTLD put `main.py` straight back. The allowlist handles dotted
identifiers, the extension blocklist handles the ccTLD collisions, and the
measurement is what showed that both are load-bearing.

`RESULT` — Two smaller defects: paths absorbed the sentence's full stop
(`~/.ssh/id_ed25519.`), so the handle resolved to a value the agent would never
pass back; and `account_number` matched `9007199254740991`, JavaScript's
`MAX_SAFE_INTEGER`. The first is fixed. The second is **not**, and the reason is
recorded: one code-heavy corpus is not grounds for weakening a default, removing
the kind breaks contracts that declare it, and the admission verdict is
unchanged either way — which was checked, not assumed.

`FACT` — `everything.get-env` advertises `readOnlyHint: true`, is genuinely
read-only, and is the one call in the corpus that must never be captured,
because it returns the process environment. Read-only is not the same as safe,
and the annotation that would have told a monitor to relax is attached to
exactly that tool.

`FACT` — Six servers, one of them reading a fixture this benchmark wrote, is not
representative traffic. Sealing density ranges from 0% (`time`) to 43%
(`memory`) across them, which is the honest answer to anyone wanting a single
number for what sealing costs.

---

## Thread 3i — The whole pipeline, off-benchmark (2026-09-12)

`EXPERIMENT` — Ran the `idensec.mcp` proxy in front of an unmodified
`@modelcontextprotocol/server-filesystem`, with a document containing an HTML
comment instructing the assistant to overwrite a payroll file and move a secrets
file. Agent assumed fully hijacked. Two source labellings, same attack.
`examples/mcp/attack_filesystem.py`.

`RESULT` — **The published boundary reproduces off-benchmark.** Under the
labelling an operator would actually write, the injected *overwrite* of a file
the server listed **succeeds**, and the injected *move* to a destination nothing
ever named is **refused**. That is:

> IDENSEC contains attacks that introduce a new destination. It does not contain
> attacks that merely select among legitimate ones.

written months earlier from AgentDojo, and now observed on software we did not
write, through the real proxy, with a real injection. It is the closest thing to
independent confirmation this project has.

`RESULT` — **The strict labelling refuses the principal's own read.** 100%
security and 0% utility, on a two-step task. Reporting that as a security result
would be the dishonest version of this entry.

`RESULT` — **Our own flagship example contract covered 4 of the server's 14
tools**, the missing ten including `read_text_file`, the primary read path. It
failed closed, which is the right direction and no use at all. The per-API cost
this project claims to reduce is no longer an abstraction: fourteen tools, every
effect declared by hand.

`FACT` — **An agent cannot address a filesystem whose root it has not been
told.** Every path-taking tool needs a path; the principal wrote "my notes
folder". The only way in is `list_allowed_directories`, which takes no arguments
and therefore has nothing to refuse. Any containment design has this bootstrap
problem, and a server without a zero-argument discovery tool cannot be used
under one at all. Recorded as a finding about the ecosystem, not about us.

`INFERENCE` — **Path construction is the filesystem's version of computed
amounts.** A path joined from a principal-named leaf and a server-named root is
a string neither ever emitted, so it traces to nobody. Amounts had a fallback —
a budget bounds a magnitude. A path has none. Whether a joined path can be
attributed component-wise is the open question; we have not built it and are not
claiming it works.

`FACT` — `edit_file.dryRun` is a safety flag, and role cannot express "this
boolean may be strengthened but not weakened". Marking it `AUTHORITY` would deny
every legitimate edit, because booleans are not attributable. Left advisory,
with the gap written into the shipped contract where a reviewer will see it.

---

## Thread 3j — Composition: the boundary is about values (2026-09-12)

`EXPERIMENT` — Thread 3i found that a path the agent *builds* -- a root the
server disclosed joined to a name the principal wrote -- traces to nobody and is
denied under every labelling, the principal's own request included. That entry
recorded "no mechanism is proposed, because we do not have one". It was wrong,
and the reason it was wrong is the interesting part.

`INFERENCE` — **Entity ids have no internal structure. Paths do.** Reference
binding (ADR-0011) had to reach outside the value -- to a directory of records
and whether the principal named one. A path needs nothing outside itself: it
splits at separators into parts that mean something alone. Attribute and
authorise each part and the join is decided.

`RESULT` — Built as `Policy.compose_paths`, off by default, and measured on the
same real filesystem server with the same injection:

| labelling | principal's read | injected overwrite | injected move |
| --- | --- | --- | --- |
| server authoritative for nothing | deny | deny | deny |
| server authoritative for every path it returns | allow | **ALLOW** | deny |
| server authoritative for its **root**, paths compose | **allow** | deny | deny |

The third row is the first configuration that gets all three right.

`INFERENCE` (**the one that matters**) — This qualifies a claim this repository
has published since the AgentDojo results:

> IDENSEC contains attacks that introduce a new destination. It does not contain
> attacks that merely select among legitimate ones.

That held because the **value was opaque**. It is a statement about identifiers
lacking internal structure, not about intent being unknowable. Decompose the
value and the boundary moves. So the honest reading of Threads 3e–3f is narrower
than it looked: we had been describing a property of *provenance* when we were
describing a property of the *values* we happened to be attributing.

`FACT` — The check must be **universal**, where ADR-0008 makes the rest of the
system existential. The prefix chooses the tree and the remainder chooses the
file, so an attacker supplying either half has chosen something. An existential
check would let an authorised root carry a leaf only an injection named -- which
is the entire attack.

`RESULT` — A first implementation ran composition only where attribution
*failed*. Against a real server it therefore never fired at all: a path read out
of a directory listing is perfectly attributable, to a listing the source is not
authoritative for. The common case is attribution succeeding and being
**unauthorised**, and that is now where it runs.

`FACT` — It generalises no further than its grammar. *"Open the oldest file"*
names nothing to split. An entity id does not split. What composition converts
is the case where the principal named a **component**, which for filesystems is
most of real work and for entity directories is none of it.

`HYPOTHESIS` — URLs, ARNs and git remotes also decompose. Whether the same
universal check is sound for them is **unmeasured**, and a wrong answer on a URL
*host* is considerably worse than on a path segment, so it is on the roadmap
rather than in the code.

---

## Thread 3k — A dangerous miss, found by a number moving (2026-09-12)

`RESULT` — Re-running AgentDojo after the extraction and deriver changes moved
the curve **down** on utility: the best configuration above 90% security went
from 91.6%/68.0% to 91.8%/64.9%. Four banking tasks were lost.

`FACT` — The cause, isolated by bisecting the commits: the deriver had been
drafting a bare `id` parameter as **ADVISORY** — unchecked — whenever its schema
said ``integer``. On AgentDojo's banking suite that is
``update_scheduled_transaction(id, amount, recipient)``, where ``id`` decides
which transaction a financial write lands on.

    before:  id -> advisory        after:  id -> authority

`INFERENCE` — This is a **dangerous miss** by the project's own definition, in
the component whose entire purpose is not to make them, present since that
component existed, through two milestones that reported its numbers approvingly.
The utility it was buying was not utility; it was an unchecked authority
parameter on a financial tool.

`INFERENCE` — **It was found because a number moved in the wrong direction.** A
project reporting a single headline figure would have been *improved* by leaving
the hole in. That is the argument for publishing a curve rather than a score,
and it only paid off once something regressed.

`RESULT` — Two further gaps surfaced while tracking it down, both real and
neither rewarded by this benchmark:

* **Numeric leaves were never indexed.** ``{"id": 7}`` was dropped on the
  observation walk, so an integer-keyed record was permanently unattributable.
  Now indexed, never sealed -- a handle would change the JSON type the agent has
  to send back. Booleans stay excluded: ``true`` identifies nothing.
* **Only dict-keyed directories counted as entity records.**
  ``{"events": {"5": {…}}}`` did; ``[{"id": 5, …}]`` did not, which is the shape
  every JSON array returns, so reference binding had never fired on a list.

`FACT` — Neither moved a benchmark number, because AgentDojo's grants do not
cover the paths where they apply. Recorded because they were fixed, not because
they paid.

`INFERENCE` (**uncomfortable**) — Twelve defects in this component have now been
found by measurement rather than by review, and the rate is not falling. A
design whose correctness rests on that many separate judgements about what
counts as authority has a correspondingly large surface for exactly this. That
belongs in the argument *against* the approach, and is recorded in
[`REVIEW.md`](REVIEW.md) as such.

---

## Thread 3l — Testing the interaction, not the mechanisms (2026-09-12)

`FACT` — The previous review entry named the strongest criticism of this design:
twelve defects found by measurement rather than review, at a rate that is not
falling, in a system whose correctness rests on many separate judgements about
what counts as authority. The obvious untested surface is what happens when the
mechanisms are **combined**. Sealing, the quotation floor, reference binding,
path composition and spend budgets had each been measured alone.

`EXPERIMENT` — Stated the anti-injection property directly and fuzzed it:

> Observing content from a source authoritative for **nothing** never turns a
> denial into an admission.

Over four configurations (bare, composition, reference binding, everything
enabled), in both orders, and with a variant where the attacker writes out the
*exact* arguments the agent is about to send -- which is what an injection
actually does, and what random poison almost never reproduces.

`RESULT` — **It holds.** No combination admitted anything the components refused
individually. Roughly 80% of generated calls are denied before poisoning, so the
property has a real population to guard rather than passing vacuously.

`FACT` — The property is **mutation-checked**: granting the attacker source
authority makes it fail in 24 generated cases. A property test that cannot fail
is a comment, and this one was verified to be neither.

`INFERENCE` — This is reassurance about interaction, and it should not be read
as more. It says the mechanisms do not *combine* into a hole; it says nothing
about whether each is individually right, which is where all twelve defects
lived. The criticism in [`REVIEW.md`](REVIEW.md) stands unaltered.

---

## Thread 4 — What we deliberately are not building

`INFERENCE`, recorded here because negative decisions are cheaper to find in the
ledger than in the diff:

- **Not** an agent registry, agent identity provider, or credential broker.
  Converged market, incumbent advantage (Thread 1).
- **Not** a prompt-injection classifier or content guardrail. Probabilistic,
  commoditised, and orthogonal — a classifier that is 99% accurate is 100%
  bypassed by the attacker who tries twice.
- **Not** a dashboard, control plane or SaaS product. The primitive first
  (founding brief §27), and there is no evidence a UI is the blocker.
- **Not** signed cryptographic receipts, yet. See
  [ADR-0005](DESIGN_DECISIONS.md#adr-0005): there is currently no relying party
  who would verify one. A tamper-evident hash chain solves the real problem
  (local audit integrity and trace-based conformance checking) at a fraction of
  the complexity.

---

## Open questions carried forward

1. `HYPOTHESIS` — Does extraction coverage (which value kinds are recognised)
   dominate security in practice? An authority value we fail to recognise is a
   value we fail to seal. Measured by the extraction fuzz corpus; currently
   unmeasured against real-world tool output.
2. `HYPOTHESIS` — Can tool contracts be *derived* from JSON Schema with enough
   accuracy to avoid the policy-sprawl failure that killed CaMeL adoption? A
   heuristic deriver exists; its precision/recall is unmeasured.
3. `FACT` — We cannot run end-to-end model benchmarks in this environment (no
   model API egress). Security claims are therefore proven model-free (see
   [`BENCHMARKS.md`](BENCHMARKS.md)); utility claims are **not yet made**.
4. `HYPOTHESIS` — Model-side hardening (SecAlign-style injection-resistant
   models) could reduce the value of external containment. Assessed in
   [`LIMITATIONS.md`](LIMITATIONS.md) as the strongest medium-term threat to the
   thesis. Counter-argument: containment is a *soundness* property; a model that
   resists injection 99.9% of the time still cannot provide one.

---

## Sources consulted (Phase 0, 2026-09-09)

Reachability caveat at the top of this file applies to all of these.

- NIST, *Announcing the AI Agent Standards Initiative* (2026-02) and NCCoE,
  *Accelerating the Adoption of Software and AI Agent Identity and
  Authorization* concept paper (2026-02).
- OWASP GenAI Security Project, 2026 Top 10 for LLM Applications; Agent Control
  Standard; Top 10 for Agentic Applications (ASI01–ASI10).
- Model Context Protocol specification revision, 2026-07-28.
- arXiv: 2503.18813 (CaMeL), 2605.11039 (PACT), 2603.17170 (PAuth),
  2604.04035 (ARM / causality laundering), 2502.08966 (RTBAS),
  2604.23374 (Ghost in the Agent), 2606.09549 (SecureClaw),
  2607.06000 (CXI), 2607.24625 (APPA), 2601.09923 (CaMeL for computer use),
  2607.23999 (ContainmentBench), 2606.28061 (ToolPrivacyBench),
  2606.04990 (survey of evidence tracing and execution provenance),
  2505.02077 (open challenges in multi-agent security).
- AgentDojo, `github.com/ethz-spylab/agentdojo` — 97 tasks, 629 security test
  cases, four stateful domains.
- Vendor and landscape material for Zenity, Noma Security, Snyk/Invariant Labs,
  Microsoft Entra Agent ID, Okta/Auth0; 2026 market landscape reports.
