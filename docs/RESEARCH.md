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
