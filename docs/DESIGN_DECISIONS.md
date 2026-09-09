# DESIGN_DECISIONS.md — Architectural Decision Records

Each record states the problem, the alternatives that were genuinely considered,
the evidence, the decision, what was rejected, and what it costs us. Decisions
to *remove* or *not build* something are recorded with the same weight as
decisions to build.

Status values: `accepted`, `superseded`, `rejected`, `revisit`.

---

## ADR-0001 — Do not build a delegated-authority authorization platform

**Status:** accepted · 2026-09-09

### Problem

The founding brief's hypothesis was "stateful delegated authority for autonomous
agents": authorization that is chain-aware, task-scoped, revocable and stateful.
Is this the right thing to build?

### Alternatives considered

1. Build it as stated — an authorization engine over principal / agent /
   delegation chain / task / resource / context / history.
2. Build a narrower slice of it (e.g. delegation-chain verification only).
3. Reject it and keep searching.

### Evidence

- The 2026 market has converged on exactly this vocabulary: agent registry,
  human sponsor, short-lived scoped credentials, MCP-layer enforcement, runtime
  authorization. Incumbents (Microsoft Entra Agent ID, GA April 2026; Okta;
  Auth0) plus several well-funded 2026 entrants.
- Microsoft Research published `PAuth` (arXiv 2603.17170, March 2026), which is
  the sharper version of the same idea — task-scoped *implicit* authorization
  with operand-level envelopes.
- NIST NCCoE's February 2026 concept paper points agent identity at existing
  standards (OAuth 2.0, OIDC, SPIFFE/SPIRE), which favours incumbents.

See [`RESEARCH.md` Thread 1](RESEARCH.md#thread-1--is-stateful-delegated-authority-for-agents-an-open-problem).

### Decision

**Reject option 1 and 2.** Do not build an agent identity, registry, credential
or delegation-chain product. The hypothesis is not wrong about the world; it is
wrong about the opportunity.

### Consequences

- We give up the enterprise-IAM buyer and the compliance narrative that comes
  with it. That is a real cost.
- We must find a primitive that is *complementary* to agent identity rather than
  competitive with it — which turns out to be a better position, because every
  identity vendor needs an answer to containment and none of them has one.
- Delegation does not disappear from the model; it is re-expressed as
  provenance. See [`DELEGATION_MODEL.md`](DELEGATION_MODEL.md).

---

## ADR-0002 — The decision unit is the argument, not the invocation

**Status:** accepted · 2026-09-09

### Problem

At what granularity should an agent authorization decision be made?

### Alternatives considered

1. **Invocation granularity** — "may agent A call tool T?" This is what
   essentially every commercial product does.
2. **Content granularity** — classify the text flowing through for
   attack-shaped patterns.
3. **Argument granularity** — "what determined the value of this specific
   parameter of this specific call?"

### Evidence

- PACT (arXiv 2605.11039) frames it directly: indirect prompt injection becomes
  dangerous *not* when untrusted content appears in context, but when it
  **determines an authority-bearing argument**.
- Invocation granularity forces a false choice in mixed-trust workflows: allow
  untrusted content to influence a call (and accept hijacked destinations), or
  quarantine the call (and break benign retrieve-then-act). Both failure modes
  are reported for flat invocation-level monitors.
- Content classification has an attacker-searchable false-negative rate. A
  control whose bypass can be found by trying variants is not a control.

### Decision

**Argument granularity, with field-level provenance inside structured tool
results.** A decision is made per parameter, not per call; a call is admitted
only if every parameter is admissible.

### Rejected

- Invocation granularity — provably too coarse for the workflows people
  actually run.
- Content classification — wrong failure model for a security boundary. It may
  be layered *on top* by a user; it is not in our decision path.

### Consequences

- We need a tool contract per tool (which parameters bear authority). This is
  the policy-sprawl risk that is reported to have killed CaMeL adoption; it is
  addressed by ADR-0004, and it remains our largest adoption risk.
- We must be in the data path on *both* boundaries (results in, calls out), not
  just the call boundary. This constrains the deployment model to SDK hook,
  MCP proxy or harness integration.

---

## ADR-0003 — No language model in the decision path

**Status:** accepted · 2026-09-09

### Problem

Provenance and semantic role can be inferred by a model at runtime. Should they
be?

### Alternatives considered

1. Ask the model to self-report which sources determined each argument.
2. Use a secondary "judge" model to label roles and provenance.
3. Compute both structurally, with no model involved.

### Evidence

- PACT's ablation is decisive: **oracle provenance yields 100% utility and 100%
  security; model-inferred provenance yields 100% security and 38.1–46.4%
  utility**, and the residual errors concentrate in *role assignment and
  provenance inference*.
- The founding brief's own constraint (§10): model output is untrusted input,
  and critical authorization decisions must not depend on it.
- A model in the decision path is also a model an attacker can address. The
  content being labelled is the content the attacker wrote.

### Decision

**No model in the decision path.** Provenance is computed structurally at the
boundary. Roles are declared statically in tool contracts. The monitor's verdict
is a pure function of (session state, contracts, policy, call) and is
reproducible from a trace.

### Rejected

- Self-reported provenance — asks the potentially-hijacked component to
  describe its own hijacking.
- Judge models — moves the attack surface rather than removing it, and imports
  the utility collapse PACT measured.

### Consequences

- Where structure genuinely runs out — free prose that carries meaning but no
  extractable identifier — we cannot decide, and we must say so rather than
  guess. This shows up as `UNATTRIBUTED` and as an explicit escalation path.
- The engine has **zero required runtime dependencies** and no network calls,
  which is a large supply-chain and latency win for a security component.
- Determinism is testable: the same trace must always produce the same verdict.
  This is enforced by test.

---

## ADR-0004 — Semantic role is a property of the tool interface, not of the call

**Status:** accepted · 2026-09-09

### Problem

Who decides that `to` in `sendEmail(to, subject, body)` is authority-bearing and
`body` is not?

### Alternatives considered

1. Infer per call, at runtime (rejected by ADR-0003).
2. Hand-author a policy function per tool (CaMeL's approach).
3. Declare it once per tool interface, in a portable, versionable artefact, and
   derive a first draft from the tool's JSON Schema.

### Evidence

- `sendEmail`'s `to` parameter is authority-bearing in *every invocation that
  will ever exist*. It is a static fact about the interface. Re-deriving it per
  call is not just wasteful, it is the thing that costs the utility (ADR-0003).
- Policy sprawl — "a Python policy function per tool, which in a large
  organisation becomes inconsistent, duplicated and unauditable" — is a reported
  cause of zero adoption for the per-tool-policy approach.

### Decision

**Tool contracts:** a declarative, serialisable artefact mapping each parameter
to a *role* (`AUTHORITY` / `PAYLOAD` / `ADVISORY`) and each tool to a set of
*effect classes*. Contracts are data, not code. A heuristic deriver produces a
starting contract from a JSON Schema; the deriver is explicitly marked as a
*draft-generator*, never as an authority.

### Rejected

- Policy-as-code per tool. Code is not shareable across organisations, not
  diffable in a useful way, not signable as a corpus, and is the documented
  adoption blocker.

### Consequences

- The contract corpus becomes a shared, accumulating asset — the most plausible
  moat available to this project, and the one thing here that gets more valuable
  with adoption.
- A wrong contract is a security hole. Contracts need their own review
  discipline, and `derive_contract()` must fail closed (unknown parameter ⇒
  treated as `AUTHORITY`, the restrictive choice).

---

## ADR-0005 — Hash-chained decision records, not signed receipts

**Status:** accepted · 2026-09-09

### Problem

The founding brief asks whether IDENSEC should emit verifiable cryptographic
decision records, and explicitly warns against building them because they sound
advanced.

### Alternatives considered

1. Signed receipts / verifiable credentials per decision.
2. Tamper-evident hash chain over decision records.
3. Plain unstructured logging.

### Evidence

- Signatures are only worth their complexity when there is a **relying party**
  who verifies them and changes behaviour on the result. Today there is none:
  no standard consumes an agent authorization receipt, no auditor asks for one,
  and no counterparty would reject an unsigned one.
- There *is* a real, immediate problem a hash chain solves: a decision log that
  can be silently edited is worthless for incident reconstruction, and
  trace-based conformance checking (the ContainmentBench framing — endpoint
  outcomes do not show what happened between exposure and commit) requires an
  ordered, complete, tamper-evident record.

### Decision

**Option 2.** Every decision produces a canonical record; records are chained by
SHA-256 over `(previous_digest ‖ canonical_record)`. The chain is verifiable
offline with no keys. Signing is deliberately deferred until a verifier exists.

### Rejected

Signed receipts, for now — recorded as a *removal*, not an omission. Revisit
when either (a) a standard body defines a consumer format, or (b) a real
counterparty asks to verify records they did not produce.

### Consequences

- Cheap, dependency-free, and honest. The chain proves *integrity*, not
  *authenticity* — the docs must not blur the two.
- The canonicalisation must be stable across versions or old chains break. It is
  versioned and tested.

---

## ADR-0006 — Python for the reference implementation, stdlib only

**Status:** accepted · 2026-09-09 · `revisit` when latency is measured under
production-shaped load

### Problem

What should a security-critical, latency-sensitive, data-path component be
written in?

### Alternatives considered

1. Rust core with Python/Node bindings.
2. Go service / sidecar.
3. Python library, standard library only.

### Evidence

- The adoption surface — MCP SDKs, agent frameworks, AgentDojo and every
  research baseline we would be compared against — is Python. A Rust core with
  bindings roughly doubles the build cost and delays the proof that the thesis
  is even correct.
- The hot path is regex extraction over tool output and dictionary lookups over
  a ledger. ARM reports sub-millisecond policy evaluation for a comparable
  graph-based monitor; extraction, not decision, is expected to dominate.
- A security library with a transitive dependency tree is a supply-chain
  liability. Zero required runtime dependencies is a real feature here, not
  asceticism.

### Decision

Python ≥3.11, **zero required runtime dependencies**, `from __future__` not
needed, full type annotations, with the extraction and decision paths separated
behind narrow interfaces so a native core can replace either without touching
callers.

### Rejected

- Rust-first: right answer eventually, wrong answer before the thesis is
  validated.
- A service/sidecar as the *primary* form: adds a network hop and an operational
  burden to something that should be an in-process function call. A proxy
  deployment is a *packaging* of the library, not its core.

### Consequences

- We must publish real latency numbers and not hide behind "it's Python".
  Benchmarks are part of the definition of done.
- If measured latency fails the budget, the interface boundary is already in
  place to port the hot path.

---

## ADR-0007 — `UNATTRIBUTED` is denied, not allowed

**Status:** accepted · 2026-09-09

### Problem

An authority-bearing argument arrives whose value matches no seal and no trusted
source text. What should happen?

### Alternatives considered

1. Allow it — it matched no known-untrusted value, so it is "clean".
2. Deny it — it is not positively attributable to an authorised source.

### Evidence

Option 1 is the natural implementation and it is **unsound**. It defines safety
as "does not match a known-bad value", which is a blocklist. An attacker who
writes `bob at evil dot com` in prose defeats value extraction entirely; the
model reconstitutes `bob@evil.com` at call time; the reconstituted value matches
no recorded untrusted operand; option 1 admits it. Every paraphrase, encoding
and spelling trick is a bypass.

Option 2 defines safety as "is positively derivable from an authorised source",
which is an allowlist. Laundering an untrusted value cannot make it
trusted-derivable — it can only make it *unattributable*, which is already
denied.

### Decision

**Positive attribution is required.** `UNATTRIBUTED` is a first-class provenance
verdict and is non-authoritative by default. Sealing removes the easy path;
this rule closes the laundering path; neither is sufficient alone.

### Consequences

- This is the design's load-bearing security claim and its main utility cost.
  Tasks where the agent must legitimately *originate* an authority value (choose
  a new path, mint an identifier) are denied by default.
- The cost is exposed as a policy knob (`DENY` ⇄ `ESCALATE`), never hidden, and
  is the first thing to measure when utility benchmarking becomes possible.
- Both halves are directly tested: `tests/test_adversarial.py` includes the
  obfuscated-reconstruction attack that defeats sealing alone.

---

## ADR-0008 — Existential attribution, not universal

**Status:** accepted · 2026-09-09

### Problem

A value appears in *both* the user's trusted task text and an untrusted web
page. Its provenance set has two entries, one authorised and one not. Admit or
deny?

### Alternatives considered

1. **Universal** — every contributing source must be authorised (conservative).
2. **Existential** — at least one contributing source must be authorised.

### Evidence

Universal attribution looks safer and is actually just wrong. If the user typed
`bob@corp.com` in the task, that value is authorised *independently* of anything
an attacker writes. Under universal attribution an attacker could **deny-of-
service the legitimate flow** simply by mentioning the user's own address in a
page the agent fetches — a free availability attack.

The attacker gains nothing from existential attribution: they cannot cause a
*new* address to appear in the user's own task text, and echoing a value that is
already authorised adds no authority.

### Decision

**Existential.** An operand is admissible for an authority role if *any* of its
recorded provenance entries is authorised for that operand kind.

### Consequences

- Confidentiality is the mirror image and must use the opposite quantifier: for
  sensitivity, we take the **maximum** over contributing sources, because
  touching one confidential source taints the result regardless of what else
  contributed. Integrity is existential-permissive; confidentiality is
  universal-restrictive. Getting these backwards is a classic IFC bug and is
  tested.

---

## ADR-0009 — Denials are silent by default, and budgeted

**Status:** accepted · 2026-09-09 · partial mitigation, residual risk documented

### Problem

ARM (arXiv 2604.04035) demonstrates *causality laundering*: an adversary probes
a protected action, observes the denial, and exfiltrates the inferred
information through a later benign call. The denial itself is a channel that
data-flow provenance does not capture.

### Alternatives considered

1. Ignore it and document it.
2. Full counterfactual provenance — model denial-induced causal influence as
   graph edges (ARM's approach).
3. Reduce the channel: strip content from denial feedback and bound the number
   of probes.

### Evidence

A verbose denial (`"denied: recipient attacker@evil.com is not authoritative"`)
returns attacker-chosen content *and* a discriminating oracle to the agent's
context. A content-free denial reduces the channel to approximately one bit per
attempt. Bounding attempts bounds the total leak.

Option 2 is the right long-term answer and is a substantially larger build.

### Decision

**Option 3 now, option 2 on the roadmap.** Denial feedback returned to the agent
is a fixed, content-free string; full reasons go only to the audit record.
Sessions carry a denial budget; exhausting it halts the session rather than
continuing to answer probes.

### Consequences

- **This does not close the channel.** One bit per attempt, times the budget, is
  a real residual leak and is recorded as such in
  [`THREAT_MODEL.md`](THREAT_MODEL.md) and [`LIMITATIONS.md`](LIMITATIONS.md).
  We do not claim causality laundering is solved.
- Silent denials make debugging harder. The audit record carries the full
  reason, and the policy can be flipped for development.

---

## ADR-0010 — Sealing applies to untrusted content only

**Status:** accepted · 2026-09-09

### Problem

Should trusted content (the user's task, system instructions) also have its
authority-bearing values replaced with opaque handles?

### Alternatives considered

1. Seal everything uniformly.
2. Seal untrusted sources only; record trusted operands in the ledger without
   rewriting the text.

### Evidence

Sealing the user's own task text would make the task unreadable to the model
("send the report to ⟨idn:email:9f2a⟩") for no security gain — the value is
authorised anyway. It would also destroy the model's ability to reason about the
task, which is a pure utility loss.

Recording trusted operands in the ledger *without* rewriting is what makes a
literal argument attributable: an argument matching a recorded trusted operand
is positively attributed to the trusted source.

### Decision

Option 2. Trusted sources are *indexed*, untrusted sources are *sealed*.

### Consequences

- The trusted/untrusted boundary must be declared correctly by the integrator.
  Mislabelling a source as trusted is a total bypass; this is stated as the
  first deployment assumption in [`THREAT_MODEL.md`](THREAT_MODEL.md).
- Tool *descriptions* sit at the bottom of the integrity lattice, below
  untrusted tool output, because MCP tool poisoning makes them attacker-
  controllable while they look like configuration.
