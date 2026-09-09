# COMPETITORS.md

Landscape as understood on **2026-09-09**. Read the reachability caveat in
[`RESEARCH.md`](RESEARCH.md) first: this map is built from search-result
summaries and vendor marketing, not from hands-on evaluation of any product.
Nothing here should be quoted as a technical fact about a competitor.

We do not claim "nobody is doing this." Many people are doing adjacent things,
several are doing overlapping things, and the closest work to ours is published
research, not a product.

---

## 1. Why this map is drawn by *layer*, not by company

Almost every vendor in this space describes itself as "AI agent security". The
descriptions are not distinguishing. What distinguishes them is **the unit at
which they make a decision**:

| Layer | Decision unit | Question answered |
| --- | --- | --- |
| L1 Identity | The principal | *Who is this agent, and who sponsors it?* |
| L2 Credential | The token | *What scopes does it hold, for how long?* |
| L3 Invocation | The tool call | *May this agent call this tool at all?* |
| L4 Content | The bytes | *Does this text look like an attack?* |
| **L5 Operand** | **The argument** | ***What determined this value?*** |

IDENSEC is an L5 system. Practically every commercial product we found operates
at L1–L4. Practically every 2026 research system operates at L5. That split *is*
the opportunity, and it is also the warning: if L5 were easy to ship, the L1–L4
vendors would have shipped it.

---

## 2. Agent identity and authorization (L1–L2)

| Player | Core primitive | Buyer | Overlap with IDENSEC |
| --- | --- | --- | --- |
| Microsoft Entra Agent ID | Agent as a first-class directory object; GA April 2026 | Enterprise IT / IAM | **Low.** Complementary — Entra says *who*, IDENSEC says *what determined the argument*. |
| Okta / Auth0 (agent-native capability, cross-app access) | Agent identity + delegated OAuth grants | Enterprise IAM, developers | **Low–medium.** Delegation chains overlap conceptually; enforcement granularity does not. |
| 2026 funded entrants in agent identity (reported: Oak, NewCore, Keycard) | Registry + sponsor binding + short-lived scoped credentials | Enterprise security | **Low–medium.** Same vocabulary, different decision unit. |
| SPIFFE / SPIRE | Workload identity, attested SVIDs | Platform teams | **None, and useful.** A natural source of trustworthy `source_id` attestation for IDENSEC labels. |

**Assessment.** This is the converged market described in
[`RESEARCH.md` Thread 1](RESEARCH.md#thread-1--is-stateful-delegated-authority-for-agents-an-open-problem).
Incumbents own the directory, the SSO integration and the enterprise
relationship. Competing here means competing with Microsoft on directory
integration. We do not.

**Could they add L5?** Yes — but it would be a poor fit for their architecture.
Identity providers sit at the *authentication* boundary and do not see tool
results or tool-call arguments. Seeing those requires being in the data path,
which is a different product with a different deployment story.

---

## 3. Policy engines and authorization services (L3)

| Player | Core primitive | Overlap |
| --- | --- | --- |
| OPA / Rego, Cedar / AWS Verified Permissions, OpenFGA, SpiceDB/AuthZed, Cerbos, Oso, Permit.io | Evaluate a policy over attributes you supply | **None, and structurally complementary.** |

**Assessment.** This is the single most important "is this just X?" test, and it
has a clean answer. A policy engine evaluates a decision over attributes that
*someone else computed*. The entire difficulty in agent containment is
**computing the attribute** — "this `to` argument was determined by a web page
fetched at step 3" is not something Cedar or OPA can derive; it is something
they would need to be told.

IDENSEC is an attribute *producer*, not a competing decision engine. The correct
long-term relationship is that IDENSEC emits provenance facts and an existing
policy engine renders the verdict. That is on the roadmap, not built.

**Could they add L5?** Not without becoming a data-path component, which is
contrary to how these products are deployed.

---

## 4. Agent runtime security, gateways and firewalls (L3–L4)

| Player | Reported enforcement | Overlap |
| --- | --- | --- |
| Zenity | "Boundaries" engine, MCP Live View: per-request identity, tool invoked, block/modify on live context | **Medium.** Same position in the traffic path, coarser decision unit. |
| Noma Security | Agent Access Control (per-agent identity, tool-level approve/review/block); Open Enforcement across agent hooks, MCP gateways, AI gateways, SDKs; Kong AI Gateway plugin | **Medium.** Broadest enforcement-surface story we found. |
| Snyk / Invariant Labs (`mcp-scan`) | Static scan of MCP server manifests for tool poisoning and injection patterns | **Low.** Point-in-time, pre-connection; explicitly cannot catch a server that turns malicious after approval. |
| AI/LLM gateways generally (Kong AI Gateway, Cloudflare AI Gateway, LiteLLM-class proxies) | Routing, rate limits, key management, some content filtering | **Low.** Distribution channel more than competitor. |
| Prompt-injection classifiers and guardrail products | Probabilistic detection of attack-shaped content | **Low, and we should not compete.** Different failure model. |

**Assessment.** These are the closest *commercial* competitors and the most
likely acquirers of this idea. Their advantage is real: distribution, existing
enterprise deployments, and a control plane customers already trust.

**Honest evaluation of the "they could just add it" risk:** they could, and
some form of it is likely to appear. What is hard to copy quickly is not the
concept but three things that have to be *earned*:

1. **Soundness under adversarial pressure.** An L5 monitor that is 95% right is
   not a security control. Getting the unattributed/laundering interaction right
   is where these designs break; our own regression suite exists precisely
   because we broke it ourselves (see [`THREAT_MODEL.md`](THREAT_MODEL.md)).
2. **The tool contract corpus.** Argument roles and effect classes for real
   tools are an accumulating shared asset. The literature's stated adoption
   blocker is policy sprawl; whoever solves the corpus problem, not the engine
   problem, wins the deployment.
3. **Determinism as a product property.** Products in this tier lean on
   classifiers and live context. A monitor whose verdict is reproducible from a
   trace is auditable in a way a classifier is not.

**Where we should be complementary rather than competitive:** these platforms
are already in the traffic path with a policy control plane. An L5 engine that
emits provenance facts into their enforcement points is a better outcome for
adoption than trying to displace them.

---

## 5. Research systems (L5) — the real prior art

This is where we must be scrupulous. **IDENSEC does not claim to have invented
argument-level provenance, integrity lattices, opaque handles, or effect-sink
authorization.** All of these are published.

| System | Reported contribution | Relationship to IDENSEC |
| --- | --- | --- |
| **CaMeL** (2503.18813) | Dual-LLM plan/quarantine split + taint-tracking interpreter + capability policies. Provable guarantees. | **Ancestor.** We take the capability/IFC framing. We reject the architecture: it requires the agent to be rewritten as a planned program, and a Python policy per tool. Reported zero production adoption. |
| **PACT** (2605.11039) | Provenance-Aware Capability Contracts at argument granularity. Oracle provenance → 100/100; inferred → 100% security, 38–46% utility. Names role assignment and provenance inference as the bottleneck. | **Direct intellectual parent, and the paper we are trying to beat on exactly the axis it identifies.** Our thesis is that its bottleneck is an artefact of inferring what can be made structural. |
| **PAuth** (2603.17170) | Task-scoped implicit authorization; NL slices; envelopes binding operands to symbolic provenance, verified server-side. | **Strongest overlap with the *founding* hypothesis.** Requires server-side cooperation; we deliberately require none. |
| **SecureClaw** (2606.09549) | Trusted gateway returns opaque high-entropy handles plus bounded summaries; authorization at the effect sink; plaintext confinement at the read boundary. | **Closest to our sealing mechanism.** We must cite it and must not claim handle indirection as ours. Our addition is the unattributed rule and the source-authority matrix. |
| **CXI** (2607.06000) | Opaque data slots; deterministic gate binding field authority + exact-effect authorization + invocation authority to one action manifest. | **Very close in spirit,** including the commitment to a deterministic gate. |
| **ARM** (2604.04035) | Provenance graph, five-tier integrity lattice, counterfactual edges from denied actions; blocks causality laundering; sub-ms policy evaluation. | **Identifies a channel we do not fully close.** We adopt the lattice, implement partial mitigations (silent denial, denial budget) and document the residual risk rather than claiming it solved. |
| **RTBAS** (2502.08966), **Ghost in the Agent** (2604.23374), **APPA** (2607.24625) | IFC variants for agents | Same family; differ in recovery, granularity and labelling. |
| **ContainmentBench** (2607.23999), **ToolPrivacyBench** (2606.28061), **AgentDojo** | Evaluation | **Targets, not competitors.** Our evaluation story is incomplete until we run against these. |

**Assessment.** The honest summary is uncomfortable and worth stating plainly:
*there is no unclaimed conceptual primitive in this space.* Every idea we would
want to build has a 2025–2026 paper attached to it. What there is not, on the
evidence available to us, is **a deployable implementation with zero required
dependencies, no agent rewrite, no model in the decision path, and a shared
contract corpus.** That is a smaller claim than "we invented something", and it
is the claim we can actually defend.

---

## 6. Kill test (founding brief §6)

| Question | Answer |
| --- | --- |
| Is this just IAM? | No. IAM never observes argument values or their origin. |
| Is this just RBAC / ABAC / ReBAC? | No — but it *produces* an attribute those models cannot compute for themselves. |
| Is this just an API gateway? | No. A gateway sees the call, not what determined the call's operands. |
| Is this just a policy engine? | No, and it should be *paired* with one. §3. |
| Is this just an agent firewall? | No. Firewalls classify content probabilistically; this is a dataflow property computed deterministically. |
| Is this just observability? | No. It denies. Observability that cannot deny is not containment. |
| Is this just a kill switch? | No. A kill switch is a coarse manual control; this is per-argument and automatic. |
| Is this just provenance / audit? | Provenance is the mechanism, not the product. The product is the *decision* the provenance enables. |
| Is this just red teaming? | No. Our adversarial suite is a means of proving the control, not the deliverable. |
| Is this just an agent registry? | No. |
| Is this just a guardrail? | No — and this is the sharpest distinction. A guardrail is a classifier with a false-negative rate an attacker can search against. This monitor's security property does not depend on recognising the attack. |
| Is this an existing product with an AI wrapper? | No. There is no model in the decision path, by design. |
| Can a customer solve this with existing infrastructure? | **No.** No IAM, gateway or policy engine computes argument provenance. They would have to build it. |
| Is the pain severe enough to create budget? | Prompt injection is the top-ranked agentic risk in OWASP's 2026 lists and is reported as unsolved. Budget evidence is *hypothesis*, not fact — we have no customers. See [`ROADMAP.md`](ROADMAP.md). |
| Does the problem grow with autonomy? | Yes. More tools, more steps, more delegation ⇒ more arguments determined by content nobody vetted. |
| Can this become infrastructure rather than a feature? | Plausibly. A contract format plus a deterministic monitor is the shape of infrastructure. Unproven. |
| Is there a meaningful technical moat? | Not from the concept — it is published. Candidate moats are the contract corpus, the adversarial regression suite, and determinism as an auditable property. All must be earned. |

---

## 7. The strongest arguments against IDENSEC

Kept here deliberately, and revisited at every milestone.

1. **"The research is published and unadopted for a reason."** The most likely
   reason is that argument-level containment costs utility that product teams
   will not pay. If our utility numbers land where PACT's *deployed* row landed
   rather than its *oracle* row, the thesis fails and we should say so.
2. **"Models will fix this."** Injection-resistant model training could reduce
   the need for external containment. Counter: containment is a soundness
   property; a hardened model reduces the rate of attack success but cannot
   provide a guarantee.
3. **"The frameworks will absorb it."** If agent frameworks and MCP hosts ship
   provenance natively, an external library becomes redundant. Counter: this is
   the *good* outcome for the mission; it argues for a specification and
   contract format, not just an engine.
4. **"Contracts are the same policy sprawl that killed CaMeL."** The fairest
   criticism. Our answer — schema derivation plus a shared corpus — is a
   hypothesis, not a demonstrated result.
