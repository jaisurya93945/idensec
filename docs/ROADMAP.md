# ROADMAP.md

Ordered by what would most change what we know, not by what would be most
impressive to ship.

Status: `done` · `next` · `later` · `blocked`

---

## Now: prove or refute the thesis

Everything here exists to answer one question — *does argument-level enforcement
cost more task success than teams will pay?* Until it is answered, no amount of
additional engineering makes the project more true.

| | Item | Why it is first |
| --- | --- | --- |
| `done` | **AgentDojo evaluation, model-free** | Unblocked by realising AgentDojo publishes attacker *and* correct calls as data, so both security and utility can be replayed without a model. **92.0% security, 51.5% utility.** [`BENCHMARKS.md`](BENCHMARKS.md). |
| `next` | **Raise utility past 70%, or record the thesis as disproven** | 51.5% is nearer PACT's deployed row than its oracle row. The number moved 22.7% → 51.5% in one sitting on contract fixes, so it has not converged — but nothing else on this roadmap matters more, and leaving it in a table while building features is the failure mode ([`REVIEW.md`](REVIEW.md)). |
| `blocked` | **Re-verify the literature against primary sources.** | Every comparative claim is still `INFERENCE` from search summaries. Nothing comparative is published outside this repository, and the AgentDojo numbers are deliberately *not* placed beside CaMeL's or PACT's, which measure a different quantity. |
| `done` | **Extraction coverage study** (synthetic corpus) | 69% → 93% recall at zero false positives; six new kinds, three broadened patterns. Priced the `ipv4` trade-off rather than guessing it. [`BENCHMARKS.md`](BENCHMARKS.md). |
| `next` | **Coverage against *real* MCP traffic** | The synthetic corpus measures our patterns against our own expectations. Partially addressed: the proxy now runs against the reference `mcp-server-time`, and AgentDojo supplied four real-shaped environments. |
| `done` | **Contract derivation precision/recall** | 25 hand-labelled schemas: authority recall 95.2% → **100%**, dangerous misses 2 → **0**. Both misses were real deriver bugs, now regression-tested and gated in CI. [`BENCHMARKS.md`](BENCHMARKS.md). |

## Next: make it deployable

| | Item | Notes |
| --- | --- | --- |
| `done` | **MCP proxy** | Built: stdio transport, both boundaries, contract drafting, observe mode, audit to JSONL. 19 end-to-end tests against a hostile server over real pipes. See [`MCP.md`](MCP.md). Surfaced a protocol-level finding — MCP has no trusted channel for principal intent ([`RESEARCH.md`](RESEARCH.md) Thread 3b). |
| `done` | **Contract linter** | Built: 11 checks over contracts and source grants, three severities, JSON output, and the same checks run at proxy startup. Dogfooded in CI against our own shipped contracts. |
| `next` | **A seeded contract corpus** for common MCP servers, versioned and reviewable. | The one candidate moat that grows with adoption ([`COMPETITORS.md`](COMPETITORS.md) §4). |
| `next` | **Streamable HTTP transport** for the proxy | Same interception points as stdio; the remaining half of MCP deployments. |
| `next` | **Propose a principal-intent field to the MCP spec** | The concrete standards contribution this project can make, and a prerequisite for *any* containment design deploying cleanly over MCP. |
| `later` | **Framework adapters** — agent SDK tool hooks, LangGraph. | Lower leverage than MCP; each is a separate integration surface. |
| `later` | **Attribute provider for OPA / Cedar** | Emit provenance facts and let an existing policy engine render the verdict. The right long-term shape: we compute the attribute nobody else can, they own the decision language. |

## Later: close known gaps

| | Item | Gap it closes |
| --- | --- | --- |
| `later` | **Counterfactual provenance** for denial-induced influence, following ARM (arXiv 2604.04035). | P01. Capacity is now bounded, *measured* (`denial_channel_bits`) and optionally contained; the general fix remains a larger build. |
| `done` | **Aggregate constraints** — session budgets over calls, sums and distinct destinations | U04. The founding brief's flight example is now a test. Deployable through proxy config. Residual: a budget must be *stated*, because "under 50,000" being a limit rather than a preference is intent, and provenance does not carry intent. |
| `later` | **Portable label format** for cross-process provenance between sub-agents. | Section 4.5 of the limitations; also the natural specification to standardise. |
| `later` | **Token index over observed text.** | The linear attribution walk; needed before ~10 000-step sessions ([`BENCHMARKS.md`](BENCHMARKS.md)). |
| `later` | **Single-pass extraction** via combined alternation. | ~2× on the read boundary. Explicitly deferred: it changes overlap resolution from priority-ordered to leftmost-first, a subtle semantic change in a security path for a speedup nothing currently needs. |

## Not planned

Recorded so the decisions are visible rather than merely absent.

| Item | Why not |
| --- | --- |
| Signed decision receipts | No relying party exists who would verify one (ADR-0005). Revisit when a standard body defines a consumer format, or a real counterparty asks. |
| Agent identity / registry / credential brokering | Converged market, incumbent advantage (ADR-0001). Complementary, not competitive. |
| Prompt-injection classifier | Wrong failure model. A control with an attacker-searchable false-negative rate is a filter, not a boundary. |
| Dashboard / control plane / SaaS | The primitive first. No evidence a UI is the blocker. |
| Rust core | Right answer eventually, wrong answer before the thesis is validated (ADR-0006). The interface boundary is already in place. |

---

## Business validation — hypotheses, labelled

**There are no users, no customers, no pilots, and no interviews.** Nothing
below is evidence. Each line is a claim we intend to test, written down so that
being wrong is visible.

| Question | Status |
| --- | --- |
| Who has the problem? | `HYPOTHESIS` — teams running tool-using agents against untrusted content: coding agents on external repos, support agents on inbound mail, browser and computer-use agents. |
| How painful is it? | `INFERENCE` — prompt injection is top-ranked in OWASP's 2026 agentic list and reported unsolved. Pain is inferred from public reporting, not observed. |
| Who owns the budget? | `HYPOTHESIS` — application security or platform engineering, not IAM. Untested. |
| What do they use today? | `FACT` (as reported) — invocation-level allow-lists, gateways and content classifiers. |
| Why is that insufficient? | `INFERENCE` — granularity mismatch, documented in the research ledger. |
| What would make them adopt? | `HYPOTHESIS` — a drop-in MCP proxy, a contract corpus they did not have to write, and a utility number they believe. |
| What would make them reject it? | `HYPOTHESIS` — false denials in normal workflows. This is also the thing we have not measured, which is not a coincidence. |
| Could this become mandatory infrastructure? | `HYPOTHESIS` — plausible if a standards body adopts a provenance/contract format. NIST's agent identity track and OWASP's Agent Control Standard are the places to watch. Nothing about that is in our control. |

---

## Ten-year test

Reassessed at every milestone. The direction of each arrow is what matters, not
the confidence of any single row.

| | 2026 | 2028 | 2030 | 2035 |
| --- | --- | --- | --- | --- |
| Agent autonomy | rising | ↑ | ↑ | ↑ |
| Tool calls per task | rising | ↑ | ↑ | ↑ |
| Agent-to-agent delegation | early | ↑ | ↑ | ↑ |
| Untrusted content in agent context | universal | ↑ | ↑ | ↑ |
| "Which data determined this argument?" | rarely asked | asked | expected | assumed |
| Identity solves it | no | no | no | no |

The thesis survives as long as the last two rows hold. It fails if models become
reliably injection-resistant *and* the industry accepts a probabilistic
guarantee — or if frameworks make provenance native, in which case the mission
succeeds and the project is redundant. Both are recorded in
[`LIMITATIONS.md`](LIMITATIONS.md) §7.
