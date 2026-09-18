# REVIEW.md — milestone self-criticism

A rolling record, newest first. The questions come from the founding brief §34
and are answered to be useful rather than reassuring. If an entry here reads as
comfortable, it was written badly.

---

## 2026-09-18 — a mechanism for one server found a hole in a mechanism for another

The roadmap has listed *composition beyond paths* since ADR-0012 shipped, with a
warning attached: a wrong answer on a URL host is worse than one on a path
segment. Six measured cases settled it, and the interesting results are the two
nobody was looking for.

### The obvious implementation fails completely

Parse the URL; check scheme, host, path segments, query parameters. It denies
all six cases including the principal's own. `/`, `:` and `@` are identifier
characters, so `api.corp.example` is never a *whole token* of any URL anybody
wrote — semantic decomposition produces components no source ever emitted.

That is a statement about the design, not a bug: **attribution works on strings
a source could have said, not on meanings.** It is also why the prefix/remainder
split refuses lookalike hosts and userinfo confusion *structurally* rather than
by getting URL parsing right — which is historically the least reliable code in
any security boundary.

### The shipped mechanism had an egress hole

`https://api.corp.example/4471029833` — authorised host, confidential account
number as the leaf — came back **ALLOW with no findings at all**.

Composition merges the origins of both halves, and `principal_directed()` was
existential. One principal-supplied component made the whole destination look
principal-chosen, which skipped the egress block and took `confidential_egress`
with it. Live in `compose_paths` since ADR-0012; never bit because the
filesystem server it was built against has no egress tool.

> Composition conflates *this source may name this value* with *this value may
> appear in this position*. For a path those coincide. For an egress URL they do
> not: a path segment is content leaving the building.

### Is the thesis disproven?

**No, and this milestone is the first in a while that is straightforwardly good
news** — which is exactly when to be careful. What was actually demonstrated is
narrow: one mechanism extended to one more value grammar, priced over six
hand-written cases, shipping off by default. The AgentDojo curve has not moved.
Nobody is using any of it.

The genuinely valuable part is the hole, and it is not a credit to the review
process: it was found because a *different* server had an egress tool. Nothing
about reading ADR-0012 would have surfaced it, and I had read ADR-0012 several
times while writing the entries above.

### What should happen next

1. **`git_remote` and ARNs stay excluded until measured.** They are one line of
   code away and that is exactly the reason to be suspicious of adding them.
2. ~~**Price the escalation.**~~ Done in this milestone rather than deferred:
   `idensec.lint` now reports `composition-without-egress-guard` when
   composition is on, a contract can egress, and `confidential_egress` is set to
   ALLOW — the combination that is defensible setting by setting and unsound
   together. The proxy runs it at startup.
3. **Users.** Unchanged, and now the oldest item in this document.

### The strongest criticism, updated again

> *"Every one of your mechanisms has turned out to have a hole that only showed
> up when someone pointed it at software you had not tried. How many servers are
> you away from the next one?"*

Unknown, and the honest answer is that the number is not obviously large. Three
servers have each produced a defect the previous two could not: filesystem found
constructed paths, memory found mixed-role parameters, git found U08 and a
scoring bug, and an egress tool that exists in none of them found this one. The
pattern is not converging — each new *shape* of tool finds something, and there
are more shapes than servers.

The defence is that all four were found, published with the failing
configurations beside the working ones, and regression-tested. That is a process
that surfaces its own errors. It is not evidence that the surface is small.

---

## 2026-09-16 — the grant did not say what we thought it said

The previous entry recorded U08: a field-path grant asserts something about data
the operator never sees, and `idensec.lint` cannot check it because at lint time
there is no data. The obvious response was to supply the data, so
`idensec.preview` now observes a corpus of real tool output and asks the **real**
`Session.admit` what the grants would admit.

It found something on its first run.

### `unclassified` means something much larger than it reads

| grant on `mcp-server-git` | admitted, of 1489 tokens | bare English words |
| --- | ---: | ---: |
| `git_status.**: [posix_path]` | 0 | 0 |
| `git_status.**: [posix_path, unclassified]` | 48 | 28 |
| `**: [posix_path, unclassified]` | **1475 (99%)** | 793 |

An `unclassified` grant is not authority over the identifiers a tool returns. It
is authority over **every token the tool emits** — its prose, and the
`{"type": "text"}` label MCP wraps results in. More than half the values the
*scoped* grant admits are words like `Changes`, `add`, `branch` and `discard`.

This was always what the code did. Nobody had looked, and the config file reads
like a grant over paths.

### And the safest-looking grant does nothing at all

`git_status.**: ["posix_path"]` admits **zero** values: `posix_path` needs a
leading separator and git reports repo-relative names. The narrow, kind-scoped
grant an operator would reach for first fails closed silently while they believe
they configured something. That is the worse failure of the two — an
over-permissive grant at least leaves a trail.

### Is the thesis disproven?

**No, and this is the first milestone that made a published number look better
rather than worse — which is a reason for suspicion, not comfort.** The honest
summary is narrower: a tool that reports a grant's surface is a usability and
review improvement, not a security result. U08 is unchanged. The preview reports
what a grant admits against *a* corpus; the repository it meets in production is
a different one.

What did change is the *quality of the argument for scoping*. "Scope your
grants" was advice. It is now a measured 99% → 3%, on software we did not write.

### One thing was closed by being rejected

The containment form of U08 — a grant that declares the operand shape it expects
and refuses a surprise — is now in **Not planned**, with the reason. It fails on
its own motivating case: the expected shape under `git_status` is *a
repo-relative path*, and `.env` is a repo-relative path. What separates the
secret from the changelog is sensitivity, which is semantic, so the mechanism
collapses into the prompt-injection classifier this project refuses to build.

Writing that down is worth more than leaving it as a roadmap item nobody priced.

### The strongest criticism, updated again

> *"Three milestones running, the defect was in what you could see, not in what
> the code did. That is not a mechanism you have validated — it is a mechanism
> you keep failing to observe."*

That is the correct reading and I will not soften it. A dangerous miss found by
a number moving the wrong way; a scoring bug that credited us with git's
defence; a grant whose plain reading understated its surface by two orders of
magnitude. None was in the enforcement path. All three were in the view of it.

A fourth arrived while writing this entry, and it is the least flattering.
Timing the examples showed two of the three had **never completed an MCP
handshake**: they waited out a 60-second timeout three times per run, discarded
the missing reply without checking it, and carried on. That had been true in CI
through three milestones whose results this repository reported approvingly.
The measured outcomes turn out to be unaffected — the servers did start, late,
and every call in the published tables was really made — but nobody noticed six
minutes of dead time, which is not a defence of the process, it is the
indictment.

The defence — such as it is — is that a design nobody can inspect is not
deployable regardless of whether it is sound, so the view *is* part of the
product. But it does mean this project's claim to have measured itself carefully
should be read as *measured itself repeatedly*, which is a different and weaker
thing.

---

## 2026-09-14 — the first user we guessed at, and a result we had to take back

[`ROADMAP.md`](ROADMAP.md) has named the same first user since the project
started: *coding agents on external repos*. It had never been tested. This
milestone tested it — the proxy in front of an unmodified `mcp-server-git`, the
injection in a source comment, the goal exfiltration by commit — and three
things came out of it, in descending order of how much they hurt.

### 1. A result was scored wrong in our favour, and we published nothing before catching it

The example checks whether an injected `git_add .env` succeeds. Under the broad
grant the token did not end up staged, and the example reported **ok**.

It was not ok. The proxy had **allowed** the call. Git's own `.gitignore`
refused the write. The example was scoring the effect on disk, so in the one
configuration that had already been bypassed it recorded a pass, and attributed
to IDENSEC a defence supplied by a tool we do not ship, do not control, and did
not mention.

Nothing was published from it. That is luck, not process: the only reason it was
caught is that the result *seemed too good* — three labellings in a row getting
every row right is not what this project's other measurements look like.

Every row now prints the verdict before the effect, and the exit status is
computed from verdicts.

**This is the second consecutive milestone where the thing that was wrong was a
measurement, not a mechanism.** The previous one was a dangerous miss found by
bisecting a utility *drop*. Both were caught by disbelieving a pass. Neither was
caught by review, and the review in both cases was mine.

### 2. U08 — a grant can be correct against the data you inspected and wrong against the data you get

Per-tool scoping is the setting that works on this server: grant
`git_status.**` and the legitimate unnamed file is admitted while the injected
one is refused. Clean result, right for a reason — the working tree is not
content, and injections live in content.

Then we ran the same policy against a repository whose `.env` is not in
`.gitignore`. `git_status` names the secret itself, the grant makes it
authoritative, and the token is staged and committed. **Same policy, same tools,
no diff.**

So `.gitignore` appeared twice in one experiment doing opposite work: once
masking a policy failure, once holding up a policy success.

> A field-path grant is a claim about data the operator has not seen. Whether it
> holds is decided outside the policy, `idensec.lint` cannot check it — at lint
> time there is no data — and the audit log only shows it after the call.

Recorded as U08, unmitigated. It is a different kind of limit from the ones
already listed: §4.1 and §4.2b bound what provenance can *decide*; U08 bounds
what an operator can *know they have configured*.

### 3. `strict` is not merely costly on this server, it is unusable

On the filesystem server, `strict` refused the principal's own read. Here it
refuses the ordinary act of staging a file `git_status` has just reported — and
developers say *"commit my changes"*, not *"commit README.md and
CHANGELOG.md"*. The operands a developer omits are exactly the ones the
repository supplies, so the quotation floor has nothing to work with.

A fourth finding is smaller but concrete: **all twelve `mcp-server-git` tools
take `repo_path`**, so under the unattributed rule the *first* call of every
session is denied. §4.2e had stated the bootstrap requirement abstractly; it now
has a named instance, and the remedy is outside the policy — the host must name
the checkout.

### Is the thesis disproven?

**No, and the confidence in the numbers should go down anyway.**

The AgentDojo curve was produced with grants we wrote against data we could
inspect in full. U08 says that is precisely the condition which does not hold in
deployment. The honest reading is that **the published curve is an upper bound
on what an operator would get**, not an estimate of it, and nothing in this
milestone tells us how far below it the real number sits.

Set against that, the mechanism did what it claims on software we did not write,
against an attack with a plausible payoff and no exotic capability. That is the
third such server, and the first that matches the user we have always named.

### What should happen next

1. **Make U08 visible at configuration time.** A grant that could declare the
   operand *shape* it expects and refuse a surprise would be containment rather
   than detection. Whether that is expressible without becoming a classifier —
   the thing this project refuses to build — is genuinely unknown, and it should
   not be attempted until it is answered.
2. **Stop adding servers for a while.** Three is enough to know the cost per
   server; a fourth mostly buys confidence, and confidence is not what is short.
3. **Users.** Unchanged from every previous entry, and now conspicuous: the
   coding-agent case is demonstrated *technically* and still has nobody in it.

### The strongest criticism, updated again

> *"You have now found that your own security results depend on data you never
> looked at, one server after the numbers you publish were fixed. Why should
> anyone believe the numbers rather than the pattern?"*

The pattern is the more honest thing to believe. Four milestones, four defects
found by measurement rather than review, and this one was in the measurement
itself. The counter-argument is thin and should be stated as thin: every defect
is now a regression test, every number is published as a curve rather than a
figure, and the project reports the labellings that fail beside the ones that
work — which is why this entry exists at all. That is a process that surfaces
its own errors. It is not evidence that there are few left.

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
