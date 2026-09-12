# BENCHMARKS.md

Measured numbers, the method that produced them, and what they do **not** show.

Reproduce with:

```
python3 benchmarks/bench_monitor.py            # 300 iterations per measurement
python3 benchmarks/bench_monitor.py --quick    # 50, for a fast sanity check
python3 benchmarks/bench_monitor.py --json out.json
```

---

## What is measured

Only the monitor. No model is involved in any figure here, because no model is
involved anywhere in the decision path (ADR-0003). These are the costs an agent
pays per tool result and per tool call.

## What is *not* measured, and must not be inferred

- **No end-to-end agent latency.** An LLM call is seconds; everything below is
  sub-millisecond to tens of milliseconds. Do not present these as agent
  performance numbers.
- **No security rate, from the timing benchmarks.** Security is established by
  construction, by the adversarial suite ([`THREAT_MODEL.md`](THREAT_MODEL.md)),
  and by the AgentDojo replay below — never by timing.
- **No utility rate, from the timing benchmarks.** Utility is measured against
  AgentDojo further down this file, model-free, as a *lower bound*: whether the
  monitor would have refused the calls a correct agent makes. End-to-end task
  success under a real model is still unmeasured and needs API access this
  environment does not have. See [`LIMITATIONS.md`](LIMITATIONS.md) and
  [`ROADMAP.md`](ROADMAP.md).

---

## Environment

| | |
| --- | --- |
| Python | CPython 3.11.15 |
| Platform | Linux 6.18.44 x86-64, glibc 2.39 |
| Host | Shared container, no CPU pinning, no isolated cores |
| Date | 2026-09-10 |
| Commit | the one that introduced this file |

**The host is shared and unpinned.** These numbers are indicative, not precise.
Run-to-run spread was measured directly rather than assumed: two consecutive
full runs differed by under 8% at p50 for every measurement above 0.3 ms, and by
up to 30% for the sub-0.15 ms measurements, where timer resolution and scheduler
noise dominate. Treat one-significant-figure differences as noise.

---

## Results (p50 / p95 / p99, milliseconds, n=300)

### Read boundary — `observe()`

| Measurement | p50 | p95 | p99 |
| --- | ---: | ---: | ---: |
| observe untrusted page (1 KB) | 0.98 | 1.61 | 3.27 |
| observe untrusted page (8 KB) | 6.84 | 11.43 | 14.28 |
| observe untrusted page (64 KB) | 55.57 | 86.41 | 88.95 |

Roughly linear in content size at about **1.2 MB/s**, dominated by regex
scanning across the nine registered operand kinds. 64 KB of fetched HTML costs
~55 ms.

That is slow in absolute terms and acceptable in context: it is paid once per
tool result, against an LLM call measured in seconds. A single-pass combined
alternation would cut it materially, and is **deliberately not done** — it
changes overlap resolution from priority-ordered to leftmost-first, which is a
subtle semantic change in a security-relevant path for a speedup nothing
currently needs. Recorded in [`ROADMAP.md`](ROADMAP.md) with that caveat
attached.

### Write boundary — `admit()`

| Measurement | p50 | p95 | p99 |
| --- | ---: | ---: | ---: |
| admit allow (3 args, 1 KB payload) | 0.092 | 0.135 | 0.156 |
| admit deny (injected destination) | 0.073 | 0.110 | 0.136 |

**Sub-millisecond**, which is the number that decides whether a deterministic
monitor is deployable at all. For comparison, ARM (arXiv 2604.04035) reports
sub-millisecond policy evaluation for a graph-based monitor; we are in the same
range, on a decision that includes attribution rather than only policy
evaluation.

### Scaling with session length

| Measurement | p50 | p95 | p99 |
| --- | ---: | ---: | ---: |
| admit allow after 10 observations | 0.082 | 0.117 | 0.157 |
| admit allow after 100 observations | 0.313 | 0.366 | 0.396 |
| admit allow after 1 000 observations | 2.70 | 2.84 | 2.87 |

### Worst case — attribution miss

A value matching nothing forces a full walk of every observation for every
declared source before it can be declared `UNATTRIBUTED`.

| Measurement | p50 | p95 | p99 |
| --- | ---: | ---: | ---: |
| admit deny, no match, 100 observations | 0.400 | 0.430 | 0.449 |
| admit deny, no match, 1 000 observations | 3.22 | 3.33 | 3.35 |

**Linear in the number of observations.** A 1 000-step session pays ~3 ms per
decision. Honest reading: this is the design's clearest scaling weakness, it is
tolerable for the session lengths agents currently run, and it will need an
index — a token or n-gram index over observed text — before it is comfortable at
10 000 steps. On the roadmap.

---

## Two performance bugs found by benchmarking

Recorded because "we benchmarked it" means nothing without saying what the
benchmark changed.

**Quadratic overlap resolution in extraction.** Each candidate operand span was
checked against every already-claimed span with a linear scan, making extraction
O(n²) in the number of operands. Invisible on a sentence, ruinous on a 64 KB
page — exactly the input a fetched document produces. Replaced with a bisect
over sorted spans.

**Re-normalising the corpus on every attribution.** `derivable_from` recomputed
the whitespace-collapsed, case-folded form of *every observation* on *every*
lookup, so `admit` scaled with the total size of everything observed rather than
its length. Normalisation moved to observation time.

Together these took `admit` after 1 000 observations from 4.85 ms to 2.70 ms
(−44%) and the worst case from 6.17 ms to 3.22 ms (−48%).

---

## Extraction coverage (2026-09-10)

Coverage is a security parameter, not a quality metric, and it was unmeasured
until now. Run it with:

```
python3 benchmarks/extraction_coverage.py
```

Against a **synthetic** corpus of 43 authority-bearing values in realistic
surface forms, plus 16 prose samples containing none:

| kind set | recall | correct kind | false-positive samples |
| --- | ---: | ---: | ---: |
| `DEFAULT_KINDS` (13 kinds) | 40/43 · **93%** | 40/43 | **0/16** |
| every registered kind (+`ipv4`) | 42/43 · 97% | 42/43 | 2/16 |

The first measurement, before this study changed anything, was **69%**. The
gaps it found were all real: home-relative and parent-relative paths
(`~/.ssh/id_ed25519`, `../../etc/shadow` — a traversal is an authority
decision), UNC paths, non-HTTP URI schemes (`s3://`, `postgres://`), scp-style
git remotes, EVM wallet addresses, AWS ARNs and IPv4 literals. Six new kinds and
three broadened patterns closed all but one.

**The one deliberate omission.** `ipv4` is registered but excluded from the
defaults. Four dotted decimals are genuinely ambiguous with version strings and
no deterministic rule separates `1.2.3.4` the address from `1.2.3.4` the
release. The asymmetry settles it: a missed seal is **not a bypass** — an
unsealed untrusted value still matches its source observation at the write
boundary and is refused by the unattributed rule — whereas a false positive
mangles every version number the agent reads. Deployments whose tools take
addresses enable it explicitly, and the table above prices that choice rather
than arguing about it.

**The one unclosed gap:** paths containing spaces (`/srv/docs/q3 report.pdf`).
Extending a path pattern across whitespace would swallow surrounding prose,
which costs the readability that makes sealing usable at all. Recorded as a
known miss rather than papered over.

**Limitation, stated plainly:** the corpus is synthetic — hand-written from our
own idea of what tool output looks like. These figures describe our patterns
against our own expectations, not against production MCP traffic. A study
against real traffic remains owed, and is listed below.

---

## Contract derivation accuracy (2026-09-10)

The claim that schema derivation answers policy sprawl was asserted repeatedly
before it was measured. Against 25 hand-labelled tool schemas modelled on real
MCP servers and common APIs — 71 parameters, 42 of them authority-bearing in
ground truth:

| | before | after |
| --- | ---: | ---: |
| authority recall | 95.2% | **100%** |
| **dangerous misses** | **2** | **0** |
| authority precision | 81.6% | 85.7% |
| exact role match | 84.5% | 90.1% |
| over-restrictions | 9 | 7 |

**The metric is dangerous misses, not accuracy.** The two errors are wildly
asymmetric: an authority-bearing parameter drafted as `PAYLOAD` is a silent hole
if a reviewer skims past it, while a payload parameter drafted as `AUTHORITY`
costs review effort and nothing else. A deriver that marked everything
`AUTHORITY` would score zero dangerous misses and be useless, so precision is
reported next to it rather than buried.

The two misses were real bugs, and both are now regression-tested:

- `reply_email.message_id` was drafted as `PAYLOAD`, because *message* reads as
  content and the suffix that turns it into a reference was ignored. An
  identifier suffix now outranks every content hint: which-thing is authority.
- `git_push.force` was downgraded to `ADVISORY` for being a boolean. Booleans
  carry authority when they widen what an action destroys, so `force`,
  `recursive`, `overwrite`, `purge` and friends stay `AUTHORITY`.

Only two over-restrictions were "fixed" (`reason` → payload, `priority`/`style`
→ advisory). The rest — `pattern`, `query`, `payload`, `values`, `reference` —
were left restrictive on purpose: `query` is SQL on some tools and prose on
others, and the draft exists for a human to relax, not to be trusted as-is.

CI fails on any dangerous miss or on recall below 100%.

**Limitation:** ground truth is hand-labelled by us. These numbers measure the
deriver against our own judgement of what carries authority, not against a
neutral standard.

---

## AgentDojo: the security–utility trade-off (2026-09-12)

**The first measurement of either against an independent benchmark.** The result
is not a number; it is a **surface**, and the surface is the finding.

AgentDojo publishes both halves as data — each injection task carries the tool
call the attacker wants, each user task carries the calls a *correct* agent
makes — so both can be measured with **no model involved anywhere**. Setup,
reproduction, and every artefact we had to author:
[`benchmarks/agentdojo/README.md`](../benchmarks/agentdojo/README.md).

Scale: 97 user tasks, 27 injection tasks, 609 in-scope security cases, four
suites. Security assumes the model is **always** hijacked, which is harsher than
AgentDojo's own metric. Utility replays the ground-truth calls a *correct* agent
would make, and is therefore a **lower bound**.

### Two knobs, swept together

Reporting one number per labelling was wrong, and an earlier version of this
file did it. Two policy settings move the result, they interact, and neither has
a defensible universal value:

- `min_quotation_length` — characters before quoting a value counts as evidence.
- `min_reference_word` — characters before a lone quoted word counts as *naming*
  a record.

Below, every labelling is swept over the quotation floor. There is no single
security number and no single utility number for this design; there is a
surface, and an operator picks a point on it.

| floor | `strict` | `permissive` | `scoped` | `recommended` | `referenced` |
| ---: | --- | --- | --- | --- | --- |
| 1 | 95.4 / 34.0 | 55.8 / 46.4 | 85.7 / 69.1 | 85.1 / **77.3** | 91.1 / 68.0 |
| 2 | 95.4 / 34.0 | 55.8 / 46.4 | 85.7 / 61.9 | 85.1 / 70.1 | 91.1 / 68.0 |
| 3 | 95.9 / 34.0 | 56.3 / 46.4 | 92.3 / 57.7 | 91.6 / 66.0 | **91.6 / 68.0** |
| 4 | 95.9 / 34.0 | 56.3 / 43.3 | 92.3 / 57.7 | 91.6 / 66.0 | **91.6 / 68.0** |
| 6 | **96.6** / 34.0 | 57.0 / 40.2 | **96.6** / 43.3 | 95.7 / 50.5 | 95.7 / 52.6 |
| 8 | **96.6** / 33.0 | 57.8 / 38.1 | **96.6** / 41.2 | 95.7 / 47.4 | 95.7 / 49.5 |

*security % / utility %. `min_reference_word` held at 8; it is priced below.*

**The Pareto frontier over all thirty configurations** — the only rows an
operator should ever consider:

| security | utility | configuration |
| ---: | ---: | --- |
| 96.6% | 43.3% | `scoped`, floor 6 |
| 95.7% | 52.6% | `referenced`, floor 6 |
| 92.3% | 57.7% | `scoped`, floor 3 |
| **91.6%** | **68.0%** | `referenced`, floor 3–4 |
| 85.7% | 69.1% | `scoped`, floor 1 |
| 85.1% | 77.3% | `recommended`, floor 1 |

> **No configuration reaches 90% security and 70% utility together.** The
> project's own falsification criterion asked for both. The closest is
> 91.6%/68.0% — two points of utility short — and it is reported here instead of
> the flattering row.

`permissive` is dominated everywhere: it gives up forty points of security to
buy twelve of utility, and three other labellings beat it on both axes.

### What reference binding was worth

Entity selection was named in the previous milestone as the binding constraint,
and reference binding (ADR-0011) is the answer that was built for it. Measured
rather than assumed:

**On the suite that exercises it, it works.** The workspace suite is calendar,
inbox and drive — reschedule *that* event, share *that* file — and it is where
entity selection lives:

| workspace suite, floor 3 | security | utility |
| --- | ---: | ---: |
| `recommended` (blanket directory grant) | 100% | 70.0% |
| `referenced` (only records the principal named) | 100% | **77.5%** |

Three more legitimate selections admitted, **no** security cost.

**In aggregate, it is worth two tasks out of ninety-seven.** The best
configuration above 90% security moves from `recommended`/floor-3 at
91.6%/66.0% to `referenced`/floor-3 at 91.6%/68.0%. That is the honest headline,
and it is a fraction of what the roadmap hoped for.

**It also loses a banking task, and the loss is the mechanism working.** A
blanket grant over a file directory authorises not only the file *ids* but the
contents of every file — which is how `recommended` passes *"read
address-change.txt and update my address"*. AgentDojo never charges for that
grant, because its banking injections target transfers rather than profile
fields, so the benchmark scores the less safe configuration higher. The charge
is real and is asserted as a test rather than argued:
`TestWhatTheBlanketGrantCostsElsewhere`.

**What it changes most is the shape.** `referenced` returns 68.0% utility at
every floor from 1 to 4; `recommended` swings 77.3% → 66.0% across the same
range. The reference check does not care whether an id is long enough to quote,
so it decouples entity selection from a character-count threshold. That is a
usability property, not a security one.

`min_reference_word` — the lone-word threshold — was swept at floor 3 across
4, 6, 8, 10 and 14 characters. It moved neither axis on this benchmark: every
setting returned 91.6%/68.0%. AgentDojo's records are named by multi-word
titles, so the lone-word rule never decides anything here. **The knob is
therefore unpriced**, not shown to be safe, and a deployment whose records are
named by single opaque tokens should expect it to matter.

### Why the exchange rate exists at all

Labellings differ mainly in whether the workspace is authoritative over its own
**entity directories** — the file list, the calendar, the contact records.
Granting that is worth an enormous amount of utility because most real agent
work is *selecting an existing entity*: reschedule **that** event, share
**that** file, reply to **that** thread.

It costs security for exactly the same reason. Once the file directory is
authoritative, an injection reading *"delete file 13"* names a file that really
is in the directory, and provenance cannot distinguish **selection by the
principal** from **selection by an injection**. That is intent, not origin.

Reference binding converts the cases where the principal *named* the record. It
does nothing for selection by **property** — "the cheapest hotel", "the oldest
file" — which is what remains.

> **Oracle provenance would not help either.** Knowing precisely where a value
> came from still does not tell you whether the principal meant it. `INFERENCE`
> — PACT's reported oracle-provenance result of 100% utility at 100% security is
> hard to reconcile with entity-selection workflows, which suggests its
> diagnostic suites may not contain that pattern. We cannot check: the paper is
> not reachable from this environment ([`RESEARCH.md`](RESEARCH.md)
> reachability caveat).

### Per suite (`referenced`, floor 3)

| suite | security | utility | note |
| --- | ---: | ---: | --- |
| travel | 65.8% | 100% | escapes are U01/U05, below |
| workspace | 100% | 77.5% | entity selection, as above |
| banking | 95.8% | 81.2% | amounts as content + a spend budget |
| slack | 96.2% | 9.5% | **inherent — see below** |

**Slack's 9.5% is the monitor being right, not wrong.** In that suite the
channel directory *and* the web-content store are themselves injection vectors,
so the legitimate tasks are things like "fetch the URL you found in a Slack
message" — precisely the pattern that gets agents exploited. There is no field a
grant can safely cover. Counting those refusals as lost utility flatters the
attacker.

**Banking needed a different control, not a different grant.** Its amounts are
*computed* — "prices rose 10%, send the difference" yields a number appearing
nowhere in the instruction — and arithmetic is a semantic derivation quotation
cannot follow. Treating an amount as authority-bearing denies the legitimate
case exactly as often as the attacker's. Making the amount content and bounding
it with a `Budget` took banking from 37.5% to 81.2% utility at 95.8% security:
**provenance handles identifiers, budgets handle magnitudes**
([`LIMITATIONS.md`](LIMITATIONS.md) §4.2c).

### Every escape traced to a cause

None is unexplained, and all fall into limitations documented *before* this
measurement existed:

| cause | limitation |
| --- | --- |
| Attacker **selects a legitimate entity by property** — a real hotel a poisoned review recommended | U01 — provenance is not intent; reference binding covers *naming*, not *properties* |
| Target call has **no authority-bearing argument** (`create_calendar_event`: all content and timestamps) | U05 — non-identifier authority |
| **Low-entropy token collision** — "what are we doing on June 13" authorises `delete_file(id="13")` | U02 — quotation is not intent; the quotation floor prices it |
| Speech-only injections (no tool call at all) | excluded, not counted either way |

The boundary this draws is crisp, and is what a reader should take away:

> **IDENSEC contains attacks that introduce a *new* destination, and attacks
> that select a record the principal never named. It does not contain attacks
> that select among legitimate records by *property*, nor attacks whose target
> call has no authority-bearing argument at all.**

### Nine defects the measurement found

All in code that was written carefully and tested, none found by review. The
last three are in reference binding itself, found by measuring the thing built
to fix the previous six:

1. Attribution kept only the **first** matching origin, though the authority
   check is existential — so an unauthorised origin could mask an authorised one.
2. **Dict keys were never observed.** `calendar.events["5"]` carries the entity
   id in the key, so every follow-up call on it was unattributable.
3. Numeric **re-spellings** did not match: a tool takes `4.0` where the
   principal wrote `4`.
4. `recipient` was constrained to `email`, failing every IBAN transfer.
5. `url` was constrained to `url`, failing every scheme-less fetch.
6. **Temporal parameters** were treated as authority-bearing — the single
   largest source of false denials. Later found to be matched by *exact name*
   only, so `new_start_time` was authority while `start_time` was advisory.
7. **Whole-field reference matching fired on nothing.** Requiring the principal
   to quote a record's field in full matched zero selections; real instructions
   name a record partially.
8. **Ids were bound without their collection.** Events, emails and files all
   number from 1, so naming *calendar event 13* authorised deleting *file 13* —
   reference binding reproducing the attack it exists to refuse.
9. **The `referenced` column was invariant by construction**, having pinned its
   own quotation floor while the sweep varied everyone else's. It would have
   been reported as a finding.

### What this does not show

- **Not end-to-end utility.** Ground-truth calls are not model behaviour.
- **Not a comparison with CaMeL or PACT.** They report end-to-end numbers on a
  different quantity; placing these beside them would mislead, and is done
  nowhere in this repository.
- **Not a claim about real deployments.** Four benchmark suites, with effect
  classes, field-path grants and entity-collection declarations we authored for
  APIs we do not own.

---

## MCP schemas we did not write (2026-09-12)

Every earlier measurement of the deriver used a corpus **we authored** —
schemas modelled on real servers, labelled by us — and this file has said so
since the corpus existed. This one uses `tools/list` output captured over stdio
from seven published MCP servers, checked in at
[`benchmarks/data/mcp_tools.json`](../benchmarks/data/mcp_tools.json) so it
reproduces without network access:

```
python3 benchmarks/mcp_corpus.py            # replay the captured corpus
python3 benchmarks/mcp_corpus.py --capture  # re-probe the live servers
```

**52 tools, 94 parameters**, from `everything`, `filesystem`, `memory`,
`sequential-thinking`, `time`, `git` and `fetch`.

**What this measures.** The *schemas* are not ours, so the shapes, naming
conventions and annotation habits are real. The *labels* are still ours —
nobody publishes ground truth for which MCP parameters bear authority — so this
is **not** an accuracy measurement and is not reported as one. It measures
review burden, coverage and linter yield on real inputs.

| server | tools | params | authority | with a kind | annotated |
| --- | ---: | ---: | ---: | ---: | ---: |
| everything | 13 | 16 | 6 | 0 | 13 |
| filesystem | 14 | 25 | 18 | 11 | 14 |
| git | 12 | 28 | 21 | 12 | 12 |
| memory | 9 | 8 | 8 | 0 | 9 |
| sequential | 1 | 9 | 6 | 0 | 1 |
| time | 2 | 4 | 0 | 0 | 2 |
| fetch | 1 | 4 | 1 | 1 | 0 |
| **total** | **52** | **94** | **60** | **24** | **51** |

**64% of parameters are drafted `AUTHORITY`, and only 40% of those carry a kind
the extractor recognises.** The other 36 fall to the fail-closed path where the
whole value must be attributed. That is the review burden, stated in the units
an operator actually faces: sixty parameters to check across seven servers.

### MCP servers volunteer effect hints, and 62% of them claim to be harmless

51 of 52 tools carry an `annotations` object. What they claim:

| hint | count | what we do with it |
| --- | ---: | --- |
| `readOnlyHint: true` | **32** | **ignored** |
| `readOnlyHint: false` | 19 | ignored |
| `destructiveHint: true` | 7 | believed → adds `DELETE`, `IRREVERSIBLE` |
| `destructiveHint: false` | 34 | ignored |
| `openWorldHint: true` | 1 | believed → adds `NETWORK_EGRESS` |
| `openWorldHint: false` | 50 | ignored |
| `idempotentHint` | 41 | says nothing about what a tool reaches |

**The rule is one line: an annotation may add an effect and may never remove
one.** Annotations arrive from the server, which sits at the *bottom* of the
integrity lattice — the same channel as the tool descriptions this project
seals, and for the same reason. So each hint is judged by direction:

> A server claiming to be **destructive** is believed, because a hostile server
> lying that way only denies its own tools. A server claiming to be
> **read-only** is ignored, because believing it is a total bypass: mark the
> exfiltration tool read-only and every confidentiality rule stops firing.

Thirty-two real tools make exactly that claim today, which is what moves this
from a hypothetical to a live concern. The asymmetry is asserted in
`TestAnnotationsAreReadOneWay`, including a case that checks no combination of
hints can remove a declared effect.

The believed hints completed **8 of 52 drafts** that would otherwise have had
no effects at all — every one in the restrictive direction. The remaining 44
`no-effects-declared` findings are correct and are the point: effects are the
one thing the deriver refuses to infer.

### Four defects the real schemas found

None would have been found by a corpus we wrote, because we do not write
schemas like these:

1. **`"type": ["string", "null"]` crashed the deriver.** JSON Schema's `type` is
   a string *or a list*; reading it as a string raised `TypeError` on the first
   server that used a union. Unions are now downgraded only when *every* member
   is a type that cannot hold an identifier.
2. **camelCase was invisible.** Hints were matched by splitting on `_` only, so
   `sortBy` stayed `AUTHORITY` while `sort_by` was advisory, and `fileId` missed
   the identifier suffix that `file_id` matched. Every JavaScript server in the
   corpus names parameters this way.
3. **The linter reported `unclassified` as a typo.** It is a pseudo-kind with no
   extraction pattern, so it is absent from `KIND_REGISTRY` by design — and the
   linter called it an unregistered kind at `ERROR` severity on **23 of 94**
   parameters. A quarter of an operator's first run, all wrong, on the checks
   that exist to be trusted.
4. **`branchId` drafted the collection `**.branchs`.** A glob that matches
   nothing makes reference binding silently never fire for that parameter.

### What this says about reference binding

The collection draft fires on **2 of 60** authority-bearing parameters, and only
after the camelCase fix. Published servers name things `path`, `repo_path`,
`branch_name` and `source` — not `<noun>_id`. Against these servers an operator
must hand-author every `collection`, or reference binding never runs at all.

That is a real qualification of [ADR-0011](DESIGN_DECISIONS.md) and it is worth
stating plainly: the mechanism was measured on AgentDojo, whose environments are
keyed dictionaries with `_id` parameters, and the servers people actually deploy
do not look like that.

### What this does not show

- **Not accuracy.** The labels are ours. Independent ground truth for MCP
  parameter roles does not exist, and inventing it here would measure our
  judgement against itself.
- **Not coverage of tool *output*.** This is schemas only. What fraction of
  authority-bearing values in real MCP *responses* the extractor recognises is
  still unmeasured, and is still the gap listed below.
- **Not a representative sample.** Seven servers, all reference or
  first-party implementations. Servers written against a deadline by people who
  have never read the MCP annotations spec are the interesting case, and are
  not here.

---

## Method notes

- One untimed warm-up call per measurement, so lazily compiled regexes and
  import-time work do not land in the first sample.
- `time.perf_counter()` around each call; p50/p95/p99 from sorted samples.
- Fresh session per measurement group; the observation intake budget is raised
  only so repeated timed observations do not trip it mid-run. That is **not** a
  recommended production setting and the benchmark says so at the call site.
- No result is discarded, no outlier is trimmed, and the raw samples are
  available via `--json`.

## Benchmarks we owe but do not have

1. **Utility under enforcement** — AgentDojo task success with and without the
   monitor. Blocked on model API access. The most important gap in the project.
2. **Security under a real model** — the adversarial suite proves the monitor;
   it does not prove that a real agent plus the monitor resists a real attack
   suite end to end.
3. **Extraction coverage against *real* tool output.** The synthetic study
   above is a floor, not a substitute: it measures our patterns against our own
   idea of the world. What fraction of authority-bearing values in real MCP
   responses are recognised is still unmeasured.
4. **Contract derivation against schemas we did not write.** The corpus above
   is modelled on real servers but labelled by us; running it against a large
   set of published MCP schemas with independent labels is the real test.
5. **`min_reference_word` priced against records with opaque names.** Every
   setting from 4 to 14 returned the same numbers on AgentDojo, whose records
   carry multi-word titles, so the lone-word rule never decided anything. The
   knob is **unpriced**, which is not the same as harmless.
6. **A second benchmark.** Four suites with effect classes and field-path grants
   we authored ourselves is not a population, and optimising further against it
   measures our fit to it rather than the design.
