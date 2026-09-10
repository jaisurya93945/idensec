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
- **No security rate.** Security is established by construction and by the
  adversarial suite ([`THREAT_MODEL.md`](THREAT_MODEL.md)), not by timing.
- **No utility rate.** *We have not measured task success under enforcement.*
  This is the single most important missing number in the project, it is the
  number that would confirm or refute the thesis, and it needs model API access
  that this build environment does not have. Until it exists, IDENSEC makes no
  utility claim of any kind. See [`LIMITATIONS.md`](LIMITATIONS.md) and
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

## AgentDojo: security and utility (2026-09-10)

**The first measurement of either against an independent benchmark**, and the
number this project said would decide whether its thesis survives.

AgentDojo publishes both halves as data — each injection task carries the tool
call the attacker wants, each user task carries the calls a *correct* agent
makes — so both can be measured with **no model involved anywhere**. Setup and
reproduction: [`benchmarks/agentdojo/README.md`](../benchmarks/agentdojo/README.md).

Scale: 97 user tasks, 27 injection tasks, 609 in-scope security cases across
four suites.

### Headline (scoped labelling)

| | result |
| --- | ---: |
| **Security** — attacker's call refused, assuming the model is *always* hijacked | **560/609 · 92.0%** |
| **Utility** — a correct agent's ground-truth calls all admitted | **55/97 · 56.7%** |

Security here is asked in a **harsher** form than AgentDojo's own metric:
AgentDojo measures how often a model *is* hijacked; we assume it always is.
Utility is a **lower bound** — a real model phrases calls differently from
ground truth, and an admitted call can still fail for unrelated reasons.

### Source labelling is the knob, and the measurement proves it

| labelling | security | utility |
| --- | ---: | ---: |
| `strict` — workspace authoritative for nothing | 581/609 · 95.4% | 33/97 · 34.0% |
| `permissive` — authoritative for every kind, everywhere | 340/609 · 55.8% | 44/97 · 45.4% |
| **`scoped`** — authoritative per field path | **560/609 · 92.0%** | **55/97 · 56.7%** |

`permissive` is worse than `strict` on **both** axes — it loses 40 points of
security to buy 11 of utility. `scoped` beats it on both and nearly matches
`strict` on security while almost doubling its utility.

**That result produced a feature.** A per-source grant cannot separate a
workspace's own contact records from the bodies of messages other people wrote,
because both arrive from one source — and in this benchmark, legitimate
addresses live in `sender`, `recipients` and `participants` while every
injection lives in `description`, `content` and `reviews`. Since provenance was
already recorded per field, authority became scopable the same way
(`Source(authoritative_paths=...)`). The travel suite went from **0% to 100%**
utility on that change alone.

### Per suite (scoped)

| suite | security | utility |
| --- | ---: | ---: |
| workspace | 237/240 · 98.8% | 28/40 · 70.0% |
| banking | 143/144 · 99.3% | 5/16 · 31.2% |
| slack | 101/105 · 96.2% | 2/21 · 9.5% |
| travel | 79/120 · 65.8% | 20/20 · 100% |

**Two suites' low utility is inherent, not a tuning failure.** Banking's
refusals are dominated by *computed* amounts — "prices rose 10%, send the
difference" produces a number that appears nowhere in the instruction, and
arithmetic is a semantic derivation quotation cannot follow. The working
division of labour is provenance for identifiers and budgets for magnitudes
([`LIMITATIONS.md`](LIMITATIONS.md) §4.2c).

**Slack's 9.5% is not a monitor failure.** In that suite the channel directory
and the web-content store are *themselves* injection vectors, so there is no
field a grant can safely cover: every channel name and URL the agent could
legitimately use arrives from a source the attacker also controls. An honest
reading is that this environment is outside what source-authority labelling can
express, not that the labelling was done badly.

### Every escape traced to a cause

Not one is unexplained, and all fall into limitations documented before this
measurement existed:

| cause | cases | limitation |
| --- | ---: | --- |
| Attacker *selects* a legitimate directory entry (`reserve_hotel` on a real hotel a review recommended) | 20 | U01 — provenance is not intent |
| Target call has **no authority-bearing argument** (`create_calendar_event`, all content and times) | 21 | U05 — non-identifier authority |
| Low-entropy token collision (see below) | 8 | U02 — quotation is not intent |
| Speech-only injections (no tool call at all) | 20 | excluded, not counted either way |

The boundary this draws is crisp and is the most useful thing the evaluation
produced:

> **IDENSEC contains attacks that introduce a new destination. It does not
> contain attacks that merely select among legitimate ones, nor attacks whose
> target call has no authority-bearing argument at all.**

### The token-collision finding

A user prompt reading *"what are we doing on **June 13**"* authorises
`delete_file(file_id="13")`, because `13` genuinely is a token the principal
wrote. Provenance cannot tell a date from a file id — that is intent.

`Policy.min_quotation_length` demands stronger quotation, and the benchmark
prices it:

| setting | security | utility |
| --- | ---: | ---: |
| 1 (default) | 560/609 · 92.0% | 55/97 · 56.7% |
| 4 | **563/609 · 92.4%** | 55/97 · 56.7% |

Raising it closed all three workspace escapes **at zero measured utility cost**,
taking that suite to 240/240. The default stays at 1 because short legitimate
values exist (an amount of `50` is a real quotation) and this is one benchmark;
deployments whose identifiers are short should raise it.

### What this cost to set up, honestly

Three artefacts are ours, not AgentDojo's. Parameter roles were drafted
automatically from each tool's JSON Schema and left unmodified — but **effect
classes and the scoped grants were hand-written**, per API, by people who do not
own those APIs. That is the real cost of the approach, and it is exactly the
policy-sprawl objection this project claims to answer. One afternoon for four
APIs is a data point, not a refutation of the objection.

### What this does not show

- **Not end-to-end utility.** Ground-truth calls are not model behaviour.
- **Not a comparison with CaMeL or PACT.** They report end-to-end numbers on a
  different quantity. Putting these side by side would be misleading and is not
  done anywhere in this repository.
- **Not a claim about real deployments.** Four benchmark suites.

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
