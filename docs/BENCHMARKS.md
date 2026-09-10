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
4. **Contract derivation precision/recall** — how often `derive_contract()`
   drafts the right role for a real schema.
