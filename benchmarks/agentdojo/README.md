# AgentDojo evaluation

Measures IDENSEC's **security and utility** against a published, independent
benchmark — without a model.

## Why this is possible without a model

AgentDojo publishes both halves of the question as data:

* each **injection task** carries `ground_truth()` — the tool call the attacker
  is trying to induce;
* each **user task** carries `ground_truth()` — the calls a *correct* agent makes.

So we can ask two questions directly:

| | question | how |
| --- | --- | --- |
| **security** | if the model is hijacked, does the monitor refuse the attacker's call? | replay the injection's ground truth |
| **utility** | would the monitor have blocked a *correct* agent? | replay the user task's ground truth |

The security question is asked in a **harsher** form than AgentDojo's own
metric. AgentDojo measures how often a model *is* hijacked; we assume it always
is, and ask whether the call is refused anyway.

The utility question is a **lower bound**, not end-to-end utility: a real model
phrases calls differently from ground truth, and a call the monitor admits may
still fail for unrelated reasons.

## Reproducing

```bash
git clone --depth 1 https://github.com/ethz-spylab/agentdojo.git /tmp/agentdojo
python3 -m pip install --target /tmp/adenv \
    "pydantic[email]>=2" pyyaml python-dateutil deepdiff docstring-parser

python3 benchmarks/agentdojo/run_eval.py \
    --agentdojo /tmp/agentdojo/src \
    --deps /tmp/adenv \
    --loader benchmarks/agentdojo \
    [--suite workspace] [--limit 20] [--min-quotation 4] [--json out.json]
```

`load_agentdojo.py` fabricates the model-provider SDKs on demand rather than
installing them. That keeps a large dependency tree out of the way and makes it
structurally obvious that **no model is involved anywhere in this evaluation**.

## What we had to author

Three artefacts are ours, not AgentDojo's, and every result inherits that:

1. **`effects.py`** — effect classes per tool. Effects cannot be read off a
   schema; that is the one inference `derive_contract()` refuses to make, so a
   human declares them, which is what an operator would do. Where a name was
   ambiguous the more dangerous reading was taken.
2. **`SCOPED_GRANTS`** in `run_eval.py` — which *field paths* of the
   environment are authoritative for which operand kinds. Derived by inspecting
   where AgentDojo actually stores addresses and where it actually plants
   injections.
3. **Parameter roles** — drafted automatically by `derive_contract()` from each
   tool's own JSON Schema, unmodified.

Only (3) is automatic. (1) and (2) are per-API work, which is the honest cost of
the approach and is reported as such.

## Labellings

The point of the design is that **source authority is the knob**, so three
settings are measured side by side:

| labelling | the workspace is authoritative for… |
| --- | --- |
| `strict` | nothing |
| `permissive` | every operand kind, everywhere |
| `scoped` | specific kinds under specific field paths |

`scoped` exists because the first two are both wrong, and measuring them is what
showed it: a per-source grant cannot separate a workspace's own contact records
from the bodies of messages other people wrote, and both arrive from one source.

## Reading the output

* `speech-only` — injection tasks with no tool call at all; the attacker's goal
  is to change what the model *says*. An action monitor cannot address speech,
  so these are excluded rather than counted as either successes or failures.
* Escapes and refusals are listed with `--verbose`, which is how every finding
  in [`../../docs/BENCHMARKS.md`](../../docs/BENCHMARKS.md) was traced to a cause.
