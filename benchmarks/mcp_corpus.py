#!/usr/bin/env python3
"""Contract drafting against MCP schemas **we did not write**.

Every previous measurement of the deriver used a corpus we authored: schemas
modelled on real servers, labelled by us. That prices the deriver against our
own idea of the world, which [`docs/BENCHMARKS.md`](../docs/BENCHMARKS.md) has
said in as many words since the corpus existed.

This one uses real ``tools/list`` output, captured over stdio from seven
published MCP servers, checked in at ``data/mcp_tools.json`` so the measurement
reproduces without network access. Re-capture it with ``--capture``.

**What this measures and what it does not.** The *schemas* are not ours, so the
shapes, the naming conventions and the annotation habits are real. The *labels*
are still ours -- nobody has published ground truth for which MCP parameters
bear authority -- so this is not an accuracy measurement and is not reported as
one. What it does measure, without any labelling at all:

* **review burden** -- how many parameters a human must check per server, and
  how many the deriver flags as authority-bearing;
* **coverage** -- how many parameters carry a kind the extractor recognises;
* **linter yield** -- what the shipped checks say about drafts from real
  servers, which is the same report an operator gets on day one;
* **annotation prevalence** -- how many real tools volunteer effect hints, and
  in which direction.

Usage:
    python3 benchmarks/mcp_corpus.py
    python3 benchmarks/mcp_corpus.py --json out.json
    python3 benchmarks/mcp_corpus.py --capture     # re-probe live servers
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from idensec import ContractRegistry, Role, derive_contract  # noqa: E402
from idensec.contracts import _WIDENING_ANNOTATIONS  # noqa: E402
from idensec.lint import Severity, lint_contract  # noqa: E402

DATA = Path(__file__).resolve().parent / "data" / "mcp_tools.json"

SERVERS = {
    "everything": ["npx", "-y", "@modelcontextprotocol/server-everything"],
    # The filesystem server needs a root to serve; the schemas it reports do
    # not depend on which one, and nothing here reads or writes through it.
    "filesystem": [
        "npx", "-y", "@modelcontextprotocol/server-filesystem",
        tempfile.gettempdir(),
    ],
    "memory": ["npx", "-y", "@modelcontextprotocol/server-memory"],
    "sequential": ["npx", "-y", "@modelcontextprotocol/server-sequential-thinking"],
    "time": ["uvx", "mcp-server-time"],
    "git": ["uvx", "mcp-server-git", "--repository", str(ROOT)],
    "fetch": ["uvx", "mcp-server-fetch"],
}


def draft(tool: dict) -> tuple:
    schema = tool.get("inputSchema")
    annotations = tool.get("annotations")
    contract = derive_contract(
        tool["name"],
        schema if isinstance(schema, dict) else None,
        description=str(tool.get("description", ""))[:200],
        annotations=annotations if isinstance(annotations, dict) else None,
    )
    return contract, annotations or {}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", type=Path)
    parser.add_argument(
        "--capture",
        action="store_true",
        help="re-probe the live servers and rewrite data/mcp_tools.json",
    )
    args = parser.parse_args()

    if args.capture:
        from mcp_probe import capture

        capture(SERVERS, DATA)

    corpus = json.loads(DATA.read_text(encoding="utf-8"))

    print("contract drafting against MCP schemas we did not write")
    print(f"corpus: {DATA.relative_to(ROOT)}\n")
    print(f"{'server':<12} {'tools':>6} {'params':>7} {'authority':>10} "
          f"{'kinds':>6} {'annot':>6} {'lint≥warn':>10}")
    print("-" * 64)

    totals = Counter()
    hints = Counter()
    findings: Counter = Counter()
    per_server = {}

    for name in sorted(corpus):
        entry = corpus[name]
        tools = entry["tools"]
        registry = ContractRegistry()
        counts = Counter()
        for tool in tools:
            contract, annotations = draft(tool)
            registry.add(contract)
            counts["tools"] += 1
            for spec in contract.parameters.values():
                counts["params"] += 1
                if spec.role is Role.AUTHORITY:
                    counts["authority"] += 1
                    if spec.kinds:
                        counts["kinds"] += 1
                    if spec.collection:
                        counts["collections"] += 1
            if annotations:
                counts["annotated"] += 1
            for hint, value in annotations.items():
                hints[f"{hint}={value}"] += 1
            for diagnostic in lint_contract(contract):
                if diagnostic.severity >= Severity.WARNING:
                    counts["lint"] += 1
                    findings[diagnostic.code] += 1

        print(f"{name:<12} {counts['tools']:>6} {counts['params']:>7} "
              f"{counts['authority']:>10} {counts['kinds']:>6} "
              f"{counts['annotated']:>6} {counts['lint']:>10}")
        totals.update(counts)
        per_server[name] = dict(counts)

    print("-" * 64)
    print(f"{'TOTAL':<12} {totals['tools']:>6} {totals['params']:>7} "
          f"{totals['authority']:>10} {totals['kinds']:>6} "
          f"{totals['annotated']:>6} {totals['lint']:>10}")

    params = max(1, totals["params"])
    authority = max(1, totals["authority"])
    print(
        f"\n{totals['authority']}/{totals['params']} parameters drafted AUTHORITY "
        f"({totals['authority'] / params:.0%}); of those, "
        f"{totals['kinds']}/{totals['authority']} carry a recognised operand kind "
        f"({totals['kinds'] / authority:.0%}) and "
        f"{totals['collections']}/{totals['authority']} an entity collection "
        f"({totals['collections'] / authority:.0%})."
    )

    print("\nannotations volunteered by the servers themselves:")
    for key in sorted(hints):
        believed = ""
        hint = key.split("=")[0]
        if key.endswith("=True") and hint in _WIDENING_ANNOTATIONS:
            believed = "  <- believed: it can only restrict"
        elif hint == "readOnlyHint" and key.endswith("=True"):
            believed = "  <- IGNORED: believing it would only ever permit"
        print(f"  {hints[key]:>3}  {key}{believed}")

    print("\nlint findings at WARNING or above, by code:")
    for code, count in findings.most_common():
        print(f"  {count:>3}  {code}")

    print(
        "\nThe labels are still ours: nobody publishes ground truth for which MCP\n"
        "parameters bear authority, so this is a measurement of review burden,\n"
        "coverage and linter yield on real inputs -- not of accuracy."
    )

    if args.json:
        args.json.write_text(
            json.dumps(
                {
                    "servers": per_server,
                    "totals": dict(totals),
                    "annotations": dict(hints),
                    "lint": dict(findings),
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
