#!/usr/bin/env python3
"""What a field-path grant actually admits, against real MCP output.

``authoritative_paths`` is the setting that makes retrieve-then-act work and the
setting an operator can least check. This measures its surface: for a given
grant, how many of the values a real server emitted would become authoritative.

Run against the checked-in corpus of responses captured from published servers
(``benchmarks/data/mcp_results.json``), so it reproduces offline.

    python3 benchmarks/grant_surface.py
    python3 benchmarks/grant_surface.py --json surface.json

The number this exists to publish is not a score. It is the gap between what a
grant *looks* like it says and what it *does*, and on one real server that gap
is two orders of magnitude.

**A lower bound, twice over.** Candidates are single tokens and recognised
operands, so multi-token quotations are not counted; and the corpus is what six
servers happened to return on a handful of calls, not their whole surface.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from idensec.labels import Sensitivity, Source, Trust
from idensec.policy import Policy
from idensec.preview import preview_grants

DATA = Path(__file__).resolve().parent / "data" / "mcp_results.json"

PATHY = ("posix_path", "unclassified")

SHAPES: tuple[tuple[str, str, dict[str, tuple[str, ...]]], ...] = (
    (
        "kind-scoped",
        "one tool, recognised paths only",
        {"git_status.**": ("posix_path",)},
    ),
    (
        "tool-scoped",
        "one tool, any token it emits",
        {"git_status.**": PATHY},
    ),
    (
        "blanket",
        "every tool, any token it emits",
        {"**": PATHY},
    ),
)


def _calls(server: str) -> list[tuple[str, Any]]:
    data = json.loads(DATA.read_text(encoding="utf-8"))[server]
    return [
        (record["tool"], record["result"])
        for record in data["results"]
        if record.get("result") and not record.get("error")
    ]


def _source(paths: dict[str, tuple[str, ...]]) -> Source:
    return Source(
        id="server",
        trust=Trust.TOOL_UNTRUSTED,
        sensitivity=Sensitivity.INTERNAL,
        authoritative_paths=tuple(
            (prefix, frozenset(kinds)) for prefix, kinds in paths.items()
        ),
    )


FLOORS = (1, 3)
"""``min_quotation_length`` settings to price the shapes at.

1 is the shipped default; 3 is what the shipped examples use. The floor decides
how short a token may be and still count as a quotation, so it bounds the same
surface from the other side, and reporting a grant's size without saying which
floor produced it would be meaningless.
"""


def measure(server: str) -> dict[str, Any]:
    calls = _calls(server)
    rows = []
    for name, note, paths in SHAPES:
        at_floor = {}
        for floor in FLOORS:
            preview = preview_grants(
                _source(paths), calls, policy=Policy(min_quotation_length=floor)
            )
            words = sorted({a.value for a in preview.admissions if a.value.isalpha()})
            at_floor[floor] = {
                "admitted": len(preview.admissions),
                "candidates": preview.candidates,
                "bare_words": len(words),
                "inert": list(preview.inert_grants),
                "sample_words": words[:8],
            }
        rows.append({
            "shape": name,
            "note": note,
            "grant": {k: list(v) for k, v in paths.items()},
            "floors": at_floor,
        })
    return {"server": server, "calls": len(calls), "shapes": rows}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", default="git", help="corpus server key")
    parser.add_argument("--json", type=Path, help="write machine-readable results")
    args = parser.parse_args()

    report = measure(args.server)
    print(
        f"grant surface on {report['server']!r}, "
        f"{report['calls']} captured call(s)\n"
    )
    head = "  ".join(f"{'floor ' + str(f):>12}" for f in FLOORS)
    print(f"  {'shape':<12}  {head}   note")
    for row in report["shapes"]:
        cells = []
        for floor in FLOORS:
            cell = row["floors"][floor]
            share = cell["admitted"] / cell["candidates"] if cell["candidates"] else 0.0
            cells.append(f"{cell['admitted']:>6} ({share:>3.0%})")
        print(f"  {row['shape']:<12}  " + "  ".join(cells) + f"   {row['note']}")
    print("\n  values admitted, of every token the corpus contains\n")
    for row in report["shapes"]:
        cell = row["floors"][FLOORS[-1]]
        if cell["inert"]:
            print(
                f"  {row['shape']}: admitted nothing at all. A grant that cannot be\n"
                f"  demonstrated against real output has not been reviewed, and this\n"
                f"  one fails closed silently -- the operator believes they configured\n"
                f"  something."
            )
        elif cell["bare_words"]:
            print(
                f"  {row['shape']}: {cell['bare_words']} of the admitted values are "
                f"bare words from the\n  tool's own prose -- "
                + ", ".join(repr(w) for w in cell["sample_words"][:5])
                + "."
            )
    print(
        "\n  An `unclassified` grant does not grant authority over the identifiers a\n"
        "  tool returns. It grants authority over every token the tool emits, its\n"
        "  prose and the MCP envelope included. Nothing in the policy file says so,\n"
        "  which is U08: run `python -m idensec.preview` before trusting one."
    )

    if args.json:
        args.json.write_text(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
