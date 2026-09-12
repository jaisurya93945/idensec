#!/usr/bin/env python3
"""What the read boundary actually does to **real MCP tool output**.

The schema corpus measured drafting against servers we did not write. This
measures the other half: what `observe()` does to the JSON those servers
actually return.

Three questions, two of which need no labelling at all:

* **Fidelity.** Sealing must be lossless -- resolving every handle in a sealed
  result must reproduce the original byte for byte. This is a property, not a
  score, and it is checked on every captured response.

  There is exactly one intended exception, and this benchmark found it on its
  first run: untrusted text containing something *shaped like* a handle has that
  shape defused (``[[idn:`` becomes ``[[idn-quoted:``), so attacker content
  cannot masquerade as a reference (threat model T05). Defusals are counted
  separately; anything else is a failure and exits non-zero.
* **Density.** How much of a real response gets replaced by handles. Sealing is
  only usable if prose survives it, and "prose passes through untouched" has
  been an assertion in this repository since the first commit.
* **What is found.** The kind histogram over real output: what a real session
  seals, as opposed to what our synthetic corpus said it would.

Recall -- the fraction of authority-bearing values that *should* have been
sealed and were -- still needs labels, and the labels would be ours. It is
reported for a hand-labelled subset, marked as such, and is the weakest number
here.

## What is captured, and what is deliberately not

Every call is **read-only and local**. Servers are launched by this process; the
filesystem server is pointed at a fixture directory this benchmark writes
itself; nothing reaches a third party. Two deliberate exclusions:

* `fetch` is never called. Its only tool retrieves a URL, which is a request to
  someone else's infrastructure.
* `everything.get-env` is never called, even though it advertises
  `readOnlyHint: true` and would have been the easiest call in the corpus. It
  returns the process environment, and a benchmark that commits its own
  environment to a public repository is a secret-leaking benchmark. That a tool
  can be genuinely read-only and still be the most dangerous one to call is the
  point worth keeping.

Usage:
    python3 benchmarks/mcp_output.py
    python3 benchmarks/mcp_output.py --capture   # re-probe the live servers
    python3 benchmarks/mcp_output.py --json out.json
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from idensec import Sensitivity, Session, Source, Trust  # noqa: E402
from idensec.kinds import DEFAULT_KINDS, extract  # noqa: E402
from idensec.ledger import _SEAL_DECOY, _SEAL_DECOY_REPLACEMENT  # noqa: E402

DATA = Path(__file__).resolve().parent / "data" / "mcp_results.json"
GIT_REVISION = "9e31e7227b67b6c2bb6d187f33467af6567d9ab9"
FIXTURE = Path(__file__).resolve().parent / "data" / "fixture"

FIXTURE_FILES = {
    "onboarding.md": (
        "# Onboarding\n\n"
        "Mail your signed form to ana.ramos@corp.example and cc "
        "payroll@corp.example.\n"
        "The handbook lives at https://intranet.corp.example/handbook/v4 and "
        "the deploy key at ~/.ssh/id_ed25519.\n"
        "Questions: +44 20 7946 0958.\n"
    ),
    "invoice-2291.txt": (
        "Invoice 2291\n"
        "Pay to GB29NWBK60161331926819 at sortcode 60-16-13, account 31926819.\n"
        "Remit by 2026-03-01. Reference ACME-4417.\n"
    ),
    "notes.txt": (
        "Nothing in this file is an identifier. It is three sentences of "
        "ordinary prose about the weather, written so that a sealing pass has "
        "something to leave alone. If any of it comes back changed, the "
        "no-op claim is wrong.\n"
    ),
}


def _fixture() -> Path:
    FIXTURE.mkdir(parents=True, exist_ok=True)
    for name, body in FIXTURE_FILES.items():
        (FIXTURE / name).write_text(body, encoding="utf-8")
    return FIXTURE


def _servers() -> dict:
    fixture = str(_fixture())
    return {
        "filesystem": {
            "argv": [
                "npx", "-y", "@modelcontextprotocol/server-filesystem", fixture,
            ],
            "calls": [
                ("list_directory", {"path": fixture}),
                ("directory_tree", {"path": fixture}),
                ("read_text_file", {"path": f"{fixture}/onboarding.md"}),
                ("read_text_file", {"path": f"{fixture}/invoice-2291.txt"}),
                ("read_text_file", {"path": f"{fixture}/notes.txt"}),
                ("get_file_info", {"path": f"{fixture}/onboarding.md"}),
                ("search_files", {"path": fixture, "pattern": "*.txt"}),
                ("list_allowed_directories", {}),
            ],
        },
        "git": {
            "argv": ["uvx", "mcp-server-git", "--repository", str(ROOT)],
            "calls": [
                ("git_status", {"repo_path": str(ROOT)}),
                ("git_log", {"repo_path": str(ROOT), "max_count": 5}),
                ("git_branch", {"repo_path": str(ROOT), "branch_type": "local"}),
                # Pinned, not HEAD. A corpus whose content changes with every
                # commit is not a fixture, and this revision was chosen because
                # its diff is code-heavy *and* contains six occurrences of this
                # project's own handle syntax -- which is what exercises the
                # decoy-defusing path at the read boundary.
                ("git_show", {"repo_path": str(ROOT), "revision": GIT_REVISION}),
            ],
        },
        "time": {
            "argv": ["uvx", "mcp-server-time"],
            "calls": [
                ("get_current_time", {"timezone": "UTC"}),
                ("convert_time", {
                    "source_timezone": "UTC",
                    "time": "12:00",
                    "target_timezone": "America/New_York",
                }),
            ],
        },
        "memory": {
            "argv": ["npx", "-y", "@modelcontextprotocol/server-memory"],
            "calls": [
                ("create_entities", {"entities": [{
                    "name": "ana.ramos@corp.example",
                    "entityType": "person",
                    "observations": ["owns https://intranet.corp.example/handbook/v4"],
                }]}),
                ("read_graph", {}),
                ("search_nodes", {"query": "person"}),
            ],
        },
        "everything": {
            # get-env is excluded on purpose -- see the module docstring.
            "argv": ["npx", "-y", "@modelcontextprotocol/server-everything"],
            "calls": [
                ("echo", {"message": "mail ana.ramos@corp.example about ACME-4417"}),
                ("get-sum", {"a": 2, "b": 3}),
                ("get-structured-content", {"location": "London"}),
                ("get-resource-links", {"count": 3}),
                ("get-annotated-message", {"messageType": "success"}),
            ],
        },
        "sequential": {
            "argv": [
                "npx", "-y", "@modelcontextprotocol/server-sequential-thinking",
            ],
            "calls": [
                ("sequentialthinking", {
                    "thought": "Check whether ana.ramos@corp.example signed.",
                    "thoughtNumber": 1,
                    "totalThoughts": 1,
                    "nextThoughtNeeded": False,
                }),
            ],
        },
    }


def capture(target: Path) -> None:
    from mcp_probe import probe

    captured = {}
    for name, spec in _servers().items():
        try:
            result = probe(spec["argv"], calls=spec["calls"])
        except OSError as exc:
            print(f"  {name}: {exc}")
            continue
        if result and result.get("results"):
            captured[name] = {
                "server": result["server"],
                "results": result["results"],
            }
            print(f"  {name}: {len(result['results'])} responses")
        else:
            print(f"  {name}: no responses")
    if not captured:
        raise SystemExit("captured nothing; refusing to overwrite the corpus")
    target.write_text(
        json.dumps(captured, indent=1, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"wrote {target}")


def _texts(node) -> list[str]:
    """Every string leaf of a captured response."""
    if isinstance(node, str):
        return [node]
    if isinstance(node, dict):
        return [t for value in node.values() for t in _texts(value)]
    if isinstance(node, list):
        return [t for value in node for t in _texts(value)]
    return []


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", type=Path)
    parser.add_argument("--capture", action="store_true")
    args = parser.parse_args()

    if args.capture:
        capture(DATA)

    corpus = json.loads(DATA.read_text(encoding="utf-8"))

    print("the read boundary against real MCP tool output")
    print(f"corpus: {DATA.relative_to(ROOT)}\n")
    print(f"{'server':<12} {'calls':>6} {'chars':>9} {'sealed':>7} "
          f"{'density':>8} {'lossless':>9} {'defused':>8}")
    print("-" * 65)

    kinds: Counter = Counter()
    totals = Counter()
    per_server = {}
    damaged: list[str] = []

    for name in sorted(corpus):
        entry = corpus[name]
        counts = Counter()
        for call in entry["results"]:
            payload = call.get("result")
            if payload is None:
                continue
            counts["calls"] += 1
            session = Session(
                sources=[Source("srv", Trust.TOOL_UNTRUSTED, Sensitivity.INTERNAL)],
                max_observed_chars=64_000_000,
            )
            sealed = session.observe("srv", payload)
            for text in _texts(payload):
                counts["chars"] += len(text)
                for match in extract(text, DEFAULT_KINDS):
                    kinds[match.kind] += 1
                    counts["operands"] += 1
                    counts["sealed_chars"] += match.end - match.start
            # Fidelity: resolving the sealed form must reproduce the original,
            # up to the one rewrite the read boundary makes deliberately.
            for original, out in zip(
                _texts(payload), _texts(sealed), strict=False
            ):
                restored = session.ledger.resolve(out).text
                if restored == original:
                    continue
                defused = _SEAL_DECOY.sub(_SEAL_DECOY_REPLACEMENT, original)
                if restored == defused:
                    counts["defused"] += 1
                    continue
                damaged.append(f"{name}.{call['tool']}")
                counts["damaged"] += 1
        chars = max(1, counts["chars"])
        print(f"{name:<12} {counts['calls']:>6} {counts['chars']:>9} "
              f"{counts['operands']:>7} {counts['sealed_chars'] / chars:>7.1%} "
              f"{'yes' if not counts['damaged'] else 'NO':>9} "
              f"{counts['defused']:>8}")
        totals.update(counts)
        per_server[name] = dict(counts)

    print("-" * 65)
    chars = max(1, totals["chars"])
    print(f"{'TOTAL':<12} {totals['calls']:>6} {totals['chars']:>9} "
          f"{totals['operands']:>7} {totals['sealed_chars'] / chars:>7.1%} "
          f"{'yes' if not damaged else 'NO':>9} {totals['defused']:>8}")

    print("\nkinds found in real tool output:")
    for kind, count in kinds.most_common():
        print(f"  {count:>4}  {kind}")
    if not kinds:
        print("  (none)")

    print(
        f"\nSealing replaced {totals['sealed_chars']} of {totals['chars']} "
        f"characters ({totals['sealed_chars'] / chars:.1%}). Everything else "
        "passed through unchanged."
    )
    if totals["defused"]:
        print(
            f"\n{totals['defused']} response(s) contained handle-shaped text and "
            "had that shape defused. That is threat model T05 working, not\n"
            "damage: this repository documents its own handle syntax, so a "
            "`git show` of it is the most natural source of decoys there is."
        )
    if damaged:
        print(f"\nFIDELITY FAILURES ({len(damaged)}): {damaged[:10]}")

    if args.json:
        args.json.write_text(
            json.dumps(
                {
                    "servers": per_server,
                    "totals": dict(totals),
                    "kinds": dict(kinds),
                    "fidelity_failures": damaged,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
    return 1 if damaged else 0


if __name__ == "__main__":
    raise SystemExit(main())
