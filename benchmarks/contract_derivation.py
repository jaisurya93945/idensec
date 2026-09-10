#!/usr/bin/env python3
"""Measure how well contracts can be drafted from a tool's own schema.

IDENSEC's answer to the policy-sprawl problem -- reportedly the reason
capability defences went unadopted -- is that nobody should hand-write a
contract for a server they did not build: ``derive_contract()`` drafts one from
the advertised JSON Schema and a human completes it. That is a load-bearing
claim and it has been asserted rather than measured.

The metric that matters is **not** overall accuracy. The two errors are wildly
asymmetric:

* **Dangerous miss** -- a truly authority-bearing parameter drafted as PAYLOAD
  or ADVISORY. If a reviewer does not catch it, the deployment has a silent
  hole. This is the number to minimise, and the linter is the second line of
  defence behind it.
* **Over-restriction** -- a payload parameter drafted as AUTHORITY. Costs
  utility and reviewer attention, costs no security.

A deriver that marked everything AUTHORITY would score a perfect dangerous-miss
rate and be useless, so over-restriction is reported alongside rather than
buried.

Ground truth is **hand-labelled by us** against schemas modelled on real MCP
servers and common APIs. That is a real limitation: it measures the deriver
against our own judgement of what carries authority.

    python3 benchmarks/contract_derivation.py [--json out.json] [--verbose]
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from idensec.contracts import Role, derive_contract

A, P, V = "authority", "payload", "advisory"


@dataclass(frozen=True)
class ToolCase:
    name: str
    schema: dict
    truth: dict[str, str]
    domain: str


def tool(name: str, domain: str, properties: dict, truth: dict[str, str]) -> ToolCase:
    return ToolCase(name, {"type": "object", "properties": properties}, truth, domain)


S = {"type": "string"}
N = {"type": "number"}
I = {"type": "integer"}  # noqa: E741 - matches the JSON Schema vocabulary
B = {"type": "boolean"}

CORPUS: list[ToolCase] = [
    tool("read_file", "filesystem", {"path": S}, {"path": A}),
    tool("write_file", "filesystem", {"path": S, "content": S},
         {"path": A, "content": P}),
    tool("move_file", "filesystem", {"source": S, "destination": S},
         {"source": A, "destination": A}),
    tool("list_directory", "filesystem", {"path": S, "recursive": B},
         {"path": A, "recursive": V}),
    tool("search_files", "filesystem", {"path": S, "pattern": S, "max_results": I},
         {"path": A, "pattern": P, "max_results": V}),
    tool("send_email", "mail", {"to": S, "cc": S, "subject": S, "body": S},
         {"to": A, "cc": A, "subject": P, "body": P}),
    tool("reply_email", "mail", {"message_id": S, "body": S},
         {"message_id": A, "body": P}),
    tool("search_inbox", "mail", {"query": S, "limit": I}, {"query": P, "limit": V}),
    tool("http_request", "web", {"url": S, "method": S, "headers": S, "body": S},
         {"url": A, "method": A, "headers": A, "body": P}),
    tool("fetch_page", "web", {"url": S, "timeout": I}, {"url": A, "timeout": V}),
    tool("post_webhook", "web", {"webhook_url": S, "payload": S},
         {"webhook_url": A, "payload": P}),
    tool("git_clone", "vcs", {"repository": S, "directory": S, "depth": I},
         {"repository": A, "directory": A, "depth": V}),
    tool("git_commit", "vcs", {"message": S, "files": S}, {"message": P, "files": A}),
    tool("git_push", "vcs", {"remote": S, "branch": S, "force": B},
         {"remote": A, "branch": A, "force": A}),
    tool("run_query", "database", {"connection": S, "sql": S, "timeout": I},
         {"connection": A, "sql": A, "timeout": V}),
    tool("insert_row", "database", {"table": S, "values": S},
         {"table": A, "values": P}),
    tool("post_message", "chat", {"channel": S, "text": S, "thread_ts": S},
         {"channel": A, "text": P, "thread_ts": A}),
    tool("create_event", "calendar", {"calendar_id": S, "title": S, "attendees": S,
                                      "start": S, "description": S},
         {"calendar_id": A, "title": P, "attendees": A, "start": A, "description": P}),
    tool("transfer_funds", "payments", {"iban": S, "amount": N, "currency": S,
                                        "reference": S},
         {"iban": A, "amount": A, "currency": A, "reference": P}),
    tool("refund_charge", "payments", {"charge_id": S, "amount": N, "reason": S},
         {"charge_id": A, "amount": A, "reason": P}),
    tool("upload_object", "cloud", {"bucket": S, "key": S, "body": S, "acl": S},
         {"bucket": A, "key": A, "body": P, "acl": A}),
    tool("invoke_function", "cloud", {"function_arn": S, "payload": S},
         {"function_arn": A, "payload": P}),
    tool("run_command", "shell", {"command": S, "cwd": S, "env": S},
         {"command": A, "cwd": A, "env": A}),
    tool("create_ticket", "issues", {"project": S, "title": S, "description": S,
                                     "assignee": S, "priority": S},
         {"project": A, "title": P, "description": P, "assignee": A, "priority": V}),
    tool("summarise", "llm", {"text": S, "max_words": I, "style": S},
         {"text": P, "max_words": V, "style": V}),
]


@dataclass
class Outcome:
    tool: str
    parameter: str
    truth: str
    drafted: str

    @property
    def dangerous(self) -> bool:
        """Authority in truth, not in the draft. The error that leaves a hole."""
        return self.truth == A and self.drafted != A

    @property
    def over_restrictive(self) -> bool:
        return self.truth != A and self.drafted == A

    @property
    def exact(self) -> bool:
        return self.truth == self.drafted


def evaluate() -> list[Outcome]:
    outcomes: list[Outcome] = []
    for case in CORPUS:
        drafted = derive_contract(case.name, case.schema)
        for parameter, truth in case.truth.items():
            role: Role = drafted.parameter(parameter).role
            outcomes.append(Outcome(case.name, parameter, truth, role.value))
    return outcomes


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", type=Path)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    outcomes = evaluate()
    total = len(outcomes)
    authority_truth = [o for o in outcomes if o.truth == A]
    dangerous = [o for o in outcomes if o.dangerous]
    over = [o for o in outcomes if o.over_restrictive]
    exact = sum(1 for o in outcomes if o.exact)

    recall = (len(authority_truth) - len(dangerous)) / len(authority_truth)
    precision = (
        (len(authority_truth) - len(dangerous))
        / max(1, len(authority_truth) - len(dangerous) + len(over))
    )

    print("contract derivation from JSON Schema -- hand-labelled corpus")
    print(f"{len(CORPUS)} tools, {total} parameters, "
          f"{len(authority_truth)} authority-bearing in truth\n")
    print(f"  authority recall      {recall:6.1%}   "
          f"({len(authority_truth) - len(dangerous)}/{len(authority_truth)})")
    print(f"  authority precision   {precision:6.1%}")
    print(f"  exact role match      {exact / total:6.1%}   ({exact}/{total})")
    print(f"\n  DANGEROUS MISSES      {len(dangerous):3d}   authority drafted as "
          "something weaker -- a silent hole if the reviewer misses it")
    print(f"  over-restrictions     {len(over):3d}   costs review effort, not security")

    if dangerous:
        print("\nDANGEROUS MISSES:")
        for o in dangerous:
            print(f"  {o.tool}.{o.parameter}: truth={o.truth} drafted={o.drafted}")
    if over and args.verbose:
        print("\nOVER-RESTRICTIONS:")
        for o in over:
            print(f"  {o.tool}.{o.parameter}: truth={o.truth} drafted={o.drafted}")

    print(
        "\nGround truth is hand-labelled by us against schemas modelled on real "
        "servers.\nThese numbers measure the deriver against our own judgement of "
        "what carries\nauthority, not against a neutral standard."
    )

    if args.json:
        args.json.write_text(
            json.dumps(
                {
                    "tools": len(CORPUS),
                    "parameters": total,
                    "authority_recall": recall,
                    "authority_precision": precision,
                    "exact_role_match": exact / total,
                    "dangerous_misses": [
                        {"tool": o.tool, "parameter": o.parameter, "drafted": o.drafted}
                        for o in dangerous
                    ],
                    "over_restrictions": len(over),
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
