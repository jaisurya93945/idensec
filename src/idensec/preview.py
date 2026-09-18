"""Show what a field-path grant would make authoritative, before enforcing it.

``authoritative_paths`` is the setting that makes retrieve-then-act work, and it
is the setting an operator has the least ability to check. Granting
``**.sender`` asserts that the values appearing under that path are ones the
principal would endorse — and whether that holds is decided by data nobody has
looked at. :mod:`idensec.lint` cannot help: at lint time there is no data. The
audit log can, but only after the call.

Measured consequence, recorded as U08: on ``mcp-server-git`` a grant over
``git_status.**`` correctly refuses an injected ``git_add .env`` — because
``.gitignore`` keeps ``.env`` out of ``git_status``. Against a repository
without that line the same grant stages a deploy token. Same policy, same
tools, no diff.

This module closes part of that gap by moving the observation earlier. Given a
source's grants and a corpus of real tool output, it reports **every value the
grants would make authoritative**. The operator reads the list and sees
``.env``, or an address from a message body, or a URL from a comment.

That is detection, not containment, and it should be read that way. The
alternative — letting a grant declare the operand *shape* it expects and refuse
a surprise — was considered and is not built, because it does not work on the
case that motivates it: the expected shape under ``git_status`` is *a
repo-relative path*, and ``.env`` is a repo-relative path. What separates the
secret from the changelog is sensitivity, which is semantic, and a semantic
check with an attacker-searchable error rate is a classifier. This project does
not ship one (:doc:`ROADMAP`, *Not planned*).

**How it decides.** By running the real engine. The preview builds a
:class:`~idensec.monitor.Session` with the configured source, observes the
corpus through the ordinary read boundary, and then asks
:meth:`~idensec.monitor.Session.admit` about each candidate value. A parallel
reimplementation of the authority check would be free to drift from the one
that enforces, and a preview that disagrees with enforcement is worse than no
preview.

**The principal is given no words.** A real session would admit many of these
values by quotation, because the principal named them. That is not the
question. The question is what the *grant* contributes, so the corpus is
observed against a session whose principal said nothing, and everything
reported is admitted by the grant alone.

**The report is a lower bound.** Candidates are the recognised operands plus
the single tokens of observed text. Multi-token phrases are quotable too
(``"Q3 budget"`` is a quotation), and enumerating every phrase is not
tractable. A grant's real surface is therefore at least as large as what is
printed here, never smaller.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from .contracts import Effect, ParameterContract, Role, ToolContract
from .decision import Verdict
from .kinds import DEFAULT_KINDS, UNCLASSIFIED, classify
from .labels import Source
from .monitor import Session
from .policy import Policy

__all__ = ["Admission", "Preview", "main", "preview_grants"]

_PROBE_TOOL = "__idensec_preview__"

_TOKEN = re.compile(r"[A-Za-z0-9_.@/:+%\\-]+")
"""Maximal runs of the ledger's identifier alphabet.

Kept in step with ``ledger._TOKEN_CHARS`` deliberately: a value is quotable only
when it is delimited by characters outside that set, so anything the ledger
would match as a whole token appears here as a candidate.
"""


@dataclass(frozen=True, slots=True)
class Admission:
    """One value a grant would make authoritative, and where it came from."""

    value: str
    kind: str
    grant: str
    tool: str
    occurrences: int

    def line(self) -> str:
        return f"{self.kind:<14} {self.value!r} ({self.occurrences}x)"


@dataclass(frozen=True, slots=True)
class Preview:
    source_id: str
    admissions: tuple[Admission, ...]
    candidates: int
    calls: int
    inert_grants: tuple[str, ...]
    """Grant patterns that admitted nothing in this corpus.

    Not necessarily a defect -- the corpus may simply not exercise the path --
    but a grant nobody can demonstrate against real output is a grant nobody
    has reviewed.
    """

    @property
    def kinds(self) -> Counter[str]:
        return Counter(a.kind for a in self.admissions)

    def report(self, *, limit: int = 30) -> str:
        lines = [
            f"source {self.source_id!r}: {len(self.admissions)} of "
            f"{self.candidates} candidate values would carry authority, "
            f"from {self.calls} captured call(s)"
        ]
        grouped: dict[tuple[str, str], list[Admission]] = {}
        for admission in self.admissions:
            grouped.setdefault((admission.grant, admission.tool), []).append(admission)
        for grant, tool in sorted(grouped):
            entries = sorted(grouped[(grant, tool)], key=lambda a: (-a.occurrences, a.value))
            lines.append(f"\n  grant {grant}  <-  {tool} ({len(entries)} values)")
            for entry in entries[:limit]:
                lines.append(f"    {entry.line()}")
            if len(entries) > limit:
                lines.append(f"    ... and {len(entries) - limit} more")
        if not self.admissions:
            lines.append("  nothing in this corpus becomes authoritative")
        if self.inert_grants:
            lines.append(
                "\n  admitted nothing in this corpus: " + ", ".join(self.inert_grants)
            )
        lines.append(
            "\n  A lower bound: single tokens and recognised operands only. "
            "Multi-token\n  phrases are quotable too, so the real surface is at "
            "least this large."
        )
        return "\n".join(lines)


def _strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _strings(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _strings(item)


def _candidates(text: str, minimum: int) -> set[str]:
    return {t for t in _TOKEN.findall(text) if len(t) >= minimum}


def preview_grants(
    source: Source,
    calls: Sequence[tuple[str, Any]],
    *,
    policy: Policy | None = None,
    kinds: Sequence[str] | None = None,
) -> Preview:
    """Report every value ``source``'s grants would make authoritative.

    ``calls`` is a sequence of ``(tool_name, result)`` pairs as captured from a
    real server; ``result`` is the JSON-RPC ``result`` object.

    Each grant is probed **alone, against one tool's output at a time**, in its
    own session. That is not an optimisation, it is the only way the answer can
    name a cause: a value present in two tools' output is authorised by whichever
    grant covers either of them, and a report that pooled them would credit the
    wrong one. An earlier version of this function pooled them and did exactly
    that -- listing values as arriving "via git_log" when the path that
    authorised them was ``git_status``.
    """
    policy = _unbounded(policy or Policy())
    kind_tuple = tuple(kinds or DEFAULT_KINDS)
    minimum = policy.min_quotation_length

    by_tool: dict[str, list[Any]] = {}
    candidates: dict[str, Counter[str]] = {}
    for tool, result in calls:
        by_tool.setdefault(tool, []).append(result)
        counter = candidates.setdefault(tool, Counter())
        for text in _strings(result):
            for candidate in _candidates(text, minimum):
                counter[candidate] += 1
    total = sum(len(c) for c in candidates.values())

    grants: list[tuple[str, Source]] = []
    if source.authoritative_for:
        grants.append(("(whole source)", replace(source, authoritative_paths=())))
    for pattern, allowed in source.authoritative_paths:
        grants.append((
            pattern,
            replace(
                source,
                authoritative_for=frozenset(),
                authoritative_paths=((pattern, allowed),),
            ),
        ))

    admissions: list[Admission] = []
    for label, scoped in grants:
        for tool in sorted(by_tool):
            session = _probe_session(scoped, policy, kind_tuple)
            for result in by_tool[tool]:
                session.observe(scoped.id, result, path=f"{tool}.result")
            for value, count in candidates[tool].items():
                if session.admit(_PROBE_TOOL, {"value": value}).verdict is not Verdict.ALLOW:
                    continue
                admissions.append(
                    Admission(
                        value=value,
                        kind=classify(value, kind_tuple) or UNCLASSIFIED,
                        grant=label,
                        tool=tool,
                        occurrences=count,
                    )
                )

    demonstrated = {a.grant for a in admissions}
    inert = tuple(label for label, _ in grants if label not in demonstrated)
    return Preview(
        source_id=source.id,
        admissions=tuple(admissions),
        candidates=total,
        calls=len(calls),
        inert_grants=inert,
    )


def _probe_session(source: Source, policy: Policy, kinds: tuple[str, ...]) -> Session:
    probe = ToolContract(
        tool=_PROBE_TOOL,
        effects=frozenset({Effect.READ}),
        # No declared kinds: let the engine classify the value and check the
        # grant against whatever kind it really is, exactly as in enforcement.
        parameters={"value": ParameterContract(name="value", role=Role.AUTHORITY)},
    )
    return Session(contracts=[probe], policy=policy, sources=[source], kinds=kinds)


def _unbounded(policy: Policy) -> Policy:
    """The preview denies far more than it admits, by construction.

    An offline reporting tool, not a session. This is not a production setting.
    """
    return replace(policy, denial_budget=-1)


def _load_calls(path: Path, server: str) -> list[tuple[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict) and "results" not in data:
        if not server:
            raise SystemExit(
                f"{path} holds several servers ({', '.join(sorted(data))}); "
                "pass --server"
            )
        if server not in data:
            raise SystemExit(f"{path} has no server {server!r}")
        data = data[server]
    records = data["results"] if isinstance(data, dict) else data
    calls = []
    for record in records:
        result = record.get("result")
        if record.get("error") or result is None:
            continue
        calls.append((record["tool"], result))
    return calls


def _source_from_config(path: Path) -> tuple[Source, Policy, tuple[str, ...] | None]:
    from .mcp.config import ProxyConfig

    config = ProxyConfig.load(path)
    return config.source, config.policy, None


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m idensec.preview",
        description=(
            "Report every value a source's authoritative_paths would make "
            "authoritative, against a corpus of real tool output."
        ),
    )
    parser.add_argument("--config", required=True, type=Path, help="proxy config JSON")
    parser.add_argument(
        "--corpus", required=True, type=Path, help="captured tool results JSON"
    )
    parser.add_argument(
        "--server", default="", help="server key, when the corpus holds several"
    )
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--limit", type=int, default=30, help="values shown per tool")
    args = parser.parse_args(argv)

    source, policy, kinds = _source_from_config(args.config)
    calls = _load_calls(args.corpus, args.server)
    result = preview_grants(source, calls, policy=policy, kinds=kinds)

    if args.json:
        print(
            json.dumps(
                {
                    "source": result.source_id,
                    "calls": result.calls,
                    "candidates": result.candidates,
                    "inert_grants": list(result.inert_grants),
                    "kinds": dict(result.kinds),
                    "admissions": [
                        {
                            "value": a.value,
                            "kind": a.kind,
                            "grant": a.grant,
                            "tool": a.tool,
                            "occurrences": a.occurrences,
                        }
                        for a in result.admissions
                    ],
                },
                indent=2,
                sort_keys=True,
            )
        )
    else:
        print(result.report(limit=args.limit))
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry
    sys.exit(main())
