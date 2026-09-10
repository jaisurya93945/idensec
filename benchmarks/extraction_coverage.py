#!/usr/bin/env python3
"""Measure how much authority-bearing content extraction actually recognises.

Coverage is a security parameter, not a quality metric. A value IDENSEC does not
recognise is a value it does not seal, which means the model sees it in clear
and can reproduce it verbatim. The unattributed rule still catches that at the
write boundary -- an unsealed untrusted value matches a recorded observation and
is refused -- so a miss is not a bypass. It is a *utility* loss on the legitimate
path and a weakening of defence in depth, and either way it is something we
should know the size of rather than guess at.

Two things are measured:

* **Recall** -- of the authority-bearing values in the corpus, what fraction are
  extracted, and with the right kind.
* **False positives** -- how often ordinary prose is misread as an identifier.
  Over-extraction costs readability, which is what makes sealing usable at all.

The corpus is **synthetic**, hand-written to cover surface forms seen in real
tool output. That is a real limitation and is reported alongside the numbers:
these figures describe our patterns against our own idea of the world, not
against production MCP traffic.

    python3 benchmarks/extraction_coverage.py [--json out.json] [--verbose]
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from idensec.kinds import DEFAULT_KINDS, KIND_REGISTRY, extract


@dataclass(frozen=True)
class Case:
    """One authority value, in context, with the kind it ought to be caught as."""

    kind: str
    value: str
    text: str
    note: str = ""


def case(kind: str, value: str, text: str, note: str = "") -> Case:
    return Case(kind, value, text, note)


CORPUS: list[Case] = [
    # -- email --------------------------------------------------------
    case("email", "bob@corp.example", "Contact bob@corp.example for access."),
    case("email", "Bob.Smith@Corp.Example", "Write to Bob.Smith@Corp.Example today."),
    case("email", "ops+alerts@corp.example", "Route to ops+alerts@corp.example."),
    case("email", "a@b.co", "Short one: a@b.co works."),
    case("email", "bob@mail.eu.corp.example", "Deep: bob@mail.eu.corp.example"),
    case("email", "bob@corp.example", "Display form: Bob Smith <bob@corp.example>"),
    case("email", "bob@corp.example", "As a link: mailto:bob@corp.example"),
    case("email", "bob@corp.example", "In JSON: {\"to\": \"bob@corp.example\"}"),
    case("email", "bob@corp.example", "Trailing: mail bob@corp.example."),
    case("email", "bob@corp.example", "Parenthesised (bob@corp.example) here."),
    # -- url ----------------------------------------------------------
    case("url", "https://corp.example/status", "See https://corp.example/status now."),
    case("url", "http://corp.example", "Old style http://corp.example works."),
    case("url", "https://corp.example:8443/admin", "Port: https://corp.example:8443/admin"),
    case("url", "https://corp.example/a?b=c&d=e", "Query https://corp.example/a?b=c&d=e ok"),
    case("url", "https://corp.example/a#frag", "Fragment https://corp.example/a#frag"),
    case("url", "https://corp.example/docs", "Markdown [docs](https://corp.example/docs)"),
    case("url", "https://corp.example/x", "HTML <a href=\"https://corp.example/x\">x</a>"),
    case(
        "url",
        "https://en.example.org/wiki/Foo_(bar)",
        "Brackets https://en.example.org/wiki/Foo_(bar) end",
    ),
    case("url", "https://corp.example/a", "Sentence end: https://corp.example/a."),
    # -- hostname -----------------------------------------------------
    case("hostname", "api.corp.example", "Host api.corp.example is degraded."),
    case("hostname", "corp.example", "The corp.example zone is fine."),
    case("hostname", "a-b.corp.example", "Dashes a-b.corp.example resolve."),
    # -- paths --------------------------------------------------------
    case("posix_path", "/etc/passwd", "Open /etc/passwd carefully."),
    case("posix_path", "/var/log/app.log", "Tail /var/log/app.log for detail."),
    case("posix_path", "/srv/docs/q3 report.pdf", "Quoted \"/srv/docs/q3 report.pdf\" file",
         "paths containing spaces"),
    case(
        "windows_path",
        "C:\\Users\\ana\\secrets.txt",
        "Read C:\\Users\\ana\\secrets.txt now.",
    ),
    # -- identifiers --------------------------------------------------
    case("uuid", "3f2504e0-4f89-11d3-9a0c-0305e82c3301",
         "Resource 3f2504e0-4f89-11d3-9a0c-0305e82c3301 exists."),
    case("iban", "DE89370400440532013000", "Pay DE89370400440532013000 today."),
    case("account_number", "12345678901234", "Account 12345678901234 is open."),
    case("phone", "+1 555 123 4567", "Call +1 555 123 4567 for support."),
    case("phone", "555-123-4567", "Or 555-123-4567 during hours."),
    # -- forms we expect to be weak on --------------------------------
    case(
        "posix_path",
        "~/.ssh/id_ed25519",
        "Copy ~/.ssh/id_ed25519 somewhere.",
        "home-relative path",
    ),
    case(
        "posix_path",
        "./config/settings.yml",
        "Edit ./config/settings.yml first.",
        "relative path",
    ),
    case(
        "posix_path",
        "../../etc/shadow",
        "Traverse ../../etc/shadow upward.",
        "relative traversal",
    ),
    case(
        "unc_path",
        "\\\\fileserver\\share\\docs",
        "Mount \\\\fileserver\\share\\docs now.",
        "UNC path",
    ),
    case("ipv4", "192.168.1.10", "Connect to 192.168.1.10 directly.", "IPv4 literal"),
    case("ipv4", "10.0.0.1", "Gateway 10.0.0.1 is up.", "IPv4 literal"),
    case(
        "url",
        "s3://backups/2026/q3.tar",
        "Fetch s3://backups/2026/q3.tar please.",
        "non-http scheme",
    ),
    case(
        "url",
        "ftp://files.corp.example/pub",
        "Legacy ftp://files.corp.example/pub",
        "non-http scheme",
    ),
    case(
        "git_remote",
        "git@github.com:acme/repo.git",
        "Clone git@github.com:acme/repo.git now.",
        "scp-style git remote",
    ),
    case(
        "url",
        "postgres://db.corp.example:5432/app",
        "DSN postgres://db.corp.example:5432/app",
        "database DSN",
    ),
    case("crypto_address", "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
         "Send to 0x742d35Cc6634C0532925a3b844Bc454e4438f44e address.", "EVM address"),
    case(
        "arn",
        "arn:aws:s3:::corp-backups",
        "Bucket arn:aws:s3:::corp-backups holds it.",
        "AWS ARN",
    ),
]

# Prose that contains no authority-bearing value. Anything extracted here is a
# false positive, and false positives cost the readability that makes sealing
# usable in the first place.
NEGATIVES: list[str] = [
    "The service degraded at 03:00 UTC and recovered by 05:12 the same morning.",
    "Please review report.txt and main.py before the meeting on Tuesday.",
    "The ratio is 3/4 and the split was 60/40 across both regions.",
    "Version 2.1.4 shipped on 2026-03-15 with 42 fixes.",
    "See section 4.2.1 of the handbook for the escalation policy.",
    "He said i.e. the deploy failed, e.g. because of the config.",
    "Costs rose 12.5% quarter over quarter, from 1.2M to 1.35M.",
    "Run the tests, then the linter, then push. Nothing else.",
    "The file sizes were 1024, 2048 and 4096 bytes respectively.",
    "Meeting notes: agenda.md, minutes.md, actions.md all updated.",
    # Added after broadening the patterns: each targets a new kind's false
    # positive risk directly.
    "Upgrade from 1.2.3.4 to 1.2.4.0 before the freeze.",
    "The build number is 2026.9.10.1 across all artefacts.",
    "Choose and/or decide either way, it is fine.",
    "Scores were 9.8.7.6 in the old scale and nobody liked it.",
    "The C: drive and the D: drive were both nearly full.",
    "Use arn as an abbreviation only in the appendix, not in prose.",
]


@dataclass
class Result:
    case: Case
    extracted: list[tuple[str, str]]

    @property
    def hit(self) -> bool:
        return any(value == self.case.value for _, value in self.extracted)

    @property
    def kind_correct(self) -> bool:
        return any(
            kind == self.case.kind and value == self.case.value
            for kind, value in self.extracted
        )

    @property
    def partial(self) -> bool:
        """Caught something overlapping, but not the whole value.

        Worth separating: a partial catch seals *part* of an identifier, which
        is a different failure from missing it entirely.
        """
        if self.hit:
            return False
        return any(value in self.case.value or self.case.value in value
                   for _, value in self.extracted)


ALL_KINDS = tuple(sorted(KIND_REGISTRY))


def evaluate(kinds) -> tuple[list[Result], list[tuple[str, list[tuple[str, str]]]]]:
    results = [
        Result(c, [(m.kind, m.value) for m in extract(c.text, kinds)]) for c in CORPUS
    ]
    negatives = [
        (text, [(m.kind, m.value) for m in extract(text, kinds)]) for text in NEGATIVES
    ]
    return results, negatives


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", type=Path)
    parser.add_argument("--verbose", action="store_true", help="list every case")
    args = parser.parse_args()

    results, negatives = evaluate(DEFAULT_KINDS)

    by_kind: dict[str, list[Result]] = {}
    for result in results:
        by_kind.setdefault(result.case.kind, []).append(result)

    print("extraction coverage -- synthetic corpus")
    print(f"{len(CORPUS)} authority values, {len(NEGATIVES)} negative prose samples")
    print(f"measured with DEFAULT_KINDS ({len(DEFAULT_KINDS)} kinds)\n")

    print(f"{'kind':<16} {'recall':>8} {'correct kind':>13}   cases")
    print("-" * 60)
    for kind in sorted(by_kind):
        group = by_kind[kind]
        hits = sum(1 for r in group if r.hit)
        correct = sum(1 for r in group if r.kind_correct)
        print(
            f"{kind:<16} {hits}/{len(group):<6} {correct}/{len(group):<11}   "
            f"{100 * hits // len(group)}%"
        )

    total_hits = sum(1 for r in results if r.hit)
    total_correct = sum(1 for r in results if r.kind_correct)
    print("-" * 60)
    print(
        f"{'TOTAL':<16} {total_hits}/{len(results):<6} {total_correct}/{len(results):<11}   "
        f"{100 * total_hits // len(results)}%"
    )

    misses = [r for r in results if not r.hit]
    if misses:
        print(f"\nMISSED ({len(misses)}) -- these values are never sealed:")
        for result in misses:
            note = f"  [{result.case.note}]" if result.case.note else ""
            marker = "partial" if result.partial else "none   "
            print(f"  {marker}  {result.case.kind:<14} {result.case.value!r}{note}")
            if args.verbose and result.extracted:
                print(f"            got: {result.extracted}")

    wrong_kind = [r for r in results if r.hit and not r.kind_correct]
    if wrong_kind:
        print(f"\nWRONG KIND ({len(wrong_kind)}) -- sealed, but matched against the "
              "wrong parameter kinds:")
        for result in wrong_kind:
            got = [k for k, v in result.extracted if v == result.case.value]
            print(f"  {result.case.value!r}: expected {result.case.kind}, got {got}")

    false_positives = [(t, e) for t, e in negatives if e]
    print(f"\nFALSE POSITIVES: {len(false_positives)}/{len(NEGATIVES)} prose samples")
    for text, extracted in false_positives:
        print(f"  {extracted}  in  {text[:58]!r}")

    # The opt-in kinds are measured separately so the cost of enabling them is
    # visible rather than argued about.
    opt_in = [k for k in ALL_KINDS if k not in DEFAULT_KINDS]
    if opt_in:
        full_results, full_negatives = evaluate(ALL_KINDS)
        full_hits = sum(1 for r in full_results if r.hit)
        full_fp = sum(1 for _, e in full_negatives if e)
        print(
            f"\nOPT-IN KINDS {opt_in}: enabling every registered kind raises recall to "
            f"{full_hits}/{len(full_results)} ({100 * full_hits // len(full_results)}%) "
            f"and false positives to {full_fp}/{len(NEGATIVES)}."
        )
        for text, extracted in full_negatives:
            if extracted and not dict(negatives).get(text):
                print(f"  cost: {extracted}  in  {text[:54]!r}")

    if args.json:
        args.json.write_text(
            json.dumps(
                {
                    "corpus": "synthetic",
                    "total": len(results),
                    "recall": total_hits / len(results),
                    "kind_accuracy": total_correct / len(results),
                    "false_positive_samples": len(false_positives),
                    "misses": [
                        {"kind": r.case.kind, "value": r.case.value, "note": r.case.note}
                        for r in misses
                    ],
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
