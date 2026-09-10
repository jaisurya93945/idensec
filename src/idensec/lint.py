"""Static checks on tool contracts.

A contract is the one place where a human states something IDENSEC cannot
derive, so a wrong contract is a silent bypass: mark a recipient as ``PAYLOAD``
and the monitor will faithfully allow an attacker to choose it, reporting no
finding, because as far as the engine is concerned nothing authority-bearing
was involved.

Threat model U06 names integrator error as the most likely way a real
deployment fails. That is not pessimism about integrators -- it is how every
policy system fails. This module exists to catch the mistakes that are
mechanically detectable before they reach production.

What it cannot do is decide whether a parameter *really* carries authority in
your system. It reasons from names, types, kinds and effects. Treat a clean
lint as "no known-bad patterns", never as "this contract is correct".
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from enum import IntEnum
from typing import Any

from .contracts import ContractRegistry, Effect, ParameterContract, Role, ToolContract
from .kinds import KIND_REGISTRY
from .labels import Source

__all__ = ["Diagnostic", "Severity", "lint_contract", "lint_registry", "lint_sources"]


class Severity(IntEnum):
    NOTE = 0
    WARNING = 1
    ERROR = 2

    @property
    def label(self) -> str:
        return self.name.lower()


@dataclass(frozen=True, slots=True)
class Diagnostic:
    severity: Severity
    code: str
    tool: str
    message: str
    parameter: str = ""

    def render(self) -> str:
        where = f"{self.tool}.{self.parameter}" if self.parameter else self.tool
        return f"{self.severity.label:<7} {self.code:<24} {where}: {self.message}"

    def to_dict(self) -> dict[str, Any]:
        out = {
            "severity": self.severity.label,
            "code": self.code,
            "tool": self.tool,
            "message": self.message,
        }
        if self.parameter:
            out["parameter"] = self.parameter
        return out


# Parameter names that read as authority-bearing. Matched against whole
# underscore-separated tokens so that "body" does not match "somebody" and
# "to" does not match "topic".
_AUTHORITY_TOKENS = frozenset(
    (
        "to", "recipient", "recipients", "dest", "destination", "target", "targets", "url",
        "uri", "link", "endpoint", "webhook", "callback", "host", "hostname", "domain",
        "server", "address", "addr", "path", "file", "filepath", "filename", "dir",
        "directory", "account", "iban", "card", "wallet", "phone", "msisdn", "command",
        "cmd", "exec", "script", "query_url", "redirect", "return_url", "next_url",
        "bucket", "key_path", "resource", "arn", "channel", "chat_id", "room", "mailbox",
        "cc", "bcc", "reply_to", "from", "sender",
    )
)

_AMOUNT_TOKENS = frozenset(
    ["amount", "total", "price", "value", "quantity", "qty", "sum", "limit_amount", "balance"]
)

_DANGEROUS_EFFECTS = frozenset(
    {
        Effect.WRITE,
        Effect.DELETE,
        Effect.EXECUTE,
        Effect.NETWORK_EGRESS,
        Effect.FINANCIAL,
        Effect.IRREVERSIBLE,
    }
)


def _tokens(name: str) -> set[str]:
    lowered = name.lower()
    parts = {lowered}
    for separator in ("_", "-", "."):
        parts.update(p for p in lowered.split(separator) if p)
    return parts


def _reads_as_authority(name: str) -> bool:
    return bool(_tokens(name) & _AUTHORITY_TOKENS)


def _reads_as_amount(name: str) -> bool:
    return bool(_tokens(name) & _AMOUNT_TOKENS)


def lint_contract(contract: ToolContract) -> list[Diagnostic]:
    """Check one contract for patterns that weaken or void enforcement."""
    found: list[Diagnostic] = []
    tool = contract.tool

    if not contract.effects:
        found.append(
            Diagnostic(
                Severity.ERROR,
                "no-effects-declared",
                tool,
                "no effects declared. This is what a generated draft looks like; "
                "the confidentiality rules key on effects, so an undeclared "
                "egress tool escapes them entirely.",
            )
        )

    if contract.default_role is not Role.AUTHORITY:
        found.append(
            Diagnostic(
                Severity.ERROR,
                "permissive-default-role",
                tool,
                f"default_role is {contract.default_role.value}. Any parameter the "
                "tool gains later, or that this contract forgot, will be unchecked. "
                "The fail-closed default exists precisely for the parameters nobody "
                "thought about.",
            )
        )

    authority_params = [
        name
        for name, spec in contract.parameters.items()
        if spec.role is Role.AUTHORITY
    ]

    if contract.parameters and not authority_params:
        severity = (
            Severity.ERROR
            if contract.effects & _DANGEROUS_EFFECTS
            else Severity.WARNING
        )
        found.append(
            Diagnostic(
                severity,
                "no-authority-parameter",
                tool,
                "no parameter bears authority, so nothing about this call is "
                "attributed. On a tool with "
                f"{sorted(e.value for e in contract.effects) or 'no'} effects that "
                "means an injected agent chooses freely.",
            )
        )

    if contract.can_egress and not authority_params:
        found.append(
            Diagnostic(
                Severity.ERROR,
                "unconstrained-egress",
                tool,
                "can move data outside the trust boundary but has no "
                "authority-bearing parameter, so no destination is ever checked.",
            )
        )

    for name, spec in sorted(contract.parameters.items()):
        found.extend(_lint_parameter(contract, name, spec))

    return found


def _lint_parameter(
    contract: ToolContract, name: str, spec: ParameterContract
) -> list[Diagnostic]:
    tool = contract.tool
    found: list[Diagnostic] = []

    if spec.role is not Role.AUTHORITY and _reads_as_authority(name):
        found.append(
            Diagnostic(
                Severity.ERROR,
                "authority-name-downgraded",
                tool,
                f"named like an authority-bearing parameter but declared "
                f"{spec.role.value}. If it decides where the action lands, an "
                "attacker who controls it is unopposed and no finding is raised.",
                parameter=name,
            )
        )

    if spec.role is not Role.AUTHORITY and _reads_as_amount(name):
        found.append(
            Diagnostic(
                Severity.WARNING,
                "amount-not-authority",
                tool,
                f"reads as a quantity but is declared {spec.role.value}. Amounts "
                "carry authority on financial tools.",
                parameter=name,
            )
        )

    if spec.role is not Role.AUTHORITY and spec.kinds:
        found.append(
            Diagnostic(
                Severity.WARNING,
                "kinds-on-non-authority",
                tool,
                f"declares kinds {sorted(spec.kinds)} but is {spec.role.value}; "
                "kinds only constrain authority-bearing parameters, so this has "
                "no effect and probably means the role is wrong.",
                parameter=name,
            )
        )

    unknown = sorted(k for k in spec.kinds if k not in KIND_REGISTRY)
    if unknown:
        found.append(
            Diagnostic(
                Severity.ERROR,
                "unknown-operand-kind",
                tool,
                f"declares unregistered kinds {unknown}. No value can ever match "
                "them, so every call to this tool fails on kind_mismatch. Register "
                "the kind with register_kind() or fix the spelling.",
                parameter=name,
            )
        )

    if spec.role is Role.AUTHORITY and not spec.kinds:
        found.append(
            Diagnostic(
                Severity.NOTE,
                "authority-without-kinds",
                tool,
                "authority-bearing with no declared kinds, so the whole value must "
                "be attributable. Correct and restrictive; declaring kinds buys "
                "tolerance for formatting such as \"Ana <ana@corp.example>\".",
                parameter=name,
            )
        )

    if spec.role is Role.ADVISORY and (_reads_as_authority(name) or _reads_as_amount(name)):
        found.append(
            Diagnostic(
                Severity.ERROR,
                "advisory-authority-name",
                tool,
                "declared advisory, which skips attribution entirely, despite "
                "reading as a security-relevant parameter.",
                parameter=name,
            )
        )

    return found


def lint_sources(
    sources: Iterable[Source], registry: ContractRegistry
) -> list[Diagnostic]:
    """Cross-check source grants against what contracts actually consume."""
    found: list[Diagnostic] = []
    consumed: set[str] = set()
    for contract in registry:
        for spec in contract.parameters.values():
            if spec.role is Role.AUTHORITY:
                consumed |= set(spec.kinds)

    for source in sources:
        if source.is_principal:
            found.append(
                Diagnostic(
                    Severity.WARNING,
                    "source-trusted-as-principal",
                    source.id,
                    f"labelled {source.trust.name}, which makes it authoritative for "
                    "every operand kind. Reserve that for the principal and the "
                    "operator; a tool at this tier can name any destination it likes.",
                )
            )
        for kind in sorted(source.authoritative_for):
            if kind not in KIND_REGISTRY:
                found.append(
                    Diagnostic(
                        Severity.ERROR,
                        "unknown-operand-kind",
                        source.id,
                        f"granted authority over unregistered kind {kind!r}; the "
                        "grant can never apply.",
                    )
                )
            elif kind not in consumed:
                found.append(
                    Diagnostic(
                        Severity.NOTE,
                        "unused-source-grant",
                        source.id,
                        f"authoritative for {kind!r}, which no contract's "
                        "authority-bearing parameter accepts. Dead grant, or a "
                        "contract that is missing.",
                    )
                )
    return found


def lint_registry(
    registry: ContractRegistry, sources: Sequence[Source] = ()
) -> list[Diagnostic]:
    """Lint every contract, plus source grants when they are supplied."""
    found: list[Diagnostic] = []
    if not len(registry):
        found.append(
            Diagnostic(
                Severity.ERROR,
                "empty-registry",
                "<registry>",
                "no contracts. Every tool will be unknown, and treated as writing, "
                "egressing and irreversible.",
            )
        )
    for contract in registry:
        found.extend(lint_contract(contract))
    found.extend(lint_sources(sources, registry))
    return sorted(found, key=lambda d: (-d.severity, d.tool, d.parameter, d.code))


def render(diagnostics: Sequence[Diagnostic]) -> str:
    if not diagnostics:
        return "no findings"
    lines = [d.render() for d in diagnostics]
    counts: dict[str, int] = {}
    for d in diagnostics:
        counts[d.severity.label] = counts.get(d.severity.label, 0) + 1
    summary = ", ".join(f"{counts[k]} {k}" for k in ("error", "warning", "note") if k in counts)
    lines.append(f"\n{summary}")
    return "\n".join(lines)


def to_json(diagnostics: Sequence[Diagnostic]) -> str:
    return json.dumps([d.to_dict() for d in diagnostics], indent=2)


def main(argv: Sequence[str] | None = None) -> int:
    """``python -m idensec.lint contracts.json [--config proxy.json]``"""
    import argparse
    from pathlib import Path

    parser = argparse.ArgumentParser(
        prog="python -m idensec.lint",
        description="Static checks on tool contracts and source labels.",
        epilog="Exit status is 1 if any error is found. A clean run means 'no "
        "known-bad patterns', never 'this contract is correct'.",
    )
    parser.add_argument("contracts", type=Path, help="contract file to check")
    parser.add_argument(
        "--config",
        type=Path,
        help="proxy config, so source grants can be cross-checked against the "
        "kinds contracts actually consume",
    )
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument(
        "--max-severity",
        choices=[s.label for s in Severity],
        default="error",
        help="lowest severity that fails the run (default: error)",
    )
    args = parser.parse_args(argv)

    try:
        registry = ContractRegistry.load(args.contracts)
    except (OSError, ValueError) as exc:
        print(f"idensec-lint: cannot read {args.contracts}: {exc}")
        return 2

    sources: list[Source] = []
    if args.config is not None:
        from .mcp.config import ConfigError, ProxyConfig

        try:
            sources.append(ProxyConfig.load(args.config).source)
        except ConfigError as exc:
            print(f"idensec-lint: cannot read {args.config}: {exc}")
            return 2

    diagnostics = lint_registry(registry, sources)
    print(to_json(diagnostics) if args.json else render(diagnostics))

    threshold = Severity[args.max_severity.upper()]
    return 1 if any(d.severity >= threshold for d in diagnostics) else 0


if __name__ == "__main__":
    raise SystemExit(main())
