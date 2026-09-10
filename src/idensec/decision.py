"""Decisions, findings and the failure taxonomy."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from .labels import Attribution
from .policy import Disposition

__all__ = ["AGENT_DENIAL_MESSAGE", "Decision", "Finding", "FindingCode", "Verdict"]

AGENT_DENIAL_MESSAGE = (
    "This action was not permitted. Continue with the parts of the task that do "
    "not require it, or ask the principal for guidance."
)
"""The only thing a denied agent is told (ADR-0009).

Deliberately content-free: no operand, no parameter name, no reason. A verbose
denial hands the attacker both a discriminating oracle and a channel for
returning their own chosen text to the model.
"""


class Verdict(StrEnum):
    ALLOW = "allow"
    ESCALATE = "escalate"
    DENY = "deny"

    @classmethod
    def from_disposition(cls, disposition: Disposition) -> Verdict:
        return cls(disposition.value)

    def worse_of(self, other: Verdict) -> Verdict:
        order = {Verdict.ALLOW: 0, Verdict.ESCALATE: 1, Verdict.DENY: 2}
        return self if order[self] >= order[other] else other


class FindingCode(StrEnum):
    """Why a call was not simply allowed. One code per detectable failure."""

    UNATTRIBUTED_AUTHORITY = "unattributed_authority"
    UNAUTHORISED_AUTHORITY = "unauthorised_authority"
    UNKNOWN_SEAL = "unknown_seal"
    UNKNOWN_TOOL = "unknown_tool"
    KIND_MISMATCH = "kind_mismatch"
    CONFIDENTIAL_EGRESS = "confidential_egress"
    CONFIDENTIAL_CONTEXT_EGRESS = "confidential_context_egress"
    SESSION_HALTED = "session_halted"
    UNDECLARED_PARAMETER = "undeclared_parameter"


@dataclass(frozen=True, slots=True)
class Finding:
    """One reason, tied to one parameter where applicable.

    ``detail`` may contain operand values and source ids. It is audit-only and
    must never be returned to the agent.
    """

    code: FindingCode
    parameter: str = ""
    detail: str = ""
    operand_kind: str = ""
    value: str = ""
    """The rejected operand.

    Recorded because an incident responder's first question is "where was it
    trying to send this", and a log that cannot answer it is not worth keeping.
    Only *authority-bearing* operands land here -- identifiers, destinations,
    paths -- never payload content, which is where confidential data lives.
    """

    attribution: Attribution | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"code": self.code.value}
        if self.parameter:
            out["parameter"] = self.parameter
        if self.operand_kind:
            out["operand_kind"] = self.operand_kind
        if self.value:
            out["value"] = self.value
        if self.detail:
            out["detail"] = self.detail
        if self.attribution is not None:
            out["origins"] = [o.locator() for o in self.attribution.origins]
            out["derivation"] = self.attribution.derivation
        return out


@dataclass(frozen=True, slots=True)
class Decision:
    """The monitor's verdict on one tool call."""

    verdict: Verdict
    tool: str
    step: int
    arguments: Mapping[str, Any] = field(default_factory=dict)
    """Arguments with handles resolved to real values.

    On ALLOW these are what the caller must execute -- **not** the arguments it
    passed in. Executing the original arguments would send unresolved handles
    to the tool. On DENY they are recorded for audit and must not be executed.
    """

    findings: tuple[Finding, ...] = ()
    enforced: bool = True
    """False when the decision was made under an observe-only policy."""

    @property
    def allowed(self) -> bool:
        return self.verdict is Verdict.ALLOW

    @property
    def agent_message(self) -> str:
        """What the agent is told. Never includes finding detail on denial."""
        if self.verdict is Verdict.ALLOW:
            return ""
        if self.verdict is Verdict.ESCALATE:
            return "This action requires approval from the principal before it can proceed."
        return AGENT_DENIAL_MESSAGE

    def reason(self) -> str:
        """Full human-readable explanation. Audit and operators only."""
        if not self.findings:
            return "no findings"
        return "; ".join(
            f"{f.code.value}"
            + (f" on {f.parameter}" if f.parameter else "")
            + (f"={f.value!r}" if f.value else "")
            + (f": {f.detail}" if f.detail else "")
            for f in self.findings
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "tool": self.tool,
            "step": self.step,
            "enforced": self.enforced,
            "findings": [f.to_dict() for f in self.findings],
        }
