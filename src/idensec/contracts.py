"""Tool authority contracts.

A contract states, once per tool interface, two things a runtime cannot safely
guess per call:

* **Which parameters bear authority.** ``sendEmail(to, subject, body)`` -- ``to``
  decides where the action lands, ``body`` decides what it says. That is a
  static fact about the interface, true of every invocation that will ever
  exist. PACT's ablation attributes much of its deployed utility loss to asking
  a model to re-derive facts like this on every call (ADR-0004).

* **What the tool does to the world.** Effect classes drive the confidentiality
  rules: a tool that can move bytes outside the trust boundary is the sink that
  matters for exfiltration.

Contracts are **data, not code**. Policy-as-code per tool is the approach whose
policy sprawl is the reported cause of zero production adoption for capability
defences; code cannot be shared across organisations, diffed usefully, reviewed
in bulk, or signed as a corpus. A contract is a dict, so it can be all of those.

Everything here fails closed. An undeclared parameter is ``AUTHORITY``. An
unknown tool has no contract and the monitor refuses it.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

from .kinds import UNCLASSIFIED

__all__ = [
    "ContractRegistry",
    "Effect",
    "ParameterContract",
    "Role",
    "ToolContract",
    "derive_contract",
]


def _as_frozenset(value: object) -> frozenset[str]:
    """Normalise a caller-supplied collection of operand kind names."""
    if isinstance(value, frozenset):
        return value
    if isinstance(value, (set, list, tuple)):
        return frozenset(str(item) for item in value)
    raise TypeError(f"expected a collection of operand kind names, got {type(value).__name__}")


class Role(StrEnum):
    """What a parameter's value is allowed to determine."""

    AUTHORITY = "authority"
    """The value determines what the action does to the world: a recipient, a
    destination, a path, an account, a command. Must be positively attributed
    to a source authorised for that kind of value."""

    PAYLOAD = "payload"
    """The value is content carried by the action: a body, a message, a
    description. May be derived from untrusted data -- that is the point of a
    retrieve-then-act workflow -- but it taints the call for confidentiality
    purposes."""

    ADVISORY = "advisory"
    """The value affects presentation or non-security behaviour: a page size, a
    sort order, a verbosity flag. Declared explicitly so that choosing it is a
    visible decision rather than an omission."""


class Effect(StrEnum):
    """What a tool can do. Sets, not tiers -- a tool can be several at once."""

    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    EXECUTE = "execute"
    NETWORK_EGRESS = "network_egress"
    """Can move bytes outside the trust boundary. The exfiltration sink."""
    FINANCIAL = "financial"
    IRREVERSIBLE = "irreversible"


@dataclass(frozen=True, slots=True)
class ParameterContract:
    """Declared semantics of one parameter."""

    name: str
    role: Role
    kinds: frozenset[str] = field(default_factory=frozenset)
    """Operand kinds this parameter is expected to hold. Empty means "any".

    Narrowing it is a real control: declaring ``to`` as ``{"email"}`` means a
    source authoritative only for ``uuid`` cannot fill it.
    """
    description: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "kinds", _as_frozenset(self.kinds))
        object.__setattr__(self, "role", Role(str(self.role)))

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"role": self.role.value}
        if self.kinds:
            out["kinds"] = sorted(self.kinds)
        if self.description:
            out["description"] = self.description
        return out


@dataclass(frozen=True, slots=True)
class ToolContract:
    """Declared authority semantics of one tool."""

    tool: str
    parameters: Mapping[str, ParameterContract] = field(default_factory=dict)
    effects: frozenset[Effect] = field(default_factory=frozenset)
    default_role: Role = Role.AUTHORITY
    """Applied to parameters absent from ``parameters``. Defaults to the
    restrictive choice: an undeclared parameter is assumed to carry authority."""
    version: int = 1
    description: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "effects", frozenset(Effect(e) for e in self.effects))
        object.__setattr__(self, "parameters", dict(self.parameters))
        object.__setattr__(self, "default_role", Role(str(self.default_role)))

    def parameter(self, name: str) -> ParameterContract:
        declared = self.parameters.get(name)
        if declared is not None:
            return declared
        return ParameterContract(name=name, role=self.default_role)

    @property
    def can_egress(self) -> bool:
        return Effect.NETWORK_EGRESS in self.effects

    @property
    def is_consequential(self) -> bool:
        return bool(
            self.effects
            & {
                Effect.WRITE,
                Effect.DELETE,
                Effect.EXECUTE,
                Effect.NETWORK_EGRESS,
                Effect.FINANCIAL,
                Effect.IRREVERSIBLE,
            }
        )

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "tool": self.tool,
            "version": self.version,
            "effects": sorted(e.value for e in self.effects),
            "default_role": self.default_role.value,
            "parameters": {
                name: pc.to_dict() for name, pc in sorted(self.parameters.items())
            },
        }
        if self.description:
            out["description"] = self.description
        return out

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ToolContract:
        params = {
            name: ParameterContract(
                name=name,
                role=Role(spec["role"]),
                kinds=frozenset(spec.get("kinds", ())),
                description=spec.get("description", ""),
            )
            for name, spec in data.get("parameters", {}).items()
        }
        return cls(
            tool=data["tool"],
            parameters=params,
            effects=frozenset(Effect(e) for e in data.get("effects", ())),
            default_role=Role(data.get("default_role", Role.AUTHORITY.value)),
            version=int(data.get("version", 1)),
            description=data.get("description", ""),
        )


class ContractRegistry:
    """A lookup from tool name to contract.

    Deliberately has no fallback. ``get`` returns ``None`` for an unknown tool
    and the monitor decides what that means, because "we have never seen this
    tool" is a policy question, not a data-structure question.
    """

    def __init__(self, contracts: Iterable[ToolContract] = ()) -> None:
        self._contracts: dict[str, ToolContract] = {}
        for contract in contracts:
            self.add(contract)

    def add(self, contract: ToolContract) -> ToolContract:
        self._contracts[contract.tool] = contract
        return contract

    def get(self, tool: str) -> ToolContract | None:
        return self._contracts.get(tool)

    def __contains__(self, tool: object) -> bool:
        return tool in self._contracts

    def __iter__(self) -> Iterator[ToolContract]:
        yield from sorted(self._contracts.values(), key=lambda c: c.tool)

    def __len__(self) -> int:
        return len(self._contracts)

    # -- serialisation ---------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": "idensec.contracts/v1",
            "contracts": [c.to_dict() for c in self],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ContractRegistry:
        schema = data.get("schema")
        if schema != "idensec.contracts/v1":
            raise ValueError(f"unsupported contract schema: {schema!r}")
        return cls(ToolContract.from_dict(c) for c in data.get("contracts", ()))

    @classmethod
    def load(cls, path: str | Path) -> ContractRegistry:
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))

    def dump(self, path: str | Path) -> None:
        Path(path).write_text(
            json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )


# --------------------------------------------------------------------------
# Draft generation
# --------------------------------------------------------------------------

_PAYLOAD_HINTS = (
    "body",
    "content",
    "text",
    "message",
    "subject",
    "description",
    "summary",
    "note",
    "comment",
    "caption",
    "title",
    "prompt",
    "markdown",
    "html_body",
    "reason",
    # Content that reads like a place or a label but decides nothing. Measured
    # against AgentDojo: a calendar event's "location" was treated as
    # authority-bearing and denied every legitimate event creation, for no
    # security gain -- an event in the wrong place is a nuisance, not an
    # exfiltration.
    "location",
    "venue",
    "place",
    "label",
    "tag",
    "tags",
)

_FILTER_HINTS = (
    "query",
    "search",
    "search_term",
    "keyword",
    "keywords",
    "term",
    "filter",
    "pattern",
)
"""Names that select what to look at rather than what to do.

Downgraded to PAYLOAD **only on read-only tools**. On anything that writes,
executes or egresses, a "query" may well be a command -- an SQL statement is
the obvious case -- so the restrictive reading is kept. The linter's
no-authority-parameter check is the backstop for a read-only tool that turns out
to be dangerous after all.
"""

_IDENTIFIER_SUFFIXES = (
    "_id",
    "_ids",
    "_arn",
    "_key",
    "_uri",
    "_url",
    "_path",
    "_ref",
    "_handle",
    "_token",
)
"""Suffixes that make a name an identifier, whatever else it contains.

Measured against a hand-labelled corpus, the deriver's worst error was
``reply_email.message_id`` drafted as PAYLOAD: "message" reads as content, and
the suffix that turns it into a reference was ignored. A name ending in one of
these denotes *which thing*, and which-thing is authority. The suffix wins over
any content hint.
"""

_DANGEROUS_FLAGS = (
    "force",
    "recursive",
    "overwrite",
    "permanent",
    "hard",
    "purge",
    "cascade",
    "no_verify",
    "skip_checks",
    "allow_delete",
    "confirm",
    "yes",
)
"""Booleans that decide what happens to the world, not how it is presented.

The other measured miss was ``git_push.force``, downgraded to ADVISORY for
being a boolean. Booleans carry authority when they widen what an action
destroys: --force overwrites history, recursive delete removes a tree.
"""

_ADVISORY_HINTS = (
    "limit",
    "offset",
    "page",
    "page_size",
    "per_page",
    "sort",
    "order",
    "format",
    "verbose",
    "dry_run",
    "locale",
    "timezone",
    "priority",
    "style",
    # Temporal parameters. Measured against AgentDojo, these were the single
    # largest source of false denials: a date determines *when* an action
    # happens, not what it does to whom, and the agent legitimately derives
    # "2024-05-26" from "May 26th" -- a semantic step no provenance system can
    # follow. Treating them as authority-bearing denied most calendar work for
    # no security gain. A destructive tool whose parameters are *all* advisory
    # is still caught by the linter's no-authority-parameter check.
    "date",
    "day",
    "time",
    "datetime",
    "timestamp",
    "start",
    "end",
    "start_time",
    "end_time",
    "start_date",
    "end_date",
    "since",
    "until",
    "before",
    "after",
    "year",
    "month",
    "week",
    "duration",
    "start_day",
    "end_day",
    "day_of_week",
    "hour",
    "minute",
)

_KIND_HINTS: tuple[tuple[tuple[str, ...], str | tuple[str, ...]], ...] = (
    # "recipient" is not a synonym for "email address": a payments API sends
    # to an IBAN, a wallet API to a chain address. Measured against AgentDojo,
    # constraining it to {"email"} failed every legitimate transfer on
    # kind_mismatch. The kinds list is a *shape* check layered on top of
    # attribution, so widening it costs no security -- the value must still be
    # attributed to an authorised source.
    (("recipient", "recipients", "payee", "beneficiary"),
     ("email", "iban", "account_number", "crypto_address", UNCLASSIFIED)),
    (("email", "mail", "to", "cc", "bcc", "sender", "from"), "email"),
    # A "url" parameter routinely receives a scheme-less host such as
    # "www.example.com", which extracts as a hostname rather than a url.
    # Measured against AgentDojo, constraining these to {"url"} alone failed
    # every legitimate web fetch on kind_mismatch.
    (("url", "link", "endpoint", "webhook", "callback", "href"), ("url", "hostname")),
    (("host", "hostname", "domain", "server"), "hostname"),
    # A path parameter routinely receives a bare name such as
    # "bill-december.txt", which has no path grammar at all. UNCLASSIFIED is
    # listed so the shape check accepts it; attribution is unaffected.
    (("path", "file", "filename", "filepath", "dir", "directory"),
     ("posix_path", "windows_path", "unc_path", UNCLASSIFIED)),
    (("account", "iban", "card", "wallet"), "iban"),
    (("phone", "msisdn", "mobile"), "phone"),
    # Deliberately narrow: an "_id" suffix does not mean RFC 4122. Constraining
    # every *_id parameter to the uuid kind made every call carrying a short
    # opaque id fail on kind_mismatch, measured against AgentDojo. Such
    # parameters stay AUTHORITY with no kind constraint, which requires the
    # whole value to be attributable -- the restrictive reading.
    (("uuid", "guid"), "uuid"),
)


def _kinds_for(name: str) -> frozenset[str]:
    lowered = name.lower()
    for tokens, kinds in _KIND_HINTS:
        if any(token == lowered or token in lowered.split("_") for token in tokens):
            return frozenset({kinds} if isinstance(kinds, str) else kinds)
    return frozenset()


def derive_contract(
    tool: str,
    schema: Mapping[str, Any] | None = None,
    *,
    parameters: Sequence[str] | None = None,
    effects: Iterable[Effect | str] = (),
    description: str = "",
) -> ToolContract:
    """Produce a **draft** contract from a JSON Schema or a parameter list.

    This is a starting point for a human, not an authority. It exists because
    hand-authoring contracts for hundreds of tools is the failure mode that
    stopped capability defences being adopted, and a draft that is 80% right is
    a far smaller review job than a blank file.

    Its bias is toward ``AUTHORITY``: only parameters whose names clearly read
    as content or presentation are downgraded. A misclassified payload
    parameter costs utility; a misclassified authority parameter costs
    security, so the deriver never guesses in that direction.

    ``effects`` is **not** inferred. A tool's effects cannot be read off its
    schema, and silently guessing that something is read-only would be the most
    dangerous inference in the whole system. The caller must state them.
    """
    names: list[str] = []
    props: Mapping[str, Any] = {}
    if schema is not None:
        props = schema.get("properties", {}) or {}
        names = list(props.keys())
    if parameters is not None:
        names = list(parameters)

    declared_effects = frozenset(Effect(e) for e in effects)
    read_only = bool(declared_effects) and declared_effects <= {Effect.READ}

    declared: dict[str, ParameterContract] = {}
    for name in names:
        lowered = name.lower()
        prop = props.get(name, {}) if isinstance(props, Mapping) else {}
        if lowered.endswith(_IDENTIFIER_SUFFIXES):
            # Checked first: an identifier suffix outranks every content hint.
            role = Role.AUTHORITY
        elif read_only and any(
            hint == lowered or hint in lowered.split("_") for hint in _FILTER_HINTS
        ):
            role = Role.PAYLOAD
        elif lowered in _DANGEROUS_FLAGS:
            role = Role.AUTHORITY
        elif lowered in _ADVISORY_HINTS:
            role = Role.ADVISORY
        elif any(hint == lowered or hint in lowered.split("_") for hint in _PAYLOAD_HINTS):
            role = Role.PAYLOAD
        elif isinstance(prop, Mapping) and prop.get("type") in {"boolean", "integer", "number"}:
            # Numerics and booleans cannot hold an identifier, but an amount
            # very much carries authority, so only the rest are downgraded.
            role = Role.ADVISORY if not _looks_like_amount(lowered) else Role.AUTHORITY
        else:
            role = Role.AUTHORITY
        declared[name] = ParameterContract(
            name=name,
            role=role,
            kinds=_kinds_for(name) if role is Role.AUTHORITY else frozenset(),
            description=(prop.get("description", "") if isinstance(prop, Mapping) else ""),
        )

    return ToolContract(
        tool=tool,
        parameters=declared,
        effects=declared_effects,
        default_role=Role.AUTHORITY,
        description=description or (schema.get("description", "") if schema else ""),
    )


def _looks_like_amount(name: str) -> bool:
    return any(
        token in name
        for token in ("amount", "total", "price", "value", "quantity", "qty", "sum")
    )
