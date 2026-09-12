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
import re
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
    collection: str = ""
    """Which directory this parameter's value is an id *of*, as a field-path
    glob over observed data -- ``"**.files"``, ``"inbox.emails"``.

    Only reference binding reads it, and without it reference binding does not
    fire at all. That is not a default worth softening: ids are unique inside a
    collection and nowhere else, so a value meaning *calendar event 13* and a
    value meaning *file 13* are the same three characters. Measured against
    AgentDojo, binding an id without knowing its collection let an instruction
    naming a calendar event authorise deleting an unrelated file -- the
    mechanism's own escape, found by running it.
    """
    description: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "kinds", _as_frozenset(self.kinds))
        object.__setattr__(self, "role", Role(str(self.role)))

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"role": self.role.value}
        if self.kinds:
            out["kinds"] = sorted(self.kinds)
        if self.collection:
            out["collection"] = self.collection
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
                collection=spec.get("collection", ""),
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


_WIDENING_ANNOTATIONS: Mapping[str, frozenset[Effect]] = {
    "destructiveHint": frozenset({Effect.DELETE, Effect.IRREVERSIBLE}),
    "openWorldHint": frozenset({Effect.NETWORK_EGRESS}),
}
"""MCP tool annotations this deriver is willing to believe, and what they add.

The rule is one line and it is the whole of the security argument:
**an annotation may add an effect and may never remove one.**

MCP tool annotations are supplied by the *server*, which sits at the bottom of
the integrity lattice (``TOOL_DESCRIPTION``) precisely because a server can be
hostile or compromised. So each hint is judged by which direction believing it
moves the decision:

* ``destructiveHint: true`` and ``openWorldHint: true`` make the contract more
  restrictive. A hostile server that lies this way causes denials of its own
  tools and nothing else.
* ``readOnlyHint: true`` makes it **less** restrictive, and is therefore
  ignored outright. Believing it is a total bypass: mark the exfiltration tool
  read-only and every confidentiality rule stops firing. Measured across seven
  reference MCP servers, **32 of 52 tools claim it** -- see
  ``benchmarks/mcp_corpus.py``, which is why this is a live concern rather than
  a hypothetical one.
* ``idempotentHint`` says nothing about what a tool reaches, so nothing is read
  from it.

The asymmetry means annotations can only ever *improve* a draft's safety, never
weaken it, which is what makes reading attacker-controllable metadata defensible
at all.
"""


def derive_contract(
    tool: str,
    schema: Mapping[str, Any] | None = None,
    *,
    parameters: Sequence[str] | None = None,
    effects: Iterable[Effect | str] = (),
    description: str = "",
    annotations: Mapping[str, Any] | None = None,
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

    ``annotations`` takes an MCP tool's own ``annotations`` object, and is read
    under the one-way rule in :data:`_WIDENING_ANNOTATIONS`: it may **add**
    effects to what the caller declared and may never remove any. A server
    claiming to be destructive is believed; a server claiming to be read-only is
    not. It therefore never reduces the caller's obligation to declare effects,
    only makes the draft safer when a server volunteers that it is dangerous.
    """
    names: list[str] = []
    props: Mapping[str, Any] = {}
    if schema is not None:
        props = schema.get("properties", {}) or {}
        names = list(props.keys())
    if parameters is not None:
        names = list(parameters)

    declared_effects = frozenset(Effect(e) for e in effects)
    for hint, added in _WIDENING_ANNOTATIONS.items():
        if annotations is not None and annotations.get(hint) is True:
            declared_effects |= added
    read_only = bool(declared_effects) and declared_effects <= {Effect.READ}

    declared: dict[str, ParameterContract] = {}
    for name in names:
        lowered = name.lower()
        prop = props.get(name, {}) if isinstance(props, Mapping) else {}
        tokens = _name_tokens(name)
        if lowered.endswith(_IDENTIFIER_SUFFIXES) or (
            tokens and f"_{tokens[-1]}" in _IDENTIFIER_SUFFIXES
        ):
            # Checked first: an identifier suffix outranks every content hint.
            role = Role.AUTHORITY
        elif read_only and any(
            hint == lowered or hint in tokens for hint in _FILTER_HINTS
        ):
            role = Role.PAYLOAD
        elif lowered in _DANGEROUS_FLAGS:
            role = Role.AUTHORITY
        elif any(hint == lowered or hint in tokens for hint in _ADVISORY_HINTS):
            # Token-wise, not exact. ``new_start_time`` is the same parameter as
            # ``start_time`` with a prefix, and enumerating every prefix a server
            # might use is a losing game -- AgentDojo alone supplied
            # ``new_start_time``, ``new_end_time`` and ``new_day``. Splitting on
            # ``_`` rather than substring-matching keeps ``backend_host`` out of
            # it, and the identifier-suffix branch above still wins, so
            # ``order_id`` and ``start_url`` stay AUTHORITY.
            role = Role.ADVISORY
        elif any(hint == lowered or hint in tokens for hint in _PAYLOAD_HINTS):
            role = Role.PAYLOAD
        elif _only_scalar_types(prop):
            # Numerics and booleans cannot hold an identifier, but an amount
            # very much carries authority, so only the rest are downgraded.
            role = Role.ADVISORY if not _looks_like_amount(lowered) else Role.AUTHORITY
        else:
            role = Role.AUTHORITY
        declared[name] = ParameterContract(
            name=name,
            role=role,
            kinds=_kinds_for(name) if role is Role.AUTHORITY else frozenset(),
            collection=_collection_for(name) if role is Role.AUTHORITY else "",
            description=(prop.get("description", "") if isinstance(prop, Mapping) else ""),
        )

    return ToolContract(
        tool=tool,
        parameters=declared,
        effects=declared_effects,
        default_role=Role.AUTHORITY,
        description=description or (schema.get("description", "") if schema else ""),
    )


_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")


def _name_tokens(name: str) -> list[str]:
    """Split a parameter name the way its author meant it to be read.

    ``snake_case`` **and** ``camelCase``. Measured against seven published MCP
    servers, splitting on ``_`` alone missed every JavaScript server's naming
    convention: ``sortBy`` stayed AUTHORITY where ``sort_by`` was advisory, and
    ``fileId`` missed the identifier suffix that ``file_id`` matched. The
    convention a server happens to use should not change what a parameter is
    taken to mean.
    """
    spaced = _CAMEL_BOUNDARY.sub(" ", name).replace("_", " ").replace("-", " ")
    return [token for token in spaced.lower().split() if token]


_NON_IDENTIFIER_TYPES = frozenset({"boolean", "integer", "number"})


def _only_scalar_types(prop: object) -> bool:
    """True when a schema's declared type cannot possibly hold an identifier.

    JSON Schema's ``type`` is a string **or a list of strings**, and real
    servers use the list form -- ``["string", "null"]`` for an optional field.
    Reading it as a string crashed the deriver against the first published
    server that used one, which is the sort of thing a corpus we wrote
    ourselves was never going to find.

    A union is only safe to downgrade when *every* member is a type that cannot
    carry an identifier; ``["string", "null"]`` can, so it stays AUTHORITY. An
    absent or unrecognised ``type`` is treated the same way, because the
    downgrade is the permissive direction.
    """
    if not isinstance(prop, Mapping):
        return False
    declared = prop.get("type")
    if isinstance(declared, str):
        declared = [declared]
    if not isinstance(declared, (list, tuple)) or not declared:
        return False
    return all(
        isinstance(item, str) and item in _NON_IDENTIFIER_TYPES for item in declared
    )


def _collection_for(name: str) -> str:
    """Draft which directory an ``<thing>_id`` parameter addresses.

    ``file_id`` addresses files, ``eventId`` events, ``message_ids`` messages.
    The draft is a glob over observed field paths, so it matches wherever the
    server actually puts that directory (``cloud_drive.files``, ``files``).

    Drafted rather than inferred-and-trusted, like every other field the
    deriver fills in. A **wrong** draft costs a denial, never a bypass: the
    collection only ever *narrows* which named records can bind an id, and a
    parameter with no draft binds nothing at all. ``id`` on its own gets
    nothing, because it says which-thing without saying which *kind* of thing.

    It fires on **none** of the 60 authority-bearing parameters in
    ``benchmarks/data/mcp_tools.json``: published servers name things ``path``,
    ``repo_path`` and ``branch_name``, not ``<noun>_id``. Against those servers
    every collection has to be written by hand, or reference binding never runs
    at all. That is reported in ``docs/BENCHMARKS.md`` rather than smoothed over.
    """
    tokens = _name_tokens(name)
    if len(tokens) < 2 or tokens[-1] not in ("id", "ids"):
        return ""
    noun = tokens[-2]
    if not noun:
        return ""
    return f"**.{_plural(noun)}"


_SIBILANT_ENDINGS = ("s", "x", "z", "ch", "sh")
_VOWELS = frozenset("aeiou")


def _plural(noun: str) -> str:
    """English plural of a directory noun, for the collection glob.

    Naive ``+ "s"`` produced ``**.branchs`` from ``branchId`` against a real
    server, and a collection glob that matches nothing makes reference binding
    silently never fire for that parameter -- a denial rather than a bypass, but
    a confusing one. Three rules cover the directory nouns servers actually use;
    anything stranger is why the draft is a draft.
    """
    if noun.endswith("ss"):
        # "address" is singular and ends in s; "files" is already plural. The
        # doubled s is the only cheap way to tell them apart, and getting it
        # wrong costs a denial rather than a bypass.
        return f"{noun}es"
    if noun.endswith(_SIBILANT_ENDINGS):
        return noun if noun.endswith("s") else f"{noun}es"
    if noun.endswith("y") and len(noun) > 1 and noun[-2] not in _VOWELS:
        return f"{noun[:-1]}ies"
    return f"{noun}s"


def _looks_like_amount(name: str) -> bool:
    return any(
        token in name
        for token in ("amount", "total", "price", "value", "quantity", "qty", "sum")
    )
