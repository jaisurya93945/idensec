"""Integrity and confidentiality labels.

IDENSEC decides whether a tool-call argument may carry authority. That decision
rests on two orthogonal axes, and getting their quantifiers backwards is the
classic information-flow bug:

* **Integrity** (:class:`Trust`) -- *may this value determine what happens?*
  Combined **existentially**: a value is authorised if *any* contributing source
  is authorised for it (see ADR-0008). Using ``all`` here would let an attacker
  revoke a legitimate flow simply by echoing the user's own address into a page
  the agent fetches.

* **Confidentiality** (:class:`Sensitivity`) -- *where may this value go?*
  Combined by **maximum**: touching one confidential source taints the result
  regardless of what else contributed.

The integrity tiers follow the five-level lattice used in the 2026 agent-IFC
literature (``ToolDesc < ToolUntrusted < ToolTrusted < UserInput < SysInstr``)
so that labels are comparable with published work.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import IntEnum

__all__ = [
    "Attribution",
    "AttributionState",
    "Origin",
    "Sensitivity",
    "Source",
    "Trust",
]


class Trust(IntEnum):
    """Integrity tier of a data origin. Higher is more trusted."""

    TOOL_DESCRIPTION = 0
    """Tool names, descriptions and schemas.

    Deliberately the *lowest* tier, below untrusted tool output. Tool
    descriptions look like configuration but in MCP they are supplied by the
    server, which makes them attacker-controllable (tool poisoning). Anything
    that reads like trusted configuration but crosses a trust boundary at
    runtime belongs here.
    """

    TOOL_UNTRUSTED = 1
    """Output of a tool that returns third-party content: web pages, inbound
    email, fetched documents, other agents' messages."""

    TOOL_TRUSTED = 2
    """Output of a tool the operator vouches for: an internal directory, a
    first-party database, a signed API response."""

    USER_INPUT = 3
    """The principal's own instruction for this session."""

    SYSTEM = 4
    """Operator-supplied configuration established before the session."""


class Sensitivity(IntEnum):
    """Confidentiality tier of a data origin. Higher is more restricted."""

    PUBLIC = 0
    INTERNAL = 1
    CONFIDENTIAL = 2


def _as_frozenset(value: object) -> frozenset[str]:
    if isinstance(value, frozenset):
        return value
    if isinstance(value, (set, list, tuple)):
        return frozenset(str(item) for item in value)
    raise TypeError(f"expected a collection of operand kind names, got {type(value).__name__}")


@dataclass(frozen=True, slots=True)
class Source:
    """A declared origin of data entering the agent's context.

    ``authoritative_for`` is the source-authority matrix: the set of operand
    kind names for which this source may supply a value that *determines* an
    action. A corporate directory is authoritative for ``email``; a fetched web
    page is authoritative for nothing. Sources at :attr:`Trust.USER_INPUT` or
    above are authoritative for every kind without needing to enumerate them --
    the principal is allowed to name their own destinations.
    """

    id: str
    trust: Trust
    sensitivity: Sensitivity = Sensitivity.PUBLIC
    authoritative_for: frozenset[str] = field(default_factory=frozenset)
    description: str = ""

    def __post_init__(self) -> None:
        if not self.id:
            raise ValueError("Source.id must be a non-empty string")
        # Callers reasonably pass a set or list literal; normalise so that
        # equality and hashing behave.
        object.__setattr__(self, "authoritative_for", _as_frozenset(self.authoritative_for))

    @property
    def is_principal(self) -> bool:
        """True when the source speaks for the principal or the operator."""
        return self.trust >= Trust.USER_INPUT

    def is_authoritative_for(self, kind: str) -> bool:
        """Whether this source may supply a value of ``kind`` that carries authority."""
        return self.is_principal or kind in self.authoritative_for


@dataclass(frozen=True, slots=True)
class Origin:
    """One recorded contribution of a source to a value.

    ``path`` locates the value inside a structured observation (for example
    ``results[2].url``), which is what makes field-level provenance possible
    inside a single tool result.
    """

    source_id: str
    trust: Trust
    sensitivity: Sensitivity
    step: int
    path: str = ""

    def locator(self) -> str:
        return f"{self.source_id}@{self.step}{':' + self.path if self.path else ''}"


class AttributionState(IntEnum):
    """How well a value could be traced back to a declared source."""

    UNATTRIBUTED = 0
    """Matched nothing: not a seal, not a recorded operand, not derivable from
    trusted text. Treated as non-authoritative (ADR-0007). This is the state a
    laundered value lands in."""

    ATTRIBUTED = 1
    """Traced to one or more declared sources."""


@dataclass(frozen=True, slots=True)
class Attribution:
    """The provenance verdict for a single value."""

    state: AttributionState
    origins: tuple[Origin, ...] = ()
    derivation: str = ""
    """How the value was traced: ``seal``, ``operand``, ``trusted-substring``,
    ``untrusted-substring``. Recorded for audit, never used for permission."""

    @property
    def sensitivity(self) -> Sensitivity:
        """Maximum sensitivity over contributing origins (ADR-0008)."""
        if not self.origins:
            return Sensitivity.PUBLIC
        return max(o.sensitivity for o in self.origins)

    @property
    def max_trust(self) -> Trust:
        if not self.origins:
            return Trust.TOOL_DESCRIPTION
        return max(o.trust for o in self.origins)

    def is_authorised_for(self, kind: str, sources: dict[str, Source]) -> bool:
        """Existential authority check (ADR-0008).

        Unattributed values are never authorised, regardless of how harmless
        they look.
        """
        if self.state is AttributionState.UNATTRIBUTED:
            return False
        for origin in self.origins:
            source = sources.get(origin.source_id)
            if source is not None and source.is_authoritative_for(kind):
                return True
        return False

    def principal_directed(self) -> bool:
        """True if the principal themselves is among the contributing origins."""
        return any(o.trust >= Trust.USER_INPUT for o in self.origins)


def merge_origins(*groups: Iterable[Origin]) -> tuple[Origin, ...]:
    """Union of origin groups, de-duplicated and ordered for reproducibility."""
    seen: dict[tuple[str, int, str], Origin] = {}
    for group in groups:
        for origin in group:
            seen.setdefault((origin.source_id, origin.step, origin.path), origin)
    return tuple(
        sorted(seen.values(), key=lambda o: (o.source_id, o.step, o.path))
    )
