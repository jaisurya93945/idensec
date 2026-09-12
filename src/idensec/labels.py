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

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import IntEnum

from .kinds import REFERENCED

__all__ = [
    "Attribution",
    "AttributionState",
    "Origin",
    "Sensitivity",
    "Source",
    "Trust",
    "path_covers",
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


def _split_path(path: str) -> list[str]:
    """Break ``inbox.emails[3].sender`` into its segments.

    List indices become segments of their own so that ``*`` can stand for one.
    """
    segments: list[str] = []
    current = ""
    for char in path:
        if char == ".":
            if current:
                segments.append(current)
            current = ""
        elif char == "[":
            if current:
                segments.append(current)
            current = "["
        elif char == "]":
            segments.append(current + "]")
            current = ""
        else:
            current += char
    if current:
        segments.append(current)
    return segments


def _glob_segments(pattern: list[str], path: list[str]) -> bool:
    """Match path segments against a pattern, honouring ``*`` and ``**``."""
    if not pattern:
        return True  # a consumed pattern is a prefix match
    head, rest = pattern[0], pattern[1:]
    if head == "**":
        if not rest:
            return True
        return any(_glob_segments(rest, path[i:]) for i in range(len(path) + 1))
    if not path:
        return False
    if head == "[*]":
        # An index wildcard, so that "**.participants[*]" reads naturally.
        if not path[0].startswith("["):
            return False
    elif head not in ("*", path[0]):
        return False
    return _glob_segments(rest, path[1:])


def path_covers(pattern: str, path: str) -> bool:
    """True when a grant pattern applies to a value observed at ``path``.

    Without wildcards the pattern is a prefix, and continuation must fall on a
    separator so that ``inbox.contacts`` never leaks to ``inbox.contacts_backup``.
    """
    if not pattern:
        return True
    if "*" not in pattern:
        return path == pattern or (
            path.startswith(pattern) and path[len(pattern)] in ".["
        )
    return _glob_segments(_split_path(pattern), _split_path(path))


def _as_path_grants(value: object) -> tuple[tuple[str, frozenset[str]], ...]:
    if isinstance(value, tuple) and all(isinstance(item, tuple) for item in value):
        return tuple(
            (str(prefix), _as_frozenset(kinds)) for prefix, kinds in value
        )
    if isinstance(value, Mapping):
        return tuple(
            sorted(
                ((str(prefix), _as_frozenset(kinds)) for prefix, kinds in value.items()),
                key=lambda item: item[0],
            )
        )
    raise TypeError(
        "authoritative_paths must map a field-path prefix to a set of operand kinds"
    )


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
    authoritative_paths: tuple[tuple[str, frozenset[str]], ...] = ()
    """Authority granted only under particular field paths.

    A real tool result is not uniformly trustworthy. A workspace API returns
    contact records *and* the bodies of emails other people sent; the first is
    the principal's own directory, the second is attacker territory, and both
    arrive from one source. Granting ``email`` authority to the source as a
    whole makes every address in every message body authoritative, which is the
    injection path. Granting none of it denies the legitimate lookups.

    Measured against AgentDojo, that choice cost either a third of the security
    or a quarter of the utility -- so it is the wrong choice to have to make.
    Because provenance is recorded per field, authority can be scoped the same
    way:

        Source("workspace", Trust.TOOL_TRUSTED,
               authoritative_paths={"inbox.contacts": {"email"},
                                    "calendar.events": {"email"}})

    A pattern without wildcards is a prefix: ``inbox.contacts`` covers
    ``inbox.contacts[3].email`` and never ``inbox.contacts_backup``, because
    continuation must fall on a separator.

    Patterns may also use segment wildcards, which is what real API shapes
    need. ``*`` matches one path segment and ``**`` matches any number, so
    ``**.sender`` grants authority to the sender field of every record while
    leaving ``**.body`` alone. Measured against AgentDojo, that distinction is
    the whole game: legitimate addresses live in ``sender``, ``recipients`` and
    ``participants``, and injections live in ``description`` and ``content``.
    """

    description: str = ""

    def __post_init__(self) -> None:
        if not self.id:
            raise ValueError("Source.id must be a non-empty string")
        # Callers reasonably pass a set or list literal; normalise so that
        # equality and hashing behave.
        object.__setattr__(self, "authoritative_for", _as_frozenset(self.authoritative_for))
        object.__setattr__(
            self, "authoritative_paths", _as_path_grants(self.authoritative_paths)
        )

    @property
    def is_principal(self) -> bool:
        """True when the source speaks for the principal or the operator."""
        return self.trust >= Trust.USER_INPUT

    def is_authoritative_for(self, kind: str, path: str = "") -> bool:
        """Whether this source may supply a value of ``kind`` carrying authority.

        ``path`` is where the value sat inside the source's output. A source
        with no path-scoped grants ignores it entirely, so the simple case stays
        simple.
        """
        if self.is_principal or kind in self.authoritative_for:
            return True
        return any(
            kind in kinds and path_covers(prefix, path)
            for prefix, kinds in self.authoritative_paths
        )


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
    ``untrusted-substring``, ``reference-bound``. Recorded for audit; only
    ``reference-bound`` also affects permission, and only where a source grants
    :data:`~idensec.kinds.REFERENCED`."""

    composed: bool = False
    """Every component of this value was separately attributed and authorised.

    Set only by the composition rule, which exists because a path an agent
    *builds* -- a root the server disclosed joined to a name the principal wrote
    -- is a string neither of them ever emitted, and so traces to nobody.

    It bypasses :meth:`is_authorised_for` because that check is **existential**
    and composition is **universal**: composition has already required *every*
    component to be authorised, which is strictly stronger, and re-running the
    existential rule over the merged origins would weaken it to "some component
    was fine".
    """

    reference_bound: bool = False
    """The value identifies an entity the principal quoted a field of.

    Set independently of ``derivation`` because it is a fact about the *entity*,
    not about how the id itself was traced -- the id still came from the
    directory, and the audit record should keep saying so.
    """

    @property
    def sensitivity(self) -> Sensitivity:
        """Maximum sensitivity over contributing origins (ADR-0008)."""
        if not self.origins:
            return Sensitivity.PUBLIC
        return max(o.sensitivity for o in self.origins)

    def is_authorised_for(self, kind: str, sources: dict[str, Source]) -> bool:
        """Existential authority check (ADR-0008).

        Each origin is checked against the source's grants *at that origin's
        field path*, so a source may be authoritative for addresses in its
        contact records and not in the bodies of messages other people wrote.

        Unattributed values are never authorised, regardless of how harmless
        they look.
        """
        if self.state is AttributionState.UNATTRIBUTED:
            return False
        if self.composed:
            # Already decided, and decided more strictly. See Attribution.composed.
            return True
        for origin in self.origins:
            source = sources.get(origin.source_id)
            if source is None:
                continue
            if source.is_authoritative_for(kind, origin.path):
                return True
            if self.reference_bound and source.is_authoritative_for(
                REFERENCED, origin.path
            ):
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
