"""The operand ledger: sealing, indexing and resolution.

Two boundaries exist in every agent harness, and IDENSEC mediates both.

**Read boundary** (tool result -> context). Untrusted content is *sealed*:
every extracted operand is replaced by an opaque handle before the text reaches
the model. Prose survives intact, so the model can still read and reason; the
identifiers become references it can pass along but cannot pronounce. Trusted
content is *indexed* instead -- recorded in the ledger without rewriting, so the
principal's own task text stays readable (ADR-0010).

**Write boundary** (tool call -> execution). Handles in arguments are resolved
back to values, and the ledger says exactly which sources contributed. That is
oracle-grade provenance obtained structurally, with no model involved.

The handle carries its kind in the clear (``[[idn:email:...]]``) so the model
can plan with it -- it knows the slot holds an address without knowing which
address -- and 64 bits of randomness so it cannot be guessed. Guessing is the
only way an attacker could redirect a handle they cannot see, and the denial
budget bounds the number of attempts.
"""

from __future__ import annotations

import re
import secrets
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, replace

from .kinds import DEFAULT_KINDS, extract, normalise
from .labels import Origin, Sensitivity, Source, Trust, merge_origins

__all__ = [
    "SEAL_PATTERN",
    "Observation",
    "Operand",
    "OperandLedger",
    "Resolution",
    "ResolvedSpan",
    "seal_token",
]

SEAL_OPEN = "[[idn:"
SEAL_PATTERN = re.compile(r"\[\[idn:([a-z_]+):([0-9a-f]{16})\]\]")

# Untrusted content that contains something shaped like a handle is rewritten
# so it cannot be confused for one. An unknown handle is denied anyway, but a
# model that sees plausible-looking handles in attacker text is a model being
# invited to improvise.
_SEAL_DECOY = re.compile(re.escape(SEAL_OPEN), re.IGNORECASE)
_SEAL_DECOY_REPLACEMENT = "[[idn-quoted:"


def seal_token(kind: str, operand_id: str) -> str:
    return f"{SEAL_OPEN}{kind}:{operand_id}]]"


def _default_id_factory() -> str:
    return secrets.token_hex(8)


_TOKEN_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyz0123456789_.@/:+%-\\"
)
"""Characters that can appear inside a single identifier.

A match is a *quotation* only when neither neighbour is one of these, so a
value cannot be carved out of the middle of a longer identifier.
"""


def _candidate_forms(value: str, minimum: int) -> tuple[str, ...]:
    """Normalised spellings of a value that all count as the same quotation.

    Numbers reach tools in more shapes than they appear in prose: a tool takes
    ``4.0`` where the principal wrote ``4``, or ``1200`` where they wrote
    ``1,200``. Measured against AgentDojo, that mismatch alone denied half the
    banking suite. The forms generated here are exact re-spellings of the same
    number -- no rounding, no unit conversion, nothing semantic.
    """
    base = " ".join(value.split()).casefold()
    if len(base) < minimum:
        return ()
    forms = {base}
    stripped = base.replace(",", "").replace("_", "")
    for prefix in ("$", "£", "€", "₹"):
        stripped = stripped.removeprefix(prefix)
    try:
        number = float(stripped)
    except ValueError:
        return tuple(sorted(forms))
    if number == int(number):
        forms.add(str(int(number)))
        forms.add(f"{int(number)}.0")
        # The principal may have written the grouped spelling. Generating it
        # from the value is deterministic; normalising the haystack instead
        # would rewrite text we are supposed to be quoting.
        forms.add(f"{int(number):,}")
    forms.add(stripped)
    forms.add(repr(number))
    return tuple(sorted(f for f in forms if len(f) >= minimum))


def _contains_token(haystack: str, needle: str) -> bool:
    """Substring search that requires identifier boundaries on both sides."""
    start = 0
    span = len(needle)
    while True:
        index = haystack.find(needle, start)
        if index < 0:
            return False
        left_ok = index == 0 or haystack[index - 1] not in _TOKEN_CHARS
        end = index + span
        right_ok = end == len(haystack) or haystack[end] not in _TOKEN_CHARS
        if left_ok and right_ok:
            return True
        start = index + 1


@dataclass(frozen=True, slots=True)
class Operand:
    """A value that can carry authority, with everything known about its origin."""

    id: str
    kind: str
    value: str
    normalised: str
    origins: tuple[Origin, ...]

    @property
    def seal(self) -> str:
        return seal_token(self.kind, self.id)


@dataclass(frozen=True, slots=True)
class Observation:
    """One piece of content that entered the agent's context.

    ``normalised`` is the whitespace-collapsed, case-folded form used for
    derivation matching. It is computed once here rather than on every
    attribution: recomputing it per lookup made ``admit`` scale with the total
    *size* of everything observed rather than with its length, which showed up
    immediately in the benchmark.
    """

    step: int
    source_id: str
    path: str
    text: str
    sealed: bool
    normalised: str = ""


@dataclass(frozen=True, slots=True)
class ResolvedSpan:
    """A region of a resolved string that came from a handle, not from the model."""

    start: int
    end: int
    operand: Operand


@dataclass(frozen=True, slots=True)
class Resolution:
    """Result of expanding handles in an argument value."""

    text: str
    spans: tuple[ResolvedSpan, ...] = ()
    unknown_seals: tuple[str, ...] = ()

    def covers(self, start: int, end: int) -> ResolvedSpan | None:
        """Return the handle-produced span fully containing ``[start, end)``.

        Used to tell a value the model *referenced* from one it *typed*. An
        operand that is only partially inside a resolved span -- say, a URL
        built by concatenating a legitimate handle with an attacker-chosen
        query string -- is not covered, and is attributed on its own.
        """
        for span in self.spans:
            if span.start <= start and end <= span.end:
                return span
        return None


class OperandLedger:
    """Session-scoped store of operands, observations and source text.

    Not thread-safe by design: a ledger belongs to one session, and a session
    is one agent's linear execution. Sharing one across concurrent sessions
    would cross-contaminate provenance, which is a security bug, not a
    performance one.
    """

    def __init__(
        self,
        *,
        kinds: Sequence[str] | None = None,
        id_factory: Callable[[], str] | None = None,
        max_indexed_chars: int = 4_000_000,
        min_derivation_length: int = 1,
    ) -> None:
        self._kinds = tuple(kinds) if kinds is not None else DEFAULT_KINDS
        self._id_factory = id_factory or _default_id_factory
        self._max_indexed_chars = max_indexed_chars
        self._min_derivation_length = max(1, min_derivation_length)
        self._by_key: dict[tuple[str, str], Operand] = {}
        self._by_id: dict[str, Operand] = {}
        self._observations: list[Observation] = []
        self._indexed_chars = 0

    # -- introspection ---------------------------------------------------

    @property
    def observations(self) -> tuple[Observation, ...]:
        return tuple(self._observations)

    @property
    def operands(self) -> tuple[Operand, ...]:
        return tuple(sorted(self._by_key.values(), key=lambda o: (o.kind, o.normalised)))

    def lookup(self, kind: str, value: str) -> Operand | None:
        return self._by_key.get((kind, normalise(kind, value)))

    def find_value(self, value: str) -> Operand | None:
        """Find a recorded operand by value across every kind."""
        stripped = value.strip()
        for kind in self._kinds:
            operand = self.lookup(kind, stripped)
            if operand is not None:
                return operand
        return None

    # -- recording -------------------------------------------------------

    def _record(
        self, kind: str, value: str, origin: Origin
    ) -> Operand:
        key = (kind, normalise(kind, value))
        existing = self._by_key.get(key)
        if existing is None:
            operand = Operand(
                id=self._new_id(),
                kind=kind,
                value=value.strip(),
                normalised=key[1],
                origins=(origin,),
            )
        else:
            merged = merge_origins(existing.origins, (origin,))
            if merged == existing.origins:
                return existing
            operand = replace(existing, origins=merged)
        self._by_key[key] = operand
        self._by_id[operand.id] = operand
        return operand

    def _new_id(self) -> str:
        for _ in range(8):
            candidate = self._id_factory()
            if candidate not in self._by_id:
                return candidate
        raise RuntimeError("operand id factory failed to produce a fresh id")

    def index(self, source: Source, text: str, *, step: int, path: str = "") -> str:
        """Record operands in trusted text without rewriting it (ADR-0010)."""
        self._observe(source, text, step=step, path=path, sealed=False)
        for match in extract(text, self._kinds):
            self._record(
                match.kind,
                match.value,
                Origin(source.id, source.trust, source.sensitivity, step, path),
            )
        return text

    def seal(self, source: Source, text: str, *, step: int, path: str = "") -> str:
        """Replace operands in untrusted text with opaque handles."""
        text = _SEAL_DECOY.sub(_SEAL_DECOY_REPLACEMENT, text)
        self._observe(source, text, step=step, path=path, sealed=True)
        matches = extract(text, self._kinds)
        if not matches:
            return text
        origin = Origin(source.id, source.trust, source.sensitivity, step, path)
        out: list[str] = []
        cursor = 0
        for match in matches:
            operand = self._record(match.kind, match.value, origin)
            out.append(text[cursor : match.start])
            out.append(operand.seal)
            cursor = match.end
        out.append(text[cursor:])
        return "".join(out)

    def _observe(
        self, source: Source, text: str, *, step: int, path: str, sealed: bool
    ) -> None:
        if self._indexed_chars + len(text) > self._max_indexed_chars:
            raise MemoryError(
                "ledger observation budget exhausted; start a new session or raise "
                "max_indexed_chars"
            )
        self._indexed_chars += len(text)
        self._observations.append(
            Observation(
                step=step,
                source_id=source.id,
                path=path,
                text=text,
                sealed=sealed,
                normalised=" ".join(text.split()).casefold(),
            )
        )

    # -- resolution ------------------------------------------------------

    def resolve(self, value: str) -> Resolution:
        """Expand handles in ``value`` and report which regions they produced."""
        if SEAL_OPEN not in value:
            return Resolution(text=value)
        out: list[str] = []
        spans: list[ResolvedSpan] = []
        unknown: list[str] = []
        cursor = 0
        length = 0
        for match in SEAL_PATTERN.finditer(value):
            literal = value[cursor : match.start()]
            out.append(literal)
            length += len(literal)
            operand = self._by_id.get(match.group(2))
            if operand is None or operand.kind != match.group(1):
                # An unknown or kind-mismatched handle is left verbatim; the
                # monitor denies on it rather than silently dropping it.
                unknown.append(match.group(0))
                out.append(match.group(0))
                length += len(match.group(0))
            else:
                out.append(operand.value)
                spans.append(
                    ResolvedSpan(start=length, end=length + len(operand.value), operand=operand)
                )
                length += len(operand.value)
            cursor = match.end()
        tail = value[cursor:]
        out.append(tail)
        return Resolution(
            text="".join(out), spans=tuple(spans), unknown_seals=tuple(unknown)
        )

    # -- derivation ------------------------------------------------------

    def derivable_from(self, value: str, source_ids: Iterable[str]) -> Origin | None:
        """First origin from which ``value`` is derivable, or None.

        Retained for callers that need one origin; attribution uses
        :meth:`all_derivations`, because taking only the first is a bug when the
        authority check is existential.
        """
        found = self.all_derivations(value, source_ids)
        return found[0] if found else None

    def all_derivations(
        self, value: str, source_ids: Iterable[str]
    ) -> tuple[Origin, ...]:
        """Every origin from which ``value`` is derivable.

        Returning only the first match was a real defect. Authority is decided
        existentially -- a value is admissible if *any* contributing source is
        authorised for it -- so stopping at the first match can hand the checker
        an unauthorised origin while an authorised one exists further down. In
        AgentDojo this denied legitimate calls whose entity id also happened to
        appear inside some earlier free-text field.

        The permitted derivations are deliberately narrow and deterministic:
        identity, **whole-token** quotation, case folding, whitespace
        normalisation, and numeric normalisation. Nothing semantic.

        The token-boundary requirement is a security fix, not a nicety. Plain
        substring matching lets an attacker carve a value out of the middle of
        a longer trusted token: with the principal's instruction reading
        ``Pay invoice 100234 for 50``, an amount of ``1002`` is a substring of
        ``100234`` and would be attributed to the principal. Requiring the match
        to be delimited on both sides by characters outside the identifier
        alphabet closes that.

        **Quotation is not intent.** This answers "did the principal write this
        token", not "did the principal mean it as this argument". With the
        instruction ``Pay invoice 100234 for 50``, an ``amount`` of ``100234``
        is a genuine quotation of the principal and will be attributed to them,
        even though they meant it as the invoice number. Provenance cannot
        close that gap; for financial and other high-consequence parameters,
        prefer an escalation policy over relying on attribution alone. This is
        recorded in ``docs/LIMITATIONS.md``.
        """
        needles = _candidate_forms(value, self._min_derivation_length)
        if not needles:
            return ()
        wanted = set(source_ids)
        found: list[Origin] = []
        for observation in self._observations:
            if observation.source_id not in wanted:
                continue
            if any(_contains_token(observation.normalised, n) for n in needles):
                found.append(
                    Origin(
                        source_id=observation.source_id,
                        trust=self._trust_of(observation),
                        sensitivity=self._sensitivity_of(observation),
                        step=observation.step,
                        path=observation.path,
                    )
                )
        return tuple(found)

    # Trust and sensitivity are properties of the source, but observations are
    # what we retain; the session injects the lookup so the ledger stays free
    # of source registry state.
    _trust_lookup: Callable[[str], tuple[int, int]] | None = None

    def bind_source_lookup(self, lookup: Callable[[str], tuple[int, int]]) -> None:
        self._trust_lookup = lookup

    def _trust_of(self, observation: Observation) -> Trust:
        if self._trust_lookup is None:
            return Trust.TOOL_UNTRUSTED
        return Trust(self._trust_lookup(observation.source_id)[0])

    def _sensitivity_of(self, observation: Observation) -> Sensitivity:
        if self._trust_lookup is None:
            return Sensitivity.PUBLIC
        return Sensitivity(self._trust_lookup(observation.source_id)[1])
