"""Operand kinds and deterministic extraction.

An *operand* is a value that can carry authority: an address, a URL, a
hostname, a filesystem path, an account number, a resource identifier. These
are the values that determine *what an action does to the world*, as distinct
from prose, which determines what it says.

That distinction is what makes structural provenance tractable. Prose cannot be
enumerated, substituted or matched reliably. Identifiers can: they have surface
grammar, they are finite in a given tool result, and swapping one for an opaque
handle leaves the surrounding text readable. IDENSEC therefore tracks operands
exactly and treats prose as bulk-tainted payload.

Extraction is regex-based, ordered by priority, and produces non-overlapping
spans so that a hostname inside a URL is not extracted twice.

**Coverage is a security parameter, not a convenience.** An authority-bearing
value we fail to recognise is a value we fail to seal, which is why sealing
alone is not a defence and the unattributed rule (ADR-0007) exists.
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass

__all__ = [
    "DEFAULT_KINDS",
    "KIND_REGISTRY",
    "Match",
    "OperandKind",
    "extract",
    "normalise",
    "register_kind",
]

# Extensions that look like the tail of a hostname but are not one. Without
# this, "report.txt" and "main.py" are extracted as hostnames, which is a
# utility disaster and makes tool output unreadable.
_NON_HOST_SUFFIXES = frozenset(
    (
        "txt", "md", "markdown", "json", "jsonl", "yaml", "yml", "toml", "ini", "cfg",
        "conf", "env", "lock", "log", "xml", "csv", "tsv", "py", "pyc", "js", "jsx", "ts",
        "tsx", "mjs", "cjs", "go", "rs", "rb", "php", "java", "c", "h", "cpp", "hpp", "cs",
        "swift", "kt", "sh", "bash", "zsh", "sql", "html", "htm", "css", "scss", "svg",
        "png", "jpg", "jpeg", "gif", "webp", "ico", "bmp", "pdf", "doc", "docx", "xls",
        "xlsx", "ppt", "pptx", "zip", "tar", "gz", "tgz", "bz2", "xz", "rar", "7z", "bin",
        "exe", "dll", "so", "dylib", "class", "jar", "war",
    )
)


def _strip_trailing_punctuation(value: str) -> str:
    """URLs in prose absorb the sentence's punctuation. Give it back."""
    while value and value[-1] in ".,;:!?'\"":
        value = value[:-1]
    # Balance brackets only when the closer is unmatched, so that
    # https://en.wikipedia.org/wiki/Foo_(bar) survives intact.
    while value and value[-1] in ")]}":
        opener = {")": "(", "]": "[", "}": "{"}[value[-1]]
        if value.count(opener) >= value.count(value[-1]):
            break
        value = value[:-1]
    return value


@dataclass(frozen=True, slots=True)
class OperandKind:
    """A recognisable class of authority-bearing value.

    ``priority`` resolves overlaps: the lowest number wins, so ``url`` (10)
    claims the span before ``hostname`` (70) can.

    ``case_sensitive`` controls normalisation for equality matching. Filesystem
    paths are case-sensitive on the platforms that matter for security; hosts
    and mail addresses are not.
    """

    name: str
    pattern: re.Pattern[str]
    priority: int
    case_sensitive: bool = False
    strip_punctuation: bool = False
    description: str = ""

    def normalise(self, value: str) -> str:
        value = value.strip()
        if self.strip_punctuation:
            value = _strip_trailing_punctuation(value)
        return value if self.case_sensitive else value.casefold()

    def accepts(self, value: str) -> bool:
        """Full-match test, used when attributing a whole argument value."""
        return self.pattern.fullmatch(value.strip()) is not None


@dataclass(frozen=True, slots=True)
class Match:
    """One extracted operand occurrence."""

    kind: str
    value: str
    start: int
    end: int


def _kind(
    name: str,
    pattern: str,
    priority: int,
    *,
    flags: int = 0,
    case_sensitive: bool = False,
    strip_punctuation: bool = False,
    description: str = "",
) -> OperandKind:
    return OperandKind(
        name=name,
        pattern=re.compile(pattern, flags),
        priority=priority,
        case_sensitive=case_sensitive,
        strip_punctuation=strip_punctuation,
        description=description,
    )


KIND_REGISTRY: dict[str, OperandKind] = {}


def register_kind(kind: OperandKind) -> OperandKind:
    """Add a kind to the global registry.

    Integrators add kinds for domain identifiers their tools treat as
    authority-bearing (ticket ids, tenant ids, cluster names). A kind that is
    not registered is a kind that is never sealed.
    """
    KIND_REGISTRY[kind.name] = kind
    return kind


for _k in (
    _kind(
        "url",
        r"\bhttps?://[^\s<>\"'`\\^{}|\[\]]+",
        10,
        strip_punctuation=True,
        description="Absolute HTTP(S) URL. The canonical exfiltration sink.",
    ),
    _kind(
        "email",
        r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?"
        r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)*\.[A-Za-z]{2,63}\b",
        20,
        description="Mail address.",
    ),
    _kind(
        "windows_path",
        r"\b[A-Za-z]:\\[^\s\"'<>|]*",
        25,
        case_sensitive=True,
        description="Absolute Windows path.",
    ),
    _kind(
        "posix_path",
        r"(?<![\w./~\-])/(?:[A-Za-z_.][\w.\-+@%]*)(?:/[\w.\-+@%]*)*",
        30,
        case_sensitive=True,
        description="Absolute POSIX path.",
    ),
    _kind(
        "uuid",
        r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
        r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
        40,
        description="RFC 4122 identifier, commonly a resource handle.",
    ),
    _kind(
        "iban",
        r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b",
        45,
        description="IBAN-shaped bank account identifier.",
    ),
    _kind(
        "account_number",
        r"\b\d{8,19}\b",
        50,
        description="Bare numeric account or card identifier.",
    ),
    _kind(
        "phone",
        r"\+\d[\d\s().\-]{6,}\d|\b\d{3}[-.\s]\d{3}[-.\s]\d{4}\b",
        60,
        description="Telephone number. Conservative patterns only; bare digit "
        "runs are claimed by account_number first.",
    ),
    _kind(
        "hostname",
        r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\b",
        70,
        description="Bare domain name. Filtered against common file extensions.",
    ),
):
    register_kind(_k)

DEFAULT_KINDS: tuple[str, ...] = (
    "url",
    "email",
    "windows_path",
    "posix_path",
    "uuid",
    "iban",
    "account_number",
    "phone",
    "hostname",
)
"""Kinds extracted unless an integrator narrows the set.

Chosen to fail toward over-extraction: a false positive costs readability, a
false negative costs a seal.
"""


def _plausible(kind: str, value: str) -> bool:
    """Post-filters that are clearer as code than as regex."""
    if kind == "hostname":
        # Without this, every "report.txt" in a tool result becomes a handle.
        return value.rsplit(".", 1)[-1].casefold() not in _NON_HOST_SUFFIXES
    if kind == "posix_path":
        # "/" alone or "/x" carry little authority and match too much prose.
        return value.count("/") >= 2 or len(value) >= 5
    return True


def resolve_kinds(names: Sequence[str] | None = None) -> tuple[OperandKind, ...]:
    """Look up kinds by name, ordered by extraction priority."""
    selected = tuple(names) if names is not None else DEFAULT_KINDS
    missing = [n for n in selected if n not in KIND_REGISTRY]
    if missing:
        raise KeyError(f"unregistered operand kinds: {', '.join(sorted(missing))}")
    return tuple(sorted((KIND_REGISTRY[n] for n in selected), key=lambda k: k.priority))


def extract(text: str, kinds: Sequence[str] | None = None) -> list[Match]:
    """Extract non-overlapping operands from ``text``, highest priority first.

    Deterministic: the same text and kind set always yields the same list, in
    document order. This is what lets a decision be replayed from a trace.
    """
    if not text:
        return []
    claimed: list[tuple[int, int]] = []
    found: list[Match] = []
    for kind in resolve_kinds(kinds):
        for m in kind.pattern.finditer(text):
            start, end = m.start(), m.end()
            raw = m.group(0)
            if kind.strip_punctuation:
                stripped = _strip_trailing_punctuation(raw)
                end -= len(raw) - len(stripped)
                raw = stripped
            if not raw or not _plausible(kind.name, raw):
                continue
            if any(start < c_end and c_start < end for c_start, c_end in claimed):
                continue
            claimed.append((start, end))
            found.append(Match(kind=kind.name, value=raw, start=start, end=end))
    found.sort(key=lambda m: m.start)
    return found


def normalise(kind: str, value: str) -> str:
    """Normalise a value for equality matching under its kind's rules."""
    operand_kind = KIND_REGISTRY.get(kind)
    if operand_kind is None:
        raise KeyError(f"unregistered operand kind: {kind}")
    return operand_kind.normalise(value)


def classify(value: str, kinds: Sequence[str] | None = None) -> str | None:
    """Return the kind that fully matches ``value``, if any.

    Used when attributing an argument whose entire value is a single operand.
    """
    for kind in resolve_kinds(kinds):
        if kind.accepts(value) and _plausible(kind.name, value.strip()):
            return kind.name
    return None


def iter_kinds() -> Iterator[OperandKind]:
    yield from sorted(KIND_REGISTRY.values(), key=lambda k: k.priority)


def kind_table() -> Mapping[str, str]:
    """Human-readable registry dump, used by the docs and the CLI."""
    return {k.name: k.description for k in iter_kinds()}
