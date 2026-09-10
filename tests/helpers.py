"""Small helpers shared by the test modules."""

from __future__ import annotations

from idensec.ledger import SEAL_PATTERN


def seals(text: str) -> list[str]:
    """Every handle in a sealed string, in order."""
    return [m.group(0) for m in SEAL_PATTERN.finditer(text)]
