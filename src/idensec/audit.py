"""Tamper-evident decision records.

Every decision is appended to a hash chain: ``digest_n = SHA-256(digest_{n-1} ||
canonical(record_n))``. Any edit, reorder or deletion breaks verification from
that point on, and verification needs no keys and no network.

This is deliberately *not* a signature scheme (ADR-0005). A hash chain proves
**integrity** -- the log has not been altered since it was written. It does not
prove **authenticity** -- that IDENSEC wrote it. Signing is worth its complexity
only when a relying party exists who will verify and act on the result, and
today none does. The distinction is stated here because blurring it is how
audit features become security theatre.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

__all__ = ["GENESIS", "AuditChain", "AuditRecord", "canonical_bytes"]

GENESIS = "0" * 64
CANONICALISATION_VERSION = 1


def canonical_bytes(payload: Mapping[str, Any]) -> bytes:
    """Stable byte encoding of a record.

    Pinned and versioned: changing this silently would invalidate every chain
    ever written, so the version travels inside the encoded bytes.
    """
    envelope = {"_canon": CANONICALISATION_VERSION, "payload": payload}
    return json.dumps(
        envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str
    ).encode("utf-8")


@dataclass(frozen=True, slots=True)
class AuditRecord:
    index: int
    previous: str
    digest: str
    payload: Mapping[str, Any]

    def recompute(self) -> str:
        return hashlib.sha256(
            self.previous.encode("ascii") + canonical_bytes(self.payload)
        ).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "previous": self.previous,
            "digest": self.digest,
            "payload": dict(self.payload),
        }


class AuditChain:
    """Append-only, hash-linked sequence of decision records."""

    def __init__(self, records: Sequence[AuditRecord] = ()) -> None:
        self._records: list[AuditRecord] = list(records)

    @property
    def head(self) -> str:
        return self._records[-1].digest if self._records else GENESIS

    def append(self, payload: Mapping[str, Any]) -> AuditRecord:
        previous = self.head
        digest = hashlib.sha256(
            previous.encode("ascii") + canonical_bytes(payload)
        ).hexdigest()
        record = AuditRecord(
            index=len(self._records), previous=previous, digest=digest, payload=payload
        )
        self._records.append(record)
        return record

    def verify(self) -> bool:
        """Recompute the whole chain. Returns False on the first mismatch."""
        previous = GENESIS
        for index, record in enumerate(self._records):
            if record.index != index or record.previous != previous:
                return False
            if record.recompute() != record.digest:
                return False
            previous = record.digest
        return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": "idensec.audit/v1",
            "records": [r.to_dict() for r in self._records],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> AuditChain:
        if data.get("schema") != "idensec.audit/v1":
            raise ValueError(f"unsupported audit schema: {data.get('schema')!r}")
        return cls(
            [
                AuditRecord(
                    index=r["index"],
                    previous=r["previous"],
                    digest=r["digest"],
                    payload=r["payload"],
                )
                for r in data.get("records", ())
            ]
        )

    def __len__(self) -> int:
        return len(self._records)

    def __iter__(self) -> Iterator[AuditRecord]:
        yield from self._records

    def __getitem__(self, index: int) -> AuditRecord:
        return self._records[index]
