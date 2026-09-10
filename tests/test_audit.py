"""Audit chain integrity."""

from __future__ import annotations

import pytest

from idensec.audit import GENESIS, AuditChain


class TestChain:
    def test_empty_chain_verifies(self) -> None:
        assert AuditChain().verify()
        assert AuditChain().head == GENESIS

    def test_appends_link(self) -> None:
        chain = AuditChain()
        first = chain.append({"a": 1})
        second = chain.append({"b": 2})
        assert second.previous == first.digest
        assert chain.verify()

    def test_edited_payload_breaks_verification(self) -> None:
        chain = AuditChain()
        chain.append({"verdict": "deny"})
        chain.append({"verdict": "allow"})
        tampered = chain.to_dict()
        tampered["records"][0]["payload"]["verdict"] = "allow"
        assert not AuditChain.from_dict(tampered).verify()

    def test_deleted_record_breaks_verification(self) -> None:
        chain = AuditChain()
        for i in range(3):
            chain.append({"i": i})
        tampered = chain.to_dict()
        del tampered["records"][1]
        assert not AuditChain.from_dict(tampered).verify()

    def test_reordered_records_break_verification(self) -> None:
        chain = AuditChain()
        for i in range(3):
            chain.append({"i": i})
        tampered = chain.to_dict()
        tampered["records"][1], tampered["records"][2] = (
            tampered["records"][2],
            tampered["records"][1],
        )
        assert not AuditChain.from_dict(tampered).verify()

    def test_round_trip_preserves_verification(self) -> None:
        chain = AuditChain()
        chain.append({"a": 1})
        assert AuditChain.from_dict(chain.to_dict()).verify()

    def test_unknown_schema_is_refused(self) -> None:
        with pytest.raises(ValueError, match="unsupported audit schema"):
            AuditChain.from_dict({"schema": "other/v1", "records": []})

    def test_canonicalisation_is_key_order_independent(self) -> None:
        left, right = AuditChain(), AuditChain()
        left.append({"a": 1, "b": 2})
        right.append({"b": 2, "a": 1})
        assert left.head == right.head
