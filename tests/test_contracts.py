"""Tool contracts: fail-closed defaults, serialisation, draft derivation."""

from __future__ import annotations

import json

import pytest

from idensec import (
    ContractRegistry,
    Effect,
    ParameterContract,
    Role,
    ToolContract,
    derive_contract,
)


class TestFailClosed:
    def test_undeclared_parameters_default_to_authority(self) -> None:
        contract = ToolContract(
            tool="t", parameters={"a": ParameterContract("a", Role.PAYLOAD)}
        )
        assert contract.parameter("b").role is Role.AUTHORITY

    def test_default_role_is_authority(self) -> None:
        assert ToolContract(tool="t").default_role is Role.AUTHORITY

    def test_registry_has_no_fallback(self) -> None:
        """"Unknown tool" is a policy question; the registry refuses to answer it."""
        assert ContractRegistry().get("anything") is None


class TestSerialisation:
    def test_round_trip(self) -> None:
        contract = ToolContract(
            tool="send_email",
            parameters={
                "to": ParameterContract("to", Role.AUTHORITY, frozenset({"email"})),
                "body": ParameterContract("body", Role.PAYLOAD),
            },
            effects=frozenset({Effect.NETWORK_EGRESS, Effect.WRITE}),
        )
        registry = ContractRegistry([contract])
        assert ContractRegistry.from_dict(registry.to_dict()).get("send_email") == contract

    def test_contracts_are_plain_json(self) -> None:
        """Contracts must be data so a corpus can be shared, diffed and reviewed."""
        registry = ContractRegistry([derive_contract("t", parameters=["to", "body"])])
        json.dumps(registry.to_dict())

    def test_unknown_schema_is_refused(self) -> None:
        with pytest.raises(ValueError, match="unsupported contract schema"):
            ContractRegistry.from_dict({"schema": "something/v9", "contracts": []})

    def test_file_round_trip(self, tmp_path) -> None:
        registry = ContractRegistry([derive_contract("t", parameters=["to", "body"])])
        path = tmp_path / "contracts.json"
        registry.dump(path)
        assert len(ContractRegistry.load(path)) == 1


class TestDerivation:
    def test_content_parameters_are_downgraded(self) -> None:
        contract = derive_contract("t", parameters=["to", "subject", "body", "limit"])
        assert contract.parameter("subject").role is Role.PAYLOAD
        assert contract.parameter("body").role is Role.PAYLOAD
        assert contract.parameter("limit").role is Role.ADVISORY

    def test_unrecognised_parameters_stay_authority(self) -> None:
        """The deriver never guesses toward permissiveness."""
        contract = derive_contract("t", parameters=["frobnicate"])
        assert contract.parameter("frobnicate").role is Role.AUTHORITY

    def test_kinds_are_suggested_from_names(self) -> None:
        contract = derive_contract("t", parameters=["to", "url", "path"])
        assert contract.parameter("to").kinds == frozenset({"email"})
        assert contract.parameter("url").kinds == frozenset({"url"})
        assert contract.parameter("path").kinds == frozenset({"posix_path"})

    def test_amounts_stay_authority_despite_being_numeric(self) -> None:
        schema = {"properties": {"amount": {"type": "number"}, "page": {"type": "integer"}}}
        contract = derive_contract("t", schema)
        assert contract.parameter("amount").role is Role.AUTHORITY
        assert contract.parameter("page").role is Role.ADVISORY

    def test_effects_are_never_inferred(self) -> None:
        """Guessing that a tool is read-only would be the most dangerous
        inference in the system, so the deriver refuses to make it."""
        assert derive_contract("send_email", parameters=["to"]).effects == frozenset()

    def test_schema_descriptions_are_carried_through(self) -> None:
        schema = {"properties": {"to": {"type": "string", "description": "recipient"}}}
        assert derive_contract("t", schema).parameter("to").description == "recipient"


class TestDeriverRulesFoundByMeasurement:
    """Both rules here fix a *dangerous miss* found by
    benchmarks/contract_derivation.py -- an authority-bearing parameter drafted
    as something weaker, which is a silent hole if a reviewer skims past it."""

    @pytest.mark.parametrize(
        "name",
        ["message_id", "thread_id", "charge_id", "function_arn", "api_key",
         "resource_uri", "callback_url", "file_path", "parent_ref", "session_token"],
    )
    def test_identifier_suffixes_outrank_content_hints(self, name: str) -> None:
        """'message_id' reads as content and is a reference. Which-thing is
        authority, and the suffix must win."""
        contract = derive_contract("t", parameters=[name])
        assert contract.parameter(name).role is Role.AUTHORITY

    @pytest.mark.parametrize(
        "flag", ["force", "recursive", "overwrite", "permanent", "purge", "cascade"]
    )
    def test_dangerous_booleans_stay_authority(self, flag: str) -> None:
        """Booleans carry authority when they widen what an action destroys."""
        schema = {"properties": {flag: {"type": "boolean"}}}
        assert derive_contract("t", schema).parameter(flag).role is Role.AUTHORITY

    def test_harmless_booleans_are_still_advisory(self) -> None:
        schema = {
            "properties": {
                "verbose": {"type": "boolean"},
                "dry_run": {"type": "boolean"},
            }
        }
        contract = derive_contract("t", schema)
        assert contract.parameter("verbose").role is Role.ADVISORY
        assert contract.parameter("dry_run").role is Role.ADVISORY

    def test_the_deriver_still_errs_toward_authority(self) -> None:
        """Over-restriction costs review effort; under-restriction costs
        security. When in doubt the draft must be restrictive."""
        contract = derive_contract("t", parameters=["frobnicate", "widget", "zzz"])
        assert all(
            contract.parameter(n).role is Role.AUTHORITY
            for n in ("frobnicate", "widget", "zzz")
        )


class TestEffects:
    def test_egress_detection(self) -> None:
        assert ToolContract(tool="t", effects=frozenset({Effect.NETWORK_EGRESS})).can_egress

    def test_consequential_detection(self) -> None:
        assert not ToolContract(tool="t", effects=frozenset({Effect.READ})).is_consequential
        assert ToolContract(tool="t", effects=frozenset({Effect.DELETE})).is_consequential
