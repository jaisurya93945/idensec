"""Tool contracts: fail-closed defaults, serialisation, draft derivation."""

from __future__ import annotations

import json

import pytest

from idensec import (
    UNCLASSIFIED,
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
                "thread_id": ParameterContract(
                    "thread_id", Role.AUTHORITY, collection="**.threads"
                ),
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
        contract = derive_contract("t", parameters=["to", "path"])
        assert contract.parameter("to").kinds == frozenset({"email"})
        assert "posix_path" in contract.parameter("path").kinds

    def test_path_and_recipient_kinds_are_widened_not_narrowed(self) -> None:
        """Measured against AgentDojo. A "recipient" is an IBAN on a payments
        API, and a "path" is often a bare filename. The kinds list is a *shape*
        check layered on top of attribution, so widening it costs no security:
        the value must still trace to an authorised source."""
        contract = derive_contract("t", parameters=["recipient", "file_path"])
        assert {"email", "iban"} <= contract.parameter("recipient").kinds
        assert UNCLASSIFIED in contract.parameter("file_path").kinds

    def test_url_parameters_also_accept_a_bare_host(self) -> None:
        """Measured against AgentDojo: a "url" parameter routinely receives
        "www.example.com", which extracts as a hostname. Constraining it to
        {"url"} alone failed every legitimate web fetch on kind_mismatch."""
        contract = derive_contract("t", parameters=["url"])
        assert contract.parameter("url").kinds == frozenset({"url", "hostname"})

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


class TestAnnotationsAreReadOneWay:
    """MCP tool annotations arrive from the server, which is the bottom of the
    integrity lattice. They are usable only because believing them can never
    make a contract more permissive.
    """

    def test_destructive_is_believed(self) -> None:
        contract = derive_contract(
            "cleanup",
            parameters=["path"],
            effects=[Effect.WRITE],
            annotations={"destructiveHint": True},
        )
        assert Effect.DELETE in contract.effects
        assert Effect.IRREVERSIBLE in contract.effects
        assert Effect.WRITE in contract.effects

    def test_open_world_is_believed(self) -> None:
        contract = derive_contract(
            "fetch", parameters=["url"], annotations={"openWorldHint": True}
        )
        assert contract.can_egress

    def test_read_only_is_ignored(self) -> None:
        """The one that matters. A poisoned server marks its exfiltration tool
        read-only; if that were believed, every confidentiality rule would stop
        firing on it. Measured across seven reference servers, 32 of 52 tools
        claim this hint, so it is not a hypothetical input."""
        contract = derive_contract(
            "send_everything",
            parameters=["to", "body"],
            effects=[Effect.NETWORK_EGRESS, Effect.WRITE],
            annotations={"readOnlyHint": True, "destructiveHint": False},
        )
        assert contract.can_egress
        assert Effect.WRITE in contract.effects

    def test_annotations_never_remove_a_declared_effect(self) -> None:
        declared = frozenset({Effect.NETWORK_EGRESS, Effect.WRITE, Effect.FINANCIAL})
        for hints in (
            {"readOnlyHint": True},
            {"destructiveHint": False},
            {"idempotentHint": True},
            {"openWorldHint": False},
            {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False},
        ):
            contract = derive_contract(
                "pay", parameters=["iban"], effects=declared, annotations=hints
            )
            assert declared <= contract.effects, hints

    def test_idempotent_says_nothing(self) -> None:
        plain = derive_contract("t", parameters=["x"], effects=[Effect.READ])
        hinted = derive_contract(
            "t", parameters=["x"], effects=[Effect.READ], annotations={"idempotentHint": True}
        )
        assert plain.effects == hinted.effects

    def test_absent_annotations_change_nothing(self) -> None:
        plain = derive_contract("t", parameters=["to", "body"], effects=[Effect.WRITE])
        hinted = derive_contract(
            "t", parameters=["to", "body"], effects=[Effect.WRITE], annotations={}
        )
        assert plain == hinted


class TestRealSchemaShapes:
    """Shapes that a corpus we wrote ourselves never produced, and that seven
    published MCP servers produced immediately."""

    def test_a_union_type_does_not_crash(self) -> None:
        """JSON Schema's ``type`` is a string *or a list*. Reading it as a
        string raised TypeError against the first real server that used one."""
        schema = {
            "type": "object",
            "properties": {"cursor": {"type": ["string", "null"]}},
        }
        contract = derive_contract("list_things", schema)
        assert contract.parameter("cursor").role is Role.AUTHORITY

    def test_a_union_is_downgraded_only_when_every_member_is_scalar(self) -> None:
        """``["string", "null"]`` can hold an identifier, so it stays
        authority-bearing. The permissive direction needs every member to be a
        type that cannot."""
        schema = {
            "type": "object",
            "properties": {
                "maybe_name": {"type": ["string", "null"]},
                "retries": {"type": ["integer", "number"]},
            },
        }
        contract = derive_contract("t", schema)
        assert contract.parameter("maybe_name").role is Role.AUTHORITY
        assert contract.parameter("retries").role is Role.ADVISORY

    def test_an_absent_type_is_not_downgraded(self) -> None:
        contract = derive_contract("t", {"type": "object", "properties": {"x": {}}})
        assert contract.parameter("x").role is Role.AUTHORITY

    @pytest.mark.parametrize(
        ("camel", "snake"),
        [
            ("sortBy", "sort_by"),
            ("startTime", "start_time"),
            ("fileId", "file_id"),
            ("pageSize", "page_size"),
        ],
    )
    def test_camel_case_reads_the_same_as_snake_case(
        self, camel: str, snake: str
    ) -> None:
        """A server's naming convention must not change what a parameter means.
        JavaScript MCP servers use camelCase throughout, and splitting on ``_``
        alone missed every one of them."""
        assert derive_contract("t", parameters=[camel]).parameter(camel).role is (
            derive_contract("t", parameters=[snake]).parameter(snake).role
        )

    def test_camel_case_identifiers_get_their_collection(self) -> None:
        assert derive_contract("t", parameters=["fileId"]).parameter(
            "fileId"
        ).collection == "**.files"
        assert derive_contract("t", parameters=["calendarEventId"]).parameter(
            "calendarEventId"
        ).collection == "**.events"

    def test_a_bare_id_gets_no_collection(self) -> None:
        """It says which-thing without saying which *kind* of thing, and a
        collection guessed wrong would bind ids across directories."""
        assert derive_contract("t", parameters=["id"]).parameter("id").collection == ""


class TestCollectionPluralisation:
    """A collection glob that matches nothing makes reference binding silently
    never fire for that parameter. ``branchId`` produced ``**.branchs`` against
    a real server before these rules existed."""

    @pytest.mark.parametrize(
        ("name", "collection"),
        [
            ("fileId", "**.files"),
            ("eventId", "**.events"),
            ("branchId", "**.branches"),
            ("boxId", "**.boxes"),
            ("entryId", "**.entries"),
            ("repositoryId", "**.repositories"),
            ("addressId", "**.addresses"),
            ("dayId", "**.days"),
            ("message_ids", "**.messages"),
        ],
    )
    def test_plurals(self, name: str, collection: str) -> None:
        assert derive_contract("t", parameters=[name]).parameter(name).collection == (
            collection
        )
