"""Contract linter.

The linter's job is to catch the mistakes that are mechanically detectable
before they reach production, because a wrong contract is a *silent* bypass:
the monitor faithfully allows the call and reports no finding, since as far as
it knows nothing authority-bearing was involved.

Two kinds of test here. The first asserts that each known-bad pattern is
caught. The second -- more important, and easier to forget -- asserts that
correct contracts produce nothing, because a linter that cries wolf gets
switched off and then catches nothing at all.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from idensec.contracts import (
    ContractRegistry,
    Effect,
    ParameterContract,
    Role,
    ToolContract,
)
from idensec.labels import Source, Trust
from idensec.lint import Severity, lint_contract, lint_registry, lint_sources, render

ROOT = Path(__file__).resolve().parent.parent


def codes(diagnostics) -> set[str]:
    return {d.code for d in diagnostics}


def errors(diagnostics) -> set[str]:
    return {d.code for d in diagnostics if d.severity is Severity.ERROR}


GOOD = ToolContract(
    tool="send_email",
    parameters={
        "to": ParameterContract("to", Role.AUTHORITY, frozenset({"email"})),
        "subject": ParameterContract("subject", Role.PAYLOAD),
        "body": ParameterContract("body", Role.PAYLOAD),
    },
    effects=frozenset({Effect.NETWORK_EGRESS, Effect.WRITE}),
)


class TestCatchesRealBypasses:
    def test_authority_parameter_downgraded_to_payload(self) -> None:
        """The bypass that motivates the whole module: mark the recipient as
        content and an attacker chooses it, silently."""
        contract = ToolContract(
            tool="send_email",
            parameters={
                "to": ParameterContract("to", Role.PAYLOAD),
                "body": ParameterContract("body", Role.PAYLOAD),
            },
            effects=frozenset({Effect.NETWORK_EGRESS}),
        )
        assert "authority-name-downgraded" in errors(lint_contract(contract))

    @pytest.mark.parametrize(
        "name", ["to", "recipient", "url", "webhook", "path", "iban", "cmd", "bcc"]
    )
    def test_authority_reading_names_are_recognised(self, name: str) -> None:
        contract = ToolContract(
            tool="t",
            parameters={name: ParameterContract(name, Role.PAYLOAD)},
            effects=frozenset({Effect.WRITE}),
        )
        assert "authority-name-downgraded" in errors(lint_contract(contract))

    def test_advisory_on_a_security_relevant_name(self) -> None:
        contract = ToolContract(
            tool="t",
            parameters={"destination": ParameterContract("destination", Role.ADVISORY)},
            effects=frozenset({Effect.WRITE}),
        )
        assert "advisory-authority-name" in errors(lint_contract(contract))

    def test_egress_tool_with_no_authority_parameter(self) -> None:
        contract = ToolContract(
            tool="post",
            parameters={"payload": ParameterContract("payload", Role.PAYLOAD)},
            effects=frozenset({Effect.NETWORK_EGRESS}),
        )
        assert "unconstrained-egress" in errors(lint_contract(contract))

    def test_permissive_default_role(self) -> None:
        """Undeclared parameters are exactly the ones nobody thought about."""
        contract = ToolContract(
            tool="t",
            parameters={"to": ParameterContract("to", Role.AUTHORITY, frozenset({"email"}))},
            effects=frozenset({Effect.WRITE}),
            default_role=Role.PAYLOAD,
        )
        assert "permissive-default-role" in errors(lint_contract(contract))

    def test_uncompleted_draft_is_an_error(self) -> None:
        """A contract with no effects is what --emit-contracts produces."""
        contract = ToolContract(
            tool="t",
            parameters={"to": ParameterContract("to", Role.AUTHORITY, frozenset({"email"}))},
        )
        assert "no-effects-declared" in errors(lint_contract(contract))

    def test_misspelled_kind_makes_a_tool_permanently_unusable(self) -> None:
        contract = ToolContract(
            tool="t",
            parameters={"to": ParameterContract("to", Role.AUTHORITY, frozenset({"emial"}))},
            effects=frozenset({Effect.WRITE}),
        )
        assert "unknown-operand-kind" in errors(lint_contract(contract))

    def test_amount_declared_as_payload(self) -> None:
        contract = ToolContract(
            tool="transfer",
            parameters={
                "iban": ParameterContract("iban", Role.AUTHORITY, frozenset({"iban"})),
                "amount": ParameterContract("amount", Role.PAYLOAD),
            },
            effects=frozenset({Effect.FINANCIAL}),
        )
        assert "amount-not-authority" in codes(lint_contract(contract))

    def test_kinds_on_a_payload_parameter_signal_a_wrong_role(self) -> None:
        contract = ToolContract(
            tool="t",
            parameters={
                "note": ParameterContract("note", Role.PAYLOAD, frozenset({"email"})),
                "target": ParameterContract("target", Role.AUTHORITY, frozenset({"url"})),
            },
            effects=frozenset({Effect.WRITE}),
        )
        assert "kinds-on-non-authority" in codes(lint_contract(contract))


class TestDoesNotCryWolf:
    def test_a_correct_contract_is_silent(self) -> None:
        assert lint_contract(GOOD) == []

    def test_read_only_tool_without_authority_params_is_not_an_error(self) -> None:
        contract = ToolContract(
            tool="search",
            parameters={"query": ParameterContract("query", Role.PAYLOAD)},
            effects=frozenset({Effect.READ}),
        )
        assert errors(lint_contract(contract)) == set()

    @pytest.mark.parametrize("name", ["body", "subject", "topic", "somebody", "history"])
    def test_content_names_are_not_mistaken_for_authority(self, name: str) -> None:
        """Token matching, not substring: 'topic' must not match 'to'."""
        contract = ToolContract(
            tool="t",
            parameters={
                name: ParameterContract(name, Role.PAYLOAD),
                "to": ParameterContract("to", Role.AUTHORITY, frozenset({"email"})),
            },
            effects=frozenset({Effect.WRITE}),
        )
        assert errors(lint_contract(contract)) == set()

    def test_authority_without_kinds_is_only_a_note(self) -> None:
        """Restrictive and correct, so it must not be reported as a problem."""
        contract = ToolContract(
            tool="t",
            parameters={"path": ParameterContract("path", Role.AUTHORITY)},
            effects=frozenset({Effect.READ}),
        )
        diagnostics = lint_contract(contract)
        assert codes(diagnostics) == {"authority-without-kinds"}
        assert errors(diagnostics) == set()


class TestFalsePositivesFoundAgainstRealServers:
    """Both refinements here were forced by running the linter against the
    reference MCP time server. A linter that reports errors on a correct
    contract gets switched off, and then catches nothing at all."""

    @pytest.mark.parametrize(
        "name", ["target_timezone", "source_timezone", "output_format", "target_locale"]
    )
    def test_presentational_head_nouns_are_not_authority(self, name: str) -> None:
        """'target' reads as authority; a timezone is not one."""
        contract = ToolContract(
            tool="convert_time",
            parameters={name: ParameterContract(name, Role.ADVISORY)},
            effects=frozenset({Effect.READ}),
        )
        assert errors(lint_contract(contract)) == set()

    def test_the_exemption_does_not_cover_real_authority_names(self) -> None:
        """target_url must still be flagged: no presentational token present."""
        contract = ToolContract(
            tool="t",
            parameters={"target_url": ParameterContract("target_url", Role.PAYLOAD)},
            effects=frozenset({Effect.NETWORK_EGRESS})
            | frozenset({Effect.WRITE}),
        )
        assert "authority-name-downgraded" in errors(lint_contract(contract))

    def test_read_only_tool_with_only_presentational_params_is_a_note(self) -> None:
        """get_current_time(timezone) is a correct contract, not a problem."""
        contract = ToolContract(
            tool="get_current_time",
            parameters={"timezone": ParameterContract("timezone", Role.ADVISORY)},
            effects=frozenset({Effect.READ}),
        )
        diagnostics = lint_contract(contract)
        assert errors(diagnostics) == set()
        assert all(d.severity is Severity.NOTE for d in diagnostics)

    def test_a_writing_tool_with_no_authority_parameter_is_still_flagged(self) -> None:
        """The exemption is for read-only tools only."""
        contract = ToolContract(
            tool="wipe",
            parameters={"confirm_text": ParameterContract("confirm_text", Role.PAYLOAD)},
            effects=frozenset({Effect.DELETE}),
        )
        assert "no-authority-parameter" in errors(lint_contract(contract))


class TestSourceGrants:
    def test_over_trusted_source_is_flagged(self) -> None:
        source = Source("web", Trust.USER_INPUT)
        assert "source-trusted-as-principal" in codes(
            lint_sources([source], ContractRegistry([GOOD]))
        )

    def test_grant_for_an_unregistered_kind_is_an_error(self) -> None:
        source = Source("dir", Trust.TOOL_TRUSTED, authoritative_for=frozenset({"emial"}))
        assert "unknown-operand-kind" in errors(
            lint_sources([source], ContractRegistry([GOOD]))
        )

    def test_grant_no_contract_consumes_is_a_note(self) -> None:
        source = Source("dir", Trust.TOOL_TRUSTED, authoritative_for=frozenset({"iban"}))
        diagnostics = lint_sources([source], ContractRegistry([GOOD]))
        assert "unused-source-grant" in codes(diagnostics)
        assert errors(diagnostics) == set()

    def test_a_grant_that_is_consumed_is_silent(self) -> None:
        source = Source("dir", Trust.TOOL_TRUSTED, authoritative_for=frozenset({"email"}))
        assert lint_sources([source], ContractRegistry([GOOD])) == []


class TestRegistry:
    def test_empty_registry_is_an_error(self) -> None:
        assert "empty-registry" in errors(lint_registry(ContractRegistry()))

    def test_findings_are_ordered_worst_first(self) -> None:
        bad = ToolContract(
            tool="send_email",
            parameters={"to": ParameterContract("to", Role.PAYLOAD)},
            effects=frozenset({Effect.NETWORK_EGRESS}),
        )
        diagnostics = lint_registry(ContractRegistry([bad, GOOD]))
        severities = [d.severity for d in diagnostics]
        assert severities == sorted(severities, reverse=True)

    def test_render_is_readable(self) -> None:
        output = render(lint_registry(ContractRegistry()))
        assert "empty-registry" in output and "1 error" in output


class TestShippedArtefactsLintClean:
    """Dogfooding. If our own examples do not pass, nobody else's will."""

    def test_example_contracts_are_clean(self) -> None:
        registry = ContractRegistry.load(ROOT / "examples/mcp/filesystem-contracts.json")
        assert errors(lint_registry(registry)) == set()

    def test_test_fixture_contracts_are_clean(self) -> None:
        from conftest import DEFAULT_CONTRACTS

        diagnostics = lint_registry(ContractRegistry(DEFAULT_CONTRACTS))
        assert errors(diagnostics) == set(), render(diagnostics)


class TestCLI:
    def _run(self, *args: str) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(  # noqa: S603 - fixed test command
            [sys.executable, "-m", "idensec.lint", *args],
            capture_output=True,
            cwd=ROOT,
            env={"PYTHONPATH": str(ROOT / "src"), "PATH": "/usr/bin:/bin"},
            timeout=60,
        )

    def test_clean_contracts_exit_zero(self) -> None:
        result = self._run("examples/mcp/filesystem-contracts.json")
        assert result.returncode == 0
        assert b"no findings" in result.stdout

    def test_errors_exit_nonzero(self, tmp_path: Path) -> None:
        path = tmp_path / "bad.json"
        path.write_text(
            json.dumps(
                {
                    "schema": "idensec.contracts/v1",
                    "contracts": [
                        {
                            "tool": "send_email",
                            "effects": ["network_egress"],
                            "default_role": "authority",
                            "parameters": {"to": {"role": "payload"}},
                        }
                    ],
                }
            )
        )
        result = self._run(str(path))
        assert result.returncode == 1
        assert b"authority-name-downgraded" in result.stdout

    def test_json_output_is_parseable(self, tmp_path: Path) -> None:
        result = self._run("examples/mcp/filesystem-contracts.json", "--json")
        assert json.loads(result.stdout.decode()) == []

    def test_unreadable_file_exits_two(self, tmp_path: Path) -> None:
        result = self._run(str(tmp_path / "nope.json"))
        assert result.returncode == 2
