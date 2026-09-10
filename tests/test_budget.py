"""Aggregate constraints.

Every other check judges one call alone. Budgets exist for the gap that leaves,
which the founding brief named directly: *book me a flight under 50,000* is
satisfied by each individual booking and violated by three of them.

The budget mechanism is itself worth attacking. Two failure modes matter more
than the happy path: a budget that can be exhausted by *denied* calls is a
denial-of-service handed to the attacker, and a budget that silently ignores an
argument shape it does not understand is worse than no budget, because it looks
enforced.
"""

from __future__ import annotations

import pytest

from idensec import (
    Budget,
    Disposition,
    Effect,
    FindingCode,
    Meter,
    ParameterContract,
    Policy,
    Role,
    Session,
    Source,
    ToolContract,
    Trust,
    Verdict,
)
from idensec.budget import BudgetLedger

BOOK = ToolContract(
    tool="book_flight",
    parameters={
        "flight": ParameterContract("flight", Role.AUTHORITY),
        "price": ParameterContract("price", Role.AUTHORITY),
    },
    effects=frozenset({Effect.FINANCIAL, Effect.IRREVERSIBLE}),
)
MAIL = ToolContract(
    tool="send_email",
    parameters={
        "to": ParameterContract("to", Role.AUTHORITY, frozenset({"email"})),
        "body": ParameterContract("body", Role.PAYLOAD),
    },
    effects=frozenset({Effect.NETWORK_EGRESS}),
)
LOOKUP = ToolContract(
    tool="search",
    parameters={"query": ParameterContract("query", Role.PAYLOAD)},
    effects=frozenset({Effect.READ}),
)

# The task names every value these tests use. That is not a convenience: an
# argument absent from it is unattributable and would be denied on provenance,
# so a budget test written against unnamed values would pass for the wrong
# reason and keep passing if budgets stopped working entirely.
TASK = (
    "Book me flights under 50000 total. Options: AI302 at 20000, AI511 at 20000, "
    "AI777 at 20000, and a 100 seat fee on each. Mail confirmations to "
    "ana@corp.example, bo@corp.example and cy@corp.example."
)


@pytest.fixture
def booking(ids):
    def _make(budgets, policy: Policy | None = None) -> Session:
        session = Session(
            contracts=[BOOK, MAIL, LOOKUP],
            policy=policy or Policy(),
            sources=[
                Source("principal", Trust.USER_INPUT),
                Source("web", Trust.TOOL_UNTRUSTED),
            ],
            budgets=budgets,
            id_factory=ids,
        )
        session.observe("principal", TASK)
        return session

    return _make


class TestTheFoundingExample:
    def test_individually_authorised_bookings_are_stopped_in_aggregate(self, booking) -> None:
        session = booking([
            Budget("trip_spend", 50000, Meter.SUM, parameter="price",
                   effects=frozenset({Effect.FINANCIAL}))
        ])
        verdicts = [
            session.admit("book_flight", {"flight": f, "price": 20000}).verdict
            for f in ("AI302", "AI511", "AI777")
        ]
        assert verdicts == [Verdict.ALLOW, Verdict.ALLOW, Verdict.DENY]
        assert session.budgets.used("trip_spend") == 40000

    def test_the_breach_is_explained_in_the_audit(self, booking) -> None:
        session = booking([
            Budget("trip_spend", 30000, Meter.SUM, parameter="price",
                   effects=frozenset({Effect.FINANCIAL}))
        ])
        session.admit("book_flight", {"flight": "AI302", "price": 20000})
        decision = session.admit("book_flight", {"flight": "AI511", "price": 20000})
        assert decision.findings[0].code is FindingCode.BUDGET_EXCEEDED
        assert "40000" in decision.reason() and "30000" in decision.reason()

    def test_the_agent_learns_nothing_about_the_limit(self, booking) -> None:
        """A budget the agent can read is a budget it can plan around."""
        session = booking([
            Budget("trip_spend", 30000, Meter.SUM, parameter="price",
                   effects=frozenset({Effect.FINANCIAL}))
        ])
        session.admit("book_flight", {"flight": "AI302", "price": 20000})
        decision = session.admit("book_flight", {"flight": "AI511", "price": 20000})
        assert "30000" not in decision.agent_message
        assert "budget" not in decision.agent_message.lower()


class TestMeters:
    def test_call_count(self, booking) -> None:
        session = booking([
            Budget("bookings", 2, Meter.CALLS, tools=frozenset({"book_flight"}))
        ])
        results = [
            session.admit("book_flight", {"flight": f, "price": 100}).allowed
            for f in ("AI302", "AI511", "AI777")
        ]
        assert results == [True, True, False]

    def test_distinct_destinations(self, booking) -> None:
        """Fan-out: the limit is on how many different places are touched."""
        session = booking([
            Budget("recipients", 2, Meter.DISTINCT, parameter="to",
                   effects=frozenset({Effect.NETWORK_EGRESS}))
        ])
        assert session.admit("send_email", {"to": "ana@corp.example", "body": "x"}).allowed
        assert session.admit("send_email", {"to": "bo@corp.example", "body": "x"}).allowed
        assert not session.admit("send_email", {"to": "cy@corp.example", "body": "x"}).allowed

    def test_repeating_a_destination_costs_nothing(self, booking) -> None:
        session = booking([
            Budget("recipients", 1, Meter.DISTINCT, parameter="to",
                   effects=frozenset({Effect.NETWORK_EGRESS}))
        ])
        for _ in range(4):
            assert session.admit("send_email", {"to": "ana@corp.example", "body": "x"}).allowed

    @pytest.mark.parametrize(
        "amount", [20000, 20000.0, "20000", "20,000", "20_000", "₹20000", "$20000"]
    )
    def test_numeric_shapes_are_all_counted(self, amount) -> None:
        """Measured at the ledger, deliberately.

        Tool arguments carry numbers as ints, floats, and strings with
        separators and currency marks. A meter that silently ignored a shape it
        did not understand would look enforced and not be, which is worse than
        having no budget at all.
        """
        ledger = BudgetLedger([
            Budget("spend", 30000, Meter.SUM, parameter="price",
                   effects=frozenset({Effect.FINANCIAL}))
        ])
        ledger.commit(BOOK, {"price": amount})
        assert ledger.used("spend") == 20000

    def test_unparseable_amounts_contribute_nothing(self) -> None:
        ledger = BudgetLedger([Budget("spend", 10, Meter.SUM, parameter="price")])
        ledger.commit(BOOK, {"price": "free of charge"})
        ledger.commit(BOOK, {"price": None})
        ledger.commit(BOOK, {"price": True})
        assert ledger.used("spend") == 0


class TestScope:
    def test_effect_scope_excludes_unrelated_tools(self, booking) -> None:
        session = booking([
            Budget("spend", 1, Meter.CALLS, effects=frozenset({Effect.FINANCIAL}))
        ])
        for _ in range(5):
            assert session.admit("search", {"query": "flights"}).allowed

    def test_tool_scope_is_respected(self, booking) -> None:
        session = booking([
            Budget("mails", 1, Meter.CALLS, tools=frozenset({"send_email"}))
        ])
        assert session.admit("book_flight", {"flight": "AI302", "price": 100}).allowed
        assert session.admit("send_email", {"to": "ana@corp.example", "body": "x"}).allowed
        assert not session.admit("send_email", {"to": "bo@corp.example", "body": "x"}).allowed


class TestAttacksOnTheMechanism:
    def test_denied_calls_do_not_consume_budget(self, booking) -> None:
        """Otherwise an attacker exhausts the principal's allowance with calls
        that were never going to succeed."""
        session = booking(
            [Budget("bookings", 2, Meter.CALLS, tools=frozenset({"book_flight"}))],
            policy=Policy(denial_budget=-1),
        )
        for _ in range(5):
            # Unattributable flight number: denied on provenance, not budget.
            assert not session.admit(
                "book_flight", {"flight": "ZZ999", "price": 20000}
            ).allowed
        assert session.budgets.used("bookings") == 0
        assert session.admit("book_flight", {"flight": "AI302", "price": 100}).allowed

    def test_budget_denial_does_not_consume_budget_either(self, booking) -> None:
        session = booking(
            [Budget("bookings", 1, Meter.CALLS, tools=frozenset({"book_flight"}))],
            policy=Policy(denial_budget=-1),
        )
        session.admit("book_flight", {"flight": "AI302", "price": 100})
        for _ in range(3):
            session.admit("book_flight", {"flight": "AI511", "price": 100})
        assert session.budgets.used("bookings") == 1

    def test_a_zero_limit_stops_everything_in_scope(self, booking) -> None:
        session = booking([
            Budget("no_spending", 0, Meter.CALLS, effects=frozenset({Effect.FINANCIAL}))
        ])
        assert not session.admit("book_flight", {"flight": "AI302", "price": 100}).allowed

    def test_provenance_still_applies_under_a_budget(self, booking) -> None:
        """Budgets are an additional constraint, never a replacement. A flight
        code the principal never named is still unattributable."""
        session = booking(
            [Budget("bookings", 10, Meter.CALLS)], policy=Policy(denial_budget=-1)
        )
        decision = session.admit("book_flight", {"flight": "ZZ999", "price": 20000})
        assert decision.findings[0].code is FindingCode.UNATTRIBUTED_AUTHORITY


class TestSupervision:
    def test_supervised_policy_escalates_a_breach(self, booking) -> None:
        session = booking(
            [Budget("spend", 10000, Meter.SUM, parameter="price",
                    effects=frozenset({Effect.FINANCIAL}))],
            policy=Policy(budget_exceeded=Disposition.ESCALATE),
        )
        decision = session.admit("book_flight", {"flight": "AI302", "price": 20000})
        assert decision.verdict is Verdict.ESCALATE

    def test_approval_charges_the_budget(self, booking) -> None:
        """A human overriding a limit still spends against it; otherwise the
        second override starts from zero."""
        session = booking(
            [Budget("spend", 10000, Meter.SUM, parameter="price",
                    effects=frozenset({Effect.FINANCIAL}))],
            policy=Policy(budget_exceeded=Disposition.ESCALATE),
        )
        decision = session.admit("book_flight", {"flight": "AI302", "price": 20000})
        session.approve(decision, approver="ana@corp.example")
        assert session.budgets.used("spend") == 20000


class TestComputedAmounts:
    """Provenance handles identifiers; budgets handle magnitudes.

    Measured against AgentDojo's banking suite: most legitimate amounts are
    *computed*, not quoted -- "prices increased 10%, send them the difference"
    yields 5.0, which appears nowhere in the principal's instruction. Arithmetic
    is a semantic derivation and no provenance system can follow it, so treating
    an amount as authority-bearing denies the legitimate case exactly as often
    as the attacker's.

    The coherent division of labour is to let the amount be content and bound it
    with a budget, which is a control provenance cannot provide and does not
    need to.
    """

    def _session(self, ids, amount_role: Role, budgets=()) -> Session:
        pay = ToolContract(
            tool="send_money",
            parameters={
                "recipient": ParameterContract(
                    "recipient", Role.AUTHORITY, frozenset({"iban"})
                ),
                "amount": ParameterContract("amount", amount_role),
            },
            effects=frozenset({Effect.FINANCIAL, Effect.IRREVERSIBLE}),
        )
        session = Session(
            contracts=[pay],
            policy=Policy(denial_budget=-1),
            sources=[Source("principal", Trust.USER_INPUT)],
            budgets=budgets,
            id_factory=ids,
        )
        session.observe(
            "principal",
            "Spotify raised prices 10% this month; send the difference to "
            "DE89370400440532013000.",
        )
        return session

    def test_a_computed_amount_is_denied_when_the_amount_bears_authority(self, ids) -> None:
        session = self._session(ids, Role.AUTHORITY)
        decision = session.admit(
            "send_money", {"recipient": "DE89370400440532013000", "amount": 5.0}
        )
        assert not decision.allowed
        assert decision.findings[0].code is FindingCode.UNATTRIBUTED_AUTHORITY

    def test_budget_admits_the_legitimate_amount_and_stops_the_attacker(self, ids) -> None:
        """The destination is still attributed; only the magnitude moves to a
        budget, which bounds what any amount can add up to."""
        budgets = [
            Budget("spend", 20, Meter.SUM, parameter="amount",
                   effects=frozenset({Effect.FINANCIAL}))
        ]
        session = self._session(ids, Role.PAYLOAD, budgets)
        assert session.admit(
            "send_money", {"recipient": "DE89370400440532013000", "amount": 5.0}
        ).allowed
        assert not session.admit(
            "send_money", {"recipient": "DE89370400440532013000", "amount": 9999.0}
        ).allowed

    def test_the_destination_is_still_protected(self, ids) -> None:
        """Downgrading the amount must not downgrade anything else: an
        attacker-chosen recipient is refused whatever the budget says."""
        budgets = [Budget("spend", 100000, Meter.SUM, parameter="amount")]
        session = self._session(ids, Role.PAYLOAD, budgets)
        assert not session.admit(
            "send_money", {"recipient": "GB33BUKB20201555555555", "amount": 5.0}
        ).allowed


class TestValidation:
    def test_sum_budget_must_name_a_parameter(self) -> None:
        with pytest.raises(ValueError, match="must name"):
            Budget("x", 10, Meter.SUM)

    def test_negative_limits_are_refused(self) -> None:
        with pytest.raises(ValueError, match="negative"):
            Budget("x", -1, Meter.CALLS)

    def test_duplicate_names_are_refused(self) -> None:
        with pytest.raises(ValueError, match="duplicate"):
            BudgetLedger([Budget("x", 1), Budget("x", 2)])

    def test_round_trips_as_data(self) -> None:
        budget = Budget(
            "spend", 50000, Meter.SUM, parameter="price",
            effects=frozenset({Effect.FINANCIAL}), description="trip cap",
        )
        assert Budget.from_dict(budget.to_dict()) == budget

    def test_summary_reports_usage(self, booking) -> None:
        session = booking([Budget("bookings", 3, Meter.CALLS)])
        session.admit("search", {"query": "x"})
        assert session.budgets.summary()["bookings"] == {"used": 1.0, "limit": 3}
