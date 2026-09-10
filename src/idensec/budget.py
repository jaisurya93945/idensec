"""Aggregate constraints across a session.

Every other check in IDENSEC judges one call in isolation, which leaves a gap
the founding brief named directly: *book me a flight under 50,000* is satisfied
by every individual step, and violated by three bookings of 20,000. Each call is
authorised. The outcome is not.

Provenance cannot close that, because nothing about the third booking's
provenance differs from the first's. What closes it is counting.

A budget is deliberately not a policy language. Three meters cover the cases
that actually arise:

* ``CALLS``    -- how many times may this class of action happen at all
* ``SUM``      -- what may a numeric parameter add up to
* ``DISTINCT`` -- how many different destinations may be touched

**Budgets are consumed by committed actions only.** A denied call must not
consume budget, or an attacker exhausts the allowance with calls that were never
going to succeed and denies service to the principal by failing loudly.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from .contracts import Effect, ToolContract

__all__ = ["Budget", "BudgetBreach", "BudgetLedger", "Meter"]


class Meter(StrEnum):
    CALLS = "calls"
    SUM = "sum"
    DISTINCT = "distinct"


@dataclass(frozen=True, slots=True)
class Budget:
    """One aggregate limit over a session.

    Scope is the intersection of ``tools`` and ``effects``; leaving both empty
    means the budget applies to every call, which is usually what you want for
    a ``CALLS`` cap and almost never what you want for a ``SUM``.
    """

    name: str
    limit: float
    meter: Meter = Meter.CALLS
    parameter: str = ""
    tools: frozenset[str] = field(default_factory=frozenset)
    effects: frozenset[Effect] = field(default_factory=frozenset)
    description: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "meter", Meter(str(self.meter)))
        object.__setattr__(self, "tools", frozenset(self.tools))
        object.__setattr__(self, "effects", frozenset(Effect(e) for e in self.effects))
        if self.meter in (Meter.SUM, Meter.DISTINCT) and not self.parameter:
            raise ValueError(
                f"budget {self.name!r} uses meter {self.meter.value} and must name "
                "the parameter it measures"
            )
        if self.limit < 0:
            raise ValueError(f"budget {self.name!r} has a negative limit")

    def applies_to(self, contract: ToolContract) -> bool:
        if self.tools and contract.tool not in self.tools:
            return False
        return not (self.effects and not (self.effects & contract.effects))

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "name": self.name,
            "limit": self.limit,
            "meter": self.meter.value,
        }
        if self.parameter:
            out["parameter"] = self.parameter
        if self.tools:
            out["tools"] = sorted(self.tools)
        if self.effects:
            out["effects"] = sorted(e.value for e in self.effects)
        if self.description:
            out["description"] = self.description
        return out

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Budget:
        return cls(
            name=str(data["name"]),
            limit=float(data["limit"]),
            meter=Meter(data.get("meter", Meter.CALLS.value)),
            parameter=str(data.get("parameter", "")),
            tools=frozenset(data.get("tools", ())),
            effects=frozenset(Effect(e) for e in data.get("effects", ())),
            description=str(data.get("description", "")),
        )


@dataclass(frozen=True, slots=True)
class BudgetBreach:
    """A budget this call would exceed."""

    budget: Budget
    used: float
    would_be: float

    def describe(self) -> str:
        return (
            f"{self.budget.name}: {self.budget.meter.value} would reach "
            f"{_pretty(self.would_be)} against a limit of {_pretty(self.budget.limit)} "
            f"(used {_pretty(self.used)})"
        )


def _pretty(value: float) -> str:
    return str(int(value)) if value == int(value) else f"{value:g}"


def _numeric(value: Any) -> float | None:
    """Coerce a resolved argument to a number, or None if it is not one.

    Strings are accepted because tool arguments frequently carry numbers as
    text, and a budget that silently ignored ``"20000"`` would be worse than no
    budget: it would look enforced.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        cleaned = value.strip().replace(",", "").replace("_", "")
        for prefix in ("$", "£", "€", "₹"):
            cleaned = cleaned.removeprefix(prefix)
        try:
            return float(cleaned)
        except ValueError:
            return None
    return None


class BudgetLedger:
    """Tracks consumption across one session."""

    def __init__(self, budgets: Iterable[Budget] = ()) -> None:
        self._budgets = tuple(budgets)
        names = [b.name for b in self._budgets]
        duplicates = {n for n in names if names.count(n) > 1}
        if duplicates:
            raise ValueError(f"duplicate budget names: {sorted(duplicates)}")
        self._totals: dict[str, float] = {b.name: 0.0 for b in self._budgets}
        self._seen: dict[str, set[str]] = {b.name: set() for b in self._budgets}

    @property
    def budgets(self) -> tuple[Budget, ...]:
        return self._budgets

    def used(self, name: str) -> float:
        return self._totals.get(name, 0.0)

    def check(
        self, contract: ToolContract, arguments: Mapping[str, Any]
    ) -> list[BudgetBreach]:
        """Report budgets this call would exceed. Consumes nothing."""
        breaches: list[BudgetBreach] = []
        for budget, delta in self._deltas(contract, arguments):
            used = self._totals[budget.name]
            if used + delta > budget.limit:
                breaches.append(BudgetBreach(budget, used, used + delta))
        return breaches

    def commit(self, contract: ToolContract, arguments: Mapping[str, Any]) -> None:
        """Consume budget for a call that is actually going to happen."""
        for budget, delta in self._deltas(contract, arguments):
            self._totals[budget.name] += delta
            if budget.meter is Meter.DISTINCT:
                value = arguments.get(budget.parameter)
                if value is not None:
                    self._seen[budget.name].add(str(value))

    def _deltas(
        self, contract: ToolContract, arguments: Mapping[str, Any]
    ) -> list[tuple[Budget, float]]:
        deltas: list[tuple[Budget, float]] = []
        for budget in self._budgets:
            if not budget.applies_to(contract):
                continue
            if budget.meter is Meter.CALLS:
                deltas.append((budget, 1.0))
            elif budget.meter is Meter.SUM:
                amount = _numeric(arguments.get(budget.parameter))
                if amount is not None:
                    deltas.append((budget, amount))
            elif budget.meter is Meter.DISTINCT:
                value = arguments.get(budget.parameter)
                if value is None:
                    continue
                # Repeating a destination already used costs nothing: the limit
                # is on how many different places are touched, not how often.
                delta = 0.0 if str(value) in self._seen[budget.name] else 1.0
                deltas.append((budget, delta))
        return deltas

    def summary(self) -> dict[str, dict[str, float]]:
        return {
            b.name: {"used": self._totals[b.name], "limit": b.limit}
            for b in self._budgets
        }
