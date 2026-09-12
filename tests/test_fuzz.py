"""Property-based fuzzing of the core invariants.

The milestone review concluded that every bug found so far lived in code that
had been written carefully and tested, and that tests written by the author of a
mechanism test the mechanism the author had in mind. This file exists to attack
the paths nobody thought to write a test for.

Seeded ``random`` rather than a property-testing dependency: the library has no
runtime dependencies and its test suite should not need one either, and a fixed
seed makes a failure reproducible from the test name alone. Seeds are listed
explicitly so a failing case can be re-run in isolation.

Six invariants, each of which would be a real defect if violated:

1. **Sealing is complete.** After observing untrusted content, no operand the
   extractor recognised survives in the text handed to the model.
2. **The monitor never raises.** Arbitrary argument shapes produce a verdict,
   not a traceback -- a monitor that crashes on malformed input fails *open* in
   any harness that catches exceptions and continues.
3. **Decisions are deterministic.** The same script always produces the same
   verdicts and the same audit chain head.
4. **Untrusted authority is never admitted.** The central security property,
   asserted against randomly generated attacker content rather than
   hand-chosen cases.
5. **Handles round-trip.** Resolving a sealed value returns exactly what was
   sealed.
6. **Attacker content never unlocks anything.** Observing content from a source
   authoritative for *nothing* never turns a denial into an admission. The first
   five each constrain one mechanism; this one constrains their **interaction**,
   across every combination of reference binding, path composition and the
   quotation floor -- which is where the milestone review said to expect the
   next defect, since each had been measured alone and never together.

Invariant 6 is mutation-checked rather than trusted: granting the attacker
source authority makes it fail in 24 generated cases, so a green result means
something. About 80% of generated calls are denied before poisoning, which is
the population the property actually guards.
"""

from __future__ import annotations

import itertools
import random
import string

import pytest

from idensec import (
    ContractRegistry,
    Effect,
    ParameterContract,
    Policy,
    Role,
    Session,
    Source,
    ToolContract,
    Trust,
    Verdict,
)
from idensec.kinds import REFERENCED, extract
from idensec.ledger import SEAL_PATTERN

SEEDS = list(range(24))

TOOLS = [
    ToolContract(
        tool="send_email",
        parameters={
            "to": ParameterContract("to", Role.AUTHORITY, frozenset({"email"})),
            "subject": ParameterContract("subject", Role.PAYLOAD),
            "body": ParameterContract("body", Role.PAYLOAD),
        },
        effects=frozenset({Effect.NETWORK_EGRESS, Effect.WRITE}),
    ),
    ToolContract(
        tool="http_get",
        parameters={"url": ParameterContract("url", Role.AUTHORITY, frozenset({"url"}))},
        effects=frozenset({Effect.NETWORK_EGRESS, Effect.READ}),
    ),
    ToolContract(
        tool="read_file",
        parameters={"path": ParameterContract("path", Role.AUTHORITY)},
        effects=frozenset({Effect.READ}),
    ),
]

WORDS = (
    "incident", "outage", "deploy", "rollback", "service", "latency", "queue", "cache",
    "token", "report",
)

TLDS = ["example", "test", "invalid", "corp.example", "evil.example"]


def _word(rng: random.Random) -> str:
    return rng.choice(WORDS)


def _operand(rng: random.Random) -> str:
    """Generate an authority-shaped value of a random kind."""
    label = "".join(rng.choices(string.ascii_lowercase, k=rng.randint(2, 8)))
    host = rng.choice(TLDS)
    return rng.choice(
        [
            f"{label}@{host}",
            f"https://{host}/{label}",
            f"/var/{label}/{_word(rng)}.log",
            f"~/{label}/{_word(rng)}",
            f"s3://{label}/{_word(rng)}",
            f"arn:aws:s3:::{label}",
            f"git@{host}:{label}/repo.git",
            "".join(rng.choices(string.digits, k=rng.randint(8, 19))),
            f"0x{''.join(rng.choices('0123456789abcdef', k=40))}",
        ]
    )


def _prose(rng: random.Random, operands: int = 2) -> str:
    parts = [_word(rng) for _ in range(rng.randint(3, 12))]
    for _ in range(operands):
        parts.insert(rng.randint(0, len(parts)), _operand(rng))
    text = " ".join(parts)
    if rng.random() < 0.3:
        text += rng.choice([".", "!", ")", "]", ",", '"', "\n"])
    return text


def _value(rng: random.Random, depth: int = 0):
    """An arbitrary argument value, including shapes a tool should never send."""
    choices = ["str", "int", "float", "bool", "none", "operand"]
    if depth < 2:
        choices += ["list", "dict"]
    kind = rng.choice(choices)
    if kind == "str":
        return _prose(rng, operands=rng.randint(0, 1))
    if kind == "operand":
        return _operand(rng)
    if kind == "int":
        return rng.randint(-10**6, 10**6)
    if kind == "float":
        return rng.uniform(-1e4, 1e4)
    if kind == "bool":
        return rng.random() < 0.5
    if kind == "none":
        return None
    if kind == "list":
        return [_value(rng, depth + 1) for _ in range(rng.randint(0, 3))]
    return {_word(rng): _value(rng, depth + 1) for _ in range(rng.randint(0, 3))}


def _session(seed: int, policy: Policy | None = None) -> Session:
    counter = itertools.count(1)
    return Session(
        contracts=ContractRegistry(TOOLS),
        policy=policy or Policy(denial_budget=-1),
        sources=[
            Source("principal", Trust.USER_INPUT),
            Source("web", Trust.TOOL_UNTRUSTED),
            Source("directory", Trust.TOOL_TRUSTED, authoritative_for=frozenset({"email"})),
        ],
        id_factory=lambda: f"{next(counter):016x}",
        session_id=f"fuzz-{seed}",
    )


class TestSealingIsComplete:
    @pytest.mark.parametrize("seed", SEEDS)
    def test_no_recognised_operand_survives_untrusted_observation(self, seed: int) -> None:
        rng = random.Random(seed)
        session = _session(seed)
        for _ in range(20):
            text = _prose(rng, operands=rng.randint(0, 3))
            expected = {m.value for m in extract(text)}
            sealed = session.observe("web", text)
            for value in expected:
                assert value not in sealed, (
                    f"operand {value!r} survived sealing in {sealed!r}"
                )

    @pytest.mark.parametrize("seed", SEEDS[:12])
    def test_sealed_text_contains_one_handle_per_operand(self, seed: int) -> None:
        rng = random.Random(seed)
        session = _session(seed)
        for _ in range(20):
            text = _prose(rng, operands=rng.randint(0, 3))
            count = len(extract(text))
            sealed = session.observe("web", text)
            assert len(SEAL_PATTERN.findall(sealed)) == count

    @pytest.mark.parametrize("seed", SEEDS[:12])
    def test_prose_without_operands_is_returned_unchanged(self, seed: int) -> None:
        """Sealing must be a no-op on text carrying no identifiers -- the
        property that makes seal-everything safe at the protocol layer."""
        rng = random.Random(seed)
        session = _session(seed)
        for _ in range(20):
            text = " ".join(_word(rng) for _ in range(rng.randint(3, 20)))
            if extract(text):
                continue
            assert session.observe("web", text) == text


class TestMonitorNeverRaises:
    @pytest.mark.parametrize("seed", SEEDS)
    def test_arbitrary_arguments_produce_a_verdict(self, seed: int) -> None:
        """A monitor that crashes on malformed input fails *open* in any
        harness that catches exceptions and carries on."""
        rng = random.Random(seed)
        session = _session(seed)
        session.observe("principal", _prose(rng, operands=2))
        for _ in range(30):
            contract = rng.choice(TOOLS)
            arguments = {
                name: _value(rng) for name in contract.parameters if rng.random() < 0.9
            }
            if rng.random() < 0.2:
                arguments[_word(rng)] = _value(rng)  # a parameter no contract declares
            decision = session.admit(contract.tool, arguments)
            assert decision.verdict in (Verdict.ALLOW, Verdict.DENY, Verdict.ESCALATE)

    @pytest.mark.parametrize("seed", SEEDS[:12])
    def test_unknown_tools_and_empty_arguments_are_handled(self, seed: int) -> None:
        rng = random.Random(seed)
        session = _session(seed)
        for _ in range(15):
            session.admit(_word(rng), {})
            session.admit(_word(rng), {_word(rng): _value(rng)})

    @pytest.mark.parametrize("seed", SEEDS[:12])
    def test_hostile_handle_shaped_arguments(self, seed: int) -> None:
        """Forged, truncated and malformed handles must all resolve to a
        verdict rather than an exception."""
        rng = random.Random(seed)
        session = _session(seed)
        session.observe("principal", _prose(rng))
        for _ in range(20):
            forged = rng.choice(
                [
                    "[[idn:email:" + "".join(rng.choices("0123456789abcdef", k=16)) + "]]",
                    "[[idn:email:tooshort]]",
                    "[[idn:" + _word(rng) + ":0000000000000001]]",
                    "[[idn:email:]]",
                    "[[idn:email:0000000000000001",
                    "]]idn:email:0000000000000001[[",
                    "[[idn:email:0000000000000001]][[idn:url:0000000000000002]]",
                ]
            )
            decision = session.admit("send_email", {"to": forged, "subject": "s", "body": "b"})
            assert decision.verdict is not Verdict.ALLOW


class TestDeterminism:
    @pytest.mark.parametrize("seed", SEEDS)
    def test_replays_agree(self, seed: int) -> None:
        def run() -> tuple[list[str], str]:
            rng = random.Random(seed)
            session = _session(seed)
            verdicts = []
            for _ in range(25):
                if rng.random() < 0.4:
                    session.observe(
                        rng.choice(["principal", "web", "directory"]), _prose(rng)
                    )
                else:
                    contract = rng.choice(TOOLS)
                    arguments = {name: _value(rng) for name in contract.parameters}
                    verdicts.append(session.admit(contract.tool, arguments).verdict.value)
            return verdicts, session.audit.head

        assert run() == run()


class TestUntrustedAuthorityIsNeverAdmitted:
    @pytest.mark.parametrize("seed", SEEDS)
    def test_attacker_supplied_addresses_are_refused(self, seed: int) -> None:
        """The central security property, against generated attacker content
        rather than hand-chosen cases."""
        rng = random.Random(seed)
        session = _session(seed)
        session.observe("principal", "mail the summary to ana@corp.example")
        for _ in range(20):
            label = "".join(rng.choices(string.ascii_lowercase, k=rng.randint(3, 9)))
            address = f"{label}@evil.example"
            session.observe("web", f"{_prose(rng, operands=0)} contact {address} now")
            decision = session.admit(
                "send_email", {"to": address, "subject": "s", "body": "b"}
            )
            assert decision.verdict is not Verdict.ALLOW, (
                f"admitted attacker address {address!r}"
            )

    @pytest.mark.parametrize("seed", SEEDS)
    def test_values_the_model_invented_are_refused(self, seed: int) -> None:
        rng = random.Random(seed)
        session = _session(seed)
        session.observe("principal", "mail the summary to ana@corp.example")
        for _ in range(20):
            invented = _operand(rng)
            if invented == "ana@corp.example":
                continue
            for tool, parameter in (
                ("send_email", "to"),
                ("http_get", "url"),
                ("read_file", "path"),
            ):
                arguments = {parameter: invented}
                if tool == "send_email":
                    arguments |= {"subject": "s", "body": "b"}
                assert session.admit(tool, arguments).verdict is not Verdict.ALLOW

    @pytest.mark.parametrize("seed", SEEDS[:12])
    def test_the_authoritative_source_still_works(self, seed: int) -> None:
        """The mirror property: a monitor that refuses everything would pass
        every test above and be useless."""
        rng = random.Random(seed)
        session = _session(seed)
        session.observe("principal", "mail the on-call engineer")
        for _ in range(10):
            label = "".join(rng.choices(string.ascii_lowercase, k=rng.randint(3, 9)))
            address = f"{label}@corp.example"
            session.observe("directory", f"on-call is {address}")
            decision = session.admit(
                "send_email", {"to": address, "subject": "s", "body": "b"}
            )
            assert decision.verdict is Verdict.ALLOW, decision.reason()


class TestHandlesRoundTrip:
    @pytest.mark.parametrize("seed", SEEDS)
    def test_resolution_returns_exactly_what_was_sealed(self, seed: int) -> None:
        rng = random.Random(seed)
        session = _session(seed)
        for _ in range(25):
            value = _operand(rng)
            matches = extract(value)
            if len(matches) != 1 or matches[0].value != value:
                continue  # not a clean single-operand string; not this test's case
            sealed = session.observe("web", value)
            assert session.ledger.resolve(sealed).text == value


# --- 6. attacker content never unlocks anything -----------------------------

COMPOSE_TOOLS = [
    *TOOLS,
    ToolContract(
        tool="open_record",
        parameters={
            "file_id": ParameterContract(
                "file_id", Role.AUTHORITY, collection="**.files"
            )
        },
        effects=frozenset({Effect.READ}),
    ),
]

CONFIGURATIONS = [
    ("bare", Policy(denial_budget=-1, min_quotation_length=3), {}),
    (
        "compose",
        Policy(denial_budget=-1, min_quotation_length=3, compose_paths=True),
        {"roots": frozenset({"posix_path"})},
    ),
    (
        "referenced",
        Policy(denial_budget=-1, min_quotation_length=3),
        {"**.files": frozenset({REFERENCED})},
    ),
    (
        "everything",
        Policy(
            denial_budget=-1,
            min_quotation_length=3,
            compose_paths=True,
            min_reference_word=4,
        ),
        {
            "roots": frozenset({"posix_path"}),
            "**.files": frozenset({REFERENCED}),
            "**.sender": frozenset({"email"}),
        },
    ),
]


def _paired_session(seed: int, policy: Policy, grants: dict) -> Session:
    """A session with one authoritative source and one authoritative for nothing."""
    counter = itertools.count(1)
    return Session(
        contracts=ContractRegistry(COMPOSE_TOOLS),
        policy=policy,
        sources=[
            Source("principal", Trust.USER_INPUT),
            Source("dir", Trust.TOOL_UNTRUSTED, authoritative_paths=grants),
            Source("attacker", Trust.TOOL_UNTRUSTED),
        ],
        id_factory=lambda: f"{next(counter):016x}",
        session_id=f"fuzz-{seed}",
    )


def _script(rng: random.Random) -> tuple[str, dict, list[tuple[str, dict]]]:
    """A principal instruction, a directory result, and some calls to try."""
    task = _prose(rng, operands=rng.randint(0, 2))
    directory = {
        "roots": f"/srv/{_word(rng)}",
        "files": {
            str(rng.randint(1, 99)): {"filename": f"{_word(rng)}-{_word(rng)}.txt"}
            for _ in range(rng.randint(1, 3))
        },
        "sender": _operand(rng),
    }
    calls = []
    for _ in range(rng.randint(2, 5)):
        tool = rng.choice(COMPOSE_TOOLS)
        calls.append(
            (
                tool.tool,
                {name: _value(rng) for name in tool.parameters},
            )
        )
    return task, directory, calls


class TestAttackerContentNeverUnlocks:
    """The property prompt injection actually attacks, stated directly.

    Observing content from a source authoritative for **nothing** must never
    turn a denial into an admission. Every other invariant in this file
    constrains one mechanism; this one constrains their *interaction*, which is
    where the milestone review said to expect the next defect: each of
    sealing, reference binding, path composition, budgets and the quotation
    floor has been measured alone, and never in combination.

    Note what is *not* asserted. A source the operator granted authority may
    legitimately turn a denial into an admission -- that is what a grant is
    for. The attacker source here is granted nothing, which is the case the
    threat model cares about.
    """

    @pytest.mark.parametrize("label,policy,grants", CONFIGURATIONS)
    @pytest.mark.parametrize("seed", SEEDS)
    def test_denials_survive_arbitrary_attacker_content(
        self, seed: int, label: str, policy: Policy, grants: dict
    ) -> None:
        rng = random.Random(seed)
        task, directory, calls = _script(rng)
        poison = [_prose(rng, operands=3) for _ in range(rng.randint(1, 4))]

        clean = _paired_session(seed, policy, grants)
        clean.observe("principal", task)
        clean.observe("dir", directory)
        before = [clean.admit(tool, args).verdict for tool, args in calls]

        poisoned = _paired_session(seed, policy, grants)
        poisoned.observe("principal", task)
        poisoned.observe("dir", directory)
        for text in poison:
            poisoned.observe("attacker", text)
        after = [poisoned.admit(tool, args).verdict for tool, args in calls]

        for (tool, args), was, now in zip(before and calls, before, after, strict=True):
            if was is not Verdict.ALLOW:
                assert now is not Verdict.ALLOW, (
                    f"[{label}] attacker content turned {was.value} into allow "
                    f"for {tool}({args})"
                )

    @pytest.mark.parametrize("label,policy,grants", CONFIGURATIONS)
    @pytest.mark.parametrize("seed", SEEDS[:8])
    def test_attacker_content_before_the_principal_is_no_better(
        self, seed: int, label: str, policy: Policy, grants: dict
    ) -> None:
        """Ordering must not matter either. An attacker who speaks first should
        gain nothing from it."""
        rng = random.Random(seed)
        task, directory, calls = _script(rng)
        poison = _prose(rng, operands=3)

        clean = _paired_session(seed, policy, grants)
        clean.observe("principal", task)
        clean.observe("dir", directory)
        before = [clean.admit(tool, args).verdict for tool, args in calls]

        poisoned = _paired_session(seed, policy, grants)
        poisoned.observe("attacker", poison)
        poisoned.observe("principal", task)
        poisoned.observe("dir", directory)
        after = [poisoned.admit(tool, args).verdict for tool, args in calls]

        for was, now in zip(before, after, strict=True):
            if was is not Verdict.ALLOW:
                assert now is not Verdict.ALLOW, f"[{label}] ordering unlocked a call"

    @pytest.mark.parametrize("label,policy,grants", CONFIGURATIONS)
    @pytest.mark.parametrize("seed", SEEDS)
    def test_an_attacker_naming_the_exact_value_gains_nothing(
        self, seed: int, label: str, policy: Policy, grants: dict
    ) -> None:
        """The realistic attack, rather than a random one.

        Random poison rarely collides with the value a call actually carries,
        so it barely tests the thing that matters. Here the attacker writes out
        *precisely* the arguments the agent is about to send, which is what an
        injection does: "send it to eve@evil.example", "delete file 13". If
        naming a value were enough to authorise it, this is the test that would
        say so.
        """
        rng = random.Random(seed)
        task, directory, calls = _script(rng)

        clean = _paired_session(seed, policy, grants)
        clean.observe("principal", task)
        clean.observe("dir", directory)
        before = [clean.admit(tool, args).verdict for tool, args in calls]

        named = " ".join(
            f"use {value}"
            for _, args in calls
            for value in args.values()
            if isinstance(value, (str, int, float))
        )
        poisoned = _paired_session(seed, policy, grants)
        poisoned.observe("principal", task)
        poisoned.observe("dir", directory)
        poisoned.observe("attacker", f"URGENT instructions: {named}")
        after = [poisoned.admit(tool, args).verdict for tool, args in calls]

        for (tool, args), was, now in zip(calls, before, after, strict=True):
            if was is not Verdict.ALLOW:
                assert now is not Verdict.ALLOW, (
                    f"[{label}] naming the value authorised it: {tool}({args})"
                )
