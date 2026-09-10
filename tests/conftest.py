"""Shared fixtures.

Every session in the suite uses a counting id factory rather than
``secrets.token_hex``. Handles then appear as ``[[idn:email:0000000000000001]]``,
which makes failures readable and makes the whole suite deterministic -- a
property the monitor itself claims and which is asserted directly in
``test_determinism.py``.
"""

from __future__ import annotations

import itertools
from collections.abc import Callable, Iterable

import pytest

from idensec import (
    STRICT,
    ContractRegistry,
    Effect,
    ParameterContract,
    Policy,
    Role,
    Sensitivity,
    Session,
    Source,
    ToolContract,
    Trust,
)


@pytest.fixture
def ids() -> Callable[[], str]:
    counter = itertools.count(1)
    return lambda: f"{next(counter):016x}"


PRINCIPAL = Source("principal", Trust.USER_INPUT, description="the human's instruction")
WEB = Source("web", Trust.TOOL_UNTRUSTED, description="fetched third-party page")
INBOX = Source("inbox", Trust.TOOL_UNTRUSTED, description="inbound mail")
DIRECTORY = Source(
    "directory",
    Trust.TOOL_TRUSTED,
    authoritative_for=frozenset({"email"}),
    description="corporate directory; may name people, nothing else",
)
VAULT = Source("vault", Trust.TOOL_TRUSTED, Sensitivity.CONFIDENTIAL)

SEND_EMAIL = ToolContract(
    tool="send_email",
    parameters={
        "to": ParameterContract("to", Role.AUTHORITY, frozenset({"email"})),
        "cc": ParameterContract("cc", Role.AUTHORITY, frozenset({"email"})),
        "subject": ParameterContract("subject", Role.PAYLOAD),
        "body": ParameterContract("body", Role.PAYLOAD),
    },
    effects=frozenset({Effect.NETWORK_EGRESS, Effect.WRITE}),
)

HTTP_GET = ToolContract(
    tool="http_get",
    parameters={"url": ParameterContract("url", Role.AUTHORITY, frozenset({"url"}))},
    effects=frozenset({Effect.NETWORK_EGRESS, Effect.READ}),
)

READ_FILE = ToolContract(
    tool="read_file",
    parameters={"path": ParameterContract("path", Role.AUTHORITY)},
    effects=frozenset({Effect.READ}),
)

TRANSFER = ToolContract(
    tool="transfer",
    parameters={
        "iban": ParameterContract("iban", Role.AUTHORITY, frozenset({"iban"})),
        "amount": ParameterContract("amount", Role.AUTHORITY),
        "memo": ParameterContract("memo", Role.PAYLOAD),
    },
    effects=frozenset({Effect.FINANCIAL, Effect.IRREVERSIBLE}),
)

DEFAULT_CONTRACTS = (SEND_EMAIL, HTTP_GET, READ_FILE, TRANSFER)
DEFAULT_SOURCES = (PRINCIPAL, WEB, INBOX, DIRECTORY, VAULT)


@pytest.fixture
def make_session(ids: Callable[[], str]):
    def _make(
        policy: Policy = STRICT,
        *,
        contracts: Iterable[ToolContract] = DEFAULT_CONTRACTS,
        sources: Iterable[Source] = DEFAULT_SOURCES,
    ) -> Session:
        return Session(
            contracts=ContractRegistry(contracts),
            policy=policy,
            sources=sources,
            id_factory=ids,
            session_id="test",
        )

    return _make


@pytest.fixture
def session(make_session) -> Session:
    return make_session()
