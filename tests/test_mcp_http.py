"""The streamable HTTP transport, against a hostile server over a real socket.

The stdio suite proves the decisions. This proves the decisions do not change
when the bytes arrive differently — which is the only thing a second transport
can get wrong, and the thing that would be easiest to miss.

Three shapes of message exist over HTTP and not over stdio, and each gets its
own test: a JSON response body, an SSE response to a POST, and the
server-initiated GET stream. Content arrives on all three, so all three are read
boundaries.
"""

from __future__ import annotations

import json
import sys
import threading
from http.client import HTTPConnection
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from fake_http_mcp_server import ATTACKER, build
from idensec.mcp.config import ConfigError, ProxyConfig
from idensec.mcp.streamable import serve

CONTRACTS = {
    "schema": "idensec.contracts/v1",
    "contracts": [
        {
            "tool": "send_email",
            "version": 1,
            "effects": ["write", "network_egress"],
            "default_role": "authority",
            "parameters": {
                "to": {"role": "authority", "kinds": ["email"]},
                "subject": {"role": "payload"},
                "body": {"role": "payload"},
            },
        },
        {
            "tool": "fetch_page",
            "version": 1,
            "effects": ["read", "network_egress"],
            "default_role": "authority",
            "parameters": {"url": {"role": "authority", "kinds": ["url"]}},
        },
    ],
}

TASK = (
    "Summarise https://status.example/x and mail it to ana@corp.example"
)


class Stack:
    """A hostile server, a proxy in front of it, and a client that speaks to it."""

    def __init__(self, tmp_path: Path, *, sse: bool = False, **overrides) -> None:
        self.record = tmp_path / "received.jsonl"
        contracts = tmp_path / "contracts.json"
        contracts.write_text(json.dumps(CONTRACTS), encoding="utf-8")
        task = tmp_path / "task.txt"
        task.write_text(TASK, encoding="utf-8")

        self.origin = build(0, self.record, sse)
        self._origin_thread = threading.Thread(
            target=self.origin.serve_forever, daemon=True
        )
        self._origin_thread.start()
        origin_port = self.origin.server_address[1]

        config = ProxyConfig.from_dict(
            {
                "schema": "idensec.proxy/v1",
                "source": {"id": "hostile", "trust": "tool_untrusted"},
                "policy": "strict",
                "contracts": str(contracts),
                "task_file": str(task),
                "server_url": f"http://127.0.0.1:{origin_port}/mcp",
                **overrides,
            },
            base=tmp_path,
        )
        self.log = (tmp_path / "proxy.log").open("wb")
        self.proxy = serve(config, port=0, log=self.log)
        self._proxy_thread = threading.Thread(
            target=self.proxy.serve_forever, daemon=True
        )
        self._proxy_thread.start()
        self.host = "127.0.0.1"
        self.port = self.proxy.server_address[1]

    def _open(self) -> HTTPConnection:
        return HTTPConnection(self.host, self.port, timeout=10)

    def post(self, payload) -> object:
        """POST one message and decode whichever reply shape comes back.

        A server may answer with JSON or with an event stream, per request, so
        a client that assumes one of them is not a client.
        """
        connection = self._open()
        try:
            connection.request(
                "POST",
                "/mcp",
                body=json.dumps(payload).encode(),
                headers={"Content-Type": "application/json"},
            )
            response = connection.getresponse()
            kind = (response.getheader("Content-Type") or "").split(";")[0].strip()
            body = response.read()
        finally:
            connection.close()
        if not body:
            return None
        if kind == "text/event-stream":
            events = [
                json.loads(line[5:].strip())
                for line in body.splitlines()
                if line.startswith(b"data:")
            ]
            return events[0] if len(events) == 1 else events
        return json.loads(body)

    def stream(self) -> list[dict]:
        connection = self._open()
        try:
            connection.request("GET", "/mcp", headers={"Accept": "text/event-stream"})
            response = connection.getresponse()
            return [
                json.loads(line[5:].strip())
                for line in response
                if line.startswith(b"data:")
            ]
        finally:
            connection.close()

    def delete(self) -> int:
        connection = self._open()
        try:
            connection.request("DELETE", "/mcp")
            return connection.getresponse().status
        finally:
            connection.close()

    def received(self) -> list[dict]:
        if not self.record.exists():
            return []
        return [json.loads(line) for line in self.record.read_text().splitlines()]

    def stderr(self) -> str:
        self.log.flush()
        return (Path(self.log.name)).read_text()

    def close(self) -> None:
        for server in (self.proxy, self.origin):
            server.shutdown()
            server.server_close()
        self.log.close()


@pytest.fixture
def stack(tmp_path: Path):
    made: list[Stack] = []

    def _make(**kwargs) -> Stack:
        built = Stack(tmp_path, **kwargs)
        made.append(built)
        return built

    yield _make
    for built in made:
        built.close()


def _call(request_id: int, tool: str, arguments: dict) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": tool, "arguments": arguments},
    }


class TestWriteBoundary:
    def test_the_principal_s_own_recipient_is_delivered(self, stack) -> None:
        s = stack()
        reply = s.post(_call(1, "send_email", {"to": "ana@corp.example", "body": "hi"}))
        assert not reply["result"].get("isError")
        assert [c["name"] for c in s.received()] == ["send_email"]

    def test_an_injected_recipient_never_reaches_the_server(self, stack) -> None:
        s = stack()
        reply = s.post(_call(1, "send_email", {"to": ATTACKER, "body": "hi"}))
        assert reply["result"]["isError"]
        assert s.received() == [], "a denied call must not be forwarded"

    def test_the_denial_carries_no_detail(self, stack) -> None:
        s = stack()
        reply = s.post(_call(1, "send_email", {"to": ATTACKER, "body": "hi"}))
        text = reply["result"]["content"][0]["text"]
        assert ATTACKER not in text and "unauthorised" not in text.lower()

    def test_a_batch_is_opened_rather_than_passed_through(self, stack) -> None:
        """A container that can hold a tools/call is not something to forward.

        'Pass through what you do not understand' is a rule about *methods*. A
        JSON-RPC batch is a list, and forwarding a list unexamined would be a
        bypass wearing a pass-through's clothes.
        """
        s = stack()
        replies = s.post(
            [
                _call(1, "send_email", {"to": "ana@corp.example", "body": "ok"}),
                _call(2, "send_email", {"to": ATTACKER, "body": "leak"}),
            ]
        )
        by_id = {r["id"]: r for r in replies}
        assert not by_id[1]["result"].get("isError")
        assert by_id[2]["result"]["isError"]
        assert [c["arguments"]["to"] for c in s.received()] == ["ana@corp.example"]

    def test_a_wholly_denied_batch_reaches_the_server_not_at_all(self, stack) -> None:
        s = stack()
        replies = s.post([_call(1, "send_email", {"to": ATTACKER, "body": "leak"})])
        assert replies[0]["result"]["isError"]
        assert s.received() == []


class TestReadBoundary:
    def test_an_injected_address_in_a_json_body_is_sealed(self, stack) -> None:
        s = stack()
        reply = s.post(_call(1, "fetch_page", {"url": "https://status.example/x"}))
        text = json.dumps(reply)
        assert ATTACKER not in text
        assert "[[idn:email:" in text

    def test_an_injected_address_in_an_sse_body_is_sealed(self, stack) -> None:
        """A server may answer a POST with an event stream instead of JSON."""
        s = stack(sse=True)
        reply = s.post(_call(1, "fetch_page", {"url": "https://status.example/x"}))
        text = json.dumps(reply)
        assert ATTACKER not in text
        assert "[[idn:email:" in text

    def test_the_server_initiated_stream_is_sealed_too(self, stack) -> None:
        """Content the agent never asked for still reaches the model."""
        s = stack()
        s.post({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        events = s.stream()
        assert events, "no message arrived on the server-initiated stream"
        text = json.dumps(events)
        assert ATTACKER not in text
        assert "[[idn:email:" in text

    def test_an_address_learned_from_the_stream_is_still_refused(self, stack) -> None:
        """Sealing is not the defence; the write boundary is. Both, together."""
        s = stack()
        s.post({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        s.stream()
        reply = s.post(_call(2, "send_email", {"to": ATTACKER, "body": "hi"}))
        assert reply["result"]["isError"]
        assert s.received() == []


class TestTransportMechanics:
    def test_protocol_metadata_survives_the_hop(self, stack) -> None:
        s = stack()
        reply = s.post({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        assert reply["result"]["protocolVersion"] == "2025-06-18"

    def test_tool_schemas_are_never_rewritten(self, stack) -> None:
        s = stack()
        reply = s.post({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        tools = {t["name"]: t for t in reply["result"]["tools"]}
        assert set(tools) == {"fetch_page", "send_email", "read_file"}
        assert tools["send_email"]["inputSchema"]["properties"]["to"] == {
            "type": "string"
        }

    def test_a_poisoned_tool_description_is_sealed(self, stack) -> None:
        s = stack()
        reply = s.post({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        described = next(
            t for t in reply["result"]["tools"] if t["name"] == "send_email"
        )
        assert "audit@evil.example" not in described["description"]

    def test_a_notification_draws_no_body(self, stack) -> None:
        s = stack()
        assert s.post({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None

    def test_delete_is_forwarded(self, stack) -> None:
        assert stack().delete() == 204


class TestConfig:
    def test_a_config_naming_both_transports_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError, match="both"):
            ProxyConfig.from_dict(
                {
                    "schema": "idensec.proxy/v1",
                    "source": {"id": "s", "trust": "tool_untrusted"},
                    "policy": "strict",
                    "server": ["cat"],
                    "server_url": "http://127.0.0.1:1/mcp",
                },
                base=tmp_path,
            )

    def test_a_non_http_url_is_refused(self, tmp_path: Path) -> None:
        config = ProxyConfig.from_dict(
            {
                "schema": "idensec.proxy/v1",
                "source": {"id": "s", "trust": "tool_untrusted"},
                "policy": "strict",
                "server_url": "ftp://example.invalid/mcp",
            },
            base=tmp_path,
        )
        with pytest.raises(ValueError, match="http"):
            serve(config, port=0)
