"""Minimal JSON-RPC 2.0 framing for the MCP stdio transport.

MCP's stdio transport is newline-delimited JSON: one JSON-RPC message per
line, on stdin and stdout, with no embedded newlines. That is simple enough to
implement directly, which is what we do -- pulling in an SDK would break the
zero-dependency property that makes this library safe to put in a data path
(ADR-0006).

The design rule for everything here is **pass through what you do not
understand**. A proxy that drops unrecognised messages breaks on the next
protocol revision; a proxy that forwards them keeps working. We inspect exactly
two methods and forward the rest untouched.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass
from typing import IO, Any

__all__ = ["Message", "error_result", "read_messages", "write_message"]


@dataclass(frozen=True, slots=True)
class Message:
    """One JSON-RPC message, kept as its raw decoded form.

    We deliberately do not model requests, responses and notifications as
    separate types. The proxy's job is to forward faithfully, and a rich model
    invites us to reconstruct messages we should be passing through byte-shaped
    as we received them.
    """

    payload: dict[str, Any]

    @property
    def method(self) -> str | None:
        method = self.payload.get("method")
        return method if isinstance(method, str) else None

    @property
    def id(self) -> Any:
        return self.payload.get("id")

    @property
    def is_request(self) -> bool:
        return self.method is not None and "id" in self.payload

    @property
    def is_response(self) -> bool:
        return self.method is None and "id" in self.payload

    @property
    def params(self) -> dict[str, Any]:
        params = self.payload.get("params")
        return params if isinstance(params, dict) else {}

    @property
    def result(self) -> dict[str, Any] | None:
        result = self.payload.get("result")
        return result if isinstance(result, dict) else None

    def encode(self) -> bytes:
        # separators without spaces, and no embedded newlines: the transport
        # delimits on "\n", so a pretty-printed message would corrupt the stream.
        return json.dumps(self.payload, separators=(",", ":")).encode("utf-8") + b"\n"


def read_messages(stream: IO[bytes]) -> Iterator[Message]:
    """Yield messages from a newline-delimited JSON-RPC stream.

    Blank lines are skipped. A line that is not valid JSON is skipped rather
    than raised on: a malformed line from a downstream server should not take
    the proxy down and strand the host.
    """
    for line in stream:
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except (ValueError, UnicodeDecodeError):
            continue
        if isinstance(payload, dict):
            yield Message(payload)


def write_message(stream: IO[bytes], message: Message) -> None:
    stream.write(message.encode())
    stream.flush()


def error_result(request_id: Any, text: str) -> Message:
    """A tool result carrying an error, as MCP expects.

    Deliberately a *result* with ``isError``, not a JSON-RPC error object. A
    protocol-level error tells the host something broke; this is the tool
    reporting that it declined to act, which is a normal outcome the agent
    should be able to read and continue from.
    """
    return Message(
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "content": [{"type": "text", "text": text}],
                "isError": True,
            },
        }
    )
