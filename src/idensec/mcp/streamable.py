"""The streamable HTTP transport, which is the other half of MCP deployments.

The stdio proxy in :mod:`idensec.mcp.proxy` launches a server as a child process
and mediates two pipes. A server reached over HTTP has neither, so this module
supplies the transport and reuses the enforcement unchanged:
:meth:`Proxy.handle_outbound` on the way to the server and
:meth:`Proxy.handle_inbound` on the way back, exactly as before. Everything that
decides anything lives in ``Proxy``; nothing here knows what a contract is.

**Shape.** The proxy is an HTTP *server* facing the host and an HTTP *client*
facing the real one. The host points at ``http://127.0.0.1:<port>/mcp`` instead
of at the remote endpoint.

* ``POST`` carries a JSON-RPC message. The response is either
  ``application/json`` or an SSE stream, and a server may choose either per
  request, so both are handled.
* ``GET`` opens the server-initiated SSE stream. Messages arriving on it are
  content reaching the model and are sealed like any other.
* ``DELETE`` ends the session, and is forwarded.

**Containers are opened, methods are passed through.** ``jsonrpc.py``'s rule is
to forward what we do not understand, and that is right for *methods*: a proxy
that drops the next protocol revision's messages breaks. It is wrong for
*containers*. A JSON-RPC batch is a list that can hold a ``tools/call``, so
forwarding a list unexamined would be a bypass wearing a pass-through's clothes.
Batches are therefore taken apart, each element decided on its own, and only the
survivors sent on. (MCP removed batching in 2025-06-18; this exists because a
host that still sends one must not get a free pass.)

**Standard library only**, like the rest of the package: ``http.server`` and
``http.client``. A security component in a data path should not import a web
framework to move bytes (ADR-0006).

**Who can reach the socket can speak MCP to it.** The listener binds loopback
unless told otherwise, and the proxy is not a trust boundary against whatever
connects to it -- the same statement the stdio transport makes about its stdin,
and the reason ``accept_principal_context`` is off by default.
"""

from __future__ import annotations

import json
import sys
import threading
from collections.abc import Iterator
from http.client import HTTPConnection, HTTPResponse, HTTPSConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import IO, Any
from urllib.parse import urlsplit

from .config import ProxyConfig
from .jsonrpc import Message
from .proxy import Proxy

__all__ = ["Upstream", "run_http", "serve"]

_JSON = "application/json"
_SSE = "text/event-stream"

_HOP_BY_HOP = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
        "content-length",
        "host",
    }
)
"""Headers that describe *this* connection rather than the message.

Copying them across a proxy hop is how a stream ends up double-chunked or a
content length ends up describing somebody else's body.
"""


class Upstream:
    """One HTTP connection to the real MCP server.

    A connection per request rather than a pool. This is a security component in
    front of one server, and a pool would be a source of cross-request state for
    a class of bug that buys nothing here.
    """

    def __init__(self, url: str, *, timeout: float = 60) -> None:
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ValueError(f"server_url must be an http(s) URL, got {url!r}")
        self.scheme = parts.scheme
        self.host = parts.hostname
        self.port = parts.port or (443 if parts.scheme == "https" else 80)
        self.path = parts.path or "/"
        if parts.query:
            self.path += f"?{parts.query}"
        self.timeout = timeout

    def request(
        self, method: str, headers: dict[str, str], body: bytes | None = None
    ) -> tuple[HTTPResponse, HTTPConnection | HTTPSConnection]:
        opener = HTTPSConnection if self.scheme == "https" else HTTPConnection
        connection = opener(self.host, self.port, timeout=self.timeout)
        connection.request(method, self.path, body=body, headers=headers)
        return connection.getresponse(), connection


def _forwardable(headers: Any) -> dict[str, str]:
    return {
        key: value
        for key, value in headers.items()
        if key.lower() not in _HOP_BY_HOP
    }


def _sse_messages(stream: IO[bytes]) -> Iterator[tuple[list[bytes], Message | None]]:
    """Yield each SSE event as (raw lines, decoded message or None).

    The raw lines are kept so an event carrying something other than a JSON-RPC
    message -- a comment, a retry directive, a ping -- is relayed byte for byte
    rather than reconstructed from a model that does not cover it.
    """
    event: list[bytes] = []
    for raw in stream:
        line = raw.rstrip(b"\r\n")
        if line:
            event.append(line)
            continue
        if event:
            yield event, _decode(event)
            event = []
    if event:
        yield event, _decode(event)


def _decode(event: list[bytes]) -> Message | None:
    data = b"".join(
        line[5:].lstrip() for line in event if line.lower().startswith(b"data:")
    )
    if not data:
        return None
    try:
        payload = json.loads(data)
    except (ValueError, UnicodeDecodeError):
        return None
    return Message(payload) if isinstance(payload, dict) else None


def _reencode(event: list[bytes], message: Message) -> bytes:
    """Rebuild one SSE event, keeping every field except the data."""
    kept = [line for line in event if not line.lower().startswith(b"data:")]
    body = json.dumps(message.payload, separators=(",", ":")).encode("utf-8")
    return b"\n".join([*kept, b"data: " + body]) + b"\n\n"


class _Handler(BaseHTTPRequestHandler):
    """One request, mediated. Bound to a proxy by :func:`serve`."""

    proxy: Proxy
    upstream: Upstream
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:
        # BaseHTTPRequestHandler logs to stderr, which is the proxy's own
        # channel to the operator. Access logging belongs in front of this.
        return

    # -- host -> server --------------------------------------------------

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        try:
            payload = json.loads(body) if body else None
        except (ValueError, UnicodeDecodeError):
            # Not JSON at all. The server's own error is more informative than
            # one we invent, so this goes upstream untouched.
            self._relay("POST", body)
            return

        forward: Any = None
        if isinstance(payload, dict):
            decided, answered = self._decide([Message(payload)])
            forward = decided[0].payload if decided else None
        elif isinstance(payload, list):
            messages = [Message(p) for p in payload if isinstance(p, dict)]
            decided, answered = self._decide(messages)
            forward = [m.payload for m in decided] if decided else None
        else:
            self._relay("POST", body)
            return

        if forward is None:
            # Every message was decided here. Nothing reaches the server, and
            # a notification that was denied leaves nothing to answer with --
            # which is correct: a notification has no reply by definition.
            if not answered:
                self._raw(202, {}, b"")
                return
            self._send_json(answered if isinstance(payload, list) else answered[0])
            return

        self._relay(
            "POST",
            json.dumps(forward, separators=(",", ":")).encode("utf-8"),
            extra=answered,
        )

    def _decide(self, messages: list[Message]) -> tuple[list[Message], list[Any]]:
        """Run the write boundary over each message. Returns (forward, answers)."""
        forward: list[Message] = []
        answers: list[Any] = []
        for message in messages:
            decided = self.proxy.handle_outbound(message)
            if decided is not None:
                forward.append(decided)
                continue
            answer = self.proxy.take_self_answer(message.id)
            if answer is not None:
                answers.append(answer.payload)
        return forward, answers

    def do_GET(self) -> None:
        self._relay("GET", None)

    def do_DELETE(self) -> None:
        self._relay("DELETE", None)

    # -- server -> host --------------------------------------------------

    def _relay(
        self, method: str, body: bytes | None, extra: list[Any] | None = None
    ) -> None:
        extra = extra or []
        headers = _forwardable(self.headers)
        if body is not None:
            headers["Content-Length"] = str(len(body))
        try:
            response, connection = self.upstream.request(method, headers, body)
        except OSError as exc:
            self.send_error(502, f"upstream unreachable: {exc}")
            return
        try:
            kind = (response.getheader("Content-Type") or "").split(";")[0].strip()
            if kind == _SSE:
                self._relay_sse(response)
            else:
                self._relay_body(response, extra)
        finally:
            connection.close()

    def _relay_body(self, response: HTTPResponse, extra: list[Any]) -> None:
        raw = response.read()
        headers = _forwardable(response.headers)
        try:
            payload = json.loads(raw) if raw else None
        except (ValueError, UnicodeDecodeError):
            payload = None

        if isinstance(payload, dict):
            sealed = self.proxy.handle_inbound(Message(payload))
            out: Any = sealed.payload if sealed is not None else payload
            if extra:
                out = [out, *extra]
        elif isinstance(payload, list):
            out = [
                (self.proxy.handle_inbound(Message(p)) or Message(p)).payload
                if isinstance(p, dict)
                else p
                for p in payload
            ]
            out.extend(extra)
        else:
            # Not a JSON-RPC body: an error page, an empty 202. Relay it, and
            # any denial we owe the host is lost with it -- so say so rather
            # than silently dropping a decision.
            if extra:
                self.proxy.note_relay_dropped(len(extra))
            self._raw(response.status, headers, raw)
            return

        self._send_json(out, status=response.status, headers=headers)

    def _relay_sse(self, response: HTTPResponse) -> None:
        """Relay a server-sent-event stream, sealing every message on it.

        Written back event by event and flushed each time. Buffering an SSE
        stream in a proxy converts a live channel into a stalled one, and the
        host has no way to tell that from a server that has gone quiet.
        """
        self.send_response(response.status)
        # Ours override the server's rather than joining them. Sending a header
        # twice does not replace it -- http.client joins duplicates with a
        # comma, so "text/event-stream" arrives as
        # "text/event-stream, text/event-stream" and a client that matches on
        # the value stops recognising its own stream.
        headers = _forwardable(response.headers)
        headers.pop("Content-Type", None)
        headers.pop("Cache-Control", None)
        for key, value in headers.items():
            self.send_header(key, value)
        self.send_header("Content-Type", _SSE)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            for event, message in _sse_messages(response):
                if message is None:
                    self.wfile.write(b"\n".join(event) + b"\n\n")
                else:
                    sealed = self.proxy.handle_inbound(message) or message
                    self.wfile.write(_reencode(event, sealed))
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass

    # -- writing ---------------------------------------------------------

    def _send_json(
        self, payload: Any, *, status: int = 200, headers: dict[str, str] | None = None
    ) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        merged = {
            key: value
            for key, value in (headers or {}).items()
            if key.lower() != "content-type"
        }
        merged["Content-Type"] = _JSON
        self._raw(status, merged, body)

    def _raw(self, status: int, headers: dict[str, str], body: bytes) -> None:
        self.send_response(status)
        for key, value in headers.items():
            if key.lower() not in _HOP_BY_HOP:
                self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)


def serve(
    config: ProxyConfig,
    *,
    host: str = "127.0.0.1",
    port: int = 0,
    log: IO[bytes] | None = None,
) -> ThreadingHTTPServer:
    """Build a listening proxy. The caller owns serving and shutdown."""
    if not config.server_url:
        raise ValueError("config has no 'server_url' to proxy")
    proxy = Proxy(config, log=log)
    proxy.announce()
    upstream = Upstream(config.server_url)

    handler = type(
        "_BoundHandler", (_Handler,), {"proxy": proxy, "upstream": upstream}
    )
    server = ThreadingHTTPServer((host, port), handler)
    server.daemon_threads = True
    return server


def run_http(
    config: ProxyConfig,
    *,
    host: str = "127.0.0.1",
    port: int = 8808,
    log: IO[bytes] | None = None,
) -> int:
    """Serve until interrupted."""
    server = serve(config, host=host, port=port, log=log)
    stream = log if log is not None else sys.stderr.buffer
    bound_host, bound_port = server.server_address[0], server.server_address[1]
    stream.write(
        f"[idensec] listening on http://{bound_host!s}:{bound_port} -> "
        f"{config.server_url}\n".encode()
    )
    stream.flush()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        thread.join()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        server.server_close()
    return 0
