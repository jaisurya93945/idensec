"""An MCP stdio proxy that enforces argument provenance.

The proxy sits between an MCP host and one MCP server and mediates exactly the
two boundaries IDENSEC needs, both of which the protocol already provides:

* ``tools/call`` **request** -> the write boundary. Arguments are attributed and
  the call is admitted, denied, or escalated.
* **every result** -> the read boundary. Text is sealed before it reaches the
  model.

That second rule is deliberately stated as *every* result rather than as a list
of methods. ``tools/call`` is not the only path by which content reaches a
model: ``resources/read``, ``prompts/get`` and ``resources/list`` all carry
server-supplied text, and an earlier version of this proxy sealed only tool
results, which left an attacker-controlled resource free to hand the model an
address in clear. Enumerating the content-bearing methods is a losing game
against a protocol that keeps adding them, so the default is inverted: seal
everything, and name the exceptions.

Sealing is safe to apply this broadly because it is a no-op on text containing
no operands -- prose passes through byte-for-byte. The exceptions exist for the
two places where a handle would break something structural:

* ``initialize`` -- protocol metadata. A sealed ``protocolVersion`` breaks the
  handshake.
* ``tools/list`` -- tool names and JSON Schemas must survive intact, so only the
  human-readable ``description`` is sealed. That is also where tool poisoning
  lives, so it is the field that most needs it.

Requests other than ``tools/call``, and messages we do not recognise at all, are
forwarded untouched. A proxy that only forwards what it recognises breaks on the
next protocol revision.

**The proxy is not a trust boundary against the host.** It protects the
*principal* from content the agent consumes. A host that chooses not to route
through it is simply unprotected, which is the normal situation for any
enforcement point outside the application.
"""

from __future__ import annotations

import contextlib
import json
import subprocess
import sys
import threading
from typing import IO, Any

from ..contracts import derive_contract
from ..decision import Verdict
from ..lint import Severity, lint_registry
from ..monitor import Session
from .config import ProxyConfig
from .jsonrpc import Message, error_result, read_messages, write_message

__all__ = ["Proxy", "run"]

ESCALATION_TEXT = (
    "This action requires approval from the principal before it can proceed."
)


class Proxy:
    """Mediates one MCP session.

    Both pump threads touch the session, and a :class:`Session` belongs to one
    linear execution by design -- sharing one across concurrent agents would
    cross-contaminate provenance. A single lock keeps the invariant without
    pretending the session is concurrent.
    """

    def __init__(self, config: ProxyConfig, *, log: IO[bytes] | None = None) -> None:
        self.config = config
        self._log = log if log is not None else sys.stderr.buffer
        self._lock = threading.Lock()
        self._pending: dict[Any, str] = {}
        self._denied: set[Any] = set()
        self._audit_seen = 0
        self._drafts: dict[str, dict[str, Any]] = {}
        self._host_out: IO[bytes] | None = None

        self.session = Session(
            contracts=config.contracts,
            policy=config.policy,
            sources=[config.source],
            session_id=config.source.id,
            budgets=config.budgets,
        )
        self._principal_id = f"{config.source.id}::principal"
        self._declare_principal()

    # -- setup -----------------------------------------------------------

    def _declare_principal(self) -> None:
        """Index the principal's instruction, if the host supplied one."""
        from ..labels import Source, Trust

        self.session.declare_source(
            Source(
                self._principal_id,
                Trust.USER_INPUT,
                description="the principal's instruction, read out of band",
            )
        )
        task = self.config.read_task()
        if task.strip():
            self.session.observe(self._principal_id, task)
            self._note(f"indexed principal task ({len(task)} chars)")

    def _note(self, text: str) -> None:
        self._log.write(f"[idensec] {text}\n".encode())
        self._log.flush()

    def announce(self) -> None:
        config = self.config
        self._note(
            f"proxying source '{config.source.id}' "
            f"trust={config.source.trust.name} policy={config.policy_name} "
            f"contracts={len(config.contracts)} budgets={len(config.budgets)}"
        )
        for warning in config.warnings():
            self._note(f"WARNING {warning}")
        self._lint()

    def _lint(self) -> None:
        """Report contract defects before serving traffic.

        A wrong contract is a silent bypass -- the monitor allows the call and
        raises no finding, because as far as it knows nothing authority-bearing
        was involved. Startup is the last moment anyone will look, so errors are
        surfaced here rather than left for an audit nobody runs.

        This does not refuse to start. The linter reasons from names and cannot
        know your system, so a false positive must not be able to take a
        deployment down; the operator decides.
        """
        if not len(self.config.contracts):
            return
        diagnostics = lint_registry(self.config.contracts, [self.config.source])
        problems = [d for d in diagnostics if d.severity >= Severity.WARNING]
        if not problems:
            return
        errors = sum(1 for d in problems if d.severity is Severity.ERROR)
        self._note(
            f"contract lint: {errors} error(s), {len(problems) - errors} warning(s). "
            "Run 'python -m idensec.lint <contracts>' for the full report."
        )
        for diagnostic in problems[:10]:
            self._note(f"  {diagnostic.render()}")
        if len(problems) > 10:
            self._note(f"  ... and {len(problems) - 10} more")

    # -- host -> server --------------------------------------------------

    def handle_outbound(self, message: Message) -> Message | None:
        """Inspect a message on its way to the server.

        Returns the message to forward, or ``None`` when the proxy has answered
        it itself -- which is what a denial is.
        """
        if message.method != "tools/call" or not message.is_request:
            return message

        params = message.params
        tool = params.get("name")
        arguments = params.get("arguments")
        if not isinstance(tool, str) or not isinstance(arguments, dict):
            # Malformed by MCP's own rules. Forward and let the server reject
            # it; inventing an error here would mask a protocol bug.
            return message

        with self._lock:
            decision = self.session.admit(tool, arguments)
            self._flush_audit()

        if decision.verdict is Verdict.ALLOW:
            self._pending[message.id] = tool
            forwarded = dict(message.payload)
            forwarded["params"] = {**params, "arguments": dict(decision.arguments)}
            return Message(forwarded)

        self._note(f"{decision.verdict.value.upper()} {tool}: {decision.reason()}")
        self._denied.add(message.id)
        text = (
            ESCALATION_TEXT
            if decision.verdict is Verdict.ESCALATE
            else decision.agent_message
        )
        self._respond(error_result(message.id, text))
        return None

    # -- server -> host --------------------------------------------------

    def handle_inbound(self, message: Message) -> Message | None:
        """Inspect a message on its way back to the host."""
        if not message.is_response:
            return message
        result = message.result
        if result is None:
            return message

        tool = self._pending.pop(message.id, None)
        if tool is not None:
            return self._seal_result(message, result, path=f"{tool}.result")
        if "tools" in result and isinstance(result["tools"], list):
            return self._handle_tools_list(message, result)
        if self._is_protocol_metadata(result):
            return message
        return self._seal_result(message, result, path="result")

    @staticmethod
    def _is_protocol_metadata(result: dict[str, Any]) -> bool:
        """Recognise the handshake, whose fields must survive intact."""
        return "protocolVersion" in result or "capabilities" in result

    def _seal_result(
        self, message: Message, result: dict[str, Any], *, path: str
    ) -> Message:
        """Seal every string in a result before the model sees it.

        The whole structure is walked rather than a known field, so field-level
        provenance is recorded (``result.contents[0].text``) and no new
        content-bearing shape can appear in a future protocol revision and slip
        past unsealed.
        """
        with self._lock:
            sealed = self.session.observe(self.config.source.id, result, path=path)
        payload = dict(message.payload)
        payload["result"] = sealed
        return Message(payload)

    def _handle_tools_list(self, message: Message, result: dict[str, Any]) -> Message:
        """Seal tool descriptions and, optionally, draft contracts from schemas."""
        tools = result["tools"]
        sealed_tools = []
        for tool in tools:
            if not isinstance(tool, dict):
                sealed_tools.append(tool)
                continue
            name = tool.get("name")
            if isinstance(name, str) and self.config.emit_contracts:
                self._draft(name, tool)
            description = tool.get("description")
            if self.config.seal_tool_descriptions and isinstance(description, str):
                with self._lock:
                    sealed = self.session.observe(
                        self.config.source.id,
                        description,
                        path=f"tools.{name}.description",
                    )
                sealed_tools.append({**tool, "description": sealed})
            else:
                sealed_tools.append(tool)
        if self.config.emit_contracts:
            self._write_drafts()
        payload = dict(message.payload)
        payload["result"] = {**result, "tools": sealed_tools}
        return Message(payload)

    # -- contract drafting -----------------------------------------------

    def _draft(self, name: str, tool: dict[str, Any]) -> None:
        """Derive a starting contract from a tool's advertised schema.

        A draft, never an authority. Effects are not read off the schema -- they
        cannot be, and guessing that a tool is read-only would be the most
        dangerous inference in the system. A draft with no effects is one an
        operator must complete before it means anything.

        The server's own ``annotations`` are passed through, and are read under
        the one-way rule in ``contracts._WIDENING_ANNOTATIONS``: a server saying
        it is destructive or open-world is believed, because believing it only
        ever restricts; a server saying it is read-only is ignored, because
        believing *that* would let a poisoned server mark its exfiltration tool
        safe. The annotations arrive over the same channel as the tool
        descriptions this proxy seals, and are treated with the same suspicion.
        """
        schema = tool.get("inputSchema")
        annotations = tool.get("annotations")
        contract = derive_contract(
            name,
            schema if isinstance(schema, dict) else None,
            description=str(tool.get("description", ""))[:200],
            annotations=annotations if isinstance(annotations, dict) else None,
        )
        self._drafts[name] = contract.to_dict()

    def _write_drafts(self) -> None:
        target = self.config.emit_contracts
        if target is None or not self._drafts:
            return
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            json.dumps(
                {
                    "schema": "idensec.contracts/v1",
                    "_comment": (
                        "DRAFT. Generated from advertised tool schemas. Effects are "
                        "empty because they cannot be inferred -- fill them in, check "
                        "every parameter role, then load this with 'contracts' in the "
                        "proxy config."
                    ),
                    "contracts": [self._drafts[k] for k in sorted(self._drafts)],
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        self._note(f"wrote {len(self._drafts)} draft contracts to {target}")

    # -- audit -----------------------------------------------------------

    def _flush_audit(self) -> None:
        target = self.config.audit_file
        if target is None:
            return
        records = list(self.session.audit)[self._audit_seen :]
        if not records:
            return
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("a", encoding="utf-8") as handle:
            for record in records:
                handle.write(json.dumps(record.to_dict(), sort_keys=True) + "\n")
        self._audit_seen += len(records)

    # -- plumbing --------------------------------------------------------

    def bind_host_output(self, stream: IO[bytes]) -> None:
        self._host_out = stream

    def send_to_host(self, message: Message) -> None:
        """Write one message to the host, serialised against the other pump."""
        if self._host_out is not None:
            with self._lock:
                write_message(self._host_out, message)

    def close(self) -> None:
        with self._lock:
            self._flush_audit()

    def _respond(self, message: Message) -> None:
        self.send_to_host(message)


def run(
    config: ProxyConfig,
    *,
    host_in: IO[bytes] | None = None,
    host_out: IO[bytes] | None = None,
    log: IO[bytes] | None = None,
) -> int:
    """Run the proxy until the host closes its side."""
    if not config.server_command:
        raise ValueError("config has no 'server' command to proxy")

    host_in = host_in if host_in is not None else sys.stdin.buffer
    host_out = host_out if host_out is not None else sys.stdout.buffer

    proxy = Proxy(config, log=log)
    proxy.bind_host_output(host_out)
    proxy.announce()

    server = subprocess.Popen(  # noqa: S603 - command comes from the operator's config
        list(config.server_command),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=None,
    )
    assert server.stdin is not None and server.stdout is not None

    def pump_inbound() -> None:
        try:
            for message in read_messages(server.stdout):  # type: ignore[arg-type]
                forwarded = proxy.handle_inbound(message)
                if forwarded is not None:
                    proxy.send_to_host(forwarded)
        except (BrokenPipeError, ValueError):
            pass

    reader = threading.Thread(target=pump_inbound, name="idensec-inbound", daemon=True)
    reader.start()

    try:
        for message in read_messages(host_in):
            forwarded = proxy.handle_outbound(message)
            if forwarded is not None:
                write_message(server.stdin, forwarded)
    except (BrokenPipeError, ValueError):
        pass
    finally:
        with contextlib.suppress(OSError):
            server.stdin.close()
        server.wait(timeout=10)
        reader.join(timeout=5)
        proxy.close()

    return server.returncode or 0
