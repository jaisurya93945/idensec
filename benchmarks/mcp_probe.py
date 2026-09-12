"""Capture ``tools/list`` from live MCP servers over stdio.

Separate from the benchmark because the benchmark must run without network
access: the captured corpus is checked in, and this is only used to refresh it.
The client here is deliberately minimal -- initialize, initialized, tools/list --
because anything more would be re-implementing the proxy in a benchmark.
"""

from __future__ import annotations

import json
import subprocess
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

KEEP = ("name", "description", "inputSchema", "annotations")


def probe(argv: Sequence[str], timeout: float = 120) -> dict[str, Any] | None:
    """Handshake with one server and return its advertised tools."""
    process = subprocess.Popen(  # noqa: S603 - argv comes from this file
        list(argv),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        bufsize=1,
    )

    def send(payload: dict[str, Any]) -> None:
        assert process.stdin is not None
        process.stdin.write(json.dumps(payload) + "\n")
        process.stdin.flush()

    def read(deadline: float) -> dict[str, Any] | None:
        assert process.stdout is not None
        while time.time() < deadline:
            line = process.stdout.readline()
            if not line:
                return None
            line = line.strip()
            if not line:
                continue
            try:
                return json.loads(line)
            except ValueError:
                continue  # servers log to stdout; skip anything not JSON-RPC
        return None

    try:
        send({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "idensec-corpus", "version": "0"},
            },
        })
        handshake = read(time.time() + timeout)
        if handshake is None:
            return None
        send({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
        send({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        deadline = time.time() + timeout
        while True:
            message = read(deadline)
            if message is None:
                return None
            if message.get("id") == 2:
                return {
                    "server": handshake.get("result", {}).get("serverInfo", {}),
                    "tools": [
                        {k: tool[k] for k in KEEP if k in tool}
                        for tool in message.get("result", {}).get("tools", [])
                    ],
                }
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()


def capture(servers: Mapping[str, Sequence[str]], target: Path) -> None:
    """Probe every server and rewrite the checked-in corpus."""
    captured: dict[str, Any] = {}
    for name, argv in servers.items():
        try:
            result = probe(argv)
        except OSError as exc:
            print(f"  {name}: {exc}")
            continue
        if result and result["tools"]:
            captured[name] = result
            print(f"  {name}: {len(result['tools'])} tools")
        else:
            print(f"  {name}: no tools reported; leaving the corpus unchanged")
    if not captured:
        raise SystemExit("captured nothing; refusing to overwrite the corpus")
    target.write_text(
        json.dumps(captured, indent=1, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"wrote {target}")
