"""Command line entry point:  python -m idensec.mcp --config idensec.json"""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import signal
import sys
from pathlib import Path
from types import FrameType

from .config import ConfigError, ProxyConfig
from .proxy import run
from .streamable import run_http


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m idensec.mcp",
        description="Enforce argument provenance on an MCP server, over stdio.",
        epilog=(
            "A config naming 'server' launches that server and mediates stdio; "
            "point your MCP host at this command instead of at the server. A "
            "config naming 'server_url' listens on HTTP and mediates a remote "
            "server; point your host at this proxy's address instead."
        ),
    )
    parser.add_argument("--config", required=True, type=Path, help="proxy config JSON")
    parser.add_argument(
        "--task-file",
        type=Path,
        help="override the config's task_file: where the principal's instruction is "
        "read from. Must not be writable by the agent.",
    )
    parser.add_argument(
        "--listen",
        default="127.0.0.1",
        help="address to listen on, for a config naming 'server_url'. Loopback "
        "by default: whatever can reach this socket can speak MCP to it, and "
        "this proxy is not a trust boundary against its own client.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8808,
        help="port to listen on, for a config naming 'server_url'",
    )
    parser.add_argument(
        "--emit-contracts",
        type=Path,
        help="write draft contracts derived from the server's advertised tool "
        "schemas and exit-safe. Drafts have no effects declared and are not usable "
        "until an operator completes them.",
    )
    args = parser.parse_args(argv)

    try:
        config = ProxyConfig.load(args.config)
    except ConfigError as exc:
        print(f"idensec: {exc}", file=sys.stderr)
        return 2

    if args.task_file is not None:
        config = dataclasses.replace(config, task_file=args.task_file)
    if args.emit_contracts is not None:
        config = dataclasses.replace(config, emit_contracts=args.emit_contracts)

    _exit_cleanly_on_signal()

    try:
        # The config says which transport it is by which server it names, so
        # there is no flag to get wrong and no default to be surprised by.
        if config.server_url:
            return run_http(config, host=args.listen, port=args.port)
        return run(config)
    except ValueError as exc:
        print(f"idensec: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


def _exit_cleanly_on_signal() -> None:
    """Turn SIGTERM and SIGHUP into an ordinary exit.

    Their default action kills this process outright, which skips the cleanup
    that shuts the server down -- so a host that stops the proxy would leave the
    server it launched running, holding whatever the server holds. Raising
    SystemExit instead lets ``run``'s finally clause do its job.
    """

    def stop(signum: int, _frame: FrameType | None) -> None:
        raise SystemExit(128 + signum)

    for name in ("SIGTERM", "SIGHUP"):
        received = getattr(signal, name, None)
        if received is not None:
            with contextlib.suppress(ValueError, OSError):
                signal.signal(received, stop)


if __name__ == "__main__":
    raise SystemExit(main())
