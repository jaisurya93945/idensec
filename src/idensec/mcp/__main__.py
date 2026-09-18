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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m idensec.mcp",
        description="Enforce argument provenance on an MCP server, over stdio.",
        epilog=(
            "The proxy speaks MCP on stdin/stdout and launches the server named in "
            "the config. Point your MCP host at this command instead of at the "
            "server directly."
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
