"""Command line entry point:  python -m idensec.mcp --config idensec.json"""

from __future__ import annotations

import argparse
import dataclasses
import sys
from pathlib import Path

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

    try:
        return run(config)
    except ValueError as exc:
        print(f"idensec: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
