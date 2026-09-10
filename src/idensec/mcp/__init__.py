"""MCP integration: a stdio proxy that enforces argument provenance.

MCP is the highest-leverage deployment surface for IDENSEC because the protocol
already carries both boundaries the design needs -- tool results arriving and
tool calls departing -- so a host gains enforcement without any application
change.

See ``docs/MCP.md`` for the deployment guide, including the one thing MCP does
not provide: a trusted channel for the principal's instruction.
"""

from .config import ConfigError, ProxyConfig
from .jsonrpc import Message
from .proxy import Proxy, run

__all__ = ["ConfigError", "Message", "Proxy", "ProxyConfig", "run"]
