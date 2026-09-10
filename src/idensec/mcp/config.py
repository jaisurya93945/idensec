"""Proxy configuration.

Everything here fails closed. An unreadable config, an unknown trust tier, or a
missing contract file stops the proxy rather than starting it in a weaker mode:
a security component that degrades quietly when misconfigured is worse than one
that refuses to start, because nobody notices the former.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..budget import Budget
from ..contracts import ContractRegistry
from ..labels import Sensitivity, Source, Trust
from ..policy import OBSERVE, STRICT, SUPERVISED, Policy

__all__ = ["POLICY_PRESETS", "ConfigError", "ProxyConfig"]

POLICY_PRESETS: Mapping[str, Policy] = {
    "strict": STRICT,
    "supervised": SUPERVISED,
    "observe": OBSERVE,
}

_TRUST = {t.name.lower(): t for t in Trust}
_SENSITIVITY = {s.name.lower(): s for s in Sensitivity}


class ConfigError(Exception):
    """The configuration is missing, malformed, or names something unknown."""


@dataclass(frozen=True, slots=True)
class ProxyConfig:
    """How one proxied MCP server is labelled and governed."""

    source: Source
    policy: Policy
    contracts: ContractRegistry
    policy_name: str = "strict"
    task_file: Path | None = None
    """Where the *principal's* instruction is read from.

    MCP carries no trusted channel for the user's task -- the protocol moves
    tool calls and results, not intent -- and the agent cannot be asked for it,
    because an injected agent would simply declare the attacker's goal as the
    task and launder it to ``USER_INPUT``. That is a total bypass, so the task
    must arrive out of band from something the agent cannot write.

    The host writes the principal's verbatim instruction to this file; the
    proxy reads it and indexes it as trusted. Without it there is no trusted
    corpus, every authority value is unattributable, and a strict policy denies
    essentially everything -- correctly, but uselessly. See docs/ARCHITECTURE.md.
    """

    audit_file: Path | None = None
    emit_contracts: Path | None = None
    seal_tool_descriptions: bool = True
    """Tool descriptions are server-supplied and therefore attacker territory
    (MCP tool poisoning). Sealing them is the default; turning it off is a
    deliberate weakening and is logged at startup."""

    budgets: tuple[Budget, ...] = field(default_factory=tuple)
    """Session-level aggregate limits. Every other check judges one call alone."""

    server_command: tuple[str, ...] = field(default_factory=tuple)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any], *, base: Path) -> ProxyConfig:
        schema = data.get("schema")
        if schema != "idensec.proxy/v1":
            raise ConfigError(f"unsupported proxy schema: {schema!r}")

        raw_source = data.get("source")
        if not isinstance(raw_source, Mapping) or not raw_source.get("id"):
            raise ConfigError("config needs a 'source' with an 'id'")

        trust_name = str(raw_source.get("trust", "")).lower()
        if trust_name not in _TRUST:
            raise ConfigError(
                f"source.trust must be one of {sorted(_TRUST)}, got {trust_name!r}. "
                "There is no default: labelling a source is the one decision "
                "IDENSEC cannot make for you, and guessing it wrong is a bypass."
            )
        sensitivity_name = str(raw_source.get("sensitivity", "public")).lower()
        if sensitivity_name not in _SENSITIVITY:
            raise ConfigError(
                f"source.sensitivity must be one of {sorted(_SENSITIVITY)}"
            )

        source = Source(
            id=str(raw_source["id"]),
            trust=_TRUST[trust_name],
            sensitivity=_SENSITIVITY[sensitivity_name],
            authoritative_for=frozenset(raw_source.get("authoritative_for", ())),
            description=str(raw_source.get("description", "")),
        )

        policy_name = str(data.get("policy", "strict")).lower()
        if policy_name not in POLICY_PRESETS:
            raise ConfigError(f"policy must be one of {sorted(POLICY_PRESETS)}")

        contracts_path = data.get("contracts")
        if contracts_path:
            resolved = cls._resolve(base, contracts_path)
            if not resolved.exists():
                raise ConfigError(f"contract file not found: {resolved}")
            contracts = ContractRegistry.load(resolved)
        else:
            contracts = ContractRegistry()

        return cls(
            source=source,
            policy=POLICY_PRESETS[policy_name],
            policy_name=policy_name,
            contracts=contracts,
            task_file=cls._optional(base, data.get("task_file")),
            audit_file=cls._optional(base, data.get("audit")),
            emit_contracts=cls._optional(base, data.get("emit_contracts")),
            seal_tool_descriptions=bool(data.get("seal_tool_descriptions", True)),
            budgets=cls._budgets(data.get("budgets", ())),
            server_command=tuple(data.get("server", ())),
        )

    @classmethod
    def load(cls, path: str | Path) -> ProxyConfig:
        config_path = Path(path)
        try:
            data = json.loads(config_path.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise ConfigError(f"config not found: {config_path}") from exc
        except ValueError as exc:
            raise ConfigError(f"config is not valid JSON: {exc}") from exc
        return cls.from_dict(data, base=config_path.parent)

    @staticmethod
    def _budgets(raw: Any) -> tuple[Budget, ...]:
        if not isinstance(raw, (list, tuple)):
            raise ConfigError("'budgets' must be a list")
        try:
            return tuple(Budget.from_dict(entry) for entry in raw)
        except (KeyError, TypeError, ValueError) as exc:
            raise ConfigError(f"invalid budget: {exc}") from exc

    @staticmethod
    def _resolve(base: Path, value: Any) -> Path:
        path = Path(str(value))
        return path if path.is_absolute() else (base / path)

    @classmethod
    def _optional(cls, base: Path, value: Any) -> Path | None:
        return None if value in (None, "") else cls._resolve(base, value)

    def read_task(self) -> str:
        """Read the principal's instruction, or empty if none is configured."""
        if self.task_file is None or not self.task_file.exists():
            return ""
        return self.task_file.read_text(encoding="utf-8")

    def warnings(self) -> list[str]:
        """Configuration that is legal but weakens the guarantee.

        Surfaced at startup rather than buried, because every one of these is a
        thing an operator will otherwise discover during an incident.
        """
        notes: list[str] = []
        if self.policy_name == "observe":
            notes.append(
                "policy=observe: nothing is enforced. Decisions are recorded only."
            )
        if self.task_file is None:
            notes.append(
                "no task_file: there is no trusted corpus, so every authority-bearing "
                "argument is unattributable and a strict policy will deny nearly "
                "everything."
            )
        if not self.seal_tool_descriptions:
            notes.append(
                "seal_tool_descriptions=false: tool descriptions reach the model "
                "unsealed, which is the MCP tool-poisoning path."
            )
        if not len(self.contracts):
            notes.append(
                "no contracts loaded: every tool is unknown and will be treated as "
                "writing, egressing and irreversible."
            )
        if self.source.is_principal:
            notes.append(
                f"source '{self.source.id}' is labelled {self.source.trust.name}, which "
                "makes it authoritative for every operand kind. An MCP server should "
                "rarely be trusted this far."
            )
        return notes
