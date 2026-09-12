"""The admission monitor.

A :class:`Session` mediates one agent's execution. It has exactly two jobs, one
at each boundary:

* :meth:`Session.observe` -- content arriving from a source. Untrusted content
  is sealed, trusted content is indexed.
* :meth:`Session.admit` -- a tool call the agent wants to make. Handles are
  resolved, every argument is attributed, and a verdict is produced.

The verdict is a pure function of ``(session state, contracts, policy, call)``.
No model is consulted, no network call is made, and replaying the same
observations and calls always yields the same decisions -- which is what makes
a decision auditable rather than merely logged.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import replace
from typing import Any

from .audit import AuditChain, AuditRecord
from .budget import Budget, BudgetLedger
from .contracts import ContractRegistry, Effect, ParameterContract, Role, ToolContract
from .decision import Decision, Finding, FindingCode, Verdict
from .kinds import DEFAULT_KINDS, REFERENCED, UNCLASSIFIED, classify, extract
from .labels import (
    Attribution,
    AttributionState,
    Origin,
    Sensitivity,
    Source,
    Trust,
    merge_origins,
)
from .ledger import OperandLedger, Resolution
from .policy import STRICT, Disposition, Policy

__all__ = ["Session", "SessionHalted"]


def _describing_text(record: Mapping[str, Any], limit: int = 24) -> list[str]:
    """The short string fields of a record: what a person would call it by.

    Long text is skipped deliberately. A record's *body* or *description* is
    where injections live, so quoting one must not bind a reference -- only the
    short, name-like fields count.
    """
    found: list[str] = []
    for value in record.values():
        if isinstance(value, str) and 0 < len(value) <= 120:
            found.append(value)
        elif isinstance(value, (int, float)) and not isinstance(value, bool):
            found.append(str(value))
        if len(found) >= limit:
            break
    return found


_KEY_FIELDS = ("id", "uuid", "key", "name", "slug")


def _record_key(record: Mapping[str, Any]) -> str:
    """The field of a record that identifies it, if it has an obvious one.

    Checked in order, so ``id`` beats ``name`` when a record carries both. Only
    scalars count: a nested object is not an identifier, and returning one would
    record an entity under a key no tool could ever be passed.
    """
    for field in _KEY_FIELDS:
        value = record.get(field)
        if isinstance(value, str) and value:
            return value
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return str(value)
    return ""


class SessionHalted(RuntimeError):
    """Raised by :meth:`Session.require` when the session has stopped."""


_INFORMATIONAL = frozenset({FindingCode.UNDECLARED_PARAMETER})

_UNKNOWN_TOOL_CONTRACT_EFFECTS = frozenset(
    {Effect.WRITE, Effect.NETWORK_EGRESS, Effect.IRREVERSIBLE}
)
"""Effects assumed for a tool we have no contract for.

Assuming the worst is the only sound choice: a tool we have never seen might
send mail, and treating it as read-only would make "forgot to write a contract"
a silent bypass.
"""


class Session:
    """One agent execution, mediated.

    ``budgets`` bound what the session may do *in aggregate*. Every other check
    here judges one call in isolation, which leaves individually-authorised
    actions free to sum to an outcome the principal never sanctioned.

    ``max_observed_chars`` bounds how much content one session may take in.
    Exceeding it raises rather than silently forgetting, because a ledger that
    quietly drops observations stops being able to attribute what it forgot and
    would therefore fail *open* on exactly those values. A long-running agent
    should start a new session rather than raise this without thought.
    """

    def __init__(
        self,
        *,
        contracts: ContractRegistry | Iterable[ToolContract] = (),
        policy: Policy = STRICT,
        sources: Iterable[Source] = (),
        kinds: Sequence[str] | None = None,
        id_factory: Any | None = None,
        session_id: str = "",
        max_observed_chars: int = 4_000_000,
        budgets: Iterable[Budget] = (),
    ) -> None:
        self.session_id = session_id
        self.policy = policy
        self.contracts = (
            contracts
            if isinstance(contracts, ContractRegistry)
            else ContractRegistry(contracts)
        )
        self._kinds = tuple(kinds) if kinds is not None else DEFAULT_KINDS
        self._sources: dict[str, Source] = {}
        self.ledger = OperandLedger(
            kinds=self._kinds,
            id_factory=id_factory,
            max_indexed_chars=max_observed_chars,
            min_derivation_length=policy.min_quotation_length,
        )
        self.ledger.bind_source_lookup(self._source_labels)
        self.audit = AuditChain()
        self.budgets = BudgetLedger(budgets)
        self._step = 0
        self._denials = 0
        self._halted = False
        self._confidential_context = False
        self._references_declared: bool | None = None
        for source in sources:
            self.declare_source(source)

    # -- sources ---------------------------------------------------------

    def declare_source(self, source: Source) -> Source:
        """Register a data origin.

        Getting a source's trust wrong is a total bypass: labelling a web
        fetcher as ``TOOL_TRUSTED`` and authoritative for ``email`` hands an
        attacker the recipient field. This is the first deployment assumption
        in the threat model, and it is the integrator's to get right -- IDENSEC
        cannot verify it.
        """
        existing = self._sources.get(source.id)
        if existing is not None and existing != source:
            raise ValueError(
                f"source {source.id!r} already declared with different labels; "
                "relabelling a source mid-session would retroactively change "
                "provenance"
            )
        self._sources[source.id] = source
        self._references_declared = None
        return source

    @property
    def sources(self) -> Mapping[str, Source]:
        return dict(self._sources)

    def _source(self, source_id: str) -> Source:
        try:
            return self._sources[source_id]
        except KeyError:
            raise KeyError(
                f"undeclared source {source_id!r}; declare it before observing "
                "content from it"
            ) from None

    def _source_labels(self, source_id: str) -> tuple[int, int]:
        source = self._sources.get(source_id)
        if source is None:
            return int(Trust.TOOL_UNTRUSTED), int(Sensitivity.PUBLIC)
        return int(source.trust), int(source.sensitivity)

    @property
    def _reference_binding_declared(self) -> bool:
        """True when some source is authoritative over ``REFERENCED``.

        Reference binding is opt-in per source, and asking whether a value is
        an id of a record the principal named is the most expensive question
        the monitor can ask. Skipping it entirely when no grant could act on
        the answer keeps that cost off every deployment that has not asked
        for it. Cached because it is consulted per attributed leaf, and
        invalidated by :meth:`declare_source`, which is the only thing that can
        change the answer.
        """
        if self._references_declared is None:
            self._references_declared = any(
                REFERENCED in source.authoritative_for
                or any(REFERENCED in kinds for _, kinds in source.authoritative_paths)
                for source in self._sources.values()
            )
        return self._references_declared

    @property
    def _trusted_source_ids(self) -> tuple[str, ...]:
        return tuple(s.id for s in self._sources.values() if s.is_principal)

    @property
    def _untrusted_source_ids(self) -> tuple[str, ...]:
        return tuple(s.id for s in self._sources.values() if not s.is_principal)

    # -- state -----------------------------------------------------------

    @property
    def step(self) -> int:
        return self._step

    @property
    def halted(self) -> bool:
        return self._halted

    @property
    def denials(self) -> int:
        return self._denials

    @property
    def denial_channel_bits(self) -> int:
        """Upper bound on what the denial channel may have leaked, in bits.

        Each denial tells the agent one thing: that the call was refused. With
        content-free denials that is approximately one bit, so the session's
        denial count bounds the total. Reported rather than hidden, because an
        unquantified covert channel is one nobody can reason about -- and the
        denial budget is what keeps this number finite.
        """
        return self._denials

    def _next_step(self) -> int:
        self._step += 1
        return self._step

    # -- read boundary ---------------------------------------------------

    def observe(self, source_id: str, content: Any, *, path: str = "") -> Any:
        """Bring content into the agent's context under a source label.

        Returns what the agent should actually see: sealed for untrusted
        sources, unchanged for trusted ones. Structures are walked, so a JSON
        tool result gets field-level provenance (``results[2].url``) rather
        than one label for the whole blob.
        """
        source = self._source(source_id)
        step = self._next_step()
        if source.sensitivity >= Sensitivity.CONFIDENTIAL:
            self._confidential_context = True
        return self._walk_observe(source, content, step, path)

    def _walk_observe(self, source: Source, content: Any, step: int, path: str) -> Any:
        if isinstance(content, str):
            if source.is_principal or source.trust >= Trust.TOOL_TRUSTED:
                return self.ledger.index(source, content, step=step, path=path)
            return self.ledger.seal(source, content, step=step, path=path)
        if isinstance(content, Mapping):
            # Keys are data too. A tool result shaped as {"events": {"5": {...}}}
            # carries the entity id in the key, not in any leaf, and a walk that
            # only visits leaves never sees it -- so the id the agent must pass
            # back is attributable to nothing. Keys are *indexed* rather than
            # sealed: rewriting a key would change the structure the agent has
            # to navigate, and attribution, not sealing, is what refuses an
            # attacker-chosen value at the write boundary.
            for key, value in content.items():
                if not isinstance(key, str) or not key:
                    continue
                self.ledger.index(source, key, step=step, path=path)
                if isinstance(value, Mapping):
                    # A dict under a dict is a directory record. Remember what
                    # describes it, so that selecting it can later be checked
                    # against whether the principal referred to it.
                    self.ledger.record_entity(
                        key,
                        path,
                        _describing_text(value),
                        Origin(source.id, source.trust, source.sensitivity, step, path),
                    )
            return {
                key: self._walk_observe(
                    source, value, step, f"{path}.{key}" if path else str(key)
                )
                for key, value in content.items()
            }
        if isinstance(content, (int, float)) and not isinstance(content, bool):
            # Numbers are data too, and an id that arrives as 7 rather than "7"
            # is the same id. Dropping them meant every integer-keyed record was
            # permanently unattributable -- which showed up as four banking
            # tasks failing on `id=7` the moment a bare `id` parameter was
            # correctly treated as authority-bearing.
            #
            # Indexed, never sealed: replacing a number with a handle would
            # change the JSON type the agent has to send back, and attribution
            # rather than sealing is what refuses an attacker-chosen value.
            # Booleans are excluded because true and false identify nothing.
            self.ledger.index(source, str(content), step=step, path=path)
            return content
        if isinstance(content, (list, tuple)):
            # A list of records is a directory too, and the commoner shape:
            # {"events": {"5": {...}}} keys by id, but every JSON API that
            # returns an array carries the id in an `id` field instead. Only the
            # first shape was recognised, so reference binding never fired on an
            # array -- which is most of them.
            for item in content:
                if isinstance(item, Mapping):
                    key = _record_key(item)
                    if key:
                        self.ledger.record_entity(
                            key,
                            path,
                            _describing_text(item),
                            Origin(
                                source.id, source.trust, source.sensitivity, step, path
                            ),
                        )
            walked = [
                self._walk_observe(source, value, step, f"{path}[{i}]")
                for i, value in enumerate(content)
            ]
            return type(content)(walked) if isinstance(content, tuple) else walked
        return content

    # -- write boundary --------------------------------------------------

    def admit(self, tool: str, arguments: Mapping[str, Any]) -> Decision:
        """Decide whether a tool call may proceed, and with what arguments."""
        step = self._next_step()
        enforced = self.policy is not None and self._enforcing()

        if self._halted:
            return self._finalise(
                Verdict.DENY,
                tool,
                step,
                dict(arguments),
                (Finding(code=FindingCode.SESSION_HALTED, detail="denial budget exhausted"),),
                enforced,
            )

        findings: list[Finding] = []
        verdict = Verdict.ALLOW

        contract = self.contracts.get(tool)
        if contract is None:
            findings.append(
                Finding(
                    code=FindingCode.UNKNOWN_TOOL,
                    detail=f"no contract declared for {tool!r}",
                )
            )
            verdict = verdict.worse_of(
                Verdict.from_disposition(self.policy.unknown_tool)
            )
            contract = ToolContract(
                tool=tool,
                effects=_UNKNOWN_TOOL_CONTRACT_EFFECTS,
                default_role=Role.AUTHORITY,
            )

        resolved: dict[str, Any] = {}
        sensitivity = Sensitivity.PUBLIC
        authority_attributions: list[Attribution] = []

        for name, raw in arguments.items():
            parameter = contract.parameter(name)
            if contract.parameters and name not in contract.parameters:
                findings.append(
                    Finding(
                        code=FindingCode.UNDECLARED_PARAMETER,
                        parameter=name,
                        detail=f"treated as {parameter.role.value} by default_role",
                    )
                )
            value, leaves = self._resolve(raw)
            resolved[name] = value

            for leaf_path, resolution in leaves:
                label = f"{name}{leaf_path}"
                for unknown in resolution.unknown_seals:
                    findings.append(
                        Finding(
                            code=FindingCode.UNKNOWN_SEAL,
                            parameter=label,
                            detail=f"unresolvable handle {unknown}",
                        )
                    )
                    verdict = verdict.worse_of(
                        Verdict.from_disposition(self.policy.unknown_seal)
                    )

                if parameter.role is Role.ADVISORY:
                    continue

                if parameter.role is Role.PAYLOAD:
                    for attribution in self._payload_attributions(resolution):
                        sensitivity = max(sensitivity, attribution.sensitivity)
                    continue

                leaf_findings, attributions = self._check_authority(
                    label, parameter, resolution
                )
                findings.extend(leaf_findings)
                authority_attributions.extend(attributions)
                for attribution in attributions:
                    sensitivity = max(sensitivity, attribution.sensitivity)
                for finding in leaf_findings:
                    verdict = verdict.worse_of(self._disposition_for(finding.code))

        if contract.can_egress and self._denials:
            findings.append(
                Finding(
                    code=FindingCode.DENIAL_INFLUENCED_EGRESS,
                    detail=(
                        f"{self._denials} denial(s) have occurred in this session; "
                        f"at most ~{self._denials} bit(s) may have been inferred from "
                        "them and could be encoded into this call"
                    ),
                )
            )
            verdict = verdict.worse_of(
                Verdict.from_disposition(self.policy.denial_influenced_egress)
            )

        if contract.can_egress:
            principal_directed = bool(authority_attributions) and all(
                a.principal_directed() for a in authority_attributions
            )
            if not principal_directed:
                if sensitivity >= Sensitivity.CONFIDENTIAL:
                    findings.append(
                        Finding(
                            code=FindingCode.CONFIDENTIAL_EGRESS,
                            detail=(
                                f"payload quotes {sensitivity.name} content and is "
                                "reaching a network_egress sink whose destination the "
                                "principal did not choose"
                            ),
                        )
                    )
                    verdict = verdict.worse_of(
                        Verdict.from_disposition(self.policy.confidential_egress)
                    )
                elif self._confidential_context:
                    findings.append(
                        Finding(
                            code=FindingCode.CONFIDENTIAL_CONTEXT_EGRESS,
                            detail=(
                                "a confidential source was observed in this session; "
                                "payload does not visibly quote it, but paraphrase is "
                                "not detectable"
                            ),
                        )
                    )
                    verdict = verdict.worse_of(
                        Verdict.from_disposition(self.policy.confidential_context_egress)
                    )

        for breach in self.budgets.check(contract, resolved):
            findings.append(
                Finding(
                    code=FindingCode.BUDGET_EXCEEDED,
                    detail=breach.describe(),
                )
            )
            verdict = verdict.worse_of(
                Verdict.from_disposition(self.policy.budget_exceeded)
            )

        decision = self._finalise(verdict, tool, step, resolved, tuple(findings), enforced)
        if decision.allowed:
            # Consumed by committed actions only. Charging denied calls would
            # let an attacker exhaust the principal's allowance with calls that
            # were never going to succeed.
            self.budgets.commit(contract, resolved)
        return decision

    # -- authority checking ----------------------------------------------

    def _check_authority(
        self, label: str, parameter: ParameterContract, resolution: Resolution
    ) -> tuple[list[Finding], list[Attribution]]:
        """Decide whether one authority-bearing leaf is admissible.

        Two regimes, and the difference is the incentive to declare kinds:

        * **Kinds declared** -- authority is carried by operands of those kinds.
          Every operand present must be authorised and of an accepted kind;
          surrounding text (``"Bob <...>"``, a ``mailto:`` prefix) is
          formatting and is tolerated, because the parameter has told us where
          its authority lives.
        * **No kinds declared** -- we do not know what shape authority takes
          here, so the whole leaf must be positively attributed. This is the
          fail-closed default.
        """
        text = resolution.text
        findings: list[Finding] = []
        attributions: list[Attribution] = []

        operands = extract(text, self._kinds)
        # Operands whose span was produced verbatim by a handle are attributed
        # from the ledger; anything else the model typed itself.
        for match in operands:
            span = resolution.covers(match.start, match.end)
            if span is not None:
                attribution = Attribution(
                    state=AttributionState.ATTRIBUTED,
                    origins=span.operand.origins,
                    derivation="seal",
                )
            else:
                attribution = self._attribute_literal(
                    match.value, match.kind, parameter.collection
                )
            attributions.append(attribution)

            if parameter.kinds and match.kind not in parameter.kinds:
                findings.append(
                    Finding(
                        code=FindingCode.KIND_MISMATCH,
                        parameter=label,
                        operand_kind=match.kind,
                        value=match.value,
                        detail=f"expected one of {sorted(parameter.kinds)}",
                        attribution=attribution,
                    )
                )
                continue
            findings.extend(
                self._authority_findings(
                    label, parameter, match.kind, attribution, match.value
                )
            )

        if parameter.kinds and not (
            UNCLASSIFIED in parameter.kinds
            and not any(m.kind in parameter.kinds for m in operands)
        ):
            if not any(m.kind in parameter.kinds for m in operands):
                findings.append(
                    Finding(
                        code=FindingCode.KIND_MISMATCH,
                        parameter=label,
                        detail=(
                            f"no operand of expected kind {sorted(parameter.kinds)} "
                            "present in an authority-bearing argument"
                        ),
                    )
                )
            return findings, attributions

        # Either no kinds were declared, or UNCLASSIFIED was among them and the
        # value carries no recognised operand. Both mean the same thing: the
        # whole value has to stand up on its own. This is the fail-closed path,
        # and declaring UNCLASSIFIED opts into it rather than out of anything.

        whole = self._attribute_whole(text, resolution, parameter.collection)
        attributions.append(whole)
        kind = classify(text, self._kinds) or UNCLASSIFIED
        findings.extend(self._authority_findings(label, parameter, kind, whole, text))
        return findings, attributions

    def _authority_findings(
        self,
        label: str,
        parameter: ParameterContract,
        kind: str,
        attribution: Attribution,
        value: str,
    ) -> list[Finding]:
        if attribution.state is AttributionState.UNATTRIBUTED:
            return [
                Finding(
                    code=FindingCode.UNATTRIBUTED_AUTHORITY,
                    parameter=label,
                    operand_kind=kind,
                    value=value,
                    detail="value traces to no declared source",
                    attribution=attribution,
                )
            ]
        if not attribution.is_authorised_for(kind, self._sources):
            return [
                Finding(
                    code=FindingCode.UNAUTHORISED_AUTHORITY,
                    parameter=label,
                    operand_kind=kind,
                    value=value,
                    detail=(
                        "no contributing source is authoritative for "
                        f"{kind}: "
                        + ", ".join(o.locator() for o in attribution.origins)
                    ),
                    attribution=attribution,
                )
            ]
        return []

    # -- attribution -----------------------------------------------------

    def _attribute_literal(
        self, value: str, kind: str, collection: str = ""
    ) -> Attribution:
        """Attribute a value the model typed rather than referenced."""
        operand = self.ledger.lookup(kind, value)
        if operand is not None:
            return self._or_composed(
                value,
                self._bind_reference(
                    value,
                    Attribution(
                        state=AttributionState.ATTRIBUTED,
                        origins=operand.origins,
                        derivation="operand",
                    ),
                    collection,
                ),
            )
        return self._or_composed(value, self._attribute_by_derivation(value, collection))

    def _bind_reference(
        self, value: str, attribution: Attribution, collection: str
    ) -> Attribution:
        """Mark an attribution whose value identifies an entity the principal named.

        This is the only signal in the system that distinguishes *the principal
        selected this record* from *an injection selected this record*. The ids
        are identical and so is their provenance; what differs is whether the
        principal's own instruction quotes something about the record.
        """
        if attribution.reference_bound or not self._reference_binding_declared:
            return attribution
        if not self.ledger.is_referenced(
            value,
            self._trusted_source_ids,
            self.policy.min_reference_word,
            collection,
        ):
            return attribution
        return replace(attribution, reference_bound=True)

    def _attribute_whole(
        self, text: str, resolution: Resolution, collection: str = ""
    ) -> Attribution:
        span = resolution.covers(0, len(text))
        if span is not None:
            return Attribution(
                state=AttributionState.ATTRIBUTED,
                origins=span.operand.origins,
                derivation="seal",
            )
        operand = self.ledger.find_value(text)
        if operand is not None:
            return self._or_composed(
                text,
                self._bind_reference(
                    text,
                    Attribution(
                        state=AttributionState.ATTRIBUTED,
                        origins=operand.origins,
                        derivation="operand",
                    ),
                    collection,
                ),
            )
        return self._or_composed(text, self._attribute_by_derivation(text, collection))

    def _attribute_by_derivation(
        self, value: str, collection: str = ""
    ) -> Attribution:
        """Fall back to text derivation, trusted sources first.

        Checking trusted sources first is not an optimisation. If the principal
        wrote the value, that origin is what authorises it, and an attacker
        echoing the same value into a page must not be able to change the
        answer (ADR-0008).

        *Every* matching origin is collected, not the first. Authority is
        existential, so stopping early can hand the checker an unauthorised
        origin while an authorised one exists further down -- which measurably
        denied legitimate calls whose entity id also appeared inside an earlier
        free-text field.
        """
        origins = self.ledger.all_derivations(value, self._trusted_source_ids)
        if origins:
            return Attribution(
                state=AttributionState.ATTRIBUTED,
                origins=origins,
                derivation="trusted-substring",
            )
        origins = self.ledger.all_derivations(value, self._untrusted_source_ids)
        if origins:
            return self._bind_reference(
                value,
                Attribution(
                    state=AttributionState.ATTRIBUTED,
                    origins=origins,
                    derivation="untrusted-substring",
                ),
                collection,
            )
        return self._attribute_by_reference(value, collection)

    def _attribute_by_reference(
        self, value: str, collection: str = ""
    ) -> Attribution:
        """Last resort: the value is an id of a record the principal named.

        Entity ids are frequently too short and too opaque to be quotations of
        anything -- "5" is not evidence. What *is* evidence is that the
        principal quoted the record's title, and this is the only path on which
        that counts. It is also the only way an id short enough to be excluded
        by ``min_quotation_length`` can still be used, which is what makes the
        two settings compose instead of fighting.
        """
        entities = (
            self.ledger.referenced_entities(
                value,
                self._trusted_source_ids,
                self.policy.min_reference_word,
                collection,
            )
            if self._reference_binding_declared
            else ()
        )
        if not entities:
            return Attribution(state=AttributionState.UNATTRIBUTED, derivation="none")
        return Attribution(
            state=AttributionState.ATTRIBUTED,
            origins=merge_origins(entity.origin for entity in entities),
            derivation="reference-bound",
            reference_bound=True,
        )

    _PATH_KINDS = frozenset({"posix_path", "windows_path", "unc_path"})

    def _or_composed(self, value: str, attribution: Attribution) -> Attribution:
        """Fall back to composition when the whole value will not stand up.

        Applied when attribution *fails* and, just as importantly, when it
        succeeds but is **unauthorised**. That second case is the common one and
        was missed by a first implementation: a path an agent read out of a
        directory listing is perfectly attributable -- to a listing the source
        is not authoritative for. Running composition only on the unattributed
        path meant it never fired against a real server at all.
        """
        if not self.policy.compose_paths or attribution.composed:
            # Checked first: classifying the value costs a pass over every
            # registered kind's pattern, and this runs on every attributed leaf
            # of every call. A deployment that has not opted in should pay
            # nothing at all for the feature.
            return attribution
        kind = classify(value, self._kinds) or UNCLASSIFIED
        if attribution.state is not AttributionState.UNATTRIBUTED and (
            attribution.is_authorised_for(kind, self._sources)
        ):
            return attribution
        return self._attribute_by_composition(value) or attribution

    def _attribute_by_composition(self, value: str) -> Attribution | None:
        """Admit a path the agent *built* out of parts it was given.

        The principal names a file, the server names a root, and the agent joins
        them into a string neither ever emitted. Whole-value attribution then
        traces it to nobody and denies it -- the principal's own request
        included. This is the only derivation in the system that looks *inside*
        a value, and it is confined to paths because a path has a grammar: it
        splits at separators into parts that mean something on their own, which
        prose does not.

        Every split is checked **universally**: prefix and remainder must each
        be attributed to a source authorised for it. The rest of the system is
        existential (ADR-0008) and that is right for a value with one origin;
        here the prefix chooses the tree and the remainder chooses the file, so
        an attacker supplying either half has chosen something.

        Returns ``None`` when composition does not apply, so the caller falls
        through to the ordinary answer.
        """
        if not self.policy.compose_paths or "/" not in value:
            return None
        if classify(value, self._kinds) not in self._PATH_KINDS:
            return None
        if ".." in value.split("/"):
            # A prefix and a traversal can each be attributable while their join
            # leaves the tree. Refused rather than decomposed.
            return None
        for index, character in enumerate(value):
            if character != "/" or index == 0:
                continue
            prefix, remainder = value[:index], value[index + 1 :]
            if not remainder:
                continue
            left = self._authorised_component(prefix)
            if left is None:
                continue
            right = self._authorised_component(remainder)
            if right is None:
                continue
            return Attribution(
                state=AttributionState.ATTRIBUTED,
                origins=merge_origins([*left.origins, *right.origins]),
                derivation="composed",
                composed=True,
            )
        return None

    def _authorised_component(self, part: str) -> Attribution | None:
        """Attribute one component and check it, or return ``None``."""
        attribution = self._attribute_by_derivation(part)
        if attribution.state is AttributionState.UNATTRIBUTED:
            return None
        kind = classify(part, self._kinds) or UNCLASSIFIED
        if not attribution.is_authorised_for(kind, self._sources):
            return None
        return attribution

    def _payload_attributions(self, resolution: Resolution) -> list[Attribution]:
        """Payload leaves are not authority-checked, only sensitivity-tracked."""
        attributions = [
            Attribution(
                state=AttributionState.ATTRIBUTED,
                origins=span.operand.origins,
                derivation="seal",
            )
            for span in resolution.spans
        ]
        origins: list[Origin] = []
        for source_id in (*self._trusted_source_ids, *self._untrusted_source_ids):
            origins.extend(self.ledger.all_derivations(resolution.text, (source_id,)))
        if origins:
            attributions.append(
                Attribution(
                    state=AttributionState.ATTRIBUTED,
                    origins=merge_origins(origins),
                    derivation="payload-substring",
                )
            )
        return attributions

    # -- value resolution ------------------------------------------------

    def _resolve(self, value: Any, path: str = "") -> tuple[Any, list[tuple[str, Resolution]]]:
        """Expand handles through nested structures, keeping leaf paths."""
        if isinstance(value, str):
            resolution = self.ledger.resolve(value)
            return resolution.text, [(path, resolution)]
        if isinstance(value, Mapping):
            out: dict[Any, Any] = {}
            leaves: list[tuple[str, Resolution]] = []
            for key, item in value.items():
                resolved, sub = self._resolve(item, f"{path}.{key}")
                out[key] = resolved
                leaves.extend(sub)
            return out, leaves
        if isinstance(value, (list, tuple)):
            out_list: list[Any] = []
            leaves = []
            for index, item in enumerate(value):
                resolved, sub = self._resolve(item, f"{path}[{index}]")
                out_list.append(resolved)
                leaves.extend(sub)
            return (tuple(out_list) if isinstance(value, tuple) else out_list), leaves
        if isinstance(value, bool) or value is None:
            return value, []
        if isinstance(value, (int, float)):
            # Numbers can carry authority (an amount, an account) so they are
            # attributed as text rather than waved through.
            rendered = repr(value) if isinstance(value, float) else str(value)
            return value, [(path, Resolution(text=rendered))]
        return value, []

    # -- dispositions and finalisation -----------------------------------

    def _disposition_for(self, code: FindingCode) -> Verdict:
        mapping = {
            FindingCode.UNATTRIBUTED_AUTHORITY: self.policy.unattributed_authority,
            FindingCode.UNAUTHORISED_AUTHORITY: self.policy.unauthorised_authority,
            FindingCode.UNKNOWN_SEAL: self.policy.unknown_seal,
            FindingCode.UNKNOWN_TOOL: self.policy.unknown_tool,
            FindingCode.KIND_MISMATCH: self.policy.kind_mismatch,
            FindingCode.CONFIDENTIAL_EGRESS: self.policy.confidential_egress,
            FindingCode.CONFIDENTIAL_CONTEXT_EGRESS: self.policy.confidential_context_egress,
            FindingCode.BUDGET_EXCEEDED: self.policy.budget_exceeded,
            FindingCode.DENIAL_INFLUENCED_EGRESS: self.policy.denial_influenced_egress,
        }
        disposition = mapping.get(code)
        if disposition is None:
            return Verdict.ALLOW
        return Verdict.from_disposition(disposition)

    def _enforcing(self) -> bool:
        return any(
            d is not Disposition.ALLOW
            for d in (
                self.policy.unattributed_authority,
                self.policy.unauthorised_authority,
                self.policy.unknown_seal,
                self.policy.unknown_tool,
                self.policy.kind_mismatch,
                self.policy.confidential_egress,
                self.policy.confidential_context_egress,
                self.policy.budget_exceeded,
                self.policy.denial_influenced_egress,
            )
        )

    def _finalise(
        self,
        verdict: Verdict,
        tool: str,
        step: int,
        arguments: Mapping[str, Any],
        findings: tuple[Finding, ...],
        enforced: bool,
    ) -> Decision:
        decision = Decision(
            verdict=verdict,
            tool=tool,
            step=step,
            arguments=dict(arguments),
            findings=findings,
            enforced=enforced,
        )
        self._record(decision)
        if verdict is Verdict.DENY:
            self._denials += 1
            budget = self.policy.denial_budget
            if budget >= 0 and self._denials > budget:
                self._halted = True
        return decision

    def _record(
        self, decision: Decision, extra: Mapping[str, Any] | None = None
    ) -> AuditRecord:
        payload: dict[str, Any] = {
            "session": self.session_id,
            **decision.to_dict(),
            "reason": decision.reason(),
        }
        if extra:
            payload.update(extra)
        return self.audit.append(payload)

    # -- integrator helpers ----------------------------------------------

    def require(self, tool: str, arguments: Mapping[str, Any]) -> Mapping[str, Any]:
        """Admit a call and return executable arguments, or raise.

        The convenience path for integrators who want a hard boundary: it is
        impossible to accidentally execute the *unresolved* arguments, because
        the only thing this returns is the resolved set.
        """
        decision = self.admit(tool, arguments)
        if not decision.allowed:
            raise SessionHalted(decision.agent_message)
        return decision.arguments

    def approve(self, decision: Decision, approver: str, note: str = "") -> Decision:
        """Record a human's approval of an escalated decision.

        Only ``ESCALATE`` decisions can be approved. A denial is not a request
        for permission -- it is a statement that the call is not attributable,
        and no human sign-off makes an unattributable value attributable.
        """
        if decision.verdict is not Verdict.ESCALATE:
            raise ValueError(
                f"only escalated decisions can be approved, got {decision.verdict.value}"
            )
        approved = Decision(
            verdict=Verdict.ALLOW,
            tool=decision.tool,
            step=decision.step,
            arguments=dict(decision.arguments),
            findings=decision.findings,
            enforced=decision.enforced,
        )
        contract = self.contracts.get(decision.tool)
        if contract is not None:
            self.budgets.commit(contract, decision.arguments)
        self._record(approved, {"approved_by": approver, "approval_note": note})
        return approved
