"""Policy: what to do when a check fails.

Every entry is a *disposition*, not a boolean, because the honest answer to
"this argument is not attributable" is often "ask a human", and a design that
only offers allow/deny forces integrators to pick allow.

Defaults are restrictive. A permissive default in a security library is a
vulnerability with a changelog entry.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

__all__ = ["OBSERVE", "STRICT", "SUPERVISED", "Disposition", "Policy"]


class Disposition(StrEnum):
    ALLOW = "allow"
    ESCALATE = "escalate"
    """Hand the call to a human. The agent does not proceed unaided."""
    DENY = "deny"


@dataclass(frozen=True, slots=True)
class Policy:
    """Dispositions for each failure class the monitor can detect."""

    unattributed_authority: Disposition = Disposition.DENY
    """An authority-bearing argument traced to nothing at all (ADR-0007).

    This is the anti-laundering rule and the main utility cost. Set it to
    ``ESCALATE`` for workflows where the agent legitimately originates
    identifiers -- choosing a new file path, minting a ticket id.
    """

    unauthorised_authority: Disposition = Disposition.DENY
    """Traced to a real source, but one not authoritative for that operand
    kind. This is the injected-destination case: the value came from a web page,
    and web pages do not get to choose recipients."""

    unknown_seal: Disposition = Disposition.DENY
    """A handle that does not resolve. Either a guess or a fabrication."""

    unknown_tool: Disposition = Disposition.DENY
    """No contract. We cannot know which parameters bear authority, so we
    cannot make a sound decision, so we do not make one."""

    kind_mismatch: Disposition = Disposition.DENY
    """The value's kind is not among the kinds the parameter accepts."""

    confidential_egress: Disposition = Disposition.ESCALATE
    """Confidential data heading for a sink that can move it outside the trust
    boundary, to a destination the principal did not choose. Escalation rather
    than denial by default because this is the case most likely to be a
    legitimate task the principal simply has not confirmed.

    **Best-effort, not sound.** Confidentiality is tracked by quotation: a
    payload is confidential if it quotes text observed from a confidential
    source. A model that paraphrases confidential content defeats this, because
    prose -- unlike identifiers -- cannot be enumerated or sealed. Use
    :attr:`confidential_context_egress` where soundness matters more than
    precision. See ``docs/LIMITATIONS.md``.
    """

    confidential_context_egress: Disposition = Disposition.ALLOW
    """The sound, coarse alternative: once *any* confidential source has been
    observed in this session, treat every egress call to a destination the
    principal did not choose as carrying confidential data, whether or not the
    payload visibly quotes it.

    Off by default because it over-triggers heavily -- after one confidential
    read, every outbound call is flagged. Turn it on for sessions where
    paraphrased leakage is the threat you actually care about, and accept the
    approval load that comes with it.
    """

    denial_influenced_egress: Disposition = Disposition.ALLOW
    """Egress after a denial has occurred in this session.

    The denial-feedback channel (ARM, arXiv 2604.04035) is a covert channel: the
    agent probes a protected action, learns roughly one bit from the refusal,
    and encodes it into a later call. Content-free denials remove the *content*
    channel and the denial budget bounds the *number* of probes, but neither
    closes it.

    This is the sound, coarse option: once any denial has occurred, treat every
    subsequent egress call as potentially carrying the inferred bits. Off by
    default because it over-triggers -- one denial constrains the rest of the
    session -- and because within this model the exfiltration leg usually fails
    anyway: the attacker's own destinations are never authoritative, so the bits
    have to travel through a channel the principal chose. Turn it on where that
    reasoning is not good enough.
    """

    budget_exceeded: Disposition = Disposition.DENY
    """A session-level aggregate limit this call would exceed.

    Denial rather than escalation by default: a budget is something the
    principal or operator set deliberately, and quietly asking a human to
    re-approve it on every breach is how limits stop meaning anything. The
    supervised preset escalates instead, for workflows where a person is
    genuinely present.
    """

    denial_budget: int = 3
    """Denials tolerated before the session halts.

    Bounds the denial-feedback channel described in ADR-0009: each denial leaks
    at most about one bit, so the total leak is bounded by this number. Set to
    0 to halt on the first denial; negative to disable the halt entirely (not
    recommended -- it leaves the probe channel unbounded).
    """

    silent_denials: bool = True
    """Return a fixed, content-free message to the agent on denial. Full
    reasons still reach the audit record. Turn this off in development, never
    in production."""

    def __post_init__(self) -> None:
        for name in (
            "unattributed_authority",
            "unauthorised_authority",
            "unknown_seal",
            "unknown_tool",
            "kind_mismatch",
            "confidential_egress",
            "confidential_context_egress",
            "budget_exceeded",
            "denial_influenced_egress",
        ):
            value = getattr(self, name)
            if not isinstance(value, Disposition):
                object.__setattr__(self, name, Disposition(value))


STRICT = Policy()
"""Deny everything that cannot be positively justified. The default."""

SUPERVISED = Policy(
    unattributed_authority=Disposition.ESCALATE,
    unauthorised_authority=Disposition.ESCALATE,
    confidential_egress=Disposition.ESCALATE,
    budget_exceeded=Disposition.ESCALATE,
)
"""For workflows with a human in the loop.

Both attribution failures become approval prompts rather than refusals. This is
what keeps retrieve-then-act working: "the agent wants to mail
``support@acme.example``, an address it read from ``acme.example`` -- approve?"
is a question a human can answer well, and refusing it outright is the
quarantine failure mode that argues against argument-level enforcement in the
first place.

The trade-off is real and should not be glossed: escalation moves the decision
to a human who can be worn down by volume or talked into it by the content of
the prompt. It is a weaker control than denial, and it is the right default only
where a human is genuinely present."""

OBSERVE = Policy(
    unattributed_authority=Disposition.ALLOW,
    unauthorised_authority=Disposition.ALLOW,
    unknown_seal=Disposition.ALLOW,
    unknown_tool=Disposition.ALLOW,
    kind_mismatch=Disposition.ALLOW,
    confidential_egress=Disposition.ALLOW,
    confidential_context_egress=Disposition.ALLOW,
    budget_exceeded=Disposition.ALLOW,
    denial_influenced_egress=Disposition.ALLOW,
    denial_budget=-1,
    silent_denials=False,
)
"""Enforce nothing; record everything.

For measuring what a policy *would* have done against real traffic before
turning it on. This is not a security configuration and the monitor labels
decisions made under it accordingly.
"""
