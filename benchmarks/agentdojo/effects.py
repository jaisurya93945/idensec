"""Effect classes for AgentDojo's tools.

Effects cannot be read off a schema -- that is the one inference IDENSEC's
deriver refuses to make -- so they are declared here by hand, which is exactly
what an operator would do. This file is therefore *our* labelling of somebody
else's tools, and any result that depends on it inherits that caveat.

The rule applied: a tool that changes state outside the agent gets WRITE; one
that moves bytes to a party other than the principal gets NETWORK_EGRESS; money
gets FINANCIAL; anything unrecoverable gets IRREVERSIBLE. Read-only lookups get
READ. Where a name was ambiguous the more dangerous reading was taken.
"""

from __future__ import annotations

from idensec import Effect

READ = frozenset({Effect.READ})
WRITE = frozenset({Effect.WRITE})
SEND = frozenset({Effect.WRITE, Effect.NETWORK_EGRESS})
MONEY = frozenset({Effect.WRITE, Effect.FINANCIAL, Effect.IRREVERSIBLE})
DESTRUCTIVE = frozenset({Effect.DELETE, Effect.IRREVERSIBLE})

EXPLICIT: dict[str, frozenset[Effect]] = {
    # workspace
    "send_email": SEND,
    "send_calendar_invite": SEND,
    "delete_email": DESTRUCTIVE,
    "delete_file": DESTRUCTIVE,
    "share_file": SEND,
    "append_to_file": WRITE,
    "create_file": WRITE,
    "add_calendar_event_participants": SEND,
    "create_calendar_event": WRITE,
    "cancel_calendar_event": DESTRUCTIVE,
    "reschedule_calendar_event": WRITE,
    # banking
    "send_money": MONEY,
    "schedule_transaction": MONEY,
    "update_scheduled_transaction": MONEY,
    "update_password": WRITE,
    "update_user_info": WRITE,
    # slack
    "send_direct_message": SEND,
    "send_channel_message": SEND,
    "invite_user_to_slack": SEND,
    "remove_user_from_slack": DESTRUCTIVE,
    "add_user_to_channel": WRITE,
    # travel
    "reserve_hotel": MONEY,
    "reserve_restaurant": MONEY,
    "reserve_car_rental": MONEY,
    "cancel_reservation": DESTRUCTIVE,
    "send_email_to_hotel": SEND,
}

_WRITE_PREFIXES = ("create_", "add_", "update_", "set_", "append_", "schedule_", "reserve_")
_SEND_PREFIXES = ("send_", "post_", "share_", "invite_", "email_")
_DESTRUCTIVE_PREFIXES = ("delete_", "remove_", "cancel_", "revoke_")


def effects_for(name: str) -> frozenset[Effect]:
    """Declared effects, falling back to a deliberately pessimistic guess."""
    if name in EXPLICIT:
        return EXPLICIT[name]
    if name.startswith(_SEND_PREFIXES):
        return SEND
    if name.startswith(_DESTRUCTIVE_PREFIXES):
        return DESTRUCTIVE
    if name.startswith(_WRITE_PREFIXES):
        return WRITE
    return READ
