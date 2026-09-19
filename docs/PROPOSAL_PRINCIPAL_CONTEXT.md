# A principal-context field for MCP

**Status:** draft proposal, unsubmitted, unreviewed by anyone outside this
repository. Nobody from the MCP project has seen it. Written so that the finding
behind it exists as something concrete rather than as a note in a research
ledger.

**Scope:** this asks the protocol to *carry* one thing it does not carry today.
It proposes no enforcement, no policy language, and nothing IDENSEC-specific. A
server that ignores the field is unaffected.

---

## 1. The gap

MCP moves tool calls and tool results. It does not move **what the user asked
for**, or **where the agent is pointed**.

Verified by implementing a full stdio proxy against the protocol surface:
`initialize`, `tools/list`, `tools/call`, `resources/read`, `prompts/get` and
their results carry no field in which a host can state the principal's
instruction. ([`RESEARCH.md`](RESEARCH.md) Thread 3b.)

This is not a gap for agents. It is a gap for anything that has to *judge* what
an agent does, because every such design takes the user's request as an input
and reasons from it.

## 2. Why it cannot be fixed above the protocol

Three approaches are available today and each fails for a different reason.

**Ask the agent.** A tool the agent calls to declare its task — or a convention
that the first message states it — is a total bypass. An injected agent declares
the *attacker's* goal as the task, and it arrives labelled as the user's. This
is not a hardening problem; the channel is downstream of the compromise.

**Put it in the system prompt.** It reaches the model, not the server or any
proxy between them. Nothing on the MCP wire can read it.

**Use an out-of-band side channel.** This works and is what IDENSEC does: the
host writes the principal's verbatim instruction to a file the agent cannot
write, and the proxy reads it. It requires the host and the enforcement point to
agree on a filesystem path, which means it is a private arrangement between two
components that the protocol otherwise fully specifies. Every deployment
re-invents it, and a host that does not know to provide one produces an
enforcement point that silently has nothing to enforce against.

## 3. A second, sharper instance: the bootstrap

`mcp-server-git` exposes twelve tools. All twelve take `repo_path`.

An agent that has not been told which checkout it is working on cannot ask —
there is no zero-argument tool — and any containment design that requires
arguments to be attributable therefore denies the *first* call of every session.
`@modelcontextprotocol/server-filesystem` avoids this only by accident, because
it happens to expose `list_allowed_directories`, which takes no arguments.

So the missing channel is not only the task statement. It is also **the root the
agent has been pointed at**, which today is expressed by launching the server
with a command-line argument that nothing downstream can see.

Measured: [`BENCHMARKS.md`](BENCHMARKS.md), *The coding agent*.

## 4. Proposal

Add an optional `principalContext` object, supplied by the **host**, carried in
`initialize` and optionally refreshed by a notification.

```jsonc
// initialize params
{
  "protocolVersion": "2025-06-18",
  "capabilities": { ... },
  "clientInfo": { "name": "example-host", "version": "1.0.0" },
  "principalContext": {
    "instruction": "Stage my README.md change and commit it.",
    "workingRoot": "/home/dev/widget",
    "issuedAt": "2026-09-19T09:14:02Z"
  }
}
```

| field | meaning |
| --- | --- |
| `instruction` | The principal's request, **verbatim**. Not a model's paraphrase. Optional. |
| `workingRoot` | Where the host has pointed this session, when that concept applies. Optional. |
| `issuedAt` | When the host captured it, so a stale context is detectable. Optional. |

A refresh notification carries the same object, for hosts that keep one session
across several user turns:

```jsonc
{ "jsonrpc": "2.0", "method": "notifications/principal_context_changed",
  "params": { "principalContext": { ... } } }
```

### Normative requirements

1. `principalContext` **MUST** be populated by the host from the principal's own
   input. A host **MUST NOT** populate it from model output, tool results, or
   any content the agent can influence.
2. A server or intermediary **MUST NOT** expose a tool, resource or prompt that
   lets the agent set or modify it.
3. `instruction` **SHOULD** be the principal's verbatim text. A host that can
   only supply a summary **SHOULD** omit the field rather than supply the
   summary, because a summary is model output wearing the principal's label.
4. Servers **MAY** ignore it entirely. It carries no capability and grants no
   permission.

### What this deliberately does not do

- It does not say what anyone should *do* with the context. No policy language,
  no enforcement semantics, no verdicts.
- It does not authenticate the host. A host that lies about the principal's
  instruction is outside any protocol's reach, and requirement 1 is a statement
  of responsibility, not a mechanism.
- It does not carry conversation history. One instruction and one root, because
  those are the two things an enforcement point provably cannot obtain any other
  way.

## 5. Why it belongs in the protocol rather than in each deployment

The field is small and the argument for it is not that it is useful to IDENSEC.
It is that **every containment design in the current literature needs it**, and
none of the papers surveyed appear to have flagged it, because they evaluate
inside harnesses they control rather than over a protocol they do not.

CaMeL, PACT, PAuth and comparable designs all take the trusted user query as an
input. If the dominant tool protocol has nowhere to put that query, each of them
needs a private side channel before it can be deployed over MCP — and the side
channels will not be the same, so a host cannot serve two of them at once.

*(That characterisation of the literature is `INFERENCE` from search summaries,
not verified against primary sources — see [`LIMITATIONS.md`](LIMITATIONS.md)
§3. The gap in MCP itself is `FACT`, verified by implementation.)*

## 6. Status of this document

Not submitted. Not reviewed. No conversation has taken place with the MCP
maintainers or with anyone else, and this repository has no users whose
experience informs it.

What it rests on is narrow and stated plainly: a proxy was implemented against
the real protocol and the field is not there; three published servers were
driven through it and two distinct consequences of its absence were measured.
That is enough to write a proposal. It is not evidence that anyone wants one.
