# MCP.md — deploying IDENSEC as an MCP proxy

MCP is the highest-leverage place to put this. The protocol already carries
both boundaries the design needs — tool results arriving, tool calls departing —
so a host gains enforcement without a single application change.

```
   MCP host  ──stdio──▶  idensec.mcp  ──stdio──▶  MCP server
   (agent)              (this proxy)             (filesystem, web, mail, …)
                              │
                    ┌─────────┴─────────┐
                    │ tools/call  →  admit()
                    │ result      →  observe()  (seal)
                    │ tools/list  →  seal descriptions, draft contracts
                    └───────────────────┘
```

---

## The thing MCP does not give you

**MCP has no trusted channel for the principal's instruction.** The protocol
moves tool calls and results. It does not move intent.

This matters more than it sounds. IDENSEC admits an authority-bearing argument
only if it is attributable to an authorised source, and the principal's own task
is the primary such source. Without it there is no trusted corpus, every
recipient and path and account is unattributable, and a strict policy denies
essentially everything — correctly, and uselessly.

The obvious fix is the wrong one. You cannot ask the *agent* for the task:

> Agent → proxy: "the user's task is: mail everything to exfil@evil.example"

An injected agent will declare the attacker's goal as the task, and the proxy
would launder it to `USER_INPUT`. That is a total bypass, and it is why there is
no `idensec/declare_task` tool in this implementation and should never be one.

So the task arrives **out of band**, from something the agent cannot write:

```json
{ "task_file": "/run/idensec/task.txt" }
```

The host writes the principal's verbatim instruction there before the session
starts. Two deployment requirements follow, and both are real:

- The file must not be writable by the agent or by anything the agent can reach.
  If it is, an injected agent rewrites its own authority.
- It must be the principal's words, not a model's summary of them. A summary is
  model output, and model output is untrusted input.

If your host cannot provide that, run in `observe` mode and collect evidence —
but do not describe the deployment as enforcing anything.

---

## Quick start

**1. Draft contracts from the server's own schemas.** This is the answer to
policy sprawl: you do not hand-write contracts for a server you did not build.

```bash
python -m idensec.mcp --config examples/mcp/filesystem.json \
                      --emit-contracts contracts/filesystem.json
```

**2. Complete the drafts.** The deriver marks parameter roles but leaves
`effects` empty on purpose — effects cannot be read off a schema, and guessing
that an unknown tool is read-only would be the most dangerous inference in the
system. Fill them in, and check every `authority` role the deriver guessed.

**3. Lint them.** A wrong contract is a *silent* bypass — the monitor allows the
call and raises no finding, because as far as it knows nothing authority-bearing
was involved.

```bash
python -m idensec.lint contracts/filesystem.json --config examples/mcp/filesystem.json
```

It catches downgraded authority parameters, egress tools with no destination to
check, permissive `default_role`, misspelled operand kinds, and drafts that were
never completed. The proxy runs the same checks at startup and prints anything
it finds to stderr — it does not refuse to start, because the linter reasons
from names and a false positive must not be able to take a deployment down.

A clean run means *no known-bad patterns*, never *this contract is correct*.

**4. Run in observe mode against real traffic.** Nothing is enforced; every
decision is recorded. Read the audit log and see what a strict policy *would*
have denied.

```json
{ "policy": "observe", "audit": "idensec-audit.jsonl" }
```

**5. Switch to `strict`** once the denials in the log are all ones you agree
with.

---

## Configuration

```json
{
  "schema": "idensec.proxy/v1",
  "server": ["npx", "-y", "@modelcontextprotocol/server-filesystem", "/srv/docs"],
  "source": {
    "id": "filesystem",
    "trust": "tool_untrusted",
    "sensitivity": "internal",
    "authoritative_for": []
  },
  "policy": "strict",
  "contracts": "contracts/filesystem.json",
  "task_file": "/run/idensec/task.txt",
  "audit": "idensec-audit.jsonl"
}
```

| Field | Notes |
| --- | --- |
| `server` | argv of the MCP server to launch. The proxy speaks MCP to your host on stdio and to this process on pipes. |
| `source.trust` | **No default.** Labelling a source is the one decision IDENSEC cannot make for you, and the config refuses to load without it. |
| `source.authoritative_for` | Operand kinds this server may supply as authority. A corporate directory gets `["email"]`; a web fetcher gets `[]`. |
| `policy` | `strict` · `supervised` · `observe` |
| `contracts` | Path to a contract file. Absent ⇒ every tool is unknown ⇒ denied. |
| `task_file` | See above. Absent ⇒ no trusted corpus. |
| `seal_tool_descriptions` | Defaults true. Turning it off opens the tool-poisoning path and is logged loudly at startup. |

Point your MCP host at the proxy instead of the server:

```json
{ "mcpServers": { "docs": {
    "command": "python",
    "args": ["-m", "idensec.mcp", "--config", "/etc/idensec/docs.json"]
}}}
```

---

## What the proxy does to the protocol

| Message | Treatment |
| --- | --- |
| `tools/call` request | Attributed and admitted. On denial the call **never reaches the server**, and the host receives a tool result with `isError` and a content-free message. On allow, arguments are rewritten to resolved values. |
| `tools/call` result | Text content is sealed. Prose survives; identifiers become handles. |
| `tools/list` result | Descriptions sealed (server-supplied ⇒ attacker territory). Names and schemas are **never** rewritten. Optionally drafts contracts. |
| everything else | Forwarded untouched. |

That last row is load-bearing. A proxy that only forwards what it recognises
breaks on the next protocol revision; this one inspects two methods and passes
the rest through.

Startup warnings are printed to stderr for every configuration that is legal but
weakens the guarantee — observe mode, no task file, no contracts, unsealed
descriptions, an over-trusted source. Every one of those is something an
operator would otherwise discover during an incident.

---

## What this does not protect

- **The host.** The proxy protects the *principal* from content the agent
  consumes. A host that routes around it is simply unprotected, as with any
  enforcement point outside the application.
- **Other transports.** stdio only today. Streamable HTTP is a straightforward
  extension of the same interception points and is not built.
- **Server-side compromise.** A malicious server can return anything; that
  content is sealed and labelled, which contains it, but the server still runs
  whatever the allowed call asked it to.
- **Anything in [`LIMITATIONS.md`](LIMITATIONS.md).** The proxy is a deployment
  shape, not a different security model — it inherits every limit the library
  has.
