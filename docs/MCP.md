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

## Validated against a real server

The reference `mcp-server-time` was installed from PyPI and driven through the
proxy end to end — handshake, `tools/list`, contract drafting, an allowed call
returning real data, and an uncontracted tool refused. First contact with
software we did not write also produced two linter false positives, both since
fixed; see [`RESEARCH.md`](RESEARCH.md) Thread 3d.

Three servers have since been driven through a full injection scenario, each
with a reviewed contract file in [`../examples/mcp/`](../examples/mcp):

| Server | Tools contracted | Attack | Example |
| --- | --- | --- | --- |
| `@modelcontextprotocol/server-filesystem` | 14 | injected overwrite and move, from an HTML comment in a document | `attack_filesystem.py` |
| `@modelcontextprotocol/server-memory` | 9 | injected delete, from an observation on a legitimate entity | `attack_memory.py` |
| `mcp-server-git` | 12 | exfiltration by commit, from a comment in a source file | `attack_git.py` |

Each one found something the benchmark could not, and each is listed in
[`BENCHMARKS.md`](BENCHMARKS.md) with the labellings that fail as well as the
ones that work.

**`mcp-server-git` has no zero-argument tool.** All twelve of its tools take
`repo_path`, so an agent that was not told where the checkout is cannot ask, and
under the unattributed rule its first call is denied. If you deploy the proxy in
front of it, the checkout path must appear in `task_file` — the host has to name
it, because the protocol gives the agent no way to discover it. See
[`LIMITATIONS.md`](LIMITATIONS.md) §4.2e.

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
    "id": "workspace",
    "trust": "tool_untrusted",
    "sensitivity": "internal",
    "authoritative_for": [],
    "authoritative_paths": {
      "**.sender": ["email"],
      "**.participants[*]": ["email"],
      "**.events": ["referenced"],
      "**.files": ["referenced"],
      "list_allowed_directories.**": ["posix_path"]
    }
  },
  "policy": "strict",
  "min_quotation_length": 3,
  "min_reference_word": 8,
  "compose_paths": true,
  "contracts": "contracts/workspace.json",
  "task_file": "/run/idensec/task.txt",
  "audit": "idensec-audit.jsonl"
}
```

| Field | Notes |
| --- | --- |
| `server` | argv of the MCP server to launch. The proxy speaks MCP to your host on stdio and to this process on pipes. |
| `source.trust` | **No default.** Labelling a source is the one decision IDENSEC cannot make for you, and the config refuses to load without it. |
| `source.authoritative_for` | Operand kinds this server may supply as authority, *anywhere in its output*. A corporate directory gets `["email"]`; a web fetcher gets `[]`. |
| `source.authoritative_paths` | The same, per **field path**. This is the setting that makes retrieve-then-act work: a workspace is authoritative about the `sender` of a message and not about its `body`, and both arrive from one source. A whole-source grant cannot express that, which is why deployments using only `authoritative_for` are choosing between refusing everything and trusting message bodies. |
| `policy` | `strict` · `supervised` · `observe` |
| `min_quotation_length` | Characters before quoting a value counts as evidence. Raising it closes low-entropy collisions (*"what are we doing on June 13"* authorising `delete_file(13)`) and refuses legitimate short values with them. |
| `min_reference_word` | Characters before a lone quoted word counts as *naming* a record. Only matters where a path is granted `referenced`. |
| `contracts` → `payload_paths` | Field-path globs *inside* an authority-bearing parameter whose leaves are content. Needed wherever one parameter carries both the thing being addressed and the thing being written — `create_entities([{name, observations}])` is the canonical case. Without it you must choose between denying every legitimate write and attributing nothing, and `idensec.lint` will tell you which you chose. |
| `compose_paths` | Admit a path whose **components** are each attributed and authorised. Off by default. This is what lets you grant a server authority over its own root *only* — scoped to the tool that discloses it, e.g. `"list_allowed_directories.**"` — and still have the principal open a file they named, while an injection naming a different real file in the same directory is refused. See ADR-0012. |
| `compose_urls` | The same for **URLs**, and separate on purpose: a composed filename is an address, a composed URL is an egress destination. Off by default. Six measured cases in [`BENCHMARKS.md`](BENCHMARKS.md), one of which is caught by escalation rather than denial — if you also set `confidential_egress` to allow, that leak goes through. See ADR-0013. |
| `contracts` | Path to a contract file. Absent ⇒ every tool is unknown ⇒ denied. |
| `task_file` | See above. Absent ⇒ no trusted corpus. |
| `accept_principal_context` | Read the principal's instruction from a `principalContext` object the host sends in `initialize`, instead of (or as well as) `task_file`. **Defaults false**, and not because it is unfinished: a file can only be written by something with write access to a path you chose, while this can be set by whatever speaks MCP to the proxy's stdin. Stating the task is authority — an attacker who can declare it can authorise their own calls. Enable it when the host is provably the only writer of that pipe. See [`PROPOSAL_PRINCIPAL_CONTEXT.md`](PROPOSAL_PRINCIPAL_CONTEXT.md). |
| `seal_tool_descriptions` | Defaults true. Turning it off opens the tool-poisoning path and is logged loudly at startup. |

Results are recorded at `<tool>.result`, which is what makes a grant like
`"list_allowed_directories.**"` possible: the server may name its own root and
nothing else. **This is the most useful shape of grant on servers with no field
structure to scope by.** `mcp-server-git` returns one text blob from every tool,
so there is no `sender`/`body` split to exploit — but `"git_status.**"` and
`"git_diff_unstaged.**"` are different grants, and that is the whole difference
between admitting a filename the working tree reported and admitting one a
poisoned source comment asked for. See
[`BENCHMARKS.md`](BENCHMARKS.md#the-coding-agent-and-a-defence-that-was-not-ours-2026-09-14).

> **Read U08 before you rely on a per-tool grant.** The grant asserts that
> values appearing under that path are ones your principal would endorse, and
> whether that holds is decided by data, not by the policy. The git grant above
> is safe only while `.gitignore` keeps secrets out of `git_status`; on a
> repository without that line the same policy stages a deploy token.
> [`LIMITATIONS.md`](LIMITATIONS.md) §4.2g.

### See what a grant admits, before it enforces

```
python -m idensec.preview --config docs.json --corpus captured.json --server git
```

The preview observes captured tool output through the real read boundary and
then asks `Session.admit` about every value in it, giving the principal no words
— so everything it reports is admitted by **the grant alone**. Run it against
output from your own servers before you trust a grant.

Two things it will tell you that the config file does not:

- **`unclassified` is not a grant over identifiers.** It covers every token the
  tool emits — its prose, and the `"type": "text"` label MCP wraps results in.
  Measured on six published servers: a `**` grant admits **99%** of every token
  in the corpus; the same grant scoped to one tool admits 3%. `idensec.lint`
  reports the blanket shape as `blanket-unclassified-grant`.
- **A grant can be inert and look configured.** `git_status.**: ["posix_path"]`
  admits nothing at all, because git reports repo-relative names and
  `posix_path` needs a leading separator. `Preview.inert_grants` names any grant
  that admitted nothing in the corpus.

It is a **lower bound**: single tokens and recognised operands only, so
multi-token quotations are not counted.

Both numeric knobs trade security against utility, neither has a defensible
universal value, and they interact — reference binding is meaningless below a
quotation floor, because a short id is "quoted" by any instruction containing
that token. [`BENCHMARKS.md`](BENCHMARKS.md) sweeps them together rather than
recommending one. Run `python -m idensec.lint` over your contracts and config:
a `referenced` grant that no parameter declares a collection for is inert, and
it denies everything that path would otherwise have allowed.

Point your MCP host at the proxy instead of the server:

```json
{ "mcpServers": { "docs": {
    "command": "python",
    "args": ["-m", "idensec.mcp", "--config", "/etc/idensec/docs.json"]
}}}
```

---

## Tool annotations: read one way

MCP tools may carry `annotations` — `readOnlyHint`, `destructiveHint`,
`idempotentHint`, `openWorldHint`. Across seven published servers, **51 of 52
tools carry them**, so ignoring them entirely would throw away a real signal;
believing them would be worse. They come from the *server*, which this proxy
already treats as the bottom of the integrity lattice when it seals tool
descriptions.

The rule is one line:

> **An annotation may add an effect and may never remove one.**

| annotation | treatment | why |
| --- | --- | --- |
| `destructiveHint: true` | believed — adds `DELETE`, `IRREVERSIBLE` | A hostile server lying this way denies its own tools. |
| `openWorldHint: true` | believed — adds `NETWORK_EGRESS` | Same direction. |
| `readOnlyHint: true` | **ignored** | Believing it is a total bypass: mark the exfiltration tool read-only and every confidentiality rule stops firing. **32 of 52 real tools claim it.** |
| `idempotentHint` | ignored | Says nothing about what a tool reaches. |

This never reduces your obligation to declare effects — a draft with none is
still a draft you must finish. It only makes the draft safer when a server
volunteers that it is dangerous.

---

## What the proxy does to the protocol

| Message | Treatment |
| --- | --- |
| `tools/call` request | Attributed and admitted. On denial the call **never reaches the server**, and the host receives a tool result with `isError` and a content-free message. On allow, arguments are rewritten to resolved values. |
| **every result** | Text is sealed. Prose survives byte-for-byte; identifiers become handles. Field-level provenance is recorded (`result.contents[0].text`). |
| `tools/list` result | Exception: descriptions sealed (server-supplied ⇒ attacker territory), names and JSON Schemas **never** rewritten, since a handle inside a schema would corrupt it. Optionally drafts contracts. |
| `initialize` result | Exception: protocol metadata passes through. A sealed `protocolVersion` breaks the handshake. |
| other requests, unknown messages | Forwarded untouched. A proxy that only forwards what it recognises breaks on the next protocol revision. |

**Why "every result" and not a list of methods.** `tools/call` is not the only
path by which content reaches a model — `resources/read`, `prompts/get` and
`resources/list` all carry server-supplied text. An earlier version of this
proxy sealed only tool results, which left an attacker-controlled *resource*
free to hand the model an address in clear. Enumerating content-bearing methods
is a losing game against a protocol that keeps adding them, so the default is
inverted: seal everything, name the exceptions. It is safe to apply this broadly
because sealing is a no-op on text containing no operands.

Startup warnings are printed to stderr for every configuration that is legal but
weakens the guarantee — observe mode, no task file, no contracts, unsealed
descriptions, an over-trusted source. Every one of those is something an
operator would otherwise discover during an incident.

---

## Shutting it down

Close the proxy's stdin. That is the shutdown MCP already has, and it is the one
the proxy can act on: it closes the server's stdin in turn, and escalates to
`terminate` and then `kill` if the server does not take the hint.

`SIGTERM` and `SIGHUP` are handled for the same reason — their default action
kills the proxy outright, which skips the cleanup and leaves the server it
launched running. A leaked server outlives the session that authorised it, and
one holding a repository, a database or a port blocks the next one.

Do not `SIGKILL` the proxy. Nothing can clean up after that, by design.

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
