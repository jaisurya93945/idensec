# benchmarks/data

Captured inputs, checked in so that measurements reproduce without network
access.

## `mcp_tools.json`

`tools/list` output from seven published MCP servers, captured over stdio by
[`../mcp_probe.py`](../mcp_probe.py). Refresh it with:

```bash
python3 benchmarks/mcp_corpus.py --capture
```

| server | package |
| --- | --- |
| everything | `@modelcontextprotocol/server-everything` |
| filesystem | `@modelcontextprotocol/server-filesystem` |
| memory | `@modelcontextprotocol/server-memory` |
| sequential | `@modelcontextprotocol/server-sequential-thinking` |
| time | `mcp-server-time` |
| git | `mcp-server-git` |
| fetch | `mcp-server-fetch` |

Only `name`, `description`, `inputSchema` and `annotations` are kept — the
fields a contract is drafted from. No credentials were used, no server was
asked to do anything, and nothing here was authored by this project: that is
the entire point of the file. What it is and is not evidence of is stated in
[`../mcp_corpus.py`](../mcp_corpus.py) and in
[`../../docs/BENCHMARKS.md`](../../docs/BENCHMARKS.md).
