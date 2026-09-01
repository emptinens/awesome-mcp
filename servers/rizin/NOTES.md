# rizin MCP server

MCP server exposing the [rizin](https://rizin.re) reverse-engineering framework to coding agents. 47 tools covering the full workflow: open → analyze → explore (functions/imports/exports/symbols/sections/strings/flags/relocs/comments/classes) → drill down (disasm, hexdump, xrefs, vars, graphs, pseudo-code) → annotate (rename, retype, comment, signature).

Zero runtime dependencies (Node built-ins), stdio transport, MCP `2024-11-05`. One ~670-line file.

```toml
# ~/.codex/config.toml
[mcp_servers.rizin-mcp]
command = "node"
args = ["/path/to/servers/rizin/server.mjs"]
```

Requires `rizin` on `$PATH` (tested 0.8.2). `RIZIN_BIN` overrides the binary; `RIZIN_MCP_ALLOW_DANGEROUS=1` unblocks shell/write commands in `run_command`.

## Architecture

```
MCP client ──stdio JSON-RPC── server.mjs ──r2pipe── rizin -q -0 <file>
```

One long-lived `rizin -q -0 <file>` child per open file. All state (analysis, renames, comments, seek) persists across tool calls.

### Why this design (vs. radareorg/radare2-mcp)

The reference r2mcp is ~8k lines of C with a build step. This is one Node file, no build, same MCP protocol — and it fixes protocol traps the reference glosses over.

**The three r2pipe traps. All three corrupt a naive implementation:**

1. **Leading NUL.** `rizin -0` emits one NUL byte on startup — *after* parsing the file (3.8s for a 63MB PE). Commands sent before it arrives read the *previous* command's response: a silent off-by-one. The server absorbs the startup NUL before starting the command queue.
2. **Serialization.** r2pipe is a single stdin/stdout stream. Overlapping commands mix outputs. Every command goes through one promise queue.
3. **Chunk-split UTF-8.** Responses can split mid-multibyte-character across stream chunks. Bytes accumulate as latin1 (lossless); the buffer is decoded to UTF-8 only after the terminating NUL.

**Other decisions:**

- **File as argv, not `o`.** `o` inside `-0` mode misbehaves. Reopening a file respawns the child with new argv (base/arch/bits/cpu via rizin's own `-B/-a/-b/-k` flags). Kills are instance-guarded so an old child's `exit` can't clobber the new child's state.
- **Name resolution.** Every address param also accepts flag/function names (`main`, `sym.imp.fwrite`, `fcn.000030c0`) — rizin's seek resolves both, and agents speak in names. Injection shapes (`;`, newlines, NUL) are rejected; strict-numeric fields (base_address, search values) stay strict.
- **Xref enrichment.** `xrefs_to` resolves the containing function of every xref source — the question every agent asks next.
- **JSON-first.** Every `j`-command parsed to objects; raw text fallback. Compact JSON output (no indent) to halve context usage.
- **Pagination everywhere.** Every list tool: `cursor`/`limit` (default 200, max 2000) → `{items, nextCursor, total}`. A 63MB GameAssembly's 59MB relocation JSON parses and pages fine.
- **Dangerous-command block.** `!`/`!!` (shell) and `w*` (writes) rejected in `run_command` unless opted in.
- **Analysis-level cache.** Re-analysis of a 63MB binary takes minutes; the level is tracked and skipped.
- **Truncation** at 60KB (`RIZIN_MCP_MAX_OUTPUT`).

### rizin 0.8.2 quirks (for maintainers)

- `axtj`/`axfj`/`fdj` take **no address argument** — seek first: `s 0x3560; axtj`.
- `f` alone is an error; flag listing is `flj`.
- `fr` renames by **flag names**; resolve via `fdj` first.
- `CC <text> @ <addr>` is rejected; use `s <addr>; CC <text>`.
- Search: `/zj` (string), `/xj` (hex), `/v{1,2,4,8}j` (value+width), `/aj` (asm), wide = `/zj <pat> l utf16le` (plain encoding name; the `encoding=` form errors).
- Graphs are `agf json` / `agC json` (format as argument, **not** a `j` suffix).
- No `pdc`/`pdd`/`pdg` in core — plugins. Pseudo-code via `pdsf` (function summary), `pds N` (needs a count), `pdr` (recursive disasm). Full C: install rz-ghidra.
- Analysis levels: `aa`, `aaa`, `aaaa` — `aaaaa` does not exist.

## Tool inventory (47)

| Tool | rizin | Tool | rizin |
|---|---|---|---|
| `open_file` | argv spawn | `list_comments` | `CClj` |
| `close_file` | kill child | `print_string_at` | `ps` |
| `analyze` | `aa`–`aaaa` | `read_hex` | `p8` |
| `show_info` | `ij` | `analysis_info` | `aaij` |
| `list_functions` | `aflj` | `show_function_details` | `afij` |
| `list_imports` | `iij` | `list_function_vars` | `afvlj` |
| `list_exports` | `iEj` | `list_function_calls` | `afij` callrefs |
| `list_symbols` | `isj` | `rename_function_var` | `afvn` |
| `list_sections` | `iSj` | `set_var_type` | `afvt` |
| `list_libraries` | `ilj` | `function_graph` | `agf json` |
| `list_entrypoints` | `iej`+`fdj` | `call_graph` | `agC json` |
| `list_strings` | `izj`/`izzj` | `basic_blocks` | `afbj` |
| `list_flags` | `flj` | `disassemble_function` | `pdf` |
| `list_relocations` | `irj` | `disassemble_at` | `pd N` |
| `list_classes` | `icj` | `hexdump` | `px` |
| `list_methods` | `icmj` | `read_memory` | `pxj` |
| `xrefs_to` | `axtj`+`fdj` | `xrefs_from` | `axfj`+`afij` |
| `search` | `/zj` `/xj` `/vNj` `/aj` | `lookup_address` | `fdj` |
| `lookup_symbol` | `isj`+filter | `lookup_export` | `iEj`+filter |
| `decompile_function` | `pdsf`/`pds`/`pdr` | `rename_function` | `afn` |
| `rename_flag` | `fdj`+`fr` | `set_comment` | `CCu` |
| `get_function_signature` | `afs` | `set_function_signature` | `afs` |
| `seek_to` | `s`+`sj` | `get_current_address` | `s`+`fd` |
| `run_command` | any | | |

## Verification

- 38/38 core tool checks on `/bin/ls` (open/analyze/list/disasm/xrefs/search/rename/comment/close)
- 9/9 round-2 checks (vars, relocs, comments, strings, hex, analysis info)
- 5/5 round-3 checks (name resolution, graphs, enriched xrefs)
- 63MB PE32+ (GameAssembly.dll) stress: open → analyze → list → search, incl. the 59MB relocation JSON
- Command interleaving: 10 rapid-fire calls, zero cross-contamination
- Injection: `;`/newline in params rejected; `!rm -rf /` blocked
