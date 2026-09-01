# rizin MCP server

MCP server exposing the [rizin](https://rizin.re) reverse-engineering framework to coding agents. 44 tools: open/analyze binaries, list functions/imports/exports/symbols/sections/strings, disassemble, hexdump, xrefs, search, rename, comment, set signatures, raw command escape hatch.

Zero runtime dependencies (Node built-ins), stdio transport, MCP `2024-11-05`.

```toml
# ~/.codex/config.toml
[mcp_servers.rizin-mcp]
command = "node"
args = ["/path/to/servers/rizin/server.mjs"]
```

Requires `rizin` on `$PATH` (tested with 0.8.2). Set `RIZIN_BIN` to override the binary path.

## Architecture

```
MCP client ──stdio JSON-RPC── server.mjs ──r2pipe── rizin -q -0 <file>
```

One long-lived `rizin -q -0` child per open file, speaking the **r2pipe protocol**: commands on stdin, responses NUL-terminated on stdout. All state (analysis, renames, comments, seek position) persists across tool calls.

### Why this design (vs. radareorg/radare2-mcp)

The reference r2mcp is ~8k lines of C with a build step. This is one 35KB Node file, no build, same MCP protocol, and fixes protocol quirks the reference glosses over:

**r2pipe has three traps. All three are handled:**

1. **Leading NUL.** `rizin -0` emits one NUL byte on startup — *after* parsing the file. On a 63MB PE that NUL arrives 3.8s after spawn. If you start sending commands immediately, every response is off-by-one (you read the previous command's answer). The server absorbs the startup NUL and only then starts the command queue.

2. **Response ≠ request alignment.** Commands are serialized through a promise queue (`cmdQueue`). Never overlap two commands on the pipe — the NUL-terminated reader would mix outputs. Even "harmless" pipelining corrupts state.

3. **Latin1 accumulate, UTF-8 resolve.** Responses can split mid-multibyte-character across stream chunks. Bytes accumulate as latin1 (no loss), and the complete buffer is decoded to UTF-8 only after the terminating NUL is found.

**Other decisions:**

- **File as argv, not `o` command.** `rizin -q -0 <file>` parses the binary at startup (emitting the leading NUL when ready). The `o` command inside `-0` mode misbehaves; reopening a file respawns the child with new argv. Kill of the old child is instance-guarded so its `exit` event can't clobber the new child's state.
- **JSON-first output.** Every `j`-suffixed rizin command (`aflj`, `iij`, `axtj`, `/zj`...) is parsed into structured objects; non-JSON output falls back to raw text. Agents get typed data when it exists.
- **Pagination everywhere.** Every list tool takes `cursor`/`limit` (default 200, max 2000) and returns `{items, nextCursor, total}`. A 63MB GameAssembly has ~9k functions; unpaginated dumps would blow the agent's context.
- **Address sanitizer.** `0x`-hex or decimal only; rejects injection-shaped strings before they reach rizin.
- **Dangerous command block.** `run_command` rejects shell escapes (`!`, `!!`) and file writes (`w*`) unless `RIZIN_MCP_ALLOW_DANGEROUS=1`.
- **Analysis-level cache.** `analyzed` tracks the level; `analyze` skips re-running (re-analysis of a 63MB binary takes minutes).
- **Output truncation** at 60KB (env-tunable via `RIZIN_MCP_MAX_OUTPUT`).

### rizin 0.8.2 command quirks (documented for maintainers)

- `axtj`/`axfj`/`fdj` take **no address argument** — seek first: `s 0x3560; axtj`.
- `f` alone is an error; flag listing is `flj`.
- `fr` renames by **flag names**, not addresses — resolve via `fdj` first.
- `CC <text> @ <addr>` is rejected; use `s <addr>; CC <text>`.
- `/j` doesn't exist. String search is `/zj`, hex `/xj`, value `/v{1,2,4,8}j`, asm `/aj`, wide via `/zj <pat> l encoding=utf16le`.
- No `pdc`/`pdd`/`pdg` in core (those are r2 plugins). Pseudo-code via `pdsf` (function summary: strings, calls, refs), `pds`, `pdr`. Install rz-ghidra for full C.

## Tool inventory (44)

| Tool | rizin | Notes |
|---|---|---|
| `open_file` | argv spawn | base_address/arch/bits/cpu overrides for raw binaries |
| `close_file` | kill child | |
| `analyze` | `aa`–`aaaa` | level 0–4, skip-if-done |
| `show_info` | `ij` | format/arch/bits/endian/relro/canary/PIE... |
| `list_functions` | `aflj` | regex, only_named, count |
| `list_imports` | `iij` | |
| `list_exports` | `iEj` | |
| `list_symbols` | `isj` | |
| `list_sections` | `iSj` | |
| `list_libraries` | `ilj` | |
| `list_entrypoints` | `iej` | + main symbol |
| `list_strings` | `izj`/`izzj` | data sections or whole-file |
| `list_flags` | `flj` | |
| `list_classes` | `icj` | C++/ObjC/Java |
| `list_methods` | `ic` | |
| `list_function_calls` | `afij` | callrefs + datarefs |
| `list_function_vars` | `afvlj` | args/locals: names, types, stack offsets |
| `rename_function_var` | `afvn` | rename arg/local |
| `set_var_type` | `afvt` | change var C type |
| `list_relocations` | `irj` | paginated (59MB JSON on big PEs) |
| `list_comments` | `CClj` | all comments |
| `print_string_at` | `ps` | NUL-terminated string at addr |
| `read_hex` | `p8` | compact hex pairs |
| `analysis_info` | `aaij` | fcns, xrefs, calls, coverage % |
| `show_function_details` | `afij` | size, bbcount, stack, vars, signature |
| `disassemble_function` | `pdf` | paginated |
| `disassemble_at` | `pd N` | |
| `hexdump` | `px` | |
| `read_memory` | `pxj` | JSON byte array |
| `xrefs_to` | `axtj` | |
| `xrefs_from` | `axfj`+`afij` | direct + whole-function |
| `search` | `/zj` `/xj` `/vNj` | string/hex/wide/value1-8/asm |
| `lookup_address` | `fdj` | flag+delta at address |
| `lookup_symbol` | `isj~` | |
| `lookup_export` | `iE~` | |
| `decompile_function` | `pdsf`/`pds`/`pdr` | see quirks above |
| `rename_function` | `afn` | |
| `rename_flag` | `fdj`+`fr` | resolves name first |
| `set_comment` | `CCu` | verified via `CC.` |
| `get_function_signature` | `afs` | |
| `set_function_signature` | `afs "sig"` | |
| `seek_to` | `s`+`sj` | |
| `get_current_address` | `s`+`fd` | |
| `run_command` | any | dangerous blocked by default |

## Verification

Tested end-to-end against `/bin/ls` (38+9/47 tool checks) and a 63MB PE32+ GameAssembly.dll: open → analyze → list → search → xrefs → rename → comment → close → reopen, including rapid-fire command interleaving (no response cross-contamination).
