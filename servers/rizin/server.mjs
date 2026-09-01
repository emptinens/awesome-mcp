#!/usr/bin/env node
/**
 * rizin-mcp — MCP server exposing the rizin reverse-engineering framework.
 *
 * Architecture: one long-lived `rizin -q -0 <file>` child per open file,
 * speaking r2pipe (commands in, NUL-terminated responses out). All analysis
 * state persists across tool calls.
 *
 * Zero runtime dependencies. Node >= 18. stdio transport, MCP 2024-11-05.
 *
 * r2pipe traps handled here (all three will corrupt a naive implementation):
 *  1. Leading NUL: rizin -0 emits one NUL on startup — AFTER parsing the file
 *     (3.8s for a 63MB PE). Commands sent before it arrives read the previous
 *     command's response (off-by-one). We absorb it before starting the queue.
 *  2. Serialization: r2pipe is a single stdin/stdout stream. Overlapping
 *     commands mix outputs; everything goes through a promise queue.
 *  3. Chunk-split UTF-8: responses can split mid-multibyte-character across
 *     stream chunks. Bytes accumulate as latin1 (lossless), decoded to UTF-8
 *     only after the terminating NUL.
 *
 * vs. radareorg/radare2-mcp: same protocol, one ~600-line Node file instead
 * of ~8k lines of C with a build step, plus name-resolution in address params
 * and xref→function enrichment that agents always need next.
 */

import { spawn } from "node:child_process";

const VERSION = "2.0.0";
const RIZIN = process.env.RIZIN_BIN || "rizin";
const MAX_OUTPUT = parseInt(process.env.RIZIN_MCP_MAX_OUTPUT || "60000", 10);
const PAGE_DEFAULT = parseInt(process.env.RIZIN_MCP_PAGE_DEFAULT || "200", 10);
const PAGE_MAX = parseInt(process.env.RIZIN_MCP_PAGE_MAX || "2000", 10);
const ALLOW_DANGEROUS = !!process.env.RIZIN_MCP_ALLOW_DANGEROUS;
// analysis level (0-3) → rizin command. 'aa' is seconds even on 63MB binaries;
// 'aaa' (refs+emulation+signatures) can take minutes on large files; aaaa is
// experimental. No 'aaaaa' exists.
const ANALYSIS = ["aa", "aa", "aaa", "aaaa"];

// ---------------------------------------------------------------- r2pipe core

let rz = null;        // child process
let openPath = null;  // currently opened file
let analyzed = -1;    // analysis level already run (-1 = never, 0-3 = level)
let rzReady = null;

function ensureRizin() {
  if (rz) return;
  const args = openPath ? ["-q", "-0", openPath] : ["-q", "-0"];
  const child = spawn(RIZIN, args, { stdio: ["pipe", "pipe", "ignore"] });
  rz = child;
  // Instance-guard: a killed OLD child's exit must not clobber the NEW one's state.
  const dead = () => { if (rz === child) { rz = null; openPath = null; analyzed = -1; } };
  child.on("exit", dead);
  child.on("error", dead);
  // Trap 1: absorb the leading NUL (arrives after file parsing).
  rzReady = new Promise((resolve) => {
    const absorb = (d) => {
      if (rz !== child) { child.stdout.off("data", absorb); resolve(); return; }
      if (d.toString("latin1").includes("\x00")) {
        child.stdout.off("data", absorb);
        resolve();
      }
    };
    child.stdout.on("data", absorb);
    setTimeout(resolve, 120000); // safety net for a dead rizin
  });
}

// Trap 2: serialize every command through one queue.
let cmdQueue = Promise.resolve();
function r2cmd(cmd, { timeout = 30000 } = {}) {
  ensureRizin();
  const run = cmdQueue.then(async () => {
    await rzReady;
    const child = rz;
    if (!child) return "";
    // Trap 3: latin1 accumulate, UTF-8 resolve after NUL.
    return new Promise((resolve) => {
      let out = "";
      let settled = false;
      const finish = (val) => {
        if (settled) return;
        settled = true;
        child.stdout.off("data", onData);
        clearTimeout(timer);
        resolve(val);
      };
      const onData = (d) => {
        out += d.toString("latin1");
        const nul = out.indexOf("\x00");
        if (nul >= 0) finish(out.slice(0, nul).toString("utf8"));
      };
      const timer = setTimeout(() => finish(out.toString("utf8")), timeout);
      child.stdout.on("data", onData);
      try { child.stdin.write(cmd + "\n"); } catch { finish(""); }
    });
  });
  cmdQueue = run.then(() => {}, () => {});
  return run;
}

async function r2json(cmd, opts) {
  const text = await r2cmd(cmd, opts);
  try { return JSON.parse(text); } catch { return text; }
}

// ---------------------------------------------------------------- helpers

/** Strict numeric: hex or decimal. For base addresses and search values. */
function checkNum(v, what = "address") {
  const s = String(v).trim();
  if (!/^(?:0x[0-9a-fA-F]+|\d+)$/.test(s)) throw new Error(`${what} must be numeric (0x… or decimal), got: ${v}`);
  return s;
}

/** Address OR flag/function name ("main", "sym.imp.fwrite") — rizin's seek
 *  resolves both. Rejects command-injection shapes. */
function addrOrName(v, what = "address") {
  const s = String(v ?? "").trim();
  if (!s) throw new Error(`${what} required`);
  if (/[\n\r\x00;]/.test(s)) throw new Error(`${what} contains forbidden characters`);
  return s.replace(/\s+/g, "");
}

function clamp(n, def, max) {
  const v = n === undefined || n === null || isNaN(Number(n)) ? def : Number(n);
  return Math.max(1, Math.min(v, max));
}

function pageSlice(items, { cursor = 0, limit } = {}) {
  const lim = clamp(limit, PAGE_DEFAULT, PAGE_MAX);
  const start = Math.max(0, parseInt(cursor, 10) || 0);
  const end = start + lim;
  return { items: items.slice(start, end), nextCursor: end < items.length ? end : null, total: items.length };
}

function truncateText(text, max = MAX_OUTPUT) {
  if (text.length <= max) return text;
  return text.slice(0, max) + `\n... [truncated ${text.length - max} chars; narrow the query or page with cursor/limit]`;
}

function requireFile() {
  if (!openPath) throw new Error("no file open — call open_file first");
}

/** paginated JSON list with optional regex filter */
async function jsonList(cmd, { regex, cursor, limit }, filterKey = "name") {
  requireFile();
  const data = await r2json(cmd);
  let items = Array.isArray(data) ? data : [];
  if (regex) {
    const re = new RegExp(String(regex), "i");
    items = items.filter((it) => re.test(it[filterKey] ?? ""));
  }
  return pageSlice(items, { cursor, limit });
}

// ---------------------------------------------------------------- tool impls

async function openFile({ file_path, base_address, arch, bits, cpu, run_analyze = true, analysis_level }) {
  const p = String(file_path ?? "");
  if (!p.startsWith("/")) throw new Error("file_path must be an absolute path");
  if (rz) { try { rz.kill(); } catch {} rz = null; }
  openPath = p;
  analyzed = -1;
  ensureRizin();
  await rzReady;
  // rizin argv already handles base/arch/bits/cpu for raw binaries
  if (base_address || arch || bits || cpu) {
    const opts = [];
    if (base_address) opts.push(`-B ${checkNum(base_address, "base_address")}`);
    if (arch) opts.push(`-a ${arch}`);
    if (bits) opts.push(`-b ${bits}`);
    if (cpu) opts.push(`-k ${cpu}`);
    // respawn with options (argv can't be set after spawn)
    if (opts.length) {
      if (rz) { try { rz.kill(); } catch {} rz = null; }
      const child = spawn(RIZIN, ["-q", "-0", ...opts.flatMap((o) => o.split(" ")), openPath], { stdio: ["pipe", "pipe", "ignore"] });
      rz = child;
      const dead = () => { if (rz === child) { rz = null; openPath = null; analyzed = -1; } };
      child.on("exit", dead);
      child.on("error", dead);
      rzReady = new Promise((resolve) => {
        const absorb = (d) => {
          if (d.toString("latin1").includes("\x00")) { child.stdout.off("data", absorb); resolve(); }
        };
        child.stdout.on("data", absorb);
        setTimeout(resolve, 120000);
      });
      await rzReady;
    }
  }
  const info = await r2json("ij");
  let level = analysis_level;
  let downgraded = false;
  // 'aaa' on a 63MB binary takes minutes — don't hang the client by default.
  if (run_analyze && analysis_level === undefined && (info?.core?.size || 0) > 20_000_000) {
    level = 1; downgraded = true;
  }
  const analysis = run_analyze ? await analyze({ level }) : null;
  if (downgraded) analysis.note = `binary >20MB: analyzed at level 1 (aa). Call analyze with level 2 for full aaa (minutes on this size).`;
  return { file: p, info, analysis };
}

async function analyze({ level = 2 }) {
  requireFile();
  const lvl = Math.max(0, Math.min(3, parseInt(level, 10) || 0));
  if (analyzed >= lvl) {
    const fns = parseInt((await r2cmd("aflc")).trim(), 10) || 0;
    return { skipped: true, level: analyzed, functions: fns, note: `already analyzed at level ${analyzed}; pass a higher level to re-run` };
  }
  const cmd = ANALYSIS[lvl];
  await r2cmd(cmd, { timeout: 600000 });
  analyzed = lvl;
  const fns = parseInt((await r2cmd("aflc")).trim(), 10) || 0;
  return { analyzed: true, level: lvl, command: cmd, functions: fns };
}

async function closeFile() {
  if (!openPath) return { closed: false };
  if (rz) { try { rz.kill(); } catch {} rz = null; }
  const p = openPath;
  openPath = null;
  analyzed = -1;
  return { closed: true, file: p };
}

const listFunctions = (a) => jsonList("aflj", a).then((r) => {
  // extra filters
  if (a.only_named) {
    const re = /\.\d+$/;
    const filtered = r.items.filter((f) => !re.test(f.name || ""));
    r.items = filtered; r.total = filtered.length; r.nextCursor = null;
  }
  return r;
});

const listImports = (a) => jsonList("iij", a);
const listExports = (a) => jsonList("iEj", a);
const listSymbols = (a) => jsonList("isj", a);
const listSections = () => r2json("iSj");
const listLibraries = () => r2json("ilj");
const listRelocations = (a) => jsonList("irj", a);
const listComments = (a) => jsonList("CClj", a, "name");
const listClasses = () => r2json("icj");
const analysisInfo = () => r2json("aaij");

async function listEntrypoints() {
  requireFile();
  const eps = await r2json("iej");
  if (!Array.isArray(eps)) return eps;
  const enriched = [];
  for (const e of eps) {
    const fd = await r2json(`s ${e.vaddr}; fdj`);
    enriched.push({ ...e, name: Array.isArray(fd) ? fd[0]?.name : fd?.name });
  }
  return { entrypoints: enriched };
}

async function listFlags(a) {
  requireFile();
  const data = await r2json("flj");
  let items = Array.isArray(data) ? data : [];
  if (a.regex) {
    const re = new RegExp(String(a.regex), "i");
    items = items.filter((f) => re.test(f.name || ""));
  }
  return pageSlice(items, { cursor: a.cursor, limit: a.limit });
}

async function listStrings({ regex, min_length = 4, all = false, cursor, limit }) {
  requireFile();
  const data = await r2json(all ? "izzj" : "izj");
  let items = Array.isArray(data) ? data : [];
  if (regex) {
    const re = new RegExp(String(regex), "i");
    items = items.filter((s) => re.test(s.string ?? ""));
  }
  if (min_length) items = items.filter((s) => (s.string ?? "").length >= min_length);
  return pageSlice(items, { cursor, limit });
}

async function listMethods({ class_name }) {
  requireFile();
  if (!class_name) throw new Error("class_name required");
  return r2json(`icmj ${JSON.stringify(String(class_name))}`);
}

async function showInfo() { requireFile(); return r2json("ij"); }

async function atAddr(address, cmd, { timeout } = {}) {
  requireFile();
  const a = addrOrName(address);
  return r2json(`s ${a}; ${cmd}`, { timeout });
}

const showFunctionDetails = (a) => atAddr(a.address, "afij");
const listFunctionVars = (a) => atAddr(a.address, "afvlj");
const getFunctionSignature = async (a) => (await atAddr(a.address, "afs")).trim();
const lookupAddress = (a) => atAddr(a.address, "fdj");
const basicBlocks = async (a) => {
  const d = await atAddr(a.address, "afbj");
  return Array.isArray(d) ? { blocks: d.length, items: d.slice(0, 500) } : d;
};

async function functionGraph(a) {
  const data = await atAddr(a.address, "agf json");
  if (typeof data === "string") return { error: "no graph — analyze first", raw: truncateText(data, 2000) };
  const nodes = data.nodes || [];
  let edges = 0;
  for (const n of nodes) edges += (n.out_nodes || []).length;
  return { blocks: nodes.length, edges, nodes };
}

async function callGraph(a) {
  requireFile();
  const data = await r2json("agC json", { timeout: 120000 });
  if (typeof data === "string") return { error: "no callgraph — analyze first", raw: truncateText(data, 2000) };
  return pageSlice((data.nodes || []).map((n) => ({ id: n.id, name: n.title, offset: n.offset, calls: (n.out_nodes || []).length })), { cursor: a.cursor, limit: a.limit });
}

async function disassembleFunction({ address, cursor, limit }) {
  requireFile();
  const a = addrOrName(address);
  const text = await r2cmd(`s ${a}; pdf`, { timeout: 60000 });
  return pageSlice(text.split("\n"), { cursor, limit });
}

async function disassembleAt({ address, count = 20 }) {
  requireFile();
  const a = addrOrName(address);
  return truncateText(await r2cmd(`s ${a}; pd ${clamp(count, 20, 500)}`));
}

async function hexdump({ address, count = 64 }) {
  requireFile();
  const a = addrOrName(address);
  return truncateText(await r2cmd(`s ${a}; px ${clamp(count, 64, 4096)}`));
}

async function readHex({ address, count = 32 }) {
  requireFile();
  const a = addrOrName(address);
  return { address: a, hex: (await r2cmd(`p8 ${clamp(count, 32, 4096)} @ ${a}`)).trim() };
}

async function readMemory({ address, count = 64 }) {
  requireFile();
  const a = addrOrName(address);
  const data = await r2json(`s ${a}; pxj ${clamp(count, 64, 8192)}`);
  return Array.isArray(data) ? { address: a, bytes: data } : data;
}

async function printStringAt({ address }) {
  requireFile();
  const a = addrOrName(address);
  return { address: a, string: (await r2cmd(`ps @ ${a}`)).trim() };
}

async function xrefsTo({ address }) {
  requireFile();
  const a = addrOrName(address);
  const data = await r2json(`s ${a}; axtj`);
  if (!Array.isArray(data) || data.length === 0) return data;
  // enrich: which function contains each xref source (the next thing agents ask)
  const enriched = [];
  for (const x of data.slice(0, 200)) {
    const fd = await r2json(`s ${x.from}; fdj`);
    enriched.push({ ...x, from_function: Array.isArray(fd) ? fd[0]?.name : fd?.name });
  }
  if (data.length > 200) enriched.push({ note: `${data.length - 200} more xrefs not enriched (pass narrower query)` });
  return enriched;
}

async function xrefsFrom({ address }) {
  requireFile();
  const a = addrOrName(address);
  const direct = await r2json(`s ${a}; axfj`);
  const finfo = await r2json(`s ${a}; afij`);
  const f = Array.isArray(finfo) ? finfo[0] : null;
  return {
    from_offset: Array.isArray(direct) ? direct : [],
    function_calls: f ? (f.callrefs || []).map((r) => ({ from: r.from, to: r.to, type: r.type })) : [],
    function_data_refs: f ? (f.datarefs || []) : [],
  };
}

async function listFunctionCalls({ address }) {
  requireFile();
  const a = addrOrName(address);
  const data = await r2json(`s ${a}; afij`);
  if (!Array.isArray(data) || !data[0]) return data;
  const f = data[0];
  return { calls: (f.callrefs || []).map((r) => ({ from: r.from, to: r.to, type: r.type })), data_refs: f.datarefs, signature: f.signature };
}

async function searchPatterns({ query, type = "string", cursor, limit }) {
  requireFile();
  const q = String(query ?? "");
  if (/[\n\r\x00;]/.test(q)) throw new Error("query contains forbidden characters");
  let cmd;
  switch (type) {
    case "hex": cmd = `/xj ${q}`; break;
    case "wide": cmd = `/zj ${q} l utf16le`; break;
    case "value1": case "value2": case "value4": case "value8":
      cmd = `/v${type.slice(5)}j ${checkNum(q, "value")}`; break;
    case "asm": cmd = `/aj ${q}`; break;
    default: cmd = `/zj ${q}`;
  }
  const data = await r2cmd(cmd, { timeout: 120000 });
  let parsed;
  try { parsed = JSON.parse(data); } catch { return { raw: truncateText(data) }; }
  return pageSlice(Array.isArray(parsed) ? parsed : [], { cursor, limit });
}

async function lookupSymbol({ name, cursor, limit }) {
  requireFile();
  const data = await r2json("isj");
  let items = Array.isArray(data) ? data : [];
  const re = new RegExp(String(name).replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i");
  items = items.filter((s) => re.test(s.name ?? "") || re.test(s.realname ?? "") || re.test(s.flagname ?? ""));
  return pageSlice(items, { cursor, limit });
}

async function lookupExport({ name }) {
  requireFile();
  const data = await r2json("iEj");
  const items = Array.isArray(data) ? data : [];
  const re = new RegExp(String(name).replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i");
  return pageSlice(items.filter((e) => re.test(e.name ?? "")), {});
}

async function decompileFunction({ address, mode = "pdsf" }) {
  requireFile();
  const a = addrOrName(address);
  const cmd = mode === "pds" ? `s ${a}; pds 5000` : mode === "pdr" ? `s ${a}; pdr` : `s ${a}; pdsf`;
  const text = await r2cmd(cmd, { timeout: 60000 });
  if (!text.trim()) return { error: "empty output — is the address inside a function? analyze first (show_function_details to check)" };
  return truncateText(text);
}

async function renameFunction({ address, new_name }) {
  requireFile();
  const a = addrOrName(address);
  const n = String(new_name ?? "").replace(/[^a-zA-Z0-9_.]/g, "_");
  await r2cmd(`s ${a}; afn ${n}`);
  return { renamed: n, address: a };
}

async function renameFlag({ address, new_name }) {
  requireFile();
  const a = addrOrName(address);
  const fd = await r2json(`s ${a}; fdj`);
  const old = Array.isArray(fd) ? fd[0]?.name : fd?.name;
  if (!old) return { error: `no flag at ${a} — check lookup_address` };
  const n = String(new_name ?? "").replace(/[^a-zA-Z0-9_.]/g, "_");
  await r2cmd(`fr ${old} ${n}`);
  return { renamed: n, was: old, address: a };
}

async function renameFunctionVar({ address, old_name, new_name }) {
  requireFile();
  const a = addrOrName(address);
  const o = String(old_name ?? "").replace(/[^a-zA-Z0-9_.$-]/g, "");
  const n = String(new_name ?? "").replace(/[^a-zA-Z0-9_.$-]/g, "");
  if (!o || !n) throw new Error("old_name and new_name required");
  const out = await r2cmd(`s ${a}; afvn ${n} ${o}`);
  if (/cannot find|error/i.test(out)) return { error: (out.trim() || `variable ${o} not found at ${a}`) };
  return { renamed: n, was: o, address: a };
}

async function setVarType({ address, var_name, type }) {
  requireFile();
  const a = addrOrName(address);
  const v = String(var_name ?? "").replace(/[^a-zA-Z0-9_.$-]/g, "");
  const t = String(type ?? "").replace(/[;\n]/g, " ");
  if (!v || !t) throw new Error("var_name and type required");
  const out = await r2cmd(`s ${a}; afvt ${v} ${t}`);
  if (/cannot find|error/i.test(out)) return { error: (out.trim() || `variable ${v} not found at ${a}`) };
  return { typed: v, type: t, address: a };
}

async function setComment({ address, comment }) {
  requireFile();
  const a = addrOrName(address);
  const text = String(comment ?? "").replace(/;/g, " ").replace(/@/g, " ").replace(/\n/g, " ");
  await r2cmd(`s ${a}; CCu ${text}`);
  return { comment: text, address: a };
}

async function setFunctionSignature({ address, signature }) {
  requireFile();
  const a = addrOrName(address);
  const sig = String(signature ?? "").replace(/"/g, '\\"');
  await r2cmd(`s ${a}; afs "${sig}"`);
  return { signature: sig, address: a };
}

async function seekTo({ address }) {
  requireFile();
  const a = addrOrName(address);
  await r2cmd(`s ${a}`);
  return r2json("sj");
}

async function getCurrentAddress() {
  requireFile();
  const addr = (await r2cmd("s")).trim();
  const fn = (await r2cmd("fd $$")).trim();
  return { address: addr, function: fn };
}

async function runCommand({ command, cursor, limit }) {
  requireFile();
  const cmd = String(command ?? "");
  if (!ALLOW_DANGEROUS && /^\s*(!|!!|w[a-zA-Z]*\s)/.test(cmd)) {
    throw new Error("dangerous command blocked (shell/file-write). Set RIZIN_MCP_ALLOW_DANGEROUS=1 to permit.");
  }
  const text = await r2cmd(cmd, { timeout: 60000 });
  return pageSlice(text.split("\n"), { cursor, limit });
}

// ---------------------------------------------------------------- MCP schema

const LIST_PROPS = {
  regex: { type: "string", description: "Regular expression to filter results (case-insensitive)" },
  cursor: { type: "integer", description: "Pagination cursor (index to start from; use nextCursor from the previous page)" },
  limit: { type: "integer", description: `Max results per page (default ${PAGE_DEFAULT}, max ${PAGE_MAX})` },
};
const listSchema = (extra = {}) => ({ type: "object", properties: { ...LIST_PROPS, ...extra } });
const ADDR = { type: "string", description: "Address (0x…, decimal) or function/flag name (e.g. main, sym.imp.fwrite)" };
const addrSchema = (extra = {}, req = []) => ({ type: "object", properties: { address: ADDR, ...extra }, required: ["address", ...req] });

const TOOLS = [
  { name: "open_file", description: "Open a binary in rizin. Call this first. base_address/arch/bits/cpu for raw (headerless) binaries. Runs analysis by default (run_analyze=false to skip).", inputSchema: { type: "object", properties: { file_path: { type: "string", description: "Absolute path to the binary" }, base_address: { type: "string", description: "Base address for PIE/raw binaries, e.g. 0x400000" }, arch: { type: "string", description: "Arch override: arm, x86, mips…" }, bits: { type: "integer", description: "Bits override: 16/32/64" }, cpu: { type: "string", description: "CPU variant: cortex, generic…" }, run_analyze: { type: "boolean", default: true }, analysis_level: { type: "integer", minimum: 0, maximum: 3, default: 2 } }, required: ["file_path"] } },
  { name: "close_file", description: "Close the open file and reset all state.", inputSchema: { type: "object", properties: {} } },
  { name: "analyze", description: "Run rizin analysis. Levels: 0=aa (symbols+entry), 2=aaa (calls+refs+emulation, default), 3=aaaa (experimental, slow). Skips if already analyzed at that level.", inputSchema: { type: "object", properties: { level: { type: "integer", minimum: 0, maximum: 3, default: 2 } } } },
  { name: "show_info", description: "Binary metadata (ij): format, arch, bits, endian, relro, canary, PIE, compiler, checksums.", inputSchema: { type: "object", properties: {} } },
  { name: "analysis_info", description: "Analysis summary (aai): function count, xrefs, calls, strings, code coverage %.", inputSchema: { type: "object", properties: {} } },
  { name: "list_functions", description: "Functions found by analysis (afl). regex filter, pagination, only_named to skip auto-numbered stubs.", inputSchema: listSchema({ only_named: { type: "boolean", description: "Skip functions like fcn.000030c0" } }) },
  { name: "list_imports", description: "Imported symbols (ii) — what the binary pulls from libraries.", inputSchema: listSchema() },
  { name: "list_exports", description: "Exported symbols (iE) — the binary's public interface.", inputSchema: listSchema() },
  { name: "list_symbols", description: "All symbols with addresses (is).", inputSchema: listSchema() },
  { name: "list_sections", description: "Sections and segments with permissions (iS).", inputSchema: { type: "object", properties: {} } },
  { name: "list_libraries", description: "Linked shared libraries (il).", inputSchema: { type: "object", properties: {} } },
  { name: "list_entrypoints", description: "Entrypoints with names (ie: program/init/fini).", inputSchema: { type: "object", properties: {} } },
  { name: "list_strings", description: "Strings (iz data sections; all=true scans the whole file via izz). regex + min_length filters.", inputSchema: listSchema({ min_length: { type: "integer", default: 4 }, all: { type: "boolean", description: "Scan the whole file (slower)" } }) },
  { name: "list_flags", description: "All flags/labels (fl) — rizin's namespace for named addresses.", inputSchema: listSchema() },
  { name: "list_relocations", description: "Relocation table (ir).", inputSchema: listSchema() },
  { name: "list_comments", description: "All comments (CCl).", inputSchema: listSchema() },
  { name: "list_classes", description: "Classes for OO binaries (ic): C++, ObjC, Java/Dalvik.", inputSchema: { type: "object", properties: {} } },
  { name: "list_methods", description: "Methods of a class (icm).", inputSchema: { type: "object", properties: { class_name: { type: "string" } }, required: ["class_name"] } },
  { name: "show_function_details", description: "Function info (afi): size, basic blocks, stack frame, signature, vars.", inputSchema: addrSchema() },
  { name: "list_function_vars", description: "Arguments and locals (afvl): names, types, stack/reg offsets.", inputSchema: addrSchema() },
  { name: "list_function_calls", description: "Calls made by a function (afij callrefs) + data refs.", inputSchema: addrSchema() },
  { name: "function_graph", description: "Control-flow graph of a function (agf): basic blocks with disasm bodies, jump edges. The closest thing to decompilation in rizin core.", inputSchema: addrSchema() },
  { name: "call_graph", description: "Global callgraph (agC): every function, offset, out-call count. Paginated.", inputSchema: listSchema() },
  { name: "basic_blocks", description: "Basic blocks of a function (afb): addr, size, instruction count.", inputSchema: addrSchema() },
  { name: "disassemble_function", description: "Full assembly of a function (pdf). Paginated by line.", inputSchema: addrSchema() },
  { name: "disassemble_at", description: "Disassemble N instructions at an address (pd).", inputSchema: addrSchema({ count: { type: "integer", default: 20, maximum: 500 } }) },
  { name: "hexdump", description: "Hexdump with ASCII column (px).", inputSchema: addrSchema({ count: { type: "integer", default: 64, maximum: 4096 } }) },
  { name: "read_hex", description: "Raw hex pairs (p8) — no ASCII column.", inputSchema: addrSchema({ count: { type: "integer", default: 32, maximum: 4096 } }) },
  { name: "read_memory", description: "Bytes at address as a JSON array (pxj).", inputSchema: addrSchema({ count: { type: "integer", default: 64, maximum: 8192 } }) },
  { name: "print_string_at", description: "NUL-terminated string at an address (ps).", inputSchema: addrSchema() },
  { name: "xrefs_to", description: "References TO an address/symbol (axt) — who calls/reads it, enriched with the containing function name.", inputSchema: addrSchema() },
  { name: "xrefs_from", description: "References FROM an address (axf + afij): what it calls and reads.", inputSchema: addrSchema() },
  { name: "search", description: "Search the binary: string, hex pairs, wide (utf16le) string, value1/2/4/8 (numeric with width), or asm text. Returns hit addresses.", inputSchema: { type: "object", properties: { query: { type: "string", description: "String text / hex pairs (e.g. 454c46) / numeric value" }, type: { type: "string", enum: ["string", "hex", "wide", "value1", "value2", "value4", "value8", "asm"], default: "string" }, ...LIST_PROPS }, required: ["query"] } },
  { name: "lookup_address", description: "What is at an address: flag name + delta (fd).", inputSchema: addrSchema() },
  { name: "lookup_symbol", description: "Find symbols by name substring (is).", inputSchema: { type: "object", properties: { name: { type: "string" }, ...LIST_PROPS }, required: ["name"] } },
  { name: "lookup_export", description: "Find exports by name substring (iE).", inputSchema: { type: "object", properties: { name: { type: "string" } }, required: ["name"] } },
  { name: "decompile_function", description: "Pseudo-code: pdsf (structured summary — strings, calls, refs; default), pds (block summary), pdr (recursive disassembly). Full C requires the rz-ghidra plugin.", inputSchema: addrSchema({ mode: { type: "string", enum: ["pdsf", "pds", "pdr"], default: "pdsf" } }) },
  { name: "rename_function", description: "Rename a function (afn).", inputSchema: addrSchema({ new_name: { type: "string" } }, ["new_name"]) },
  { name: "rename_flag", description: "Rename the flag at an address (fr).", inputSchema: addrSchema({ new_name: { type: "string" } }, ["new_name"]) },
  { name: "rename_function_var", description: "Rename an arg/local variable (afvn).", inputSchema: { type: "object", properties: { address: ADDR, old_name: { type: "string", description: "e.g. var_90h" }, new_name: { type: "string" } }, required: ["address", "old_name", "new_name"] } },
  { name: "set_var_type", description: "Change a variable's C type (afvt): int*, char[64]…", inputSchema: { type: "object", properties: { address: ADDR, var_name: { type: "string" }, type: { type: "string" } }, required: ["address", "var_name", "type"] } },
  { name: "set_comment", description: "Comment at an address — appears in disassembly (CCu).", inputSchema: addrSchema({ comment: { type: "string" } }, ["comment"]) },
  { name: "get_function_signature", description: "Current signature of a function (afs).", inputSchema: addrSchema() },
  { name: "set_function_signature", description: "Set a function's signature (afs), e.g. \"int main(int argc, char **argv)\".", inputSchema: addrSchema({ signature: { type: "string" } }, ["signature"]) },
  { name: "seek_to", description: "Move the rizin cursor (s) — subsequent pd/px default to it.", inputSchema: addrSchema() },
  { name: "get_current_address", description: "Current cursor + containing function.", inputSchema: { type: "object", properties: {} } },
  { name: "run_command", description: "Raw rizin command (escape hatch). Shell (!) and write (w*) commands blocked unless RIZIN_MCP_ALLOW_DANGEROUS=1.", inputSchema: { type: "object", properties: { command: { type: "string", description: "e.g. 'afl~main', 'pdf @ sym.main', 'izz~password'" }, ...LIST_PROPS }, required: ["command"] } },
];

const HANDLERS = {
  open_file: openFile,
  close_file: closeFile,
  analyze,
  show_info: showInfo,
  analysis_info: analysisInfo,
  list_functions: listFunctions,
  list_imports: listImports,
  list_exports: listExports,
  list_symbols: listSymbols,
  list_sections: listSections,
  list_libraries: listLibraries,
  list_entrypoints: listEntrypoints,
  list_strings: listStrings,
  list_flags: listFlags,
  list_relocations: listRelocations,
  list_comments: listComments,
  list_classes: listClasses,
  list_methods: listMethods,
  show_function_details: showFunctionDetails,
  list_function_vars: listFunctionVars,
  list_function_calls: listFunctionCalls,
  function_graph: functionGraph,
  call_graph: callGraph,
  basic_blocks: basicBlocks,
  disassemble_function: disassembleFunction,
  disassemble_at: disassembleAt,
  hexdump,
  read_hex: readHex,
  read_memory: readMemory,
  print_string_at: printStringAt,
  xrefs_to: xrefsTo,
  xrefs_from: xrefsFrom,
  search: searchPatterns,
  lookup_address: lookupAddress,
  lookup_symbol: lookupSymbol,
  lookup_export: lookupExport,
  decompile_function: decompileFunction,
  rename_function: renameFunction,
  rename_flag: renameFlag,
  rename_function_var: renameFunctionVar,
  set_var_type: setVarType,
  set_comment: setComment,
  get_function_signature: getFunctionSignature,
  set_function_signature: setFunctionSignature,
  seek_to: seekTo,
  get_current_address: getCurrentAddress,
  run_command: runCommand,
};

// ---------------------------------------------------------------- MCP stdio

const rl = (await import("node:readline")).createInterface({ input: process.stdin, terminal: false });
const write = (msg) => process.stdout.write(JSON.stringify(msg) + "\n");

rl.on("line", (line) => {
  let req;
  try { req = JSON.parse(line); } catch { return; }
  const { id, method, params } = req;
  const reply = (result) => id !== undefined && write({ jsonrpc: "2.0", id, result });
  const replyErr = (code, message) => id !== undefined && write({ jsonrpc: "2.0", id, error: { code, message } });

  switch (method) {
    case "initialize":
      write({ jsonrpc: "2.0", id, result: {
        protocolVersion: "2024-11-05",
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: "rizin-mcp", version: VERSION },
      } });
      return;
    case "notifications/initialized":
    case "notifications/cancelled":
      return;
    case "ping":
      reply({});
      return;
    case "tools/list":
      reply({ tools: TOOLS });
      return;
    case "tools/call": {
      const handler = HANDLERS[params?.name];
      if (!handler) return replyErr(-32602, `unknown tool: ${params?.name}`);
      handler(params?.arguments || {})
        .then((result) => write({ jsonrpc: "2.0", id, result: { content: [{ type: "text", text: JSON.stringify(result) }] } }))
        .catch((e) => write({ jsonrpc: "2.0", id, result: { content: [{ type: "text", text: JSON.stringify({ error: String(e?.message ?? e) }) }], isError: true } }));
      return;
    }
    default:
      if (id !== undefined) replyErr(-32601, `method not found: ${method}`);
  }
});

process.on("exit", () => { if (rz) { try { rz.kill(); } catch {} } });
process.on("SIGTERM", () => process.exit(0));
process.on("SIGINT", () => process.exit(0));
process.stderr.write(`[rizin-mcp v${VERSION}] ${TOOLS.length} tools | rizin: ${RIZIN} | pid ${process.pid}\n`);
