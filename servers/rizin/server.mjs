#!/usr/bin/env node
/**
 * rizin-mcp — MCP server exposing the rizin reverse-engineering framework.
 *
 * Architecture: long-lived `rizin -q -0` child process speaking the r2pipe
 * protocol (commands in, NUL-terminated JSON-ish responses out). One rizin
 * instance per session; the MCP client opens/analyzes files through tools.
 *
 * Zero runtime dependencies. Node >= 18. Transport: stdio (MCP JSON-RPC 2.0).
 *
 * Design decisions vs. radareorg/radare2-mcp (the C reference):
 *  - Node instead of C: no build step, trivially hackable, same protocol.
 *  - One rizin child per server (r2pipe), spawned lazily on first file open.
 *  - Output truncation + pagination on every listing tool (the C one pages too).
 *  - Address sanitizer: rejects obviously-invalid addresses before hitting rizin.
 *  - JSON mode (`j` suffix) preferred: structured output parsed into objects
 *    when valid JSON, raw text otherwise (agents handle both).
 *  - search_strings / search_hex use rizin's native search with /j JSON output.
 *  - decompile uses pdc/pdd when present; graceful error listing backends.
 */

import { spawn } from "node:child_process";

const RIZIN = process.env.RIZIN_BIN || "rizin";
const MAX_OUTPUT = parseInt(process.env.RIZIN_MCP_MAX_OUTPUT || "60000", 10);
const PAGE_DEFAULT = parseInt(process.env.RIZIN_MCP_PAGE_DEFAULT || "200", 10);
const PAGE_MAX = parseInt(process.env.RIZIN_MCP_PAGE_MAX || "2000", 10);

// ---------------------------------------------------------------- r2pipe core

let rz = null;        // child process
let openPath = null;  // currently opened file
let analyzed = 0;     // analysis level already run (0 = none)

let rzReady = null;
function ensureRizin() {
  if (rz) return;
  // Pass the file as argv when we have one — `o` inside -0 mode misbehaves.
  const args = openPath ? ["-q", "-0", openPath] : ["-q", "-0"];
  const child = spawn(RIZIN, args, { stdio: ["pipe", "pipe", "ignore"] });
  rz = child;
  // Guard by instance: a killed OLD rizin's exit must not clobber the NEW one's state.
  child.on("exit", () => {
    if (rz === child) { rz = null; openPath = null; analyzed = 0; }
  });
  child.on("error", () => {
    if (rz === child) { rz = null; openPath = null; analyzed = 0; }
  });
  // rizin -0 emits a leading NUL on startup (after parsing the file — can take
  // seconds for large binaries); absorb it so commands align.
  rzReady = new Promise((resolve) => {
    const absorb = (d) => {
      if (rz !== child) { child.stdout.off("data", absorb); resolve(); return; }
      const s = d.toString("latin1");
      if (s.includes("\x00")) {
        child.stdout.off("data", absorb);
        resolve();
      }
      // no NUL yet: keep listening — it arrives once startup completes
    };
    child.stdout.on("data", absorb);
    // safety net: resolve after 120s (dead rizin) — pipe will error anyway
    setTimeout(resolve, 120000);
  });
}

/** Execute one rizin command over r2pipe. Returns text (stripped of trailing NUL). */
let cmdQueue = Promise.resolve();
function r2cmd(cmd, { timeout = 30000 } = {}) {
  ensureRizin();
  // serialize: r2pipe is a single stdin/stdout stream — never overlap commands
  const run = cmdQueue.then(async () => { await rzReady; const child = rz; return new Promise((resolve, reject) => {
    if (!child) { resolve(""); return; }
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
    rz.stdout.on("data", onData);
    try {
      child.stdin.write(cmd + "\n");
    } catch (e) {
      finish("");
    }
  }); });
  cmdQueue = run.then(() => {}, () => {});
  return run;
}

/** Execute and try to parse as JSON (rizin `j`-suffixed commands). */
async function r2json(cmd, opts) {
  const text = await r2cmd(cmd, opts);
  try {
    return JSON.parse(text);
  } catch {
    return text; // fall back to raw
  }
}

// ---------------------------------------------------------------- helpers

const ADDR_RE = /^(?:0x[0-9a-fA-F]+|\d+)$/;
function checkAddr(addr, what = "address") {
  const s = String(addr).trim();
  if (!ADDR_RE.test(s)) throw new Error(`${what} must be numeric or 0x-hex, got: ${addr}`);
  return s;
}

function clamp(n, def, max) {
  const v = n === undefined || n === null || isNaN(Number(n)) ? def : Number(n);
  return Math.max(1, Math.min(v, max));
}

function pageSlice(items, { cursor = 0, limit } = {}) {
  const lim = clamp(limit, PAGE_DEFAULT, PAGE_MAX);
  const start = Math.max(0, parseInt(cursor, 10) || 0);
  return { items: items.slice(start, start + lim), nextCursor: start + lim < items.length ? start + lim : null, total: items.length };
}

function truncateText(text, max = MAX_OUTPUT) {
  if (text.length <= max) return text;
  return text.slice(0, max) + `\n... [truncated ${text.length - max} bytes; pass cursor/limit to page, or run_command with a narrower query]`;
}

function requireFile() {
  if (!openPath) throw new Error("no file open — call open_file first");
}

// ---------------------------------------------------------------- tool impls

async function openFile({ file_path, base_address, arch, bits, cpu, run_analyze = true, analysis_level = 2 }) {
  const p = String(file_path);
  if (!p || !p.startsWith("/")) throw new Error("file_path must be an absolute path");
  // kill existing instance; respawn with the file as argv
  if (rz) { try { rz.kill(); } catch {} rz = null; }
  openPath = p;
  analyzed = 0;
  ensureRizin();
  await rzReady;
  if (base_address) await r2cmd(`e io.va=true; m ${checkAddr(base_address, "base_address")} 0 ${0}`);
  if (arch) await r2cmd(`e asm.arch=${arch}`);
  if (bits) await r2cmd(`e asm.bits=${bits}`);
  if (cpu) await r2cmd(`e asm.cpu=${cpu}`);
  const info = await r2json("ij");
  let analysisResult = null;
  if (run_analyze) {
    analysisResult = await analyze({ level: analysis_level });
  }
  return { file: p, info, analysis: analysisResult };
}

async function analyze({ level = 2, seconds = 0 }) {
  requireFile();
  const lvl = Math.max(0, Math.min(4, parseInt(level, 10) || 0));
  if (analyzed >= lvl) {
    const fns = await r2cmd("aflc");
    return { skipped: true, message: `already analyzed at level ${analyzed} (found ${fns.trim()} functions). Pass a higher level to re-analyze.`, functions: parseInt(fns.trim(), 10) || 0 };
  }
  let cmd;
  if (seconds > 0) cmd = `aa${"a".repeat(lvl)} @@c:`; // not a timeout cmd; fall through
  // rizin analysis: aaa family. Use aac/aa for partial, aaaa for deep.
  cmd = lvl <= 0 ? "aa" : "a" + "a".repeat(Math.min(lvl, 4));
  await r2cmd(cmd, { timeout: Math.max(30000, (seconds || 120) * 1000) });
  analyzed = lvl;
  const fns = await r2cmd("aflc");
  return { analyzed: true, level: lvl, functions: parseInt(fns.trim(), 10) || 0 };
}

async function listFunctions({ regex, only_named, count = false, cursor, limit }) {
  requireFile();
  const data = await r2json("aflj");
  let items = Array.isArray(data) ? data : [];
  if (only_named) items = items.filter((f) => !/\.\d+$/.test(f.name || ""));
  if (regex) {
    const re = new RegExp(String(regex), "i");
    items = items.filter((f) => re.test(f.name || ""));
  }
  if (count) return { count: items.length };
  return pageSlice(items.map((f) => ({ offset: f.offset, name: f.name, size: f.size, ninstrs: f.ninstrs, bbsum: f.bbsum })), { cursor, limit });
}

async function listImports({ regex, cursor, limit }) {
  requireFile();
  const data = await r2json("iij");
  let items = Array.isArray(data) ? data : [];
  if (regex) {
    const re = new RegExp(String(regex), "i");
    items = items.filter((i) => re.test(i.name || ""));
  }
  return pageSlice(items.map((i) => ({ name: i.name, type: i.type, lib: i.lib || undefined, addr: i.vaddr ?? i.paddr ?? i.addr })), { cursor, limit });
}

async function listExports({ regex, cursor, limit }) {
  requireFile();
  const data = await r2json("iEj");
  let items = Array.isArray(data) ? data : [];
  if (regex) {
    const re = new RegExp(String(regex), "i");
    items = items.filter((e) => re.test(e.name || ""));
  }
  return pageSlice(items, { cursor, limit });
}

async function listSymbols({ regex, cursor, limit }) {
  requireFile();
  const data = await r2json("isj");
  let items = Array.isArray(data) ? data : [];
  if (regex) {
    const re = new RegExp(String(regex), "i");
    items = items.filter((s) => re.test(s.name || ""));
  }
  return pageSlice(items.map((s) => ({ name: s.name, addr: s.vaddr, type: s.type, size: s.size, is_import: (s.is_import ?? (s.bind === "GLOBAL" && (s.type || "").includes("IMP"))) || undefined })), { cursor, limit });
}

async function listSections() {
  requireFile();
  return r2json("iSj");
}

async function listLibraries() {
  requireFile();
  return r2json("ilj");
}

async function listEntrypoints() {
  requireFile();
  const eps = await r2json("iej");
  const mainSym = await r2json("is~main"); // best-effort text
  return { entrypoints: eps, main: typeof mainSym === "string" ? mainSym.trim() : mainSym };
}

async function showInfo() {
  requireFile();
  return r2json("ij");
}

async function showFunctionDetails({ address }) {
  requireFile();
  const a = checkAddr(address, "address");
  await r2cmd(`s ${a}`);
  return r2json("afij");
}

async function disassembleFunction({ address, cursor, limit }) {
  requireFile();
  const a = checkAddr(address, "address");
  // pd @ function: use pdf (disassemble function) via af+ pdf
  const text = await r2cmd(`s ${a}; pdf`, { timeout: 60000 });
  const lines = text.split("\n");
  return { ...pageSlice(lines, { cursor, limit }), note: "assembly lines" };
}

async function disassembleAt({ address, count = 20 }) {
  requireFile();
  const a = checkAddr(address, "address");
  const n = clamp(count, 20, 500);
  const text = await r2cmd(`s ${a}; pd ${n}`);
  return truncateText(text);
}

async function hexdump({ address, count = 64 }) {
  requireFile();
  const a = checkAddr(address, "address");
  const n = clamp(count, 64, 4096);
  const text = await r2cmd(`s ${a}; px ${n}`);
  return truncateText(text);
}

async function readMemory({ address, count = 64 }) {
  requireFile();
  const a = checkAddr(address, "address");
  const n = clamp(count, 64, 8192);
  const data = await r2json(`s ${a}; pxj ${n}`);
  return Array.isArray(data) ? { address: a, bytes: data, hex: data.map((b) => b.toString(16).padStart(2, "0")).join("") } : data;
}

async function xrefsTo({ address }) {
  requireFile();
  const a = checkAddr(address, "address");
  return r2json(`s ${a}; axtj`);
}

async function xrefsFrom({ address }) {
  requireFile();
  const a = checkAddr(address, "address");
  // axfj lists refs from a single offset (often empty at function heads).
  // For a whole-function view use the function's callrefs/datarefs from afij.
  const direct = await r2json(`s ${a}; axfj`);
  const finfo = await r2json(`s ${a}; afij`);
  const f = Array.isArray(finfo) ? finfo[0] : null;
  return {
    from_offset: Array.isArray(direct) ? direct : [],
    function_calls: f ? (f.callrefs || []).map((r) => ({ from: r.from, to: r.to, type: r.type })) : [],
    function_data_refs: f ? (f.datarefs || []) : [],
  };
}

async function listStrings({ regex, min_length = 4, cursor, limit, all = false }) {
  requireFile();
  if (!analyzed && !all) {
    // iz needs strings flag computed by analysis; izz scans whole file
    const data = await r2json("izzj");
    let items = Array.isArray(data) ? data : [];
    if (regex) {
      const re = new RegExp(String(regex), "i");
      items = items.filter((s) => re.test(s.string || ""));
    }
    items = items.filter((s) => (s.string || "").length >= min_length);
    return pageSlice(items.map((s) => ({ string: s.string, addr: s.vaddr, length: s.string?.length, section: s.section })), { cursor, limit });
  }
  const data = await r2json(all ? "izzj" : "izj");
  let items = Array.isArray(data) ? data : [];
  if (regex) {
    const re = new RegExp(String(regex), "i");
    items = items.filter((s) => re.test(s.string || ""));
  }
  return pageSlice(items, { cursor, limit });
}

async function searchPatterns({ query, type = "string", encoding, cursor, limit }) {
  requireFile();
  const q = String(query);
  let cmd;
  switch (type) {
    case "hex":
      cmd = `/xj ${q}`;
      break;
    case "value1": case "value2": case "value4": case "value8": {
      const w = type.replace("value", "");
      cmd = `/v${w}j ${checkAddr(q, "value")}`;
      break;
    }
    case "wide":
      cmd = `/zj ${q} l encoding=utf16le`;
      break;
    case "asm":
      cmd = `/aj ${q}`;
      break;
    default:
      cmd = `/zj ${q}`;
  }
  const data = await r2cmd(cmd, { timeout: 120000 });
  let parsed;
  try { parsed = JSON.parse(data); } catch { return { raw: truncateText(data) }; }
  const items = Array.isArray(parsed) ? parsed : [];
  return pageSlice(items, { cursor, limit });
}

async function lookupAddress({ address }) {
  requireFile();
  const a = checkAddr(address, "address");
  return r2json(`s ${a}; fdj`);
}

async function lookupSymbol({ name, cursor, limit }) {
  requireFile();
  const n = String(name);
  const data = await r2json("isj");
  let items = Array.isArray(data) ? data : [];
  const re = new RegExp(n.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i");
  items = items.filter((sym) => re.test(sym.name || "") || re.test(sym.realname || "") || re.test(sym.flagname || ""));
  return pageSlice(items, { cursor, limit });
}

async function lookupExport({ name }) {
  requireFile();
  const n = String(name);
  const text = await r2cmd(`iE~${n}`);
  return truncateText(text, 4000);
}

async function listClasses() {
  requireFile();
  return r2json("icj");
}

async function listMethods({ class_name }) {
  requireFile();
  if (!class_name) throw new Error("class_name required");
  return r2json(`icmj ${JSON.stringify(String(class_name))}`);
}

async function decompileFunction({ address, mode = "pdsf" }) {
  requireFile();
  const a = checkAddr(address, "address");
  // rizin 0.8.2 core has no pdc/pdd/pdg — those are plugins (rz-ghidra etc).
  // pdsf gives a structured pseudo-summary: strings, calls, refs, jumps.
  let cmd;
  if (mode === "pds") cmd = `s ${a}; pds 5000`;
  else if (mode === "pdr") cmd = `s ${a}; pdr`;  // recursive disassembly
  else cmd = `s ${a}; pdsf`;
  const text = await r2cmd(cmd, { timeout: 60000 });
  if (!text.trim()) {
    return { error: "empty decompiler output — is the address inside a function? run analyze and show_function_details first", address: a };
  }
  return truncateText(text);
}

async function listFunctionVars({ address }) {
  requireFile();
  const a = checkAddr(address, "address");
  return r2json(`s ${a}; afvlj`);
}

async function renameFunctionVar({ address, old_name, new_name }) {
  requireFile();
  const a = checkAddr(address, "address");
  if (!old_name || !new_name) throw new Error("old_name and new_name required");
  const o = String(old_name).replace(/[^a-zA-Z0-9_.$-]/g, "");
  const n = String(new_name).replace(/[^a-zA-Z0-9_.$-]/g, "");
  const out = await r2cmd(`s ${a}; afvn ${n} ${o}`);
  if (/cannot find|error/i.test(out)) return { error: out.trim() || `variable ${o} not found in function at ${a}`, address: a };
  return { renamed: n, was: o, address: a };
}

async function setVarType({ address, var_name, type }) {
  requireFile();
  const a = checkAddr(address, "address");
  if (!var_name || !type) throw new Error("var_name and type required");
  const v = String(var_name).replace(/[^a-zA-Z0-9_.$-]/g, "");
  const t = String(type).replace(/[;\n]/g, " ");
  const out = await r2cmd(`s ${a}; afvt ${v} ${t}`);
  if (/cannot find|error/i.test(out)) return { error: out.trim() || `variable ${v} not found in function at ${a}`, address: a };
  return { typed: v, type: t, address: a };
}

async function listRelocations({ regex, cursor, limit }) {
  requireFile();
  const data = await r2json("irj");
  let items = Array.isArray(data) ? data : [];
  if (regex) {
    const re = new RegExp(String(regex), "i");
    items = items.filter((r) => re.test(r.name || ""));
  }
  return pageSlice(items, { cursor, limit });
}

async function listComments({ regex, cursor, limit }) {
  requireFile();
  const data = await r2json("CClj");
  let items = Array.isArray(data) ? data : [];
  if (regex) {
    const re = new RegExp(String(regex), "i");
    items = items.filter((c) => re.test(c.name || ""));
  }
  return pageSlice(items, { cursor, limit });
}

async function printStringAt({ address }) {
  requireFile();
  const a = checkAddr(address, "address");
  const text = await r2cmd(`ps @ ${a}`);
  return { address: a, string: text.trim() };
}

async function readHex({ address, count = 32 }) {
  requireFile();
  const a = checkAddr(address, "address");
  const n = clamp(count, 32, 4096);
  const text = await r2cmd(`p8 ${n} @ ${a}`);
  return { address: a, count: n, hex: text.trim() };
}

async function analysisInfo() {
  requireFile();
  return r2json("aaij");
}

async function renameFunction({ address, new_name }) {
  requireFile();
  const a = checkAddr(address, "address");
  const n = String(new_name).replace(/[^a-zA-Z0-9_.]/g, "_");
  await r2cmd(`s ${a}; afn ${n}`);
  return { renamed: n, address: a };
}

async function renameFlag({ address, new_name }) {
  requireFile();
  const a = checkAddr(address, "address");
  // resolve the flag name at the address, then rename it (fr takes names, not addresses)
  const fd = await r2json(`s ${a}; fdj`);
  const oldName = Array.isArray(fd) ? fd[0]?.name : fd?.name;
  if (!oldName) return { error: `no flag at ${a} — run analyze, or check lookup_address`, address: a };
  const n = String(new_name).replace(/[^a-zA-Z0-9_.]/g, "_");
  await r2cmd(`fr ${oldName} ${n}`);
  return { renamed: n, was: oldName, address: a };
}

async function setComment({ address, comment }) {
  requireFile();
  const a = checkAddr(address, "address");
  // CC <text> @ addr form is rejected by rizin; seek first
  const text = String(comment).replace(/;/g, "\;").replace(/@/g, " ");
  await r2cmd(`s ${a}; CCu ${text}`);
  const check = await r2cmd(`s ${a}; CC.`);
  return { comment: check.trim() || String(comment), address: a };
}

async function setFunctionSignature({ address, signature }) {
  requireFile();
  const a = checkAddr(address, "address");
  const sig = String(signature).replace(/"/g, '\\"');
  await r2cmd(`s ${a}; afs "${sig}"`);
  return { signature, address: a };
}

async function getFunctionSignature({ address }) {
  requireFile();
  const a = checkAddr(address, "address");
  return r2cmd(`s ${a}; afs`).then((t) => t.trim());
}

async function listFunctionCalls({ address }) {
  requireFile();
  const a = checkAddr(address, "address");
  const data = await r2json(`s ${a}; afij`);
  if (!Array.isArray(data) || !data[0]) return data;
  const f = data[0];
  return { calls: (f.callrefs || []).map((r) => ({ from: r.from, to: r.to, type: r.type })), data: f.datarefs, signature: f.signature };
}

async function listGlobals() {
  requireFile();
  return r2json("f~sym.!");
}

async function getSectionsMap() {
  requireFile();
  const data = await r2json("iSj");
  if (!Array.isArray(data)) return data;
  return data.map((s) => ({ name: s.name, vaddr: s.vaddr, vsize: s.vsize, perm: s.perm, type: s.type }));
}

async function seekTo({ address }) {
  requireFile();
  const a = checkAddr(address, "address");
  await r2cmd(`s ${a}`);
  const here = await r2json("sj");
  return here;
}

async function getCurrentAddress() {
  requireFile();
  const text = await r2cmd("s");
  const fnName = await r2cmd("fd $$");
  return { address: text.trim(), function: fnName.trim() };
}

async function closeFile() {
  if (!openPath) return { closed: false, note: "no file open" };
  if (rz) { try { rz.kill(); } catch {} rz = null; }
  const p = openPath;
  openPath = null;
  analyzed = 0;
  return { closed: true, file: p };
}

async function runCommand({ command, cursor, limit }) {
  requireFile();
  const cmd = String(command);
  // safety: block shell escapes and file writes unless explicitly allowed
  if (!process.env.RIZIN_MCP_ALLOW_DANGEROUS) {
    const dangerous = /^\s*(!|!!|w\b|wf\b|wr\b|ws\b|wa\b)/.test(cmd);
    if (dangerous) throw new Error("dangerous command blocked (shell/file-write). Set RIZIN_MCP_ALLOW_DANGEROUS=1 to permit.");
  }
  const text = await r2cmd(cmd, { timeout: 60000 });
  const lines = text.split("\n");
  return { ...pageSlice(lines, { cursor, limit }), note: `rizin: ${cmd}` };
}

async function listFlags({ regex, cursor, limit }) {
  requireFile();
  const data = await r2json("flj");
  let items = Array.isArray(data) ? data : [];
  if (regex) {
    const re = new RegExp(String(regex), "i");
    items = items.filter((f) => re.test(f.name || ""));
  }
  return pageSlice(items, { cursor, limit });
}

async function listHashes() {
  requireFile();
  return r2json("omj");
}

// ---------------------------------------------------------------- MCP schema

const LIST_PROPS = {
  regex: { type: "string", description: "Regular expression to filter results" },
  cursor: { type: "integer", description: "Pagination cursor (start index)" },
  limit: { type: "integer", description: `Max results per page (default ${PAGE_DEFAULT}, max ${PAGE_MAX})` },
};
const listSchema = (extra = {}) => ({ type: "object", properties: { ...LIST_PROPS, ...extra } });
const addrSchema = (desc = "Target address (hex 0x... or decimal)") => ({ type: "object", properties: { address: { type: "string", description: desc }, cursor: { type: "integer" }, limit: { type: "integer" } }, required: ["address"] });

const TOOLS = [
  { name: "open_file", description: "Open a binary in rizin for analysis. Call this first. Optionally set base_address/arch/bits/cpu for raw (headerless) binaries. Runs analysis by default (set run_analyze=false to skip).", inputSchema: { type: "object", properties: { file_path: { type: "string", description: "Absolute path to binary" }, base_address: { type: "string", description: "Base address for PIE/raw binaries (e.g. 0x400000)" }, arch: { type: "string", description: "Architecture override (arm, x86, mips...)" }, bits: { type: "integer", description: "Bits override (16/32/64)" }, cpu: { type: "string", description: "CPU variant (cortex, generic...)" }, run_analyze: { type: "boolean", default: true }, analysis_level: { type: "integer", minimum: 0, maximum: 4, default: 2 } }, required: ["file_path"] } },
  { name: "close_file", description: "Close the currently open file.", inputSchema: { type: "object", properties: {} } },
  { name: "analyze", description: "Run rizin analysis (aa..aaaa). Higher level = more thorough. Skips if already analyzed at that level.", inputSchema: { type: "object", properties: { level: { type: "integer", minimum: 0, maximum: 4, default: 2 } } } },
  { name: "show_info", description: "Binary metadata: format, arch, bits, endian, libraries, checksums (rizin ij).", inputSchema: { type: "object", properties: {} } },
  { name: "list_functions", description: "All functions found by analysis (afl). Filter by regex, paginate. Set only_named to skip auto-numbered stubs.", inputSchema: listSchema({ only_named: { type: "boolean", description: "Skip functions like sym.func.1000016c8" }, count: { type: "boolean", description: "Return only the count" } }) },
  { name: "list_imports", description: "Imported symbols (ii) — functions/data the binary pulls from libraries. Filter by regex.", inputSchema: listSchema() },
  { name: "list_exports", description: "Exported symbols (iE) — the binary's public interface. Filter by regex.", inputSchema: listSchema() },
  { name: "list_symbols", description: "All symbols with addresses (is): functions, data, imports. Filter by regex.", inputSchema: listSchema() },
  { name: "list_sections", description: "Memory sections and segments with permissions (iS).", inputSchema: { type: "object", properties: {} } },
  { name: "list_libraries", description: "Linked shared libraries (il).", inputSchema: { type: "object", properties: {} } },
  { name: "list_entrypoints", description: "Program entrypoints and constructors (ie) + main symbol.", inputSchema: { type: "object", properties: {} } },
  { name: "list_strings", description: "Strings from data sections (iz); set all=true for whole-binary scan (izz). Filter by regex, min_length.", inputSchema: listSchema({ min_length: { type: "integer", default: 4 }, all: { type: "boolean", description: "Scan whole file, not just data sections" } }) },
  { name: "list_flags", description: "Named flags/labels (f) — rizin's symbol namespace. Filter by regex.", inputSchema: listSchema() },
  { name: "list_classes", description: "Class names for OO languages (ic): C++, ObjC, Swift, Java/Dalvik.", inputSchema: { type: "object", properties: {} } },
  { name: "list_methods", description: "Methods of a specific class.", inputSchema: { type: "object", properties: { class_name: { type: "string" } }, required: ["class_name"] } },
  { name: "list_function_calls", description: "Calls made by the function at address (afc) — callee list.", inputSchema: addrSchema("Function address") },
  { name: "list_function_vars", description: "Arguments and local variables of the function at address (afvl): names, types, stack offsets.", inputSchema: addrSchema("Function address") },
  { name: "rename_function_var", description: "Rename an argument/local variable in the function (afvn).", inputSchema: { type: "object", properties: { address: { type: "string", description: "Function address" }, old_name: { type: "string", description: "Current var name, e.g. var_90h" }, new_name: { type: "string" } }, required: ["address", "old_name", "new_name"] } },
  { name: "set_var_type", description: "Change the type of an argument/local variable (afvt), e.g. 'int*', 'char[64]'.", inputSchema: { type: "object", properties: { address: { type: "string", description: "Function address" }, var_name: { type: "string" }, type: { type: "string", description: "C type, e.g. int* or char[8]" } }, required: ["address", "var_name", "type"] } },
  { name: "list_relocations", description: "Relocation table (ir): offsets, types, targets. Filter by regex. Paginated.", inputSchema: listSchema() },
  { name: "list_comments", description: "All comments in the binary (CCl). Filter by regex. Paginated.", inputSchema: listSchema() },
  { name: "print_string_at", description: "Read the NUL-terminated string at an address (ps).", inputSchema: { type: "object", properties: { address: { type: "string" } }, required: ["address"] } },
  { name: "read_hex", description: "Compact hex bytes at address (p8) — no ASCII column, just pairs.", inputSchema: { type: "object", properties: { address: { type: "string" }, count: { type: "integer", default: 32, maximum: 4096 } }, required: ["address"] } },
  { name: "analysis_info", description: "Analysis summary (aai): function count, code coverage, xref counts.", inputSchema: { type: "object", properties: {} } },
  { name: "show_function_details", description: "Detailed info for the function at address (afi): size, basic blocks, stack frame, vars.", inputSchema: addrSchema() },
  { name: "disassemble_function", description: "Full assembly listing of the function at address (pdf). Paginated.", inputSchema: addrSchema() },
  { name: "disassemble_at", description: "Disassemble N instructions starting at address (pd N).", inputSchema: { type: "object", properties: { address: { type: "string" }, count: { type: "integer", default: 20, maximum: 500 } }, required: ["address"] } },
  { name: "hexdump", description: "Hexdump at address (px). Readable form with ASCII column.", inputSchema: { type: "object", properties: { address: { type: "string" }, count: { type: "integer", default: 64, maximum: 4096 } }, required: ["address"] } },
  { name: "read_memory", description: "Read raw bytes at address as JSON array (pxj).", inputSchema: { type: "object", properties: { address: { type: "string" }, count: { type: "integer", default: 64, maximum: 8192 } }, required: ["address"] } },
  { name: "xrefs_to", description: "Find all code references TO the address (axt) — who calls/reads it.", inputSchema: addrSchema() },
  { name: "xrefs_from", description: "References FROM an address: direct refs (axf) plus the function call and data refs (afij).", inputSchema: addrSchema() },
  { name: "search", description: "Search memory/file for patterns: string, hex, wide, or numeric value. JSON results.", inputSchema: { type: "object", properties: { query: { type: "string", description: "What to search for" }, type: { type: "string", enum: ["string", "hex", "wide", "value"], default: "string" }, ...LIST_PROPS }, required: ["query"] } },
  { name: "lookup_address", description: "What is at this address: flag, symbol, section (fd).", inputSchema: addrSchema() },
  { name: "lookup_symbol", description: "Find symbol by name — returns address and metadata.", inputSchema: { type: "object", properties: { name: { type: "string" } }, required: ["name"] } },
  { name: "lookup_export", description: "Resolve an exported name to its address.", inputSchema: { type: "object", properties: { name: { type: "string" } }, required: ["name"] } },
  { name: "decompile_function", description: "Function decompilation/pseudo-code. rizin core offers pdsf (structured summary: strings, calls, refs), pds (block summary), or pdr (recursive disassembly). For full C output install rz-ghidra (pdg).", inputSchema: { type: "object", properties: { address: { type: "string" }, mode: { type: "string", enum: ["pdsf", "pds", "pdr"], default: "pdsf" } }, required: ["address"] } },
  { name: "rename_function", description: "Rename the function at address.", inputSchema: { type: "object", properties: { address: { type: "string" }, new_name: { type: "string" } }, required: ["address", "new_name"] } },
  { name: "rename_flag", description: "Rename a flag/variable/data reference at address.", inputSchema: { type: "object", properties: { address: { type: "string" }, new_name: { type: "string" } }, required: ["address", "new_name"] } },
  { name: "set_comment", description: "Add a comment at the address (shows in disassembly).", inputSchema: { type: "object", properties: { address: { type: "string" }, comment: { type: "string" } }, required: ["address", "comment"] } },
  { name: "get_function_signature", description: "Current signature of the function at address.", inputSchema: addrSchema() },
  { name: "set_function_signature", description: "Set function signature: return type, name, args (afs).", inputSchema: { type: "object", properties: { address: { type: "string" }, signature: { type: "string", description: 'e.g. "int main(int argc, char **argv)"' } }, required: ["address", "signature"] } },
  { name: "seek_to", description: "Move the rizin cursor to the address.", inputSchema: addrSchema() },
  { name: "get_current_address", description: "Current cursor position and function name.", inputSchema: { type: "object", properties: {} } },
  { name: "run_command", description: "Execute any raw rizin command (escape hatch). Dangerous commands (shell, file writes) blocked unless RIZIN_MCP_ALLOW_DANGEROUS=1. Paginated.", inputSchema: { type: "object", properties: { command: { type: "string", description: "rizin command, e.g. 'afl', 'pdf @ sym.main', 'izz~password'" }, ...LIST_PROPS }, required: ["command"] } },
];

const HANDLERS = {
  open_file: openFile,
  close_file: closeFile,
  analyze,
  show_info: showInfo,
  list_functions: listFunctions,
  list_imports: listImports,
  list_exports: listExports,
  list_symbols: listSymbols,
  list_sections: listSections,
  list_libraries: listLibraries,
  list_entrypoints: listEntrypoints,
  list_strings: listStrings,
  list_flags: listFlags,
  list_classes: listClasses,
  list_methods: listMethods,
  list_function_calls: listFunctionCalls,
  list_function_vars: listFunctionVars,
  rename_function_var: renameFunctionVar,
  set_var_type: setVarType,
  list_relocations: listRelocations,
  list_comments: listComments,
  print_string_at: printStringAt,
  read_hex: readHex,
  analysis_info: analysisInfo,
  show_function_details: showFunctionDetails,
  disassemble_function: disassembleFunction,
  disassemble_at: disassembleAt,
  hexdump,
  read_memory: readMemory,
  xrefs_to: xrefsTo,
  xrefs_from: xrefsFrom,
  search: searchPatterns,
  lookup_address: lookupAddress,
  lookup_symbol: lookupSymbol,
  lookup_export: lookupExport,
  decompile_function: decompileFunction,
  rename_function: renameFunction,
  rename_flag: renameFlag,
  set_comment: setComment,
  get_function_signature: getFunctionSignature,
  set_function_signature: setFunctionSignature,
  seek_to: seekTo,
  get_current_address: getCurrentAddress,
  run_command: runCommand,
};

// ---------------------------------------------------------------- MCP stdio

const readline = (await import("node:readline")).createInterface({ input: process.stdin });
const write = (msg) => process.stdout.write(JSON.stringify(msg) + "\n");

readline.on("line", async (line) => {
  let req;
  try { req = JSON.parse(line); } catch { return; }
  const { id, method, params } = req;
  if (method === "initialize") {
    write({ jsonrpc: "2.0", id, result: { protocolVersion: "2024-11-05", capabilities: { tools: {} }, serverInfo: { name: "rizin-mcp", version: "1.1.0" } } });
    return;
  }
  if (method === "notifications/initialized" || method === "initialized") return;
  if (method === "ping") { write({ jsonrpc: "2.0", id, result: {} }); return; }
  if (method === "tools/list") {
    write({ jsonrpc: "2.0", id, result: { tools: TOOLS } });
    return;
  }
  if (method === "tools/call") {
    const name = params?.name;
    const args = params?.arguments || {};
    const handler = HANDLERS[name];
    if (!handler) {
      write({ jsonrpc: "2.0", id, error: { code: -32602, message: `unknown tool: ${name}` } });
      return;
    }
    try {
      const result = await handler(args);
      write({ jsonrpc: "2.0", id, result: { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] } });
    } catch (e) {
      write({ jsonrpc: "2.0", id, result: { content: [{ type: "text", text: JSON.stringify({ error: String(e.message) }) }], isError: true } });
    }
    return;
  }
  if (id !== undefined) {
    write({ jsonrpc: "2.0", id, error: { code: -32601, message: `method not found: ${method}` } });
  }
});

// cleanup on exit
process.on("exit", () => { if (rz) { try { rz.kill(); } catch {} } });
process.stderr.write(`[rizin-mcp] ready on stdio — ${TOOLS.length} tools, rizin binary: ${RIZIN}, file: ${openPath || "(none)"}\n`);
