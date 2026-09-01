// rizin-mcp self-check: node test.mjs [/bin/ls]
// Spawns the server, drives MCP over stdio, verifies the core workflow.
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const server = join(dirname(fileURLToPath(import.meta.url)), "server.mjs");
const target = process.argv[2] || "/bin/ls";
const p = spawn("node", [server], { stdio: ["pipe", "pipe", "ignore"] });
let buf = "";
p.stdout.on("data", (d) => (buf += d));
const send = (o) => p.stdin.write(JSON.stringify(o) + "\n");
const wait = (id, to = 120000) => new Promise((res, rej) => {
  const t = setTimeout(() => rej(new Error(`timeout ${id}; tail=${buf.slice(-120)}`)), to);
  const c = () => { for (const l of buf.split("\n").filter(Boolean)) { try { const m = JSON.parse(l); if (m.id === id) { clearTimeout(t); res(m); return; } } catch {} } setTimeout(c, 200); };
  c();
});
let pass = 0, fail = 0;
const test = async (id, label, name, args, check) => {
  send({ jsonrpc: "2.0", id, method: "tools/call", params: { name, arguments: args } });
  try {
    const r = await wait(id);
    if (r.error) { console.log("✗", label, "→", JSON.stringify(r.error).slice(0, 90)); fail++; return null; }
    const d = JSON.parse(r.result.content[0].text);
    if (d?.error) { console.log("✗", label, "→", String(d.error).slice(0, 90)); fail++; return null; }
    if (check && check(d) === false) { console.log("✗", label, "→", JSON.stringify(d).slice(0, 110)); fail++; return null; }
    console.log("✓", label); pass++; return d;
  } catch (e) { console.log("✗", label, "→", e.message.slice(0, 120)); fail++; return null; }
};

send({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} });
const init = await wait(1);
console.log(`rizin-mcp v${init.result.serverInfo.version} — ${init.result.serverInfo.name}`);
send({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} });
const tl = await wait(2);
console.log(`tools: ${tl.result.tools.length}`); pass++;

const opened = await test(10, "open_file", "open_file", { file_path: target }, (d) => !!d?.info?.bin?.arch);
const arch = opened?.info?.bin?.arch;
await test(11, "show_info", "show_info", {}, (d) => d?.bin?.arch === arch);
const fns = await test(12, "list_functions", "list_functions", { limit: 3 }, (d) => d?.total > 0);
await test(13, "list_imports", "list_imports", { limit: 3 }, (d) => d?.total >= 0);
await test(14, "list_symbols", "list_symbols", { limit: 3 }, (d) => d?.total >= 0);
await test(15, "list_sections", "list_sections", {}, (d) => Array.isArray(d) && d.length > 0);
await test(16, "list_strings", "list_strings", { limit: 3 }, (d) => d?.total >= 0);
const fname = fns?.items?.[0]?.name;
if (fname) {
  await test(17, `disassemble_function by name (${fname})`, "disassemble_function", { address: fname, limit: 3 }, (d) => d?.items?.length > 0);
  await test(18, "list_function_vars by name", "list_function_vars", { address: fname }, () => true);
  await test(19, "xrefs_to by name", "xrefs_to", { address: fname }, (d) => Array.isArray(d) || d === null || !d?.error);
  await test(20, "function_graph by name", "function_graph", { address: fname }, (d) => d?.blocks > 0 || d?.nodes?.length > 0);
}
await test(21, "hexdump at 0", "hexdump", { address: "0x0", count: 32 }, (d) => typeof d === "string");
await test(22, "read_hex at 0", "read_hex", { address: "0x0", count: 8 }, (d) => /^[0-9a-f]+$/.test(d?.hex || ""));
await test(23, "search hex", "search", { query: "454c46", type: "hex" }, (d) => d?.total >= 0);
await test(24, "rename_function", "rename_function", { address: fname || "0x0", new_name: "mcp_selfcheck" }, (d) => d?.renamed === "mcp_selfcheck");
await test(25, "set_comment", "set_comment", { address: fname || "0x0", comment: "selfcheck" }, (d) => !!d?.comment);
await test(26, "analyze skip", "analyze", { level: opened?.analysis?.level ?? 2 }, (d) => d?.skipped === true);
// expected to fail: injection rejected before reaching rizin
await (async () => {
  send({ jsonrpc: "2.0", id: 28, method: "tools/call", params: { name: "hexdump", arguments: { address: "x; rm -rf" } } });
  const r = await wait(28);
  const d = JSON.parse(r.result.content[0].text);
  if (d?.error && /forbidden/.test(d.error)) { console.log("✓ injection rejected"); pass++; }
  else { console.log("✗ injection NOT rejected:", JSON.stringify(d).slice(0, 80)); fail++; }
})();
const inj = await (async () => { send({ jsonrpc: "2.0", id: 29, method: "tools/call", params: { name: "run_command", arguments: { command: "!rm -rf /" } } }); const r = await wait(29); return JSON.parse(r.result.content[0].text); })();
if (inj?.error) { console.log("✓ dangerous blocked"); pass++; } else { console.log("✗ DANGEROUS NOT BLOCKED"); fail++; }

console.log("---");
console.log(`RESULT: ${pass} passed, ${fail} failed`);
p.kill();
process.exit(fail ? 1 : 0);
