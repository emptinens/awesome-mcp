#!/usr/bin/env node
/**
 * design-inspo-mcp — MCP server for web design inspiration references.
 *
 * Sources:
 *  - refframe.com    — sitemap + item pages (og: metadata)
 *  - posts.design    — sitemap + post pages (title + og: image)
 *  - collectui.com   — JS-rendered; category lists via obscura fetch
 *  - recent.design   — sitemap + item pages (og: metadata)
 *  - fontshare.com   — public JSON API (api.fontshare.com/v2) + CSS endpoint
 *  - tailwindcss.com — /docs pages, class reference
 *  - colorhunt.co    — JS-rendered palettes via obscura fetch (title carries hex codes)
 *
 * Transport: stdio (MCP JSON-RPC 2.0).
 * Node >= 18 (global fetch). No dependencies.
 *
 * Tools:
 *  list_refframe        — latest refframe shots
 *  list_recent_design   — latest recent.design items
 *  list_posts_design    — latest posts.design posts
 *  search_fonts         — fontshare font search by name/category
 *  get_font_css         — ready-to-use @font-face CSS for a font slug
 *  tailwind_docs        — fetch a tailwind docs page as markdown
 *  tailwind_classes     — list tailwind utility docs pages by prefix
 *  list_colorhunt       — colorhunt palettes (obscura-rendered)
 *  collectui_category   — collectui designs for a category (obscura-rendered)
 *  get_design_item      — full metadata (title/description/image) for any design URL
 *  design_ref_search    — cross-site: one query → all gallery sources
 */

import { spawn } from "node:child_process";

const UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";

// ---------------------------------------------------------------- utilities

async function httpGet(url, { timeout = 15000, accept = "text/html" } = {}) {
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), timeout);
  try {
    const res = await fetch(url, {
      headers: { "User-Agent": UA, Accept: accept },
      signal: ac.signal,
    });
    return { ok: res.ok, status: res.status, body: await res.text() };
  } catch (e) {
    return { ok: false, status: 0, body: String(e.message || e) };
  } finally {
    clearTimeout(t);
  }
}

async function httpGetJson(url, { timeout = 15000 } = {}) {
  const r = await httpGet(url, { timeout, accept: "application/json" });
  if (!r.ok) throw new Error(`HTTP ${r.status} from ${url}`);
  try {
    return JSON.parse(r.body);
  } catch {
    throw new Error(`invalid JSON from ${url}`);
  }
}

/** Render a JS-heavy page through the installed obscura headless browser. */
async function obscuraFetch(url, { dump = "text", timeout = 30000 } = {}) {
  return new Promise((resolve) => {
    const p = spawn("obscura", ["fetch", "--dump", dump, url], { stdio: ["ignore", "pipe", "ignore"] });
    let out = "";
    const t = setTimeout(() => p.kill("SIGKILL"), timeout);
    p.stdout.on("data", (d) => (out += d));
    p.on("close", () => { clearTimeout(t); resolve(out); });
    p.on("error", () => { clearTimeout(t); resolve(""); });
  });
}

function meta(html, prop) {
  // og: tags come in either order of attr name/value
  const patterns = [
    new RegExp(`<meta[^>]*property=["']${prop}["'][^>]*content=["']([^"']*)["']`, "i"),
    new RegExp(`<meta[^>]*content=["']([^"']*)["'][^>]*property=["']${prop}["']`, "i"),
    new RegExp(`<meta[^>]*name=["']${prop}["'][^>]*content=["']([^"']*)["']`, "i"),
  ];
  for (const re of patterns) {
    const m = re.exec(html);
    if (m) return decodeEntities(m[1]);
  }
  return null;
}

function titleOf(html) {
  const m = /<title[^>]*>([\s\S]*?)<\/title>/i.exec(html);
  return m ? decodeEntities(m[1].trim()) : null;
}

function decodeEntities(s) {
  return s
    .replace(/&amp;/g, "&")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&#x27;/g, "'")
    .replace(/&nbsp;/g, " ");
}

function sitemapUrls(xml, { limit = 50, include = null, exclude = null } = {}) {
  const urls = [];
  const re = /<loc>([^<]+)<\/loc>/g;
  let m;
  while ((m = re.exec(xml)) !== null) {
    const u = m[1];
    if (exclude && exclude.test(u)) continue;
    if (include && !include.test(u)) continue;
    urls.push(u);
    if (urls.length >= limit * 3) break; // over-fetch, slice later
  }
  return urls;
}

/** Fetch og-metadata for up to `limit` item URLs concurrently. */
async function fetchItemsMeta(urls, { limit = 10, concurrency = 5 } = {}) {
  const results = [];
  const queue = urls.slice(0, limit);
  const workers = Array.from({ length: concurrency }, async () => {
    while (queue.length) {
      const u = queue.shift();
      const r = await httpGet(u);
      if (!r.ok) continue;
      results.push({
        url: u,
        title: titleOf(r.body) || meta(r.body, "og:title") || u,
        description: meta(r.body, "og:description"),
        image: meta(r.body, "og:image"),
      });
    }
  });
  await Promise.all(workers);
  return results;
}

// ---------------------------------------------------------------- sources

// --- refframe.com ---------------------------------------------------------
async function listRefframe({ limit = 10, tags = "" }) {
  // SSR homepage carries ~36 shot links (/reference/<slug>); item pages have og: meta.
  const url = tags ? `https://refframe.com/?tags=${encodeURIComponent(tags)}` : "https://refframe.com/";
  const r = await httpGet(url);
  if (!r.ok) throw new Error(`refframe HTTP ${r.status}`);
  let slugs = [...new Set((r.body.match(/\/reference\/[a-z0-9-]{5,}/g) || []))];
  if (!slugs.length && tags) {
    // tag pages are JS-rendered: fall back to obscura links dump
    const md = await obscuraFetch(url, { dump: "links", timeout: 45000 });
    slugs = [...new Set((md.match(/\/reference\/[a-z0-9-]{5,}/g) || []))];
  }
  const urls = slugs.slice(0, limit).map((sl) => `https://refframe.com${sl}`);
  if (!urls.length) return [{ url: "https://refframe.com/", title: "refframe.com", note: "no shots extracted" }];
  return fetchItemsMeta(urls, { limit });
}

// --- recent.design ---------------------------------------------------------
async function listRecentDesign({ limit = 10 }) {
  const r = await httpGet("https://recent.design/sitemap.xml", { accept: "application/xml" });
  if (!r.ok) throw new Error(`recent.design sitemap HTTP ${r.status}`);
  const urls = sitemapUrls(r.body, { limit, include: /\/i\// });
  return fetchItemsMeta(urls.slice(0, limit * 2), { limit });
}

// --- posts.design -----------------------------------------------------------
async function listPostsDesign({ limit = 10 }) {
  const r = await httpGet("https://posts.design/sitemap.xml", { accept: "application/xml" });
  if (!r.ok) throw new Error(`posts.design sitemap HTTP ${r.status}`);
  const urls = sitemapUrls(r.body, {
    limit: limit * 2,
    include: /posts\.design\/[a-z0-9-]{6,}/,
    exclude: /(\/about|\/stats|\/brand|\/trends|\/issues|\/launches|\/favorites)$/,
  });
  return fetchItemsMeta(urls, { limit });
}

// --- fontshare --------------------------------------------------------------
async function searchFonts({ query = "", limit = 10 } = {}) {
  const q = query.trim().toLowerCase();
  // API supports ?limit= up to 100 per page; pull a larger set and filter client-side
  const data = await httpGetJson(`https://api.fontshare.com/v2/fonts?limit=100`);
  let fonts = data.fonts || [];
  if (q) {
    fonts = fonts.filter(
      (f) =>
        f.slug?.toLowerCase().includes(q) ||
        f.name?.toLowerCase().includes(q) ||
        f.category?.toLowerCase().includes(q)
    );
  }
  return fonts.slice(0, limit).map((f) => ({
    slug: f.slug,
    name: f.name,
    category: f.category,
    designers: (f.designers || []).map((d) => d.name).filter(Boolean).join(", ") || null,
    weights: (f.weights || []).map((w) => w.weight),
    styles: (f.styles || []).map((s) => s.style ?? s),
    url: `https://fontshare.com/font/${f.slug}`,
  }));
}

async function getFontCss({ slugs, weights = "400,700", display = "swap" }) {
  const list = Array.isArray(slugs) ? slugs : String(slugs).split(",").map((s) => s.trim()).filter(Boolean);
  if (!list.length) throw new Error("provide at least one font slug");
  const f = list.map((s) => `f[]=${s}@${weights}`).join("&");
  const r = await httpGet(`https://api.fontshare.com/v2/css?${f}&display=${display}`, { accept: "*/*" });
  if (!r.ok) throw new Error(`fontshare css HTTP ${r.status}`);
  return { css: r.body, htmlSnippet: `<link href="https://api.fontshare.com/v2/css?${f}&display=${display}" rel="stylesheet">` };
}

// --- tailwindcss -------------------------------------------------------------
async function tailwindDocs({ page = "installation" }) {
  let slug = String(page).replace(/^\/?docs\/?/, "").replace(/[^a-z0-9-]/gi, "").toLowerCase();
  if (!slug) slug = "installation";
  // verify against the live docs index; fuzzy-resolve on miss
  const idx = await httpGet("https://tailwindcss.com/docs");
  const known = [...new Set((idx.ok ? idx.body : "").match(/href="\/docs\/([a-z0-9-]+)"/g) || [])].map((h) => h.replace(/href="\/docs\/|"/g, ""));
  if (known.length && !known.includes(slug)) {
    const prefix = slug.slice(0, 4);
    const close = known.filter((k) => k.startsWith(prefix) || k.includes(slug));
    if (close.length) {
      slug = close[0];
    } else {
      throw new Error(`/docs/${slug} not found. Use tailwind_classes to list available pages.`);
    }
  }
  const r = await httpGet(`https://tailwindcss.com/docs/${slug}`);
  if (!r.ok) throw new Error(`tailwind docs HTTP ${r.status} for /docs/${slug}`);
  const resolved = String(page).toLowerCase() !== slug ? `resolved '${page}' -> '${slug}'` : undefined;
  return { url: `https://tailwindcss.com/docs/${slug}`, title: titleOf(r.body), description: meta(r.body, "og:description"), note: resolved };
}

async function tailwindClasses({ prefix = "" }) {
  const r = await httpGet("https://tailwindcss.com/docs");
  if (!r.ok) throw new Error(`tailwind docs index HTTP ${r.status}`);
  const hrefs = [...new Set((r.body.match(/href="\/docs\/[a-z0-9-]+"/g) || []).map((h) => h.replace(/href="\/docs\/|"/g, "")))];
  const p = String(prefix).toLowerCase().replace(/^-/, "");
  const filtered = p ? hrefs.filter((h) => h.startsWith(p)) : hrefs;
  return { total: hrefs.length, matched: filtered.length, classes: filtered.slice(0, 100) };
}

// --- colorhunt (JS-rendered; obscura) ----------------------------------------
async function listColorhunt({ limit = 10, sort = "new", tags = "" }) {
  // Native endpoint: POST /php/feed.php with step/sort/tags/timeframe.
  // Response: [{"code":"24hexchars","likes":"123","date":"2 days"}, ...]
  const body = new URLSearchParams({ step: "0", sort: sort === "popular" ? "new" : sort, tags: String(tags || ""), timeframe: "" });
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), 15000);
  let json;
  try {
    const res = await fetch("https://colorhunt.co/php/feed.php", {
      method: "POST",
      headers: { "User-Agent": UA, "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
      signal: ac.signal,
    });
    json = JSON.parse(await res.text());
  } finally {
    clearTimeout(t);
  }
  return (json || []).slice(0, limit).map((p) => {
    const codes = (p.code.match(/.{6}/g) || []).map((c) => `#${c.toUpperCase()}`);
    return {
      colors: codes,
      likes: p.likes,
      date: p.date,
      url: `https://colorhunt.co/palette/${p.code}`,
    };
  });
}

// --- collectui (JS-rendered; obscura) ----------------------------------------
async function collectuiCategory({ category = "sign-up", limit = 10 }) {
  const cat = String(category).toLowerCase().replace(/[^a-z0-9-]/g, "");
  if (!cat) throw new Error("category required");
  const url = `https://collectui.com/designs/${cat}`;
  // collectui is a JS shell; render via obscura and pull design links from the DOM.
  const md = await obscuraFetch(url, { dump: "links", timeout: 45000 });
  let items = [...new Set((md.match(new RegExp(`designs/${cat}/[a-zA-Z0-9-]+`, "g")) || []))];
  if (!items.length) {
    // fallback: scrape --eval (full render)
    const out = await new Promise((resolve) => {
      const p = spawn("obscura", ["scrape", url, "--eval",
        `JSON.stringify([...document.querySelectorAll('a[href*="designs/${cat}"]')].map(a=>a.getAttribute('href')).slice(0,${limit * 2}))`,
        "--timeout", "50"], { stdio: ["ignore", "pipe", "ignore"] });
      let o = "";
      const t = setTimeout(() => p.kill("SIGKILL"), 60000);
      p.stdout.on("data", (d) => (o += d));
      p.on("close", () => { clearTimeout(t); try { resolve(JSON.parse(JSON.parse(o).results[0].eval || "[]")); } catch { resolve([]); } });
      p.on("error", () => { clearTimeout(t); resolve([]); });
    });
    items = (Array.isArray(out) ? out : []).map((h) => String(h));
  }
  const urls = items.slice(0, limit).map((h) => (h.startsWith("http") ? h : `https://collectui.com/${h.replace(/^\//, "")}`));
  if (!urls.length) {
    return [{ url, title: `collectui — ${cat}`, note: "JS-gated; no items extracted. Visit manually or check the category slug." }];
  }
  return fetchItemsMeta(urls, { limit });
}

// --- generic item metadata ----------------------------------------------------
async function getDesignItem({ url }) {
  const u = String(url);
  if (!/^https?:\/\//i.test(u)) throw new Error("provide full URL");
  const r = await httpGet(u);
  if (!r.ok) throw new Error(`HTTP ${r.status} from ${u}`);
  return {
    url: u,
    title: titleOf(r.body),
    description: meta(r.body, "og:description") || meta(r.body, "description"),
    image: meta(r.body, "og:image"),
    siteName: meta(r.body, "og:site_name"),
  };
}

// --- cross-site search ---------------------------------------------------------
async function designRefSearch({ query = "", limit = 5 } = {}) {
  const q = String(query).trim();
  const results = { query: q, sources: {} };

  // fontshare search (has real search semantics)
  try {
    results.sources.fontshare = (await searchFonts({ query: q, limit })).map((f) => ({
      title: f.name, category: f.category, url: f.url, slug: f.slug,
    }));
  } catch (e) { results.sources.fontshare = { error: String(e.message) }; }

  // tailwind docs prefix match
  try {
    const tw = await tailwindClasses({ prefix: q.toLowerCase().split(/\s+/)[0] || "" });
    results.sources.tailwind = tw.matched ? tw.classes.slice(0, limit).map((c) => ({ page: c, url: `https://tailwindcss.com/docs/${c}` })) : [];
  } catch (e) { results.sources.tailwind = { error: String(e.message) }; }

  // gallery items: filter latest lists by query substring
  const matchTitle = (items) => (q ? items.filter((i) => (i.title || "").toLowerCase().includes(q.toLowerCase())) : items).slice(0, limit);
  try { results.sources.recent_design = matchTitle(await listRecentDesign({ limit: 25 })); } catch (e) { results.sources.recent_design = { error: String(e.message) }; }
  try { results.sources.posts_design = matchTitle(await listPostsDesign({ limit: 25 })); } catch (e) { results.sources.posts_design = { error: String(e.message) }; }
  try { results.sources.refframe = matchTitle(await listRefframe({ limit: 15 })); } catch (e) { results.sources.refframe = { error: String(e.message) }; }

  return results;
}

// ---------------------------------------------------------------- MCP plumbing

const TOOLS = [
  {
    name: "list_refframe",
    description: "Design reference shots from refframe.com. Optional tags filter (button, card, hero, accordion, pricing, dark, 3d, grid, timeline, faq, portfolio, etc). Each item: url, title, description, image.",
    inputSchema: { type: "object", properties: { limit: { type: "integer", minimum: 1, maximum: 30, default: 10 }, tags: { type: "string", default: "" } }, required: [] },
  },
  {
    name: "list_recent_design",
    description: "Latest items from recent.design (daily curated design work). Each item: url, title, description, image.",
    inputSchema: { type: "object", properties: { limit: { type: "integer", minimum: 1, maximum: 30, default: 10 } }, required: [] },
  },
  {
    name: "list_posts_design",
    description: "Latest posts from posts.design (design posts and showcases). Each item: url, title, description, image.",
    inputSchema: { type: "object", properties: { limit: { type: "integer", minimum: 1, maximum: 30, default: 10 } }, required: [] },
  },
  {
    name: "search_fonts",
    description: "Search Fontshare fonts by name, slug, or category (Sans, Serif, Display, Handwriting...). Returns slug, name, category, weights, styles, url.",
    inputSchema: { type: "object", properties: { query: { type: "string" }, limit: { type: "integer", minimum: 1, maximum: 50, default: 10 } }, required: ["query"] },
  },
  {
    name: "get_font_css",
    description: "Get ready-to-use @font-face CSS + <link> snippet for Fontshare fonts. Pass slugs (string or array), optional weights (default '400,700').",
    inputSchema: { type: "object", properties: { slugs: { type: ["string", "array"], items: { type: "string" } }, weights: { type: "string", default: "400,700" }, display: { type: "string", enum: ["swap", "auto", "block", "fallback"], default: "swap" } }, required: ["slugs"] },
  },
  {
    name: "tailwind_docs",
    description: "Fetch a Tailwind CSS docs page (title + description + URL). Use page slug like 'flexbox', 'animation', 'background-clip'.",
    inputSchema: { type: "object", properties: { page: { type: "string", default: "installation" } }, required: [] },
  },
  {
    name: "tailwind_classes",
    description: "List Tailwind utility docs pages, optionally filtered by prefix (e.g. 'bg', 'text', 'flex'). Returns matching doc slugs.",
    inputSchema: { type: "object", properties: { prefix: { type: "string", default: "" } }, required: [] },
  },
  {
    name: "list_colorhunt",
    description: "Color palettes from colorhunt.co (4 hex colors per palette). sort: 'new', 'popular', or 'random'. Uses obscura headless browser for JS rendering.",
    inputSchema: { type: "object", properties: { limit: { type: "integer", minimum: 1, maximum: 30, default: 10 }, sort: { type: "string", enum: ["new", "popular", "random"], default: "new" } }, required: [] },
  },
  {
    name: "collectui_category",
    description: "CollectUI designs for a category (e.g. 'sign-up', 'login', 'checkouts', 'forms'). JS-rendered via obscura; each item has image + link.",
    inputSchema: { type: "object", properties: { category: { type: "string", default: "sign-up" }, limit: { type: "integer", minimum: 1, maximum: 20, default: 10 } }, required: ["category"] },
  },
  {
    name: "get_design_item",
    description: "Fetch full og-metadata (title, description, image, site name) for any design item URL.",
    inputSchema: { type: "object", properties: { url: { type: "string" } }, required: ["url"] },
  },
  {
    name: "design_ref_search",
    description: "Cross-site design reference search: one query hits fontshare, tailwind docs, recent.design, posts.design, and refframe simultaneously. Best entry point when building UI and looking for references.",
    inputSchema: { type: "object", properties: { query: { type: "string" }, limit: { type: "integer", minimum: 1, maximum: 10, default: 5 } }, required: ["query"] },
  },
];

const HANDLERS = {
  list_refframe: (a) => listRefframe(a),
  list_recent_design: (a) => listRecentDesign(a),
  list_posts_design: (a) => listPostsDesign(a),
  search_fonts: (a) => searchFonts(a),
  get_font_css: (a) => getFontCss(a),
  tailwind_docs: (a) => tailwindDocs(a),
  tailwind_classes: (a) => tailwindClasses(a),
  list_colorhunt: (a) => listColorhunt(a),
  collectui_category: (a) => collectuiCategory(a),
  get_design_item: (a) => getDesignItem(a),
  design_ref_search: (a) => designRefSearch(a),
};

// stdio JSON-RPC loop
const readline = (await import("node:readline")).createInterface({ input: process.stdin });
const write = (msg) => process.stdout.write(JSON.stringify(msg) + "\n");

readline.on("line", async (line) => {
  let req;
  try { req = JSON.parse(line); } catch { return; }
  const { id, method, params } = req;
  if (method === "initialize") {
    write({
      jsonrpc: "2.0", id,
      result: {
        protocolVersion: "2024-11-05",
        capabilities: { tools: {} },
        serverInfo: { name: "design-inspo-mcp", version: "1.0.0" },
      },
    });
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
      write({
        jsonrpc: "2.0", id,
        result: { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] },
      });
    } catch (e) {
      write({
        jsonrpc: "2.0", id,
        result: { content: [{ type: "text", text: JSON.stringify({ error: String(e.message) }) }], isError: true },
      });
    }
    return;
  }
  if (id !== undefined) {
    write({ jsonrpc: "2.0", id, error: { code: -32601, message: `method not found: ${method}` } });
  }
});

process.stderr.write("[design-inspo-mcp] ready on stdio (11 tools: refframe, recent.design, posts.design, collectui, colorhunt, fontshare, tailwind)\n");
