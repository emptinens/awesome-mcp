---
title: "design-inspo-mcp — MCP server for design reference sites"
source: custom build
created: 2026-09-01
tags: [design, mcp, ai-agents, codex, tools, references, anti-slop]
location: /home/xxx/.config/design-inspo-mcp/server.mjs
---

# design-inspo-mcp — MCP server for design reference sites

Custom MCP server that gives coding agents (Codex, and any MCP client) direct access to seven design-reference sources. Built for the anti-slop workflow: pull real references, real fonts, real palettes, real Tailwind docs into the agent's context instead of letting it default to generic output.

## Sources & access methods

| Source | Method | Notes |
|---|---|---|
| **refframe.com** | SSR HTML scrape | Homepage carries ~36 `/reference/<slug>` shot links; each item page has full og: metadata (title, description, image). `?tags=` filter falls back to obscura for JS pages. |
| **recent.design** | sitemap.xml + og: meta | Sitemap lists `/i/<id>-<slug>` items; item pages are SSR with og: metadata. |
| **posts.design** | sitemap.xml + og: meta | 1283 URLs in sitemap; posts SSR. |
| **collectui.com** | obscura (JS render) | Site is now a JS shell (~8KB HTML); category pages need headless rendering. `obscura scrape --eval` as fallback. |
| **colorhunt.co** | **native API**: `POST /php/feed.php` | Params: `step`, `sort` (new/random), `tags` (blue/pastel/vintage/...), `timeframe`. Returns `[{code: "24hex", likes, date}]`. Palette URL: `/palette/<code>`. |
| **fontshare.com** | **native API**: `api.fontshare.com/v2` | `/fonts?limit=100` for search; `/css?f[]=slug@400,700` for ready @font-face CSS. Accept header must be `*/*` (text/css triggers 406). |
| **tailwindcss.com** | SSR HTML | `/docs` index lists all utility pages; per-page og: metadata. Fuzzy slug resolution (flexbox → flex). |

## Tools (11)

- `list_refframe(limit, tags)` — design shots; tags: button, card, hero, accordion, pricing, dark, 3d, grid, timeline, portfolio...
- `list_recent_design(limit)` — latest curated design work
- `list_posts_design(limit)` — design posts and showcases
- `search_fonts(query, limit)` — Fontshare search by name/category
- `get_font_css(slugs, weights, display)` — ready-to-use @font-face CSS + `<link>` snippet
- `tailwind_docs(page)` — docs page metadata with fuzzy slug resolution
- `tailwind_classes(prefix)` — list utility doc pages (bg*, flex*, text*...)
- `list_colorhunt(limit, sort, tags)` — 4-hex palettes with likes
- `collectui_category(category, limit)` — category designs (JS-rendered via obscura)
- `get_design_item(url)` — full og: metadata for any design URL
- `design_ref_search(query, limit)` — cross-site: one query hits fontshare + tailwind + all galleries

## Install (already done)

```bash
# server location
/home/xxx/.config/design-inspo-mcp/server.mjs

# wired into ~/.codex/config.toml:
[mcp_servers.design-inspo]
command = "node"
args = ["/home/xxx/.config/design-inspo-mcp/server.mjs"]
```

Node ≥ 18 required (global fetch). Zero dependencies. Uses `obscura` (installed at `/usr/bin/obscura`) only for the two JS-gated sources (collectui, refframe tag pages).

## Discovery notes (how each site was cracked)

- **colorhunt**: rendered page text has no palette hex codes (lazy-loaded). The jQuery bundle (`/js/*.js`) revealed `$.ajax({ url: '/php/feed.php', data: {step, sort, tags, timeframe} })` — a native POST endpoint returning JSON with concatenated hex codes. GET returns `[]`; POST works.
- **refframe**: Next.js RSC app. Sitemap only has blog/changelog. SSR homepage embeds 36 `/reference/<slug>` links directly in HTML. Item pages are SSR with complete og: tags. Tag-filtered pages (`/?tags=button`) are client-rendered → obscura. Their backend is `refframe-prod-ltbwc.ondigitalocean.app/api` (hashed routes, 404 on probe).
- **collectui**: was SSR historically; now an 8KB JS shell. All design grids hydrate client-side. Category slugs still resolve (`/designs/sign-up`), content needs headless rendering.
- **fontshare**: clean public JSON API. The CSS endpoint (`/v2/css`) 406s on `Accept: text/css` (server irony) — works with `Accept: */*`.
- **posts.design / recent.design**: clean sitemaps + SSR og: metadata — the well-behaved pattern.

## Usage in codex

Restart codex after config change, then the tools are available in any session:

```
> use design_ref_search to find "hero section" references
> get_font_css for clash-display, then use it in the landing page
> list_colorhunt tags=dark for the color scheme
```

## Related

- [[Web is Splitting into Two Extremes — Guillermo Rauch]] — why agent-driven design tooling matters
- [[refero-styles-design-md-library]] — DESIGN.md constraint files (complementary: constraints vs references)
- [[obscura-rust-browser-for-agents]] — the headless browser powering JS-gated sources
