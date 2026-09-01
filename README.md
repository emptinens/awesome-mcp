<div align="center">

# ⚡ awesome-mcp

**MCP servers I built.**

Zero-dependency. Stdio transport. Plug into Codex, Claude Code, or any MCP client.

[![Made with Node](https://img.shields.io/badge/node-%3E%3D18-339933?style=flat-square&logo=node.js&logoColor=white)](https://nodejs.org)
[![MCP](https://img.shields.io/badge/protocol-MCP-6E6E6E?style=flat-square)](https://modelcontextprotocol.io)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)

</div>

---

## Servers

### [design-inspo](servers/design-inspo/) — web design references for coding agents

11 tools pulling real references from 7 design sites, so agents build UI from **actual design work** instead of defaulting to generic output.

| Source | Method | Tools |
|---|---|---|
| [refframe.com](https://refframe.com) | SSR scrape + og: meta | `list_refframe` (tag filter: hero, button, dark, 3d…) |
| [recent.design](https://recent.design) | sitemap + og: meta | `list_recent_design` |
| [posts.design](https://posts.design) | sitemap (1,283 posts) | `list_posts_design` |
| [collectui.com](https://collectui.com) | headless render ([obscura](https://github.com/h4ckf0r0day/obscura)) | `collectui_category` |
| [colorhunt.co](https://colorhunt.co) | native API (`POST /php/feed.php`) | `list_colorhunt` (sort, tag filter) |
| [fontshare.com](https://fontshare.com) | native API (`api.fontshare.com/v2`) | `search_fonts`, `get_font_css` → ready `@font-face` |
| [tailwindcss.com](https://tailwindcss.com) | SSR docs | `tailwind_docs` (fuzzy slug), `tailwind_classes` |
| any URL | og: extraction | `get_design_item` |
| **all at once** | cross-site | `design_ref_search` |

**Install:**

```toml
# ~/.codex/config.toml
[mcp_servers.design-inspo]
command = "node"
args = ["/path/to/servers/design-inspo/server.mjs"]
```

Node ≥ 18. No npm dependencies. Optional: [obscura](https://github.com/h4ckf0r0day/obscura) on `$PATH` for the two JS-gated sources (collectui, refframe tag pages) — everything else works without it.

**Example session:**

```
> design_ref_search "hero section"
> get_font_css ["clash-display"] weights="400,700"
> list_colorhunt tags="dark" limit=5
> collectui_category "sign-up"
```

Full discovery notes (how each site's data access was reverse-engineered) in [servers/design-inspo/NOTES.md](servers/design-inspo/NOTES.md).

---

## Conventions

Every server in this repo:

- **stdio JSON-RPC 2.0**, MCP spec `2024-11-05`
- **Zero runtime deps** — Node built-ins only
- **Graceful degradation** — JS-gated sources fall back to headless rendering, native APIs preferred over scraping
- **Typed tool schemas** — every tool declares its input schema

## Adding a server

```
servers/<name>/
├── server.mjs    # the MCP server (zero-dep, stdio)
└── NOTES.md      # discovery notes: how the data source works
```

## License

MIT
