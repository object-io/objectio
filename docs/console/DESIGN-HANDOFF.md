# ObjectIO Console — design handoff

This folder is the source of truth for the console redesign. It is written to be read by
Claude Code (or any engineer) working in `console/`. Everything here maps onto the existing
Vite + React 19 + Tailwind v4 app; nothing requires a rewrite.

```
design/
  HANDOFF.md            this file — spec, migration order, component contracts
  tokens.css            semantic CSS variables, light on :root, dark on [data-theme="dark"]
  chart-palette.json    validated categorical series colors + chart rules
  mockups/*.html        static, self-contained mockups — open in a browser, read the markup
  brand/                logo SVGs (type outlined), favicon.ico, README banner
```

Live, editable version of the same screens: the "ObjectIO Console Design" artifact on claude.ai
(ask the owner for the link). The mockup HTML here is exported from it.

## 1. Brand

Mark: the **Shard Ring** — an O of eight shards, six data (ink/paper) and two parity (amber,
at 12 and 6 o'clock). `brand/objectio-mark*.svg`. Never rotate, never recolor the parity pair.
Under 48 px use `brand/favicon-small.svg` (solid ring). Wordmark: "ObjectIO" in Sora 600 with
"IO" in accent blue; use the outlined SVGs, do not set it as live text.

Fonts (Google Fonts): **Sora** 500/600 (page titles, big numbers), **IBM Plex Sans** 400/500/600
(everything else, base 13px), **IBM Plex Mono** 400/500 (identifiers, labels, code).
Replace the Inter / JetBrains Mono `<link>` in `index.html`, `ops.html`, `tenant.html`.

## 2. Tokens → Tailwind

`tokens.css` defines `--oio-*` variables. Wire them into Tailwind v4 once, then use utilities:

```css
/* console/src/index.css */
@import "tailwindcss";
@import "./design/tokens.css";      /* or move the file next to index.css */

@theme inline {
  --color-bg: var(--oio-bg);
  --color-surface: var(--oio-surface);
  --color-surface-2: var(--oio-surface2);
  --color-border: var(--oio-border);
  --color-border-strong: var(--oio-border-strong);
  --color-text: var(--oio-text);
  --color-text-2: var(--oio-text2);
  --color-muted: var(--oio-muted);
  --color-faint: var(--oio-faint);
  --color-accent: var(--oio-accent);
  --color-accent-soft: var(--oio-accent-soft);
  --color-primary: var(--oio-primary);
  --color-primary-fg: var(--oio-primary-fg);
  --color-ok: var(--oio-ok);     --color-ok-soft: var(--oio-ok-soft);
  --color-warn: var(--oio-warn); --color-warn-soft: var(--oio-warn-soft); --color-warn-dot: var(--oio-warn-dot);
  --color-err: var(--oio-err);   --color-err-soft: var(--oio-err-soft);
  --font-display: var(--oio-font-display);
  --font-sans: var(--oio-font-body);
  --font-mono: var(--oio-font-mono);
  --radius-control: 8px; --radius-card: 12px; --radius-dialog: 16px;
}
body { @apply bg-bg text-text font-sans antialiased; font-size: 13px; }
```

Then `bg-surface border-border text-muted rounded-card` etc. Dark mode = `data-theme="dark"`
on `<html>`; persist the choice in localStorage; default light.

Color meaning is fixed: **blue** = data, links, focus, active nav, primary charts series.
**Amber** = attention (warnings, rebalance, parity, near-full). **Ink** = the one primary button.
Status = ok / warn / err / neutral, always with a dot or icon, never color alone.

## 3. Shell (unchanged structure, new skin)

Keep `components/Layout.tsx` as is structurally: 208px sidebar, same nav order, same
`adminOnly` / `feature` gating. Restyle:

| element | spec |
|---|---|
| sidebar | `bg-surface border-r border-border`; brand block 26px small mark + wordmark 15px + "OPS CONSOLE" / "CONSOLE" mono 10px caps muted |
| nav item | `px-2.5 py-1.5 rounded-control text-[12px] font-medium gap-2.5`, icon 15px; active `bg-accent-soft text-accent`; locked `text-faint` + lock 11px |
| user block | name 11px/500, role 10px muted, sign-out icon button |
| main | `bg-bg`, pages own `p-6` |
| page header | h1 Sora 17px/600, description 12px muted, actions right; `mb-4` |

## 4. Components (build these once, delete the inline copies)

Sizes: controls 32px, table rows 36px, radius 8 / 12 / 16, icon 13–15px (lucide, stroke 1.75).

- **Button** `variant: primary | secondary | ghost | danger | accent`, `size: md | sm`.
  primary = ink bg / white text (dark: paper bg / ink text). md = `px-3 py-1.5 text-[12px] font-medium`.
  Retire both the `bg-gray-900` and `bg-blue-600` inline buttons.
- **Input / Select** 32px, `border-border-strong rounded-control text-[13px]`, optional leading
  icon 13px at left-2.5, focus ring `ring-2 ring-accent-soft border-accent`. Label 11px/600 above.
- **Badge** `kind: ok | warn | err | info | neutral`, 11px/500, `px-1.5 py-px rounded-[5px]`, 5px dot.
  Replaces `StatusBadge` and unifies with `StatusDot` palette (emerald/amber → ok/warn tokens).
- **Chip** 11px, `bg-surface-2 border-border`, `mono` prop for identifiers (pools, tenants, tags).
- **Card** `bg-surface border-border rounded-card shadow-sm`; optional header: mono 11px caps muted
  title + right action slot. Body `p-4`.
- **Table** header row `bg-surface-2`, th mono 11px caps muted `px-3.5 py-2`; td `px-3.5 py-2`
  `border-t border-border`; row actions right-aligned icon buttons revealed on hover; loading
  row (64px track + accent bar) and empty row (centered 12px muted, with a link) built in;
  optional footer line 11px muted.
- **Tabs** `variant: pill | underline` — pill container `bg-surface-2 border-border p-0.5 rounded-control`,
  active tab `bg-surface shadow-sm`; underline active `border-b-2 border-accent text-accent`.
- **Banner** `kind: ok | warn | err`, soft background, icon 16px, optional action slot.
- **CapacityBar** 6px track, fill accent; `≥75%` warn-dot, `≥90%` err. Label 11px muted.
- **Drawer** in-flow (not overlay), 320px, `border-l border-border`, header 12/16 with title mono 14/600.
- **StatTile** mono 11px caps label, Sora 22–24px value (`tabular-nums`, no wrap), 11px muted
  sub-line, optional 120×26 sparkline bottom-right.
- **ChartCard** title 13/500 + subtitle 11 muted, legend top-right (only when >1 series),
  chart below. Charts on Recharts (already a dependency) — see §6.
- **RangePills** `5m 1h 6h 24h 7d 30d` pill tabs; **FilterSelect** 30px bordered select with mono value.

## 5. Screens → files

| mockup | route / file | notes |
|---|---|---|
| login.html | `pages/Login.tsx` | 400px card, mark 40px, Account / Access key / Secret key, ink Connect, SSO divider, provider buttons |
| dashboard.html | `pages/Dashboard.tsx` | health banner + range pills · 5 StatTiles · request-rate + latency ChartCards · Capacity (data/parity split + 30d trend) · Pools PG fill · Hosts · Recent events |
| monitoring.html | `pages/Monitoring.tsx` | filters row · 5 tiles · 6 charts (see §6). Keep 5s poll, 60 points |
| topology.html | `pages/Topology.tsx` | tabs Topology / Nodes & drives / Storage pools / Balancing · status strip · amber rebalance banner · tree rows with level label, name, count chip, capacity bar, status dot · host Drawer |
| nodes.html | `pages/Drives.tsx` | fill-distribution bar + host latency line · search / All-Has issues pills / Group-by-rack toggle · grid table `28px 1.2fr 110px 1.4fr 1.3fr 130px 40px`, rack group rows, expandable OSD rows |
| pools.html | `pages/Pools.tsx` | list table · wizard: pill tabs, radio cards RS / LRC / Replication, k / local / global / domain, tags / PGs / quota, toggles · SummaryPanel with validation strip + amber callout |
| tenants.html | `pages/Tenants.tsx` | storage-by-tenant line + requests-by-tenant stacked bars · table with quota CapacityBar, OIDC chip, admins, status |
| users.html | `pages/Users.tsx` | underline tabs with counts · new-credentials warn Banner with copy buttons · expandable access-key row |
| buckets.html | `pages/Buckets.tsx` | search + All / Versioned / Locked pills · table Name / Tenant / Versioning / Pool / Size · footer totals |
| objects.html | `pages/Objects.tsx` | breadcrumb with bucket, prefix, toolbar · 4 info tiles · folder/file rows, `..` row |
| tables.html | `pages/IcebergCatalog.tsx` | breadcrumb + warehouse chip · commits-per-namespace bars + namespace card · table with snapshots, size, last commit, governance badge |
| components.html | — | visual reference for §4 |
| *dark.html | — | same pages with `data-theme="dark"` |

Migration order that keeps the app shippable at every step:
1. tokens.css + fonts + `@theme inline` (nothing visible changes yet)
2. Button, Input, Badge, Card, Table, Tabs, Banner — replace inline classes page by page
3. Layout + Login
4. Dashboard, Monitoring (ChartCard, StatTile, RangePills)
5. Cluster tabs (Topology, Drives, Pools, Balancing)
6. Tenants, Users, Buckets, Objects, Tables, then the rest (Policies, Identity, Unity, Sharing, Encryption, License, MyAccount) using the same primitives
7. dark theme toggle in the user block

## 6. Charts (Recharts)

Series colors from `chart-palette.json`, in order: blue, amber, teal, violet — assign per entity
in a fixed order, never by index of whatever is currently visible. Max 4 series. One y-axis.
Grid = `--oio-border`, axis text = `--oio-faint` mono 10px, line 2px with end dot, no area fill
when >1 series, tooltip = surface bg + border-strong, crosshair dashed muted. Legend only for ≥2
series. Every ChartCard exposes a "table view" in its ⋯ menu.

Metric sources (already in `/metrics`): `objectio_s3_requests_total{operation}`,
`objectio_s3_request_duration_seconds` (p50/p95/p99 from the histogram),
`objectio_http_responses_total{status}`, `objectio_iceberg_requests_total`.
Needed for per-tenant / per-node charts: add `tenant` and `node` labels to those counters.

## 7. Suggested prompt for Claude Code

> Read `console/design/HANDOFF.md` and the files it references. Implement step 1 and step 2 of
> the migration order: wire `tokens.css` into `console/src/index.css` via `@theme inline`, swap
> the fonts, then create `src/components/ui/{Button,Input,Badge,Chip,Card,Table,Tabs,Banner,
> CapacityBar,StatTile,ChartCard}.tsx` matching §4 and `design/mockups/components.html`.
> Do not change page behaviour or API calls. Run `npm run lint` and `npm run build`.
