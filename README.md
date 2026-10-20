# Tenable VM Dashboard

Independent Flask dashboard that fills reporting and visibility gaps in **Tenable Vulnerability Management** (formerly Tenable.io).

This is not an official Tenable product. It connects to your own Tenable account when API keys are configured, syncs findings into a local store, then lets you review remediation performance, assets, tags, open ports, SSL expiry, and server reboot health in one place - without buying Lumin or rebuilding the same spreadsheet every month.

**Live demo (fictional data):** [preview.priyankraval.com/#dashboard](https://preview.priyankraval.com/#dashboard)
## Project overview

Tenable Vulnerability Management is strong at scanning and finding vulnerabilities. Teams on Reddit and elsewhere still struggle with the next step: showing whether remediation is working over a closed month.

Common complaints about the built-in dashboards and reports include:

- Reporting and dashboard customization feel limited. many people export to Excel, Power BI, or Metabase instead.
- Charts that compare “what was open 30 days ago” with “what is open now” are hard or impossible inside the product.
- Management-friendly trend views often depend on **Lumin** (extra license), which is not always available.
- SLA tracking and month-end remediation summaries are frequently described as weak or unusable for stakeholders.
- Summary lists (top assets, totals by platform, one combined report) often require multiple CSV exports and manual merge.
- There is no simple way to hand a **team-scoped** remediation dashboard to an owner or asset team using the tags you already maintain in Tenable.

This project addresses those gaps: sync vulnerability data from Tenable into local SQLite, freeze closed months so the story does not drift, filter the whole dashboard by an asset tag (for example `Owner: Alice` or `Asset Team: Platform`), and keep operational views (inventory, tags, ports, SSL, reboot age) in the same app.

## Key features

Six areas share one header and navigation.

### Dashboard

Monthly remediation performance against your local vulnerability store:

- Active findings, Critical/High split, SLA breaches (**Critical 14 days**, **High 30 days**), resurfaced and weaponized counts
- Frozen closed months: backlog start, new, resurfaced, fixed, derived end vs observed end
- Charts for backlog trend, monthly waterfall, median days to fix (MTTR), and SLA attainment
- Month-to-date panel (provisional until the month closes)
- Fix-before / fix-after plugin tables, patch family flow, top assets by VPR
- Recast/accept findings listed separately and excluded from the main counts
- **Filter by asset tag** - scope every KPI and chart to one tag (see below)
- **Daily sync / Full sync / Refresh / Export Report** in the header

### Filter dashboard by tag

Use the **Asset tag** dropdown on the dashboard to restrict metrics to assets that carry that tag in Tenable.

Typical tags:

| Example tag | What you see |
|-------------|--------------|
| `Owner: …` | Remediation dashboard for that owner’s assets |
| `Asset Team: …`  | Dashboard for that team’s estate |
| `Environment: Production` | Production-only remediation view |
| Any other category:value | Same idea - whatever you already tag in Tenable |

How it behaves:

1. Options are built from your Tenable tag registry plus asset export (with asset counts).
2. Selecting a tag recalculates KPIs, charts, tables, and month-to-date for **only** assets with that tag UUID.
3. Choosing **All assets** returns to the estate-wide view.
4. Estate-wide closed months are **frozen** after sync. Tag-scoped months are computed **live** for that filter (they are not written as frozen snapshots).

This is the main answer to “can each team see their own remediation dashboard?” - tag the assets in Tenable, then pick the tag here.

### Asset Inventory

On-demand asset view from Tenable’s asset export (TTL cache, default 2 hours):

- Hostname, IP, OS, sources (Scan / Agent), tags, first seen / last seen
- Search, column sort and filter, pagination, CSV export, row detail drawer
- **Refresh** forces a new asset export from Tenable

### Tag Management

Browse and manage Tenable tag categories and values from the same UI:

- Category / value listing and coverage
- Create and update tags through the Tenable Tags API (**changes apply in Tenable**)

Use Tag Management to keep Owner / Asset Team tags accurate; the dashboard filter depends on those tags being on the right assets.

### Open Ports

Open port findings from the asset export (when `INCLUDE_OPEN_PORTS` is true):

- Flat and per-asset views, protocol split, exposure bars, column filters, CSV export
- **Refresh** re-exports assets with open ports

### SSL Certificates

Certificate posture from Nessus plugin **10863**:

- Valid / expiring / expired KPIs and timeline, internet-facing filter, table, detail drawer
- Synced into a local SQLite store for this tab (**Refresh** pulls from Tenable)

### Server Health

Last reboot posture from plugins **56468** (Linux) and **92366** (Windows):

- Summary by health band, host counts by OS/version, Linux and Windows matrix grids, filterable table, detail drawer
- **Refresh** exports last-reboot plugin data into the local store


## How syncing works

The dashboard does **not** call Tenable for every page load. Vulnerability metrics come from a **local SQLite database** that you fill with sync. Other tabs use their own refresh/export paths.

### Dashboard buttons

| Action | What it does | When to use it |
|--------|----------------|----------------|
| **Full sync** | Exports vulnerabilities from Tenable since epoch (all states), loads them into SQLite, then freezes closed months | First run, after a long gap, or when you need a clean rebuild of history |
| **Daily sync** | Incremental export since the last sync, plus a refresh of the open finding set (recast / VPR / expiry), then closes months that are ready to freeze | Regular updates (for example once a day) after the first full sync |
| **Refresh** | Reloads metrics from the **local** store only - no Tenable export | After sync finishes, or when you only changed the tag filter |
| **Export Report** | Downloads the current metrics payload as JSON | Stakeholders, audits, offline copies |

Progress appears in the sync panel while an export runs. Wait for it to finish before trusting KPIs. A second sync while one is running is rejected.

### Suggested first-time flow

1. Configure `.env` and start the app (see below).
2. Open the Dashboard and run **Full sync** once. Large estates can take several minutes.
3. When sync completes, confirm frozen months and current KPIs look right for **All assets**.
4. Open **Asset Inventory** or wait for tags to load, then use **Asset tag** to open a team/owner view.
5. On later days, use **Daily sync** instead of Full unless you need a full rebuild.
6. Use each tab’s own **Refresh** for inventory, ports, SSL, and server health when you want fresh data for that view.

### What stays local

| Data | Where | How it updates |
|------|--------|----------------|
| Vulnerabilities / dashboard metrics | `vulnerabilities.db` (path configurable) | Full / Daily sync |
| SSL certificates | Local SSL DB | SSL tab Refresh |
| Server health | Local server-health DB | Server Health Refresh |
| Assets, open ports, tag options | In-memory TTL cache | Inventory / Ports / Tags Refresh (or cache expiry) |
| Optional raw JSON chunks | `data/vuln_raw/` (gitignored) | Written during vuln sync |

## Live demo

A hosted walkthrough with **fictional** sample data (no API keys, no live Tenable connection):

| Link | View |
|------|------|
| [preview.priyankraval.com/#dashboard](https://preview.priyankraval.com/#dashboard) | Remediation dashboard |
| […/#inventory](https://preview.priyankraval.com/#inventory) | Asset inventory |
| […/#tags](https://preview.priyankraval.com/#tags) | Tags |
| […/#ports](https://preview.priyankraval.com/#ports) | Open ports |
| […/#ssl](https://preview.priyankraval.com/#ssl) | SSL certificates |
| […/#health](https://preview.priyankraval.com/#health) | Server health |


## Stack and architecture

| Layer | Role |
|-------|------|
| Flask (`app.py`, port **7200** by default) | HTTP app and page routes |
| `services/` | Tenable export/sync, SQLite, tags, asset cache |
| `utils/` | Parsers, Lumin-style metrics, tag scope, SSL/server-health helpers |
| `templates/` + `static/` | UI; Chart.js on the dashboard |
| Local SQLite | Vulnerability, SSL, and server-health data after sync |
| TTL cache | Assets and tags (default `CACHE_TTL_SEC=7200`) |

Flow: Tenable API → export/sync → local store / cache → metrics and pages. Open ports come from the asset export when `INCLUDE_OPEN_PORTS` is true.

## Run the Flask application

### Requirements

- Python 3.10+ recommended
- Tenable Vulnerability Management API access key and secret key
- Network access to `https://cloud.tenable.com` (or your configured base URL)

### Setup

1. Clone the repository and create a virtual environment if you want one.
2. Copy `.env.example` to `.env` and set at least:

   ```env
   TENABLE_ACCESS_KEY=your_access_key
   TENABLE_SECRET_KEY=your_secret_key
   TENABLE_BASE_URL=https://cloud.tenable.com
   PORT=7200
   ```

3. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

4. Start the app:

   ```bash
   python app.py
   ```

5. Open [http://127.0.0.1:7200/](http://127.0.0.1:7200/).

6. On the Dashboard, run **Full sync**, then use **Daily sync** on a schedule that fits your program.

Optional settings (see `.env.example`): cache TTL, open-ports inclusion, vuln export chunk size, poll intervals, and storage paths.

## Use cases

- **Show remediation over a closed month** - backlog in, new/resurfaced, fixed, and end, without a Lumin license or a monthly Excel rebuild.
- **Team / owner dashboards** - tag assets with Owner or Asset Team in Tenable, then filter the dashboard to that tag.
- **Stakeholder / audit snapshot** - Export Report JSON; use the live preview when you only need the UI with fictional data.
- **Operational triage** - assets, tags, open ports, certificate expiry, and reboot age beside the remediation view.
- **Keep scanning in Tenable** - use this app for the reporting views the console does not provide cleanly.


## Current limitations

- Not a replacement for Tenable’s full console, Explore workbenches, or official reporting.
- Not a free-form widget builder; charts and tables are fixed to what this app implements.
- Tag filter applies to the **Dashboard** metrics scope, other tabs are not the same.
- Tag-scoped months are live (not frozen snapshots). Estate-wide closed months are frozen after sync.
- Vulnerability totals by OS / plugin family (beyond Server Health and dashboard tables) are not a dedicated rollup.
- SLA numbers use this app’s rules (14 / 30 days).they do not rewrite how Tenable ages plugins in its own UI.
- Tag create/update changes tags in Tenable - **use carefully**.
- The public preview [preview.priyankraval.com](https://preview.priyankraval.com ) uses fictional data only and never calls Tenable.

## Future roadmap

- [x] Frozen monthly remediation dashboard (backlog, waterfall, MTTR, SLA)
- [x] Dashboard filter by asset tag (Owner / Asset Team / any category:value)
- [x] Daily and Full vulnerability sync into local SQLite
- [x] Asset inventory with export
- [x] Open ports view
- [x] SSL certificate health (plugin 10863)
- [x] Server health / last reboot (plugins 56468 / 92366)
- [x] Basic tag browse and edit against the Tags API
- [ ] Improved Tag Management
- [ ] Historical asset tracking over time
- [ ] Additional monitoring views (for example vulnerability totals by platform or plugin family)

## Issues and pull requests are welcome
Useful contributions:
- Clear feature proposals that fit the gaps above
- Documentation improvements

## Disclaimer
This project is an independent tool for use with the Tenable Vulnerability Management API. It is not affiliated with or endorsed by Tenable, Inc. Product names above are trademarks of their respective owners.
