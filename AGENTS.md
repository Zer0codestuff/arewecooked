# AGENTS.md

## Purpose
AreWeCooked? is a portfolio data story about cybersecurity from 2015 to late 2026, focused on the AI era:
vulnerability volume, how many flaws are found with AI, exploitation speed, AI software as a target, incidents and ransomware, spending, and the workforce.
Audience: curious non-specialists. Tone: clear, not dumbed down, not chatty. Snapshot date: 22 Oct 2026 (`AS_OF` in `pipeline/common.py`).

## Architecture
- `pipeline/fetch.py` downloads public raw data to `data/raw/` (gitignored, about 2 GB). NVD comes from the fkie-cad mirror; the official NVD feeds are slow and flaky.
- Two processing paths coexist (a parallel commit, 0c59393, added the second on 22 Oct 2026):
  - `pipeline/steps/` (data story, renders the website): `fetch_extra.py` for extra raw data, `run_all.py` runs `cve_extract` (CVE List zip to `data/interim/cves.parquet`), `vulns`, `threats`, `ecosystem`, `context`, `nvd_status` (NVD backlog; also writes `data/interim/nvd.parquet` with NVD severity, score, CWE and first CPE vendor/product per CVE), `anatomy` (CWE families, memory safety by vendor, AI vs rest, MCP/prompt injection, Linux kernel AI review incl. Sashiko, OpenAlex research counts, daily calendar, severity with NVD fallback), `weapon` (PoC-in-GitHub exploit repos, Exploit-DB, KEV product taxonomy and speed), `triage` (rolling monthly backtest of CVSS vs historical EPSS snapshots against KEV additions in the next 90 days), `ransom` (countries per capita with World Bank data, brand ranks and churn, sectors), `credits` (distinct people vs AI systems in CVE credits since 2023; names are counted, never published), `explore` (profiles of the top 250 vendors, vendor key = NVD CPE vendor else normalized CVE vendor, percentile ranks for the compare radar). `fetch_extra.py` also fetches PoC-in-GitHub (shallow clone), monthly EPSS snapshots since 2023, OpenAlex and World Bank. Helpers live in `pipeline/steps/_common.py`, independent of `pipeline/common.py`.
  - `pipeline/build.py` + `pipeline/sources/` + `pipeline/export.py` + `pipeline/indicators.py` (source processors, clean CSVs, `site/public/data/story.json`, a "cooked index"), covered by `tests/`. The site does not read `story.json` yet.
  - Consolidating the two is an open decision for the user.
- `pipeline/ai_patterns.py`: regex rules for "AI-attributed" CVEs (credits and explicit description statements, org list based on Berkeley's tracker, plus the Anthropic-Credited-CVEs list) and for "CVEs in AI software". This is a documented lower bound.
- `data/manual/story/series.csv` (report figures, one source URL per row), `data/manual/story/timeline.csv` (incidents and AI milestones) and `data/manual/story/ai_releases.csv` (16 major model releases with date, short label, label `priority` 1 to 3 and the lab's announcement URL). `context.py` exports the releases to `context.json`. Other `data/manual/*.csv` belong to the `pipeline/build.py` path and are validated by its tests.
- Outputs: `data/clean/*.csv` (committed, reusable) and `site/public/data/*.json` (committed, read by the site).
- `site/`: Vite + TypeScript + D3, no framework. `src/lib/figure.ts` (figure shell, legend, table view, tooltip), `src/lib/charts2.ts` (calendar heatmap, bump chart, world choropleth via world-atlas + topojson-client, small multiples, binned sequential legends), `src/lib/charts.ts` (columns, lines with `xDomain`/`points`, hbars/dumbbell, radar; `releases: true` draws the AI model release rail above monthly/time charts, labels placed by priority, the rest stay as hover-only markers), `src/lib/page.ts` (palette and layout helpers), `src/sections/*.ts` one per chapter (14 chapters incl. the vendor explorer, numbered automatically in render order by `chapter()` in `page.ts`; `figure.reset()` drops old renderers before redrawing a figure, used by toggles and the explorer). `main.ts` tags naive pipeline timestamps as UTC at load (`utcify`); without it monthly labels shift back one month for readers east of UTC.

## Run
```sh
uv venv && uv pip install -e ".[story,dev]"
.venv/bin/python pipeline/fetch.py
.venv/bin/python pipeline/steps/fetch_extra.py
.venv/bin/python pipeline/steps/run_all.py
.venv/bin/python -m pytest -q
cd site && npm install && npm run dev      # npm run build for production
```

## Deploy
Live at https://gabrielemonni.me/arewecooked/ (GitHub Pages, published 23 Oct 2026 with the user's approval). The custom domain comes from the user site repo `Zer0codestuff.github.io`; this repo has no CNAME of its own. `.github/workflows/pages.yml` deploys on every push to `main` that touches `site/**`, or by manual `workflow_dispatch`. Vite `base` is `./`, so the build works under the `/arewecooked/` subpath.

## Preferences and constraints
- All project text in English. No em dashes anywhere.
- Visual direction: dark terminal / ASCII aesthetic, sober. Mono for chrome and labels, IBM Plex Sans for prose.
- Charts follow the dataviz skill rules: one y-axis, thin marks, validated palette (green #34a870 first slot, validated on #101312), hover tooltips, table view for every chart, legends for 2+ series.
- Every number must trace to a source; partial-year values must be labeled.
- Git: branches, PRs, frequent merges. Commits authored by Zer0codestuff only, no agent signatures or Co-authored-by trailers.
- User likes radar charts and ASCII art.

## Status
Data pipeline complete; site with 14 chapters and about 60 charts is live on GitHub Pages (desktop and mobile checked).

## Recent changes
- 23 Oct 2026: AI model release markers on 8 time charts (replace the old "Glasswing" annotations); light UI polish (scroll progress line, card corner accents, chapter rules, figure reveal on scroll, tooltip accent, EOF footer). Data spot check against raw files passed; fixed one AI-attribution false positive (Huawei Nebula Security Lab, 2023), AI-credited total is now 1,250.

- 23 Oct 2026 (later): big expansion. New chapters Anatomy (03), From bug to weapon (06), The triage game (07); calendar heatmap (flood), severity from 2016 with NVD fallback (noise), Sashiko kernel AI review and research boom (hunters), MCP and prompt-injection CVEs (target), ransomware world map, brand bump chart, churn and sectors (damage), two new radar axes (verdict), tl;dr findings list under the hero. AI classifier now reads Sashiko/LLM-review mentions in fix descriptions (AI-credited total 1,433). Fixed a timezone bug that shifted monthly labels by one month east of UTC.

- 23 Oct 2026 (third pass): people vs AI in CVE credits (People chapter), Claude vs vendor/maintainer severity matrices (hunters), interactive vendor explorer with compare radar (new chapter before Data), `matrix` chart, findings list now has 8 lines.

## Known issues / next steps
- Triage backtest uses current CVSS scores (historical CVSS snapshots are not available); EPSS uses historical snapshots.
- PoC-in-GitHub misses deleted repositories; some indexed repos are fakes or malware.
- SEC 8-K Item 1.05 incident filings not included (EDGAR requires a contact email in the User-Agent).
- Some 2026 report figures come from press coverage rather than the original reports (labeled in series.csv).

## Do not
- Do not add agent signatures to commits or PRs.
- Do not use dual-axis charts or rainbow palettes.
- Do not add more subtitles or explanatory copy as "UI detail"; the user wants visual polish only.
- Do not add a CNAME file to this repo or change the custom domain (it is managed in `Zer0codestuff.github.io`).
