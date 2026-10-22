# AGENTS.md

## Purpose
AreWeCooked? is a portfolio data story about cybersecurity from 2015 to late 2026, focused on the AI era:
vulnerability volume, how many flaws are found with AI, exploitation speed, AI software as a target, incidents and ransomware, spending, and the workforce.
Audience: curious non-specialists. Tone: clear, not dumbed down, not chatty. Snapshot date: 22 Oct 2026 (`AS_OF` in `pipeline/common.py`).

## Architecture
- `pipeline/fetch.py` downloads public raw data to `data/raw/` (gitignored, about 2 GB). NVD comes from the fkie-cad mirror; the official NVD feeds are slow and flaky.
- Two processing paths coexist (a parallel commit, 0c59393, added the second on 22 Oct 2026):
  - `pipeline/steps/` (data story, renders the website): `fetch_extra.py` for extra raw data, `run_all.py` runs `cve_extract` (CVE List zip to `data/interim/cves.parquet`), `vulns`, `threats`, `ecosystem`, `context`. Helpers live in `pipeline/steps/_common.py`, independent of `pipeline/common.py`.
  - `pipeline/build.py` + `pipeline/sources/` + `pipeline/export.py` + `pipeline/indicators.py` (source processors, clean CSVs, `site/public/data/story.json`, a "cooked index"), covered by `tests/`. The site does not read `story.json` yet.
  - Consolidating the two is an open decision for the user.
- `pipeline/ai_patterns.py`: regex rules for "AI-attributed" CVEs (credits and explicit description statements, org list based on Berkeley's tracker, plus the Anthropic-Credited-CVEs list) and for "CVEs in AI software". This is a documented lower bound.
- `data/manual/story/series.csv` (report figures, one source URL per row) and `data/manual/story/timeline.csv` (incidents and AI milestones). Other `data/manual/*.csv` belong to the `pipeline/build.py` path and are validated by its tests.
- Outputs: `data/clean/*.csv` (committed, reusable) and `site/public/data/*.json` (committed, read by the site).
- `site/`: Vite + TypeScript + D3, no framework. `src/lib/figure.ts` (figure shell, legend, table view, tooltip), `src/lib/charts.ts` (columns, lines, hbars/dumbbell, radar), `src/lib/page.ts` (palette and layout helpers), `src/sections/*.ts` one per chapter.

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
GitHub Pages via `.github/workflows/pages.yml` (manual `workflow_dispatch`). Pages is not enabled yet: waiting for the user's approval after reviewing the local result.

## Preferences and constraints
- All project text in English. No em dashes anywhere.
- Visual direction: dark terminal / ASCII aesthetic, sober. Mono for chrome and labels, IBM Plex Sans for prose.
- Charts follow the dataviz skill rules: one y-axis, thin marks, validated palette (green #34a870 first slot, validated on #101312), hover tooltips, table view for every chart, legends for 2+ series.
- Every number must trace to a source; partial-year values must be labeled.
- Git: branches, PRs, frequent merges. Commits authored by Zer0codestuff only, no agent signatures or Co-authored-by trailers.
- User likes radar charts and ASCII art.

## Status
Data pipeline complete; full site with 10 chapters and 30+ charts renders locally (desktop and mobile checked).

## Known issues / next steps
- NVD feed download is slow and incomplete; NVD data is not used yet (could add NVD backlog status and CVSS for pre-2022 severity).
- SEC 8-K Item 1.05 incident filings not included (EDGAR requires a contact email in the User-Agent).
- Some 2026 report figures come from press coverage rather than the original reports (labeled in series.csv).

## Do not
- Do not add agent signatures to commits or PRs.
- Do not use dual-axis charts or rainbow palettes.
- Do not enable GitHub Pages or publish without the user's go-ahead.
