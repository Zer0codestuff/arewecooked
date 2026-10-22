# AGENTS.md

## Purpose
AreWeCooked? is a portfolio data story about the state of cybersecurity (2015 to late 2026), with a focus on the AI era:
vulnerability volume, how many flaws are found with AI, exploitation speed, incidents and breaches, ransomware, money spent on security, and the workforce.
Audience: curious non-specialists. Tone: clear, not dumbed down.

## Architecture
- `pipeline/` Python (uv venv in `.venv`). `fetch.py` downloads public raw data to `data/raw/` (gitignored). Processing scripts build clean tables in `data/clean/` (committed, CSV) and compact JSON for the site in `site/public/data/`.
- `data/manual/` hand-curated tables transcribed from published reports. Every row carries a source URL.
- `site/` static data-story website (Vite + TypeScript + D3), deployed to GitHub Pages.

## Run
```sh
uv venv && uv pip install -r pyproject.toml
.venv/bin/python pipeline/fetch.py        # downloads ~2 GB of raw data
.venv/bin/python pipeline/build.py        # clean tables + site JSON
cd site && npm install && npm run dev
```

## Preferences and constraints
- All project text in English. No em dashes anywhere.
- Visual direction: dark terminal / ASCII aesthetic, sober, readable charts. Follow the dataviz skill rules (one axis, thin marks, validated palette, tooltips, table view).
- Use clean, reproducible data; cite every manual number with a primary source.
- Git: work on branches, open PRs, merge often. Commits authored by Zer0codestuff only, no agent signatures or Co-authored-by trailers.

## Status
Initial setup: data pipeline scaffolding and research in progress.

## Do not
- Do not add agent signatures to commits or PRs.
- Do not use dual-axis charts or rainbow palettes.
