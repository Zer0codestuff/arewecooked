<img src="assets/icon.svg" width="64" height="64" alt="">

# AreWeCooked?

A data story about cybersecurity in the AI era, built from 412,863 CVE records and 20+ public datasets (snapshot: 22 October 2026).

**Live:** https://gabrielemonni.me/arewecooked/

**What it covers**

1. **The flood**: CVE disclosures roughly doubled in 2026, who files them, and the daily rhythm (Patch Tuesday).
2. **Signal or noise**: severity mix since 2016 (NVD fallback), the share that gets exploited, the NVD backlog.
3. **Anatomy of a flaw**: weakness families over time, memory safety by vendor (Android's drop after Rust), AI-found vs other bugs.
4. **The machines are hunting**: CVEs credited to AI finders, Anthropic's disclosure funnel, Google's Sashiko reviewing the Linux kernel, the research boom.
5. **Faster than the patch**: days from disclosure to confirmed exploitation, zero-days, most-exploited vendors.
6. **From bug to weapon**: exploit code on GitHub vs Exploit-DB, exploit code within a day, which product types get exploited and how fast.
7. **The triage game**: a 43-month out-of-sample backtest of CVSS vs EPSS for predicting the next exploits.
8. **AI is also the target**: vulnerabilities in AI software, MCP connectors and prompt injection, leaked secrets (Railway breach), poisoned packages, AI-run attacks.
9. **The damage**: ransomware victims (world map, per capita), brand churn, sectors, ransom payments, FBI losses, breach costs, incident timeline.
10. **Follow the money**: security spending, cyber stocks, venture funding, bug bounties.
11. **People**: distinct human bug finders vs AI in CVE credits, workforce, the skills gap, job postings.
12. **Verdict**: two radar charts (threat pressure vs defensive capacity) and a "doneness" meter.
13. **Explore**: compare any two of the 250 vendors with the most CVEs on a radar, a yearly chart and a table.

**Highlights (as of 22 Oct 2026)**

- 85,356 CVEs published in 2026, 2.2x the same period of 2025. Microsoft, Oracle and Google Chrome each file several times more CVEs than in 2025, with the jump starting around April 2026.
- At least 1,433 CVEs are publicly credited to AI vulnerability finders (1,288 in 2026), including 162 Linux kernel fixes flagged by Google's Sashiko reviewer. Anthropic's own ledger shows 29,439 AI findings but only 516 confirmed fixes.
- Memory-safety bugs fell from 77% to 25% of Android CVEs (2019 to 2026); AI-credited CVEs are memory bugs more often than others (27% vs 18%).
- GitHub hosted 8,406 new exploit repositories in 2026 so far, Exploit-DB 233. 1,070 CVEs of 2026 had exploit code within a day.
- Patching the top 5% of open CVEs by EPSS caught 41% of the next 90 days' exploits; by CVSS, 25% (543 exploits, Jan 2023 to Jul 2026).
- 9,045 different people were credited as finders of 2026 CVEs, up from 1,710 in 2023; AI systems were credited on 1,288.
- CVEs about MCP connectors for AI agents: 99 in 2025, 842 in 2026. Italy ranks 5th for ransomware victims in 2026 (238).
- Only about 0.23% of 2026 CVEs are known to be exploited, but the median time from publication to confirmed exploitation fell from 24 days (2022 CVEs) to 4 days (2026 CVEs).

## Repository layout

```
pipeline/fetch.py    raw downloads (data/raw, gitignored)
pipeline/build.py    source processors -> data/clean tables + site/public/data/story.json
pipeline/steps/      data-story steps -> site/public/data/{vulns,threats,anatomy,weapon,triage,ransom,...}.json (what the site renders)
pipeline/ai_patterns.py  rules that tag AI-found CVEs and CVEs in AI software
data/manual/         hand-transcribed report tables (data/manual/story/ is used by the site)
data/clean/          tidy CSV outputs, free to reuse
site/                Vite + TypeScript + D3 data story
```

## Run it

```sh
uv venv && uv pip install -e ".[story,dev]"
.venv/bin/python pipeline/fetch.py               # about 2 GB into data/raw (gitignored)
.venv/bin/python pipeline/steps/fetch_extra.py   # prices, MSRC, ransomware.live, AI trackers, PoC-in-GitHub, EPSS history, OpenAlex, World Bank
.venv/bin/python pipeline/steps/run_all.py       # site JSON + clean CSVs used by the website
.venv/bin/python pipeline/build.py               # source processors + story.json (optional)
.venv/bin/python -m pytest -q
cd site && npm install && npm run dev
```

## Sources

CVE Program (cvelistV5), NIST NVD (fkie-cad mirror), CISA KEV and Vulnrichment, FIRST EPSS (current and 43 monthly snapshots), PoC-in-GitHub, OpenAlex, World Bank, Berkeley Agentic Vulnerability Coverage Map, Anthropic CVD dashboard, Anthropic-Credited-CVEs tracker, Google Project Zero, MSRC, Exploit-DB, Metasploit, Nuclei, ransomware.live, OSV.dev, Have I Been Pwned, Yahoo Finance, plus published reports from FBI IC3, Gartner, Chainalysis, IBM, ISC2, Verizon, Crunchbase, GitGuardian, Google GTIG, VulnCheck, HackerOne and CyberSN. Every manual figure links to its source in `data/manual/story/series.csv`.
