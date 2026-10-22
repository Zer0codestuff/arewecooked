<img src="assets/icon.svg" width="64" height="64" alt="">

# AreWeCooked?

A data story about cybersecurity in the AI era, built from 412,863 CVE records and 15+ public datasets (snapshot: 22 October 2026).

**What it covers**

1. **The flood**: CVE disclosures roughly doubled in 2026, and who is filing them.
2. **Signal or noise**: severity mix and the share of CVEs that actually get exploited.
3. **The machines are hunting**: how many vulnerabilities are now credited to AI finders (Anthropic, AISLE, OpenAI, XBOW and others), and the gap between AI findings and fixes.
4. **Faster than the patch**: days from disclosure to confirmed exploitation, zero-days, most-exploited vendors.
5. **AI is also the target**: vulnerabilities in AI software, leaked secrets (Railway breach), poisoned packages, AI-run attacks.
6. **The damage**: ransomware victims, ransom payments, FBI cybercrime losses, breach costs, a timeline of major incidents.
7. **Follow the money**: security spending, cyber stocks, venture funding, bug bounties.
8. **People**: workforce, the skills gap, job postings and what AI is doing to security jobs.
9. **Verdict**: two radar charts (threat pressure vs defensive capacity) and a "doneness" meter.

**Highlights (as of 22 Oct 2026)**

- 85,356 CVEs published in 2026, 2.2x the same period of 2025. Microsoft, Oracle and Google Chrome each file several times more CVEs than in 2025, with the jump starting around April 2026.
- At least 1,251 CVEs are publicly credited to AI vulnerability finders (1,105 in 2026), about 1.8% of all CVEs in October 2026. Anthropic's own ledger shows 29,439 AI findings but only 516 confirmed fixes.
- Only about 0.23% of 2026 CVEs are known to be exploited, but the median time from publication to confirmed exploitation fell from 24 days (2022 CVEs) to 4 days (2026 CVEs).

## Repository layout

```
pipeline/            Python pipeline (fetch.py downloads, build.py processes)
  steps/             one script per topic
  ai_patterns.py     rules that tag AI-found CVEs and CVEs in AI software
data/manual/         hand-transcribed report figures and the timeline, with source URLs
data/clean/          tidy CSV outputs, free to reuse
site/                Vite + TypeScript + D3 data story
```

## Run it

```sh
uv venv && uv pip install -r pyproject.toml
.venv/bin/python pipeline/fetch.py      # about 2 GB into data/raw (gitignored)
.venv/bin/python pipeline/build.py      # writes data/clean and site/public/data
cd site && npm install && npm run dev
```

## Sources

CVE Program (cvelistV5), CISA KEV and Vulnrichment, FIRST EPSS, Berkeley Agentic Vulnerability Coverage Map, Anthropic CVD dashboard, Anthropic-Credited-CVEs tracker, Google Project Zero, MSRC, Exploit-DB, Metasploit, Nuclei, ransomware.live, OSV.dev, Have I Been Pwned, Yahoo Finance, plus published reports from FBI IC3, Gartner, Chainalysis, IBM, ISC2, Verizon, Crunchbase, GitGuardian, Google GTIG, VulnCheck, HackerOne and CyberSN. Every manual figure links to its source in `data/manual/series.csv`.
