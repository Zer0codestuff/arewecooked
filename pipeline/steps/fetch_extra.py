"""Raw downloads used only by the data-story steps (not covered by pipeline/fetch.py).

- ransomware.live victims per month -> data/raw/ransomware_live/
- Yahoo Finance monthly prices      -> data/raw/prices/
- Microsoft MSRC CVRF documents     -> data/raw/msrc/
- Berkeley agentic CVE map, Anthropic CVD dashboard, Anthropic-Credited-CVEs tracker
- unzips the inner cves.zip of the CVE List release
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import time
import zipfile
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import RAW  # noqa: E402

UA = "arewecooked-data-pipeline/0.1 (research project)"


def get(url: str, dest: Path, force: bool = False, headers: dict | None = None, ua: str = UA) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists() and dest.stat().st_size > 0 and not force:
        return
    cmd = ["curl", "--http1.1", "-sSL", "--fail", "--retry", "5", "--retry-delay", "3", "-A", ua, "-o", str(dest), url]
    for k, v in (headers or {}).items():
        cmd[1:1] = ["-H", f"{k}: {v}"]
    subprocess.run(cmd, check=False)


def ransomware_live():
    today = date.today()
    for y in range(2020, today.year + 1):
        for m in range(1, 13):
            if (y, m) > (today.year, today.month):
                break
            recent = (y, m) >= ((today.year, today.month - 1) if today.month > 1 else (today.year - 1, 12))
            get(f"https://api.ransomware.live/v2/victims/{y}/{m:02d}", RAW / "ransomware_live" / f"{y}-{m:02d}.json", force=recent)
            time.sleep(1.5)


TICKERS = ["CIBR", "HACK", "BUG", "IHAK", "QQQ", "SPY", "CRWD", "PANW", "FTNT", "ZS", "NET", "S", "OKTA", "CHKP", "TENB", "RPD", "QLYS"]


def prices():
    for t in TICKERS:
        get(f"https://query1.finance.yahoo.com/v8/finance/chart/{t}?range=max&interval=1mo&events=div%2Csplit", RAW / "prices" / f"{t}.json", force=True, ua="Mozilla/5.0")
        time.sleep(1)


def msrc():
    idx = RAW / "msrc" / "updates.json"
    get("https://api.msrc.microsoft.com/cvrf/v3.0/updates", idx, force=True, headers={"Accept": "application/json"})
    for u in json.loads(idx.read_text())["value"]:
        get(u["CvrfUrl"], RAW / "msrc" / f"{u['ID']}.json", headers={"Accept": "application/json"})


def trackers():
    b = RAW / "berkeley" / "index.html"
    get("https://vuln.cs.berkeley.edu/", b, force=True)
    blocks = re.findall(r"<script[^>]*>(.*?)</script>", b.read_text(), re.S)
    data = next(json.loads(x) for x in blocks if x.strip().startswith("{"))
    (RAW / "berkeley" / "embedded.json").write_text(json.dumps(data))
    for f in ("payload", "ledger"):
        get(f"https://red.anthropic.com/2026/cvd/data/{f}.json", RAW / "anthropic_cvd" / f"{f}.json", force=True)
    for f in ("cves.yaml", "keywords.yaml"):
        get(f"https://raw.githubusercontent.com/patrickmgarrity/Anthropic-Credited-CVEs/main/{f}", RAW / "anthropic_cves" / f, force=True)


OPENALEX_QUERIES = {
    "llm_security": '"large language model" AND (vulnerability OR exploit OR "penetration testing" OR fuzzing OR malware OR "vulnerability detection")',
    "llm_all": '"large language model"',
    "ml_vuln": '("machine learning" OR "deep learning") AND ("vulnerability detection" OR fuzzing OR "penetration testing")',
}


def openalex():
    """Yearly counts of research papers (OpenAlex, title+abstract search). No key; anonymous shared quota."""
    import urllib.parse

    for name, q in OPENALEX_QUERIES.items():
        f = urllib.parse.quote(f"title_and_abstract.search:{q},publication_year:2015-{date.today().year}", safe=":,")
        get(f"https://api.openalex.org/works?filter={f}&group_by=publication_year", RAW / "openalex" / f"{name}.json", force=True)
        time.sleep(1)


def pocs():
    """nomi-sec/PoC-in-GitHub: GitHub repositories that publish exploit code per CVE (shallow clone, about 75 MB)."""
    import subprocess

    dest = RAW / "poc_github" / "repo"
    if dest.exists():
        subprocess.run(["git", "-C", str(dest), "pull", "-q", "--depth", "1"], check=False)
    else:
        dest.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "clone", "-q", "--depth", "1", "https://github.com/nomi-sec/PoC-in-GitHub.git", str(dest)], check=True)


def epss_history():
    """EPSS snapshots on the first day of each month since 2023 (used by the triage backtest)."""
    d = date(2023, 1, 1)
    while d <= date.today():
        name = f"epss_{d.isoformat()}.csv.gz"
        get(f"https://epss.empiricalsecurity.com/epss_scores-{d.isoformat()}.csv.gz", RAW / "epss" / name)
        if not (RAW / "epss" / name).exists():  # a few days are missing upstream; take the next day
            alt = d.replace(day=2)
            get(f"https://epss.empiricalsecurity.com/epss_scores-{alt.isoformat()}.csv.gz", RAW / "epss" / f"epss_{alt.isoformat()}.csv.gz")
        d = date(d.year + (d.month == 12), d.month % 12 + 1, 1)


def worldbank():
    for ind, name in (("SP.POP.TOTL", "pop_2024"), ("NY.GDP.MKTP.CD", "gdp_2024")):
        get(f"https://api.worldbank.org/v2/country/all/indicator/{ind}?date=2024&format=json&per_page=400", RAW / "worldbank" / f"{name}.json")


def unzip_cvelist():
    outer = RAW / "cvelist" / "cvelist.zip.zip"
    if outer.exists() and not (RAW / "cvelist" / "cves.zip").exists():
        with zipfile.ZipFile(outer) as z:
            z.extractall(RAW / "cvelist")


if __name__ == "__main__":
    for fn in (unzip_cvelist, trackers, prices, msrc, ransomware_live, openalex, pocs, epss_history, worldbank):
        print(f"[{fn.__name__}]")
        fn()
