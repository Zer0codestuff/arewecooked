"""Download raw datasets into data/raw/.

Usage:
    .venv/bin/python pipeline/fetch.py            # everything
    .venv/bin/python pipeline/fetch.py kev epss   # selected sources

Every source is public and needs no API key. Large files are skipped when they
already exist (delete them to refresh).
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data" / "raw"
UA = {"User-Agent": "arewecooked-data-pipeline/0.1 (research project)"}


def download(url: str, dest: Path, force: bool = False, headers: dict | None = None) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists() and dest.stat().st_size > 0 and not force:
        print(f"  skip {dest.relative_to(ROOT)} (exists)")
        return dest
    print(f"  get  {url}")
    # curl handles big files, retries and redirects well
    cmd = ["curl", "--http1.1", "-sSL", "--fail", "--retry", "5", "--retry-delay", "3", "-A", UA["User-Agent"], "-o", str(dest), url]
    for k, v in (headers or {}).items():
        cmd[1:1] = ["-H", f"{k}: {v}"]
    subprocess.run(cmd, check=True)
    return dest


def src_cvelist():
    """Full CVE List (CVE JSON 5) from the CVE Program, all records incl. ADP data."""
    rel = json.loads(subprocess.check_output(["gh", "api", "repos/CVEProject/cvelistV5/releases/latest"]))
    asset = next(a for a in rel["assets"] if a["name"].endswith("all_CVEs_at_midnight.zip.zip"))
    download(asset["browser_download_url"], RAW / "cvelist" / "cvelist.zip.zip")
    (RAW / "cvelist" / "RELEASE.txt").write_text(rel["tag_name"])


def src_nvd():
    """NVD CVE 2.0 yearly JSON feeds (NVD analysis status, CVSS, CWE, CPE)."""
    for year in range(2002, 2027):
        download(f"https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.gz", RAW / "nvd" / f"nvdcve-2.0-{year}.json.gz")
        time.sleep(1)


def src_kev():
    download("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", RAW / "kev" / "kev.json", force=True)


def src_epss():
    download("https://epss.empiricalsecurity.com/epss_scores-current.csv.gz", RAW / "epss" / "epss_current.csv.gz", force=True)


def src_exploitdb():
    download("https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv", RAW / "exploitdb" / "files_exploits.csv")


def src_metasploit():
    download(
        "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json",
        RAW / "metasploit" / "modules_metadata_base.json",
    )


def src_nuclei():
    download("https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json", RAW / "nuclei" / "cves.json")


OSV_ECOSYSTEMS = ["npm", "PyPI", "crates.io", "Go", "Maven", "RubyGems", "NuGet", "Packagist"]


def src_osv():
    for eco in OSV_ECOSYSTEMS:
        download(f"https://osv-vulnerabilities.storage.googleapis.com/{eco}/all.zip", RAW / "osv" / f"{eco}.zip")


def src_hibp():
    download("https://haveibeenpwned.com/api/v3/breaches", RAW / "hibp" / "breaches.json", force=True)


def src_p0():
    """Google Project Zero '0day In the Wild' tracking sheet (public Google Sheet)."""
    sheet = "1lkNJ0uQwbeC1ZTRrxdtuPLCIl7mlUreoKfSIgajnSyY"
    for year in range(2014, 2027):
        url = f"https://docs.google.com/spreadsheets/d/{sheet}/gviz/tq?tqx=out:csv&sheet={year}"
        try:
            download(url, RAW / "p0" / f"{year}.csv", force=True)
        except subprocess.CalledProcessError:
            print(f"  ! p0 {year} not available")


def src_ransomware():
    """ransomware.live: victims claimed on ransomware leak sites, month by month."""
    from datetime import date

    today = date.today()
    for year in range(2020, today.year + 1):
        for month in range(1, 13):
            if (year, month) > (today.year, today.month):
                break
            dest = RAW / "ransomware_live" / f"{year}-{month:02d}.json"
            current = (year, month) >= (today.year, today.month - 1)
            try:
                download(f"https://api.ransomware.live/v2/victims/{year}/{month:02d}", dest, force=current)
            except subprocess.CalledProcessError:
                print(f"  ! ransomware.live {year}-{month:02d} failed")
            time.sleep(1.5)


TICKERS = [
    # cybersecurity ETFs
    "CIBR", "HACK", "BUG", "IHAK",
    # benchmarks
    "QQQ", "SPY",
    # listed security vendors
    "CRWD", "PANW", "FTNT", "ZS", "NET", "S", "OKTA", "CHKP", "CYBR", "TENB", "RPD", "QLYS",
]


def src_prices():
    """Monthly adjusted prices from Yahoo Finance chart API."""
    for t in TICKERS:
        url = f"https://query1.finance.yahoo.com/v8/finance/chart/{t}?range=max&interval=1mo&events=div%2Csplit"
        dest = RAW / "prices" / f"{t}.json"
        dest.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["curl", "-sSL", "--fail", "-A", "Mozilla/5.0", "-o", str(dest), url], check=False)
        time.sleep(1)


def src_msrc():
    """Microsoft Security Response Center CVRF: every monthly security update."""
    idx = RAW / "msrc" / "updates.json"
    download("https://api.msrc.microsoft.com/cvrf/v3.0/updates", idx, force=True, headers={"Accept": "application/json"})
    for u in json.loads(idx.read_text())["value"]:
        download(u["CvrfUrl"], RAW / "msrc" / f"{u['ID']}.json", headers={"Accept": "application/json"})


SOURCES = {
    "ransomware": src_ransomware,
    "prices": src_prices,
    "msrc": src_msrc,
    "kev": src_kev,
    "epss": src_epss,
    "hibp": src_hibp,
    "exploitdb": src_exploitdb,
    "metasploit": src_metasploit,
    "nuclei": src_nuclei,
    "p0": src_p0,
    "osv": src_osv,
    "nvd": src_nvd,
    "cvelist": src_cvelist,
}


if __name__ == "__main__":
    wanted = sys.argv[1:] or list(SOURCES)
    for name in wanted:
        print(f"[{name}]")
        try:
            SOURCES[name]()
        except Exception as exc:  # keep going, report at the end
            print(f"  ! {name} failed: {exc}")
