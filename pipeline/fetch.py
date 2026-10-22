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
    cmd = ["curl", "-sSL", "--fail", "--retry", "5", "--retry-delay", "3", "-A", UA["User-Agent"], "-o", str(dest), url]
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


SOURCES = {
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
