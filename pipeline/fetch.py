"""Download raw datasets into data/raw/.

Usage:
    .venv/bin/python pipeline/fetch.py            # everything
    .venv/bin/python pipeline/fetch.py kev epss   # selected sources

Every source is public and needs no API key. Large files are skipped when they
already exist (delete them to refresh).
"""

from __future__ import annotations

import re
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


def latest_release(repo: str) -> dict:
    """Return the latest GitHub release metadata (public API, no token needed)."""
    resp = requests.get(f"https://api.github.com/repos/{repo}/releases/latest", headers=UA, timeout=60)
    resp.raise_for_status()
    return resp.json()


def src_cvelist():
    """Full CVE List (CVE JSON 5) from the CVE Program, all records incl. ADP data."""
    rel = latest_release("CVEProject/cvelistV5")
    asset = next(a for a in rel["assets"] if a["name"].endswith("all_CVEs_at_midnight.zip.zip"))
    download(asset["browser_download_url"], RAW / "cvelist" / "cvelist.zip.zip")
    (RAW / "cvelist" / "RELEASE.txt").write_text(rel["tag_name"])


def src_nvd():
    """NVD CVE 2.0 data via the fkie-cad/nvd-json-data-feeds mirror (xz, served by GitHub).

    The official nvd.nist.gov feed host is heavily throttled (minutes per file),
    so the default uses this daily rebuilt mirror of the same NVD API 2.0 records.
    Files are grouped by CVE ID year; processing uses the `published` field.
    """
    rel = latest_release("fkie-cad/nvd-json-data-feeds")
    for asset in rel["assets"]:
        if re.fullmatch(r"CVE-\d{4}\.json\.xz", asset["name"]):
            download(asset["browser_download_url"], RAW / "nvd" / asset["name"], force=True)
    (RAW / "nvd" / "RELEASE.txt").write_text(rel["tag_name"])


def src_nvd_official():
    """NVD CVE 2.0 yearly JSON feeds straight from nvd.nist.gov (slow, kept as fallback)."""
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


def src_ransomwarelive():
    """Ransomware leak-site victim posts per month from the public ransomware.live API (v2)."""
    from datetime import date

    today = date.today()
    for year in range(2020, today.year + 1):
        for month in range(1, 13):
            if (year, month) > (today.year, today.month):
                break
            dest = RAW / "ransomwarelive" / f"{year}-{month:02d}.json"
            current = (year, month) >= ((today.year, today.month - 1) if today.month > 1 else (today.year - 1, 12))
            try:
                download(f"https://api.ransomware.live/v2/victims/{year}/{month:02d}", dest, force=current)
            except subprocess.CalledProcessError:
                print(f"  ! ransomware.live {year}-{month:02d} not available")
            time.sleep(1)


SOURCES = {
    "kev": src_kev,
    "epss": src_epss,
    "hibp": src_hibp,
    "exploitdb": src_exploitdb,
    "metasploit": src_metasploit,
    "nuclei": src_nuclei,
    "p0": src_p0,
    "ransomwarelive": src_ransomwarelive,
    "osv": src_osv,
    "nvd": src_nvd,
    "nvd_official": src_nvd_official,
    "cvelist": src_cvelist,
}

OPT_IN = {"osv", "nvd_official"}


if __name__ == "__main__":
    # osv (package advisories, not used by the story yet) and nvd_official (slow) are opt-in.
    wanted = sys.argv[1:] or [k for k in SOURCES if k not in OPT_IN]
    for name in wanted:
        print(f"[{name}]")
        try:
            SOURCES[name]()
        except Exception as exc:  # keep going, report at the end
            print(f"  ! {name} failed: {exc}")
