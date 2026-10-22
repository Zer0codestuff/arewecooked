"""NVD (National Vulnerability Database) CVE records.

Input:  ``data/raw/nvd/CVE-YYYY.json.xz`` (fkie-cad mirror of the NVD API 2.0) or
        ``data/raw/nvd/nvdcve-2.0-YYYY.json.gz`` (official yearly feeds).
Output tables:
    cve_by_year        CVEs published per calendar year (excluding rejected)
    cve_by_month       same, per month
    cve_severity_year  CVSS severity mix per year (best available CVSS score)
    nvd_status_year    NVD analysis status per publication year (the 2024+ backlog)
It also returns ``published`` (CVE id -> publication date) for the KEV lag metric.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Iterator

import pandas as pd

from pipeline.common import START_YEAR, get_logger, month_key, parse_date, read_json

log = get_logger("nvd")

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]
# NVD vulnStatus values grouped into the buckets shown in the story.
STATUS_GROUPS = {
    "Analyzed": "analyzed",
    "Modified": "analyzed",
    "Awaiting Analysis": "waiting",
    "Received": "waiting",
    "Undergoing Analysis": "waiting",
    "Deferred": "deferred",
    "Rejected": "rejected",
}


def find_files(raw_dir: Path) -> list[Path]:
    nvd = raw_dir / "nvd"
    if not nvd.exists():
        return []
    files = sorted(nvd.glob("CVE-[0-9][0-9][0-9][0-9].json.xz"))
    if not files:
        files = sorted(nvd.glob("nvdcve-2.0-[0-9][0-9][0-9][0-9].json.gz"))
    return files


def iter_records(files: list[Path]) -> Iterator[dict]:
    """Yield raw NVD CVE objects from either feed layout."""
    for path in files:
        data = read_json(path)
        items = data.get("cve_items") or data.get("vulnerabilities") or []
        for item in items:
            yield item.get("cve", item)


def best_severity(metrics: dict) -> str | None:
    """Pick one severity per CVE: CVSS 3.1, then 3.0, then 4.0, then 2.0; NVD (Primary) first."""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if not entries:
            continue
        entries = sorted(entries, key=lambda m: 0 if m.get("type") == "Primary" else 1)
        entry = entries[0]
        sev = entry.get("cvssData", {}).get("baseSeverity") or entry.get("baseSeverity")
        if sev:
            return str(sev).upper()
    return None


@dataclass
class NvdResult:
    tables: dict[str, pd.DataFrame]
    published: dict[str, date] = field(default_factory=dict)


def process(files: list[Path], start_year: int = START_YEAR, as_of: date | None = None) -> NvdResult:
    by_year: Counter = Counter()
    rejected_year: Counter = Counter()
    by_month: Counter = Counter()
    sev_year: dict[int, Counter] = defaultdict(Counter)
    status_year: dict[int, Counter] = defaultdict(Counter)
    published: dict[str, date] = {}
    total = 0
    for cve in iter_records(files):
        total += 1
        pub = parse_date(cve.get("published"))
        if pub is None:
            continue
        status = cve.get("vulnStatus", "")
        cve_id = cve.get("id", "")
        published[cve_id] = pub
        if as_of and pub > as_of:
            continue
        group = STATUS_GROUPS.get(status, "other")
        if pub.year >= start_year:
            status_year[pub.year][group] += 1
        if group == "rejected":
            rejected_year[pub.year] += 1
            continue
        by_year[pub.year] += 1
        by_month[month_key(pub)] += 1
        sev = best_severity(cve.get("metrics") or {}) or "UNSCORED"
        sev_year[pub.year][sev] += 1
    log.info("parsed %d NVD records from %d files", total, len(files))

    years = [y for y in sorted(by_year) if y >= start_year]
    cve_by_year = pd.DataFrame(
        {"year": years, "cves": [by_year[y] for y in years], "rejected": [rejected_year[y] for y in years]}
    )
    months = [m for m in sorted(by_month) if int(m[:4]) >= start_year]
    cve_by_month = pd.DataFrame({"month": months, "cves": [by_month[m] for m in months]})
    sev_rows = []
    for y in years:
        row = {"year": y}
        for s in SEVERITIES + ["UNSCORED"]:
            row[s.lower()] = sev_year[y][s]
        sev_rows.append(row)
    cve_severity_year = pd.DataFrame(sev_rows)
    status_rows = []
    for y in sorted(status_year):
        c = status_year[y]
        status_rows.append({"year": y, **{g: c[g] for g in ["analyzed", "waiting", "deferred", "rejected", "other"]}})
    nvd_status_year = pd.DataFrame(status_rows)
    return NvdResult(
        tables={
            "cve_by_year": cve_by_year,
            "cve_by_month": cve_by_month,
            "cve_severity_year": cve_severity_year,
            "nvd_status_year": nvd_status_year,
        },
        published=published,
    )


def build(raw_dir: Path, as_of: date | None = None) -> NvdResult | None:
    files = find_files(raw_dir)
    if not files:
        log.warning("no NVD files in %s, skipping", raw_dir / "nvd")
        return None
    return process(files, as_of=as_of)
