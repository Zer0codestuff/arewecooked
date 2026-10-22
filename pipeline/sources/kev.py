"""CISA Known Exploited Vulnerabilities (KEV) catalog.

Input:  ``data/raw/kev/kev.json``
Output tables:
    kev_by_year     KEV additions per year, and how many are tied to ransomware
    kev_lag_year    for "fresh" CVEs (published since the catalog launched), the
                    median number of days between CVE publication and KEV listing,
                    and the share listed within 7 days
    kev_vendors     vendors with the most KEV entries (all time and last 3 years)

KEV launched in November 2021 with a backlog of old CVEs, so lag statistics only
use CVEs published on or after ``KEV_LAUNCH``; otherwise 2021 would be dominated
by decade-old bugs being added in bulk.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import date
from pathlib import Path

import pandas as pd

from pipeline.common import get_logger, median_or_none, parse_date, read_json

log = get_logger("kev")

KEV_LAUNCH = date(2021, 11, 3)


def load(raw_dir: Path) -> list[dict] | None:
    path = raw_dir / "kev" / "kev.json"
    if not path.exists():
        return None
    return read_json(path).get("vulnerabilities", [])


def process(entries: list[dict], published: dict[str, date] | None = None) -> dict[str, pd.DataFrame]:
    published = published or {}
    added: Counter = Counter()
    ransom: Counter = Counter()
    lags: dict[int, list[int]] = defaultdict(list)
    vendors_all: Counter = Counter()
    vendors_recent: Counter = Counter()
    latest_year = max((parse_date(e.get("dateAdded")) or date(1970, 1, 1)).year for e in entries) if entries else 0
    for e in entries:
        d = parse_date(e.get("dateAdded"))
        if d is None:
            continue
        added[d.year] += 1
        if str(e.get("knownRansomwareCampaignUse", "")).lower() == "known":
            ransom[d.year] += 1
        vendor = (e.get("vendorProject") or "Unknown").strip()
        vendors_all[vendor] += 1
        if d.year >= latest_year - 2:
            vendors_recent[vendor] += 1
        pub = published.get(e.get("cveID", ""))
        if pub and pub >= KEV_LAUNCH:
            lags[d.year].append((d - pub).days)

    years = sorted(added)
    kev_by_year = pd.DataFrame(
        {"year": years, "added": [added[y] for y in years], "ransomware_known": [ransom[y] for y in years]}
    )
    lag_rows = []
    for y in sorted(lags):
        vals = lags[y]
        lag_rows.append(
            {
                "year": y,
                "fresh_cves": len(vals),
                "median_days": median_or_none(vals),
                "share_within_7d": round(sum(1 for v in vals if v <= 7) / len(vals), 4),
                "share_same_day_or_before": round(sum(1 for v in vals if v <= 0) / len(vals), 4),
            }
        )
    kev_lag_year = pd.DataFrame(
        lag_rows, columns=["year", "fresh_cves", "median_days", "share_within_7d", "share_same_day_or_before"]
    )
    vendor_rows = [
        {"vendor": v, "all_time": n, "last_3_years": vendors_recent.get(v, 0)} for v, n in vendors_all.most_common(15)
    ]
    kev_vendors = pd.DataFrame(vendor_rows, columns=["vendor", "all_time", "last_3_years"])
    return {"kev_by_year": kev_by_year, "kev_lag_year": kev_lag_year, "kev_vendors": kev_vendors}


def build(raw_dir: Path, published: dict[str, date] | None = None) -> dict[str, pd.DataFrame] | None:
    entries = load(raw_dir)
    if entries is None:
        log.warning("no KEV file, skipping")
        return None
    if not published:
        log.warning("no NVD publication dates available: KEV lag table will be empty")
    log.info("KEV entries: %d", len(entries))
    return process(entries, published)
