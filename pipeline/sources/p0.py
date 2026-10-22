"""Google Project Zero "0day In the Wild" tracking sheet.

Input:  ``data/raw/p0/YYYY.csv`` (one tab per year, exported as CSV)
Output tables:
    zeroday_by_year    in-the-wild zero-days per year (rows with a CVE id)
    zeroday_vendors    vendors with the most in-the-wild zero-days since START_YEAR
"""

from __future__ import annotations

import csv
import re
from collections import Counter
from pathlib import Path

import pandas as pd

from pipeline.common import START_YEAR, get_logger

log = get_logger("p0")

_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")


def read_tab(path: Path) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    return [r for r in rows if _CVE.match((r.get("CVE") or "").strip())]


def process(tabs: dict[int, list[dict]], start_year: int = START_YEAR) -> dict[str, pd.DataFrame]:
    years = sorted(y for y in tabs if y >= start_year)
    by_year = pd.DataFrame({"year": years, "zero_days": [len({r["CVE"].strip() for r in tabs[y]}) for y in years]})
    vendors: Counter = Counter()
    for y in years:
        for r in tabs[y]:
            vendors[(r.get("Vendor") or "Unknown").strip()] += 1
    vendor_df = pd.DataFrame(vendors.most_common(12), columns=["vendor", "zero_days"])
    return {"zeroday_by_year": by_year, "zeroday_vendors": vendor_df}


def build(raw_dir: Path) -> dict[str, pd.DataFrame] | None:
    folder = raw_dir / "p0"
    files = sorted(folder.glob("[0-9][0-9][0-9][0-9].csv")) if folder.exists() else []
    if not files:
        log.warning("no Project Zero sheet tabs, skipping")
        return None
    tabs = {int(f.stem): read_tab(f) for f in files}
    return process(tabs)
