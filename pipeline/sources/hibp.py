"""Have I Been Pwned public breach catalog.

Input:  ``data/raw/hibp/breaches.json``
Output tables:
    breaches_by_year   verified, non-fabricated, non-spam breaches by breach year:
                       number of breaches and accounts exposed
    breaches_largest   the 15 largest breaches since START_YEAR
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

import pandas as pd

from pipeline.common import START_YEAR, get_logger, parse_date, read_json

log = get_logger("hibp")


def usable(b: dict) -> bool:
    return bool(b.get("IsVerified")) and not b.get("IsFabricated") and not b.get("IsSpamList")


def process(breaches: list[dict], start_year: int = START_YEAR) -> dict[str, pd.DataFrame]:
    count: Counter = Counter()
    accounts: Counter = Counter()
    keep = []
    for b in breaches:
        if not usable(b):
            continue
        d = parse_date(b.get("BreachDate"))
        if d is None or d.year < start_year:
            continue
        count[d.year] += 1
        accounts[d.year] += int(b.get("PwnCount") or 0)
        keep.append({"name": b.get("Title") or b.get("Name"), "breach_date": d.isoformat(), "accounts": int(b.get("PwnCount") or 0)})
    years = sorted(count)
    by_year = pd.DataFrame({"year": years, "breaches": [count[y] for y in years], "accounts": [accounts[y] for y in years]})
    largest = pd.DataFrame(sorted(keep, key=lambda r: r["accounts"], reverse=True)[:15], columns=["name", "breach_date", "accounts"])
    return {"breaches_by_year": by_year, "breaches_largest": largest}


def build(raw_dir: Path) -> dict[str, pd.DataFrame] | None:
    path = raw_dir / "hibp" / "breaches.json"
    if not path.exists():
        log.warning("no HIBP file, skipping")
        return None
    return process(read_json(path))
