"""Ransomware leak-site victim posts from the public ransomware.live API.

Input:  ``data/raw/ransomwarelive/YYYY-MM.json`` (``/v2/victims/{year}/{month}``)
Output tables:
    ransomware_by_month   unique victim posts per month (by ``discovered`` date)
    ransomware_by_year    unique victim posts and active groups per year
    ransomware_groups     the most active groups in the latest full year

Leak-site posts are claims by criminals, not confirmed incidents: some victims
never get posted (they paid), some posts are fake or recycled. Posts are
de-duplicated on (group, victim name). Trackers disagree by several percent.

ransomware.live started systematic tracking in September 2021 (that month holds
a bulk backfill), so only posts from ``COVERAGE_START`` onward are counted.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import date
from pathlib import Path

import pandas as pd

from pipeline.common import get_logger, month_key, parse_date

log = get_logger("ransomware")

COVERAGE_START = date(2022, 1, 1)


def load_posts(folder: Path) -> list[dict]:
    posts: list[dict] = []
    for path in sorted(folder.glob("[0-9][0-9][0-9][0-9]-[0-9][0-9].json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            log.warning("unreadable %s", path.name)
            continue
        if isinstance(data, list):
            posts.extend(p for p in data if isinstance(p, dict))
    return posts


def victim_name(post: dict) -> str:
    for key in ("victim", "post_title", "domain"):
        val = post.get(key)
        if val:
            return str(val).strip().lower()
    return ""


def process(posts: list[dict], as_of: date | None = None, start: date = COVERAGE_START) -> dict[str, pd.DataFrame]:
    seen: set[tuple[str, str]] = set()
    by_month: Counter = Counter()
    groups_year: dict[int, Counter] = defaultdict(Counter)
    for post in posts:
        d = parse_date(post.get("discovered") or post.get("attackdate"))
        group = str(post.get("group") or post.get("group_name") or "").strip().lower()
        name = victim_name(post)
        if d is None or not name or d < start or (as_of and d > as_of):
            continue
        key = (group, name)
        if key in seen:
            continue
        seen.add(key)
        by_month[month_key(d)] += 1
        groups_year[d.year][group] += 1
    months = sorted(by_month)
    month_df = pd.DataFrame({"month": months, "victims": [by_month[m] for m in months]})
    years = sorted(groups_year)
    year_df = pd.DataFrame(
        {
            "year": years,
            "victims": [sum(groups_year[y].values()) for y in years],
            "active_groups": [len(groups_year[y]) for y in years],
        }
    )
    full_years = [y for y in years if not as_of or y < as_of.year]
    top_year = full_years[-1] if full_years else (years[-1] if years else None)
    group_rows = []
    if top_year is not None:
        for g, n in groups_year[top_year].most_common(10):
            group_rows.append({"year": top_year, "group": g, "victims": n})
    groups_df = pd.DataFrame(group_rows, columns=["year", "group", "victims"])
    return {"ransomware_by_month": month_df, "ransomware_by_year": year_df, "ransomware_groups": groups_df}


def build(raw_dir: Path, as_of: date | None = None) -> dict[str, pd.DataFrame] | None:
    folder = raw_dir / "ransomwarelive"
    if not folder.exists():
        log.warning("no ransomware.live files, skipping")
        return None
    posts = load_posts(folder)
    log.info("ransomware.live posts loaded: %d", len(posts))
    return process(posts, as_of=as_of) if posts else None
