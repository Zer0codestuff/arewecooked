"""Who finds the bugs: people, organizations and AI systems named in CVE credits (2023 on, when credits became common).

Inputs : data/interim/cves.parquet, data/clean/ai_attributed_cves.csv
Outputs: site/public/data/credits.json, data/clean/credits_yearly.csv
Individual names are used only to count distinct finders; none are published.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from _common import AS_OF, CLEAN, INTERIM, records, write_clean_csv, write_site_json  # noqa: E402
from ai_patterns import AI_FINDERS  # noqa: E402

SKIP_TYPES = {"coordinator", "remediation developer", "remediation reviewer", "remediation verifier", "sponsor", "analyst", "other"}
ORG = re.compile(r"bug bounty|wpscan|vuldb|patchstack|wordfence|\bcert\b|\bteam\b|zero day initiative|trend micro|security research$|vulncheck|"
                 r"huntr|\bcna\b|hackerone|bugcrowd|intigriti|yeswehack|github security lab|project zero|\blab(s)?\b|security$|inc\.?$|ltd\.?$|gmbh$", re.I)
TYPE = re.compile(r"\s*\[([a-z ]*)\]\s*$")
SPLIT = re.compile(r"\s*\(|,|\s+of\s+|\s+from\s+|\s+at\s+|\s+with\s+")


def main():
    df = pd.read_parquet(INTERIM / "cves.parquet", columns=["cve_id", "state", "date_published", "credits"])
    df = df[df.state == "PUBLISHED"].copy()
    df["published"] = pd.to_datetime(df.date_published, utc=True).dt.tz_convert(None)
    df = df[(df.published >= "2023-01-01") & (df.published <= pd.Timestamp(AS_OF) + pd.Timedelta(days=1))]
    df["year"] = df.published.dt.year
    df["month"] = df.published.dt.to_period("M").dt.to_timestamp()
    ai_ids = set(pd.read_csv(CLEAN / "ai_attributed_cves.csv").cve_id)
    df["ai"] = df.cve_id.isin(ai_ids)

    rows = []
    for r in df[df.credits.notna()].itertuples():
        for part in r.credits.split(" | "):
            part = part.strip()
            m = TYPE.search(part)
            typ = m.group(1).strip() if m else ""
            name = TYPE.sub("", part).strip()
            if not name or typ in SKIP_TYPES or len(name) > 80:
                continue
            base = SPLIT.split(name)[0].strip().lower()
            if len(base) < 3:
                continue
            kind = "ai" if any(p.search(name) for _, p in AI_FINDERS) else ("org" if ORG.search(base) else "person")
            rows.append((r.cve_id, r.year, base, kind))
    c = pd.DataFrame(rows, columns=["cve_id", "year", "name", "kind"])
    people = c[c.kind == "person"]

    yearly = []
    for y in range(2023, AS_OF.year + 1):
        d = df[df.year == y]
        p = people[people.year == y]
        vc = p.name.value_counts()
        yearly.append({
            "year": y,
            "cves": int(len(d)),
            "credited": int(d.credits.notna().sum()),
            "person_credited": int(p.cve_id.nunique()),
            "ai_credited": int(d.ai.sum()),
            "distinct_people": int(p.name.nunique()),
            "new_people": 0,
            "one_off_share": float((vc == 1).mean()) if len(vc) else None,
        })
    yearly = pd.DataFrame(yearly)
    seen: set[str] = set()
    for i, y in enumerate(yearly.year):
        names = set(people[people.year == y].name)
        yearly.loc[i, "new_people"] = len(names - seen)
        seen |= names
    yearly["credited_share"] = yearly.credited / yearly.cves
    yearly["ai_share_of_credited"] = yearly.ai_credited / yearly.credited

    monthly = df[df.month >= "2024-01-01"].groupby("month").agg(cves=("cve_id", "count"), credited=("credits", lambda s: int(s.notna().sum())), ai=("ai", "sum")).reset_index()
    pm = people.merge(df[["cve_id", "month"]], on="cve_id")
    monthly = monthly.merge(pm.groupby("month").name.nunique().rename("people").reset_index(), on="month", how="left").fillna({"people": 0})
    monthly[["ai", "people"]] = monthly[["ai", "people"]].astype(int)

    write_clean_csv("credits_yearly", yearly)
    write_site_json("credits", {"yearly": records(yearly), "monthly": records(monthly)})
    print(yearly.round(3).to_string())


if __name__ == "__main__":
    main()
