"""Hand-curated report figures, the incident timeline and Anthropic's disclosure dashboard.

Inputs : data/manual/story/series.csv, data/manual/story/timeline.csv, data/manual/story/ai_releases.csv, data/raw/anthropic_cvd/payload.json
Outputs: site/public/data/context.json, site/public/data/glasswing.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from _common import MANUAL, RAW, records, write_clean_csv, write_site_json  # noqa: E402


def context():
    s = pd.read_csv(MANUAL / "story" / "series.csv")
    series = {}
    for name, sub in s.groupby("dataset"):
        series[name] = {
            "unit": sub.unit.iloc[0],
            "points": [{"year": int(r.year), "value": float(r.value), "note": r.note if isinstance(r.note, str) else None,
                        "source": r.source_name, "url": r.source_url} for r in sub.itertuples()],
        }
    t = pd.read_csv(MANUAL / "story" / "timeline.csv").sort_values("date")
    rel = pd.read_csv(MANUAL / "story" / "ai_releases.csv").fillna("").sort_values("date")
    write_site_json("context", {"series": series, "timeline": records(t), "releases": records(rel)})


def glasswing():
    p = json.loads((RAW / "anthropic_cvd" / "payload.json").read_text())
    h = p["headline"]
    funnel = [
        {"stage": "Found by Claude models", "n": h["analyzed"]},
        {"stage": "Reported to maintainers", "n": h["disclosed"]},
        {"stage": "Acknowledged by maintainers", "n": h["acknowledged"]},
        {"stage": "Patched upstream", "n": h["fixed_in_response"]},
        {"stage": "Got a CVE or GHSA ID", "n": h["advisories"]},
    ]
    led = pd.DataFrame(p["ledger"])
    led["discovered_on"] = pd.to_datetime(led.discovered_on, errors="coerce")
    led = led[led.discovered_on.notna()]
    led["week"] = led.discovered_on.dt.to_period("W-SUN").dt.start_time
    led["sev"] = led.claude_severity.fillna("unknown")
    weekly = led.pivot_table(index="week", columns="sev", values="hash", aggfunc="count", fill_value=0)
    weekly = weekly.reindex(columns=[c for c in ["critical", "high", "medium", "low", "unknown"] if c in weekly.columns], fill_value=0).reset_index()
    patched = led.groupby(led.discovered_on.dt.to_period("M").dt.to_timestamp()).agg(
        found=("hash", "count"), patched=("patched", "sum")
    ).reset_index().rename(columns={"discovered_on": "month"})
    classes = sorted(p["by_bug_class"].items(), key=lambda kv: -kv[1])[:12]
    eco = []
    for k, v in p["by_ecosystem"].items():
        eco.append({"ecosystem": k, **v, "total": sum(v.values())})
    eco.sort(key=lambda r: -r["total"])
    write_clean_csv("anthropic_cvd_ledger_weekly", weekly)
    write_site_json("glasswing", {
        "dashboard_as_of": p["as_of"][:10],
        "funnel": funnel,
        "projects": p["project_count"],
        "cves": h["cves"],
        "ghsas": h["ghsas"],
        "true_positive_rate": 0.927,
        "median_days_to_patch": p["median_days_to_patch"],
        "weekly": records(weekly),
        "monthly_patched": records(patched),
        "bug_classes": [{"cls": k, "n": v} for k, v in classes],
        "ecosystems": eco,
        "ledger_entries": int(len(led)),
    })


def main():
    context()
    glasswing()


if __name__ == "__main__":
    main()
