"""Bundle clean tables, manual tables and the cooked index into ``story.json``.

Usage:
    python -m pipeline.export

Reads only committed files (``data/clean/*.csv``, ``data/clean/meta.json`` and
``data/manual/*.csv``), so the site can be rebuilt without any raw download.
"""

from __future__ import annotations

import json
import math
import sys
from pathlib import Path as _Path

if __package__ in (None, ""):  # allow `python pipeline/export.py` as well as `python -m pipeline.export`
    sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))

from datetime import date, datetime, timezone
from pathlib import Path

import pandas as pd

from pipeline import indicators, manual
from pipeline.common import BASELINE_YEARS, CLEAN, MANUAL, SITE_DATA, START_YEAR, get_logger, write_csv
from pipeline.registry import AUTOMATED_SOURCES

log = get_logger("export")

# Clean tables produced by build.py; indicators.csv is produced here.
DERIVED = {"indicators"}


def _clean_value(v):
    if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
        return None
    if hasattr(v, "item"):  # numpy scalar
        return _clean_value(v.item())
    return v


def records(df: pd.DataFrame) -> list[dict]:
    return [{k: _clean_value(v) for k, v in row.items()} for row in df.to_dict(orient="records")]


def read_meta(clean_dir: Path) -> dict:
    path = clean_dir / "meta.json"
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    return {}


def load_clean(clean_dir: Path) -> dict[str, pd.DataFrame]:
    return {p.stem: pd.read_csv(p) for p in sorted(clean_dir.glob("*.csv")) if p.stem not in DERIVED}


def build_story(clean_dir: Path = CLEAN, manual_dir: Path = MANUAL) -> tuple[dict, pd.DataFrame, list[str]]:
    tables = load_clean(clean_dir)
    metrics, milestones, problems = manual.load(manual_dir)
    meta = read_meta(clean_dir)
    as_of = date.fromisoformat(meta.get("as_of", date.today().isoformat()))
    ind_table, summary = indicators.compute(indicators.default_indicators(tables, metrics), as_of)

    manual_out: dict[str, list[dict]] = {}
    for metric, df in metrics.groupby("metric", sort=True):
        cols = ["year", "value", "unit", "kind", "source", "source_url", "note"]
        manual_out[metric] = records(df.sort_values("year")[cols])
    manual_sources = (
        metrics[["source", "source_url"]].drop_duplicates().sort_values("source").to_dict(orient="records")
        if not metrics.empty
        else []
    )
    milestone_sources = milestones[["source", "source_url"]].drop_duplicates().to_dict(orient="records")

    story = {
        "meta": {
            "title": "AreWeCooked?",
            "as_of": as_of.isoformat(),
            "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
            "start_year": START_YEAR,
            "partial_year": as_of.year,
            "baseline_years": list(BASELINE_YEARS),
            "sources_built": meta.get("sources", {}),
        },
        "sources": {
            "automated": AUTOMATED_SOURCES,
            "manual": manual_sources,
            "milestones": milestone_sources,
        },
        "datasets": {name: records(df) for name, df in tables.items()},
        "manual": manual_out,
        "milestones": records(milestones.sort_values("date")) if not milestones.empty else [],
        "index": {"indicators": records(ind_table), "summary": summary},
    }
    return story, ind_table, problems


def main(argv: list[str] | None = None) -> int:
    story, ind_table, problems = build_story()
    if problems:
        for p in problems:
            log.error(p)
        return 1
    write_csv(ind_table, "indicators")
    SITE_DATA.mkdir(parents=True, exist_ok=True)
    out = SITE_DATA / "story.json"
    out.write_text(json.dumps(story, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    s = story["index"]["summary"]
    log.info("wrote %s (%d datasets, verdict: %s, ratio %s)", out, len(story["datasets"]), (s.get("verdict") or {}).get("label"), s.get("ratio"))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
