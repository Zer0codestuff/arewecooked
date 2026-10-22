"""Hand-curated tables in ``data/manual/`` (numbers transcribed from published reports).

Two layouts are supported:
    * metric tables: ``metric,year,value,unit,kind,source,source_url,note``
    * the AI milestone timeline: ``date,side,title,detail,figure,source,source_url``

Every row must carry an http(s) source URL. ``validate`` returns a list of
problems instead of raising, so the build can report all of them at once.
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd

from pipeline.common import MANUAL, get_logger

log = get_logger("manual")

METRIC_COLUMNS = ["metric", "year", "value", "unit", "kind", "source", "source_url", "note"]
MILESTONE_COLUMNS = ["date", "side", "title", "detail", "figure", "source", "source_url"]
MILESTONE_SIDES = {"defense", "offense", "ecosystem"}


def validate_metrics(df: pd.DataFrame, name: str) -> list[str]:
    problems: list[str] = []
    missing = [c for c in METRIC_COLUMNS if c not in df.columns]
    if missing:
        return [f"{name}: missing columns {missing}"]
    for i, row in df.iterrows():
        where = f"{name} row {i + 2}"
        if not str(row["source_url"]).startswith(("http://", "https://")):
            problems.append(f"{where}: source_url must be an http(s) URL")
        if not str(row["source"]).strip() or str(row["source"]) == "nan":
            problems.append(f"{where}: empty source")
        try:
            year = int(row["year"])
            if not 1990 <= year <= 2100:
                problems.append(f"{where}: implausible year {year}")
        except (TypeError, ValueError):
            problems.append(f"{where}: year is not an integer")
        try:
            float(row["value"])
        except (TypeError, ValueError):
            problems.append(f"{where}: value is not numeric")
    dupes = df[df.duplicated(subset=["metric", "year", "note"], keep=False)]
    if not dupes.empty:
        problems.append(f"{name}: duplicated metric/year rows {dupes[['metric', 'year']].values.tolist()}")
    return problems


def validate_milestones(df: pd.DataFrame, name: str) -> list[str]:
    problems: list[str] = []
    missing = [c for c in MILESTONE_COLUMNS if c not in df.columns]
    if missing:
        return [f"{name}: missing columns {missing}"]
    for i, row in df.iterrows():
        where = f"{name} row {i + 2}"
        if row["side"] not in MILESTONE_SIDES:
            problems.append(f"{where}: side must be one of {sorted(MILESTONE_SIDES)}")
        if not str(row["source_url"]).startswith(("http://", "https://")):
            problems.append(f"{where}: source_url must be an http(s) URL")
        if pd.isna(pd.to_datetime(row["date"], errors="coerce")):
            problems.append(f"{where}: bad date {row['date']}")
    return problems


def load(manual_dir: Path | None = None) -> tuple[pd.DataFrame, pd.DataFrame, list[str]]:
    """Return (metrics in long format, milestones, problems)."""
    manual_dir = manual_dir or MANUAL
    frames: list[pd.DataFrame] = []
    milestones = pd.DataFrame(columns=MILESTONE_COLUMNS)
    problems: list[str] = []
    for path in sorted(manual_dir.glob("*.csv")):
        df = pd.read_csv(path)
        if "metric" in df.columns:
            problems += validate_metrics(df, path.name)
            df["file"] = path.name
            frames.append(df)
        elif "side" in df.columns:
            problems += validate_milestones(df, path.name)
            milestones = df
        else:
            problems.append(f"{path.name}: unknown layout")
    metrics = pd.concat(frames, ignore_index=True) if frames else pd.DataFrame(columns=METRIC_COLUMNS + ["file"])
    if not metrics.empty:
        # Invalid rows were already reported above; drop them so callers get clean types.
        metrics["year"] = pd.to_numeric(metrics["year"], errors="coerce")
        metrics["value"] = pd.to_numeric(metrics["value"], errors="coerce")
        metrics = metrics.dropna(subset=["year", "value"]).reset_index(drop=True)
        metrics["year"] = metrics["year"].astype(int)
        metrics["value"] = metrics["value"].astype(float)
    log.info("manual metrics: %d rows, milestones: %d, problems: %d", len(metrics), len(milestones), len(problems))
    return metrics, milestones, problems


def series(metrics: pd.DataFrame, metric: str) -> pd.DataFrame:
    """One metric as a tidy (year, value) frame sorted by year."""
    df = metrics[metrics["metric"] == metric][["year", "value"]]
    return df.sort_values("year").reset_index(drop=True)
