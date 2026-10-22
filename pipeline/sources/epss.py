"""FIRST EPSS (Exploit Prediction Scoring System) daily scores.

Input:  ``data/raw/epss/epss_current.csv.gz`` (first line is a ``#model_version`` comment)
Output tables:
    epss_buckets   how many CVEs fall in each probability bucket (log-spaced)
    epss_summary   one row: model version, score date, total CVEs, counts above thresholds
"""

from __future__ import annotations

import re
from pathlib import Path

import pandas as pd

from pipeline.common import get_logger, open_maybe_compressed

log = get_logger("epss")

# Bucket edges for "probability of exploitation activity in the next 30 days".
EDGES = [0.0, 0.001, 0.01, 0.1, 0.5, 1.0000001]
LABELS = ["< 0.1%", "0.1% to 1%", "1% to 10%", "10% to 50%", ">= 50%"]


def read_scores(path: Path) -> tuple[pd.DataFrame, dict[str, str]]:
    with open_maybe_compressed(path) as fh:
        first = fh.readline()
        meta = dict(re.findall(r"([a-z_]+):([^,\s]+)", first)) if first.startswith("#") else {}
        if not first.startswith("#"):
            fh.seek(0)
        df = pd.read_csv(fh)
    return df, meta


def process(df: pd.DataFrame, meta: dict[str, str]) -> dict[str, pd.DataFrame]:
    scores = df["epss"].astype(float)
    cut = pd.cut(scores, bins=EDGES, labels=LABELS, right=False)
    counts = cut.value_counts().reindex(LABELS, fill_value=0)
    buckets = pd.DataFrame({"bucket": LABELS, "cves": counts.values.astype(int)})
    summary = pd.DataFrame(
        [
            {
                "model_version": meta.get("model_version", ""),
                "score_date": meta.get("score_date", "")[:10],
                "cves_scored": int(len(scores)),
                "above_10pct": int((scores >= 0.1).sum()),
                "above_50pct": int((scores >= 0.5).sum()),
                "share_above_10pct": round(float((scores >= 0.1).mean()), 4),
            }
        ]
    )
    return {"epss_buckets": buckets, "epss_summary": summary}


def build(raw_dir: Path) -> dict[str, pd.DataFrame] | None:
    path = raw_dir / "epss" / "epss_current.csv.gz"
    if not path.exists():
        log.warning("no EPSS file, skipping")
        return None
    df, meta = read_scores(path)
    log.info("EPSS scores: %d (model %s)", len(df), meta.get("model_version"))
    return process(df, meta)
