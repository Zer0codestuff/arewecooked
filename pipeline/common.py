"""Shared paths and output helpers for pipeline steps."""

from __future__ import annotations

import json
import math
from datetime import date, datetime
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data" / "raw"
CLEAN = ROOT / "data" / "clean"
MANUAL = ROOT / "data" / "manual"
SITE_DATA = ROOT / "site" / "public" / "data"
INTERIM = ROOT / "data" / "interim"  # big intermediate parquet files (gitignored)

for p in (CLEAN, SITE_DATA, INTERIM):
    p.mkdir(parents=True, exist_ok=True)

# The snapshot date of the analysis. Partial-year values are flagged against it.
AS_OF = date(2026, 10, 22)


def _default(o):
    if isinstance(o, (datetime, date, pd.Timestamp)):
        return o.isoformat()[:10]
    if hasattr(o, "item"):
        return o.item()
    raise TypeError(type(o))


def _clean(o):
    if isinstance(o, float) and (math.isnan(o) or math.isinf(o)):
        return None
    if isinstance(o, dict):
        return {k: _clean(v) for k, v in o.items()}
    if isinstance(o, (list, tuple)):
        return [_clean(v) for v in o]
    return o


def write_site_json(name: str, payload: dict) -> None:
    """Write compact JSON consumed by the website."""
    payload = {"as_of": AS_OF.isoformat(), **payload}
    path = SITE_DATA / f"{name}.json"
    path.write_text(json.dumps(_clean(payload), default=_default, separators=(",", ":")))
    print(f"  wrote {path.relative_to(ROOT)} ({path.stat().st_size/1024:.1f} KB)")


def write_clean_csv(name: str, df: pd.DataFrame) -> None:
    """Write a tidy, documented CSV people can download and reuse."""
    path = CLEAN / f"{name}.csv"
    df.to_csv(path, index=False)
    print(f"  wrote {path.relative_to(ROOT)} ({len(df):,} rows)")


def records(df: pd.DataFrame) -> list[dict]:
    return json.loads(df.to_json(orient="records", date_format="iso"))
