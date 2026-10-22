"""Shared paths, constants and small IO helpers for the pipeline."""

from __future__ import annotations

import gzip
import json
import logging
import lzma
import os
import re
from datetime import date, datetime
from pathlib import Path
from typing import Any, Iterable

import pandas as pd

ROOT = Path(os.environ.get("AWC_ROOT", Path(__file__).resolve().parents[1]))
RAW = ROOT / "data" / "raw"
CLEAN = ROOT / "data" / "clean"
MANUAL = ROOT / "data" / "manual"
SITE_DATA = ROOT / "site" / "public" / "data"

# The story covers 2015 to the present (late 2026 at the time of writing).
START_YEAR = 2015
# Baseline years for "how much has it grown" comparisons: the last pre-pandemic,
# pre-ChatGPT stretch.
BASELINE_YEARS = (2017, 2018, 2019)

LOG_FORMAT = "%(asctime)s %(levelname)-7s %(name)s: %(message)s"


def get_logger(name: str) -> logging.Logger:
    """Return a module logger; configure the root logger once."""
    root = logging.getLogger()
    if not root.handlers:
        logging.basicConfig(level=os.environ.get("AWC_LOG_LEVEL", "INFO"), format=LOG_FORMAT, datefmt="%H:%M:%S")
    return logging.getLogger(name)


def open_maybe_compressed(path: Path, mode: str = "rt"):
    """Open plain, .gz or .xz files transparently."""
    path = Path(path)
    if path.suffix == ".gz":
        return gzip.open(path, mode, encoding="utf-8" if "t" in mode else None)
    if path.suffix == ".xz":
        return lzma.open(path, mode, encoding="utf-8" if "t" in mode else None)
    return open(path, mode, encoding="utf-8" if "t" in mode else None)


def read_json(path: Path) -> Any:
    with open_maybe_compressed(path) as fh:
        return json.load(fh)


_DATE_RE = re.compile(r"(\d{4})[-/](\d{1,2})[-/](\d{1,2})")


def parse_date(value: Any) -> date | None:
    """Parse the many date shapes found in the sources; return None when unusable.

    Accepts ``date``/``datetime`` objects and strings that start with a
    ``YYYY-MM-DD`` (or ``YYYY/MM/DD``) date, ignoring any time or zone suffix.
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    match = _DATE_RE.search(str(value).strip()[:40])
    if not match:
        return None
    try:
        return date(int(match.group(1)), int(match.group(2)), int(match.group(3)))
    except ValueError:
        return None


def month_key(d: date) -> str:
    return f"{d.year:04d}-{d.month:02d}"


def write_csv(df: pd.DataFrame, name: str, out_dir: Path | None = None) -> Path:
    """Write a clean table as CSV (stable column order, no index)."""
    out_dir = out_dir or CLEAN
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{name}.csv"
    df.to_csv(path, index=False, lineterminator="\n")
    return path


def read_clean(name: str, clean_dir: Path | None = None) -> pd.DataFrame | None:
    path = (clean_dir or CLEAN) / f"{name}.csv"
    if not path.exists():
        return None
    return pd.read_csv(path)


def median_or_none(values: Iterable[float]) -> float | None:
    vals = sorted(v for v in values if v is not None)
    if not vals:
        return None
    mid = len(vals) // 2
    return float(vals[mid]) if len(vals) % 2 else (vals[mid - 1] + vals[mid]) / 2.0
