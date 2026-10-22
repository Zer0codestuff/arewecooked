"""Turn raw downloads into clean CSV tables, then export the site data.

Usage:
    python -m pipeline.build                      # all sources, as of today
    python -m pipeline.build --as-of 2026-10-22   # freeze the cut-off date
    python -m pipeline.build --only kev,epss      # rebuild selected sources

A source whose raw files are missing is skipped and its committed clean CSVs
are left untouched, so a partial download never wipes good data.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path as _Path

if __package__ in (None, ""):  # allow `python pipeline/build.py` as well as `python -m pipeline.build`
    sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))

from datetime import date
from pathlib import Path

from pipeline import export
from pipeline.common import CLEAN, RAW, get_logger, write_csv
from pipeline.sources import cvelist, epss, exploits, hibp, kev, nvd, p0, ransomware

log = get_logger("build")

SOURCES = ["nvd", "cvelist", "kev", "epss", "exploits", "p0", "hibp", "ransomware"]


def run(sources: list[str], as_of: date, raw_dir: Path = RAW, clean_dir: Path = CLEAN) -> dict[str, list[str]]:
    written: dict[str, list[str]] = {}
    published = {}

    def save(source: str, tables: dict | None) -> None:
        if not tables:
            return
        names = []
        for name, df in tables.items():
            if df is None:
                continue
            write_csv(df, name, clean_dir)
            names.append(name)
        written[source] = names
        log.info("%s: wrote %s", source, ", ".join(names))

    # KEV lag needs NVD publication dates, so NVD runs first whenever KEV is requested.
    if "nvd" in sources or "kev" in sources:
        result = nvd.build(raw_dir, as_of=as_of)
        if result:
            published = result.published
            if "nvd" in sources:
                save("nvd", result.tables)
    if "cvelist" in sources:
        save("cvelist", cvelist.build(raw_dir, as_of=as_of))
    if "kev" in sources:
        tables = kev.build(raw_dir, published)
        if tables and not published:
            tables.pop("kev_lag_year", None)  # keep the committed lag table
        save("kev", tables)
    if "epss" in sources:
        save("epss", epss.build(raw_dir))
    if "exploits" in sources:
        save("exploits", exploits.build(raw_dir))
    if "p0" in sources:
        save("p0", p0.build(raw_dir))
    if "hibp" in sources:
        save("hibp", hibp.build(raw_dir))
    if "ransomware" in sources:
        save("ransomware", ransomware.build(raw_dir, as_of=as_of))
    return written


def update_meta(clean_dir: Path, as_of: date, written: dict[str, list[str]]) -> dict:
    path = clean_dir / "meta.json"
    meta = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    meta["as_of"] = as_of.isoformat()
    sources = meta.setdefault("sources", {})
    for source, tables in written.items():
        sources[source] = {"built_as_of": as_of.isoformat(), "tables": tables}
    clean_dir.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return meta


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--as-of", type=date.fromisoformat, default=date.today(), help="cut-off date (YYYY-MM-DD)")
    parser.add_argument("--only", default="", help="comma separated subset of: " + ", ".join(SOURCES))
    parser.add_argument("--no-export", action="store_true", help="skip writing site/public/data/story.json")
    args = parser.parse_args(argv)
    sources = [s.strip() for s in args.only.split(",") if s.strip()] or SOURCES
    unknown = sorted(set(sources) - set(SOURCES))
    if unknown:
        parser.error(f"unknown sources: {unknown}")
    written = run(sources, args.as_of)
    if not written:
        log.warning("nothing was built: download raw data first with pipeline/fetch.py")
    update_meta(CLEAN, args.as_of, written)
    if args.no_export:
        return 0
    return export.main([])


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
