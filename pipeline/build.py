"""Run every processing step in order (after pipeline/fetch.py)."""

import runpy
import sys
from pathlib import Path

STEPS = ["cve_extract", "vulns", "threats", "ecosystem", "context"]

if __name__ == "__main__":
    wanted = sys.argv[1:] or STEPS
    here = Path(__file__).resolve().parent / "steps"
    for s in wanted:
        print(f"[{s}]")
        runpy.run_path(str(here / f"{s}.py"), run_name="__main__")
