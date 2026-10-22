"""Build the data-story JSON for the website (site/public/data/*.json) and data/clean CSVs.

Run after the raw downloads exist:
    .venv/bin/python pipeline/fetch.py cvelist kev epss exploitdb metasploit nuclei osv hibp p0
    .venv/bin/python pipeline/steps/fetch_extra.py
    .venv/bin/python pipeline/steps/run_all.py
"""

import runpy
import sys
from pathlib import Path

STEPS = ["cve_extract", "vulns", "threats", "ecosystem", "context"]

if __name__ == "__main__":
    here = Path(__file__).resolve().parent
    for s in sys.argv[1:] or STEPS:
        print(f"[{s}]")
        runpy.run_path(str(here / f"{s}.py"), run_name="__main__")
