"""The triage game: which prioritization rule catches the vulnerabilities that later get exploited?

Rolling out-of-sample test. On the first day of each month from Jan 2023 to Jul 2026, take every CVE published in the
previous 365 days that is not yet in CISA KEV, rank it by (a) CVSS base score (CVE record, NVD fallback) and (b) the EPSS
score published that day, and check which ones CISA adds to KEV in the next 90 days. Rankings are pooled across months.
CVSS scores are today's values (they rarely change after publication); EPSS uses only the historical snapshot.

Inputs : data/interim/cves.parquet, data/interim/nvd.parquet, data/raw/epss/epss_YYYY-MM-DD.csv.gz, data/raw/kev/kev.json
Outputs: site/public/data/triage.json, data/clean/triage_curves.csv
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import AS_OF, RAW, INTERIM, records, write_clean_csv, write_site_json  # noqa: E402

EFFORT = [0.005, 0.01, 0.02, 0.03, 0.05, 0.075, 0.1, 0.15, 0.2, 0.25, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]


def pct_rank(score: pd.Series, rng: np.random.Generator) -> np.ndarray:
    """Rank position (0 = patched first) as a fraction of the list, highest score first, ties at random."""
    order = np.lexsort((rng.random(len(score)), -score.fillna(-1).to_numpy()))
    r = np.empty(len(score))
    r[order] = (np.arange(len(score)) + 1) / len(score)
    return r


def main():
    cves = pd.read_parquet(INTERIM / "cves.parquet", columns=["cve_id", "state", "date_published", "cvss_score", "cvss_severity"])
    cves = cves[cves.state == "PUBLISHED"].copy()
    cves["published"] = pd.to_datetime(cves.date_published, utc=True).dt.tz_convert(None)
    nvd = pd.read_parquet(INTERIM / "nvd.parquet", columns=["cve_id", "nvd_score", "nvd_sev"])
    cves = cves.merge(nvd, on="cve_id", how="left")
    cves["score"] = cves.cvss_score.fillna(cves.nvd_score)
    sev = cves.cvss_severity.str.upper().where(cves.cvss_severity.str.upper().isin(["LOW", "MEDIUM", "HIGH", "CRITICAL"]))
    cves["sev"] = sev.fillna(cves.nvd_sev.where(cves.nvd_sev.isin(["LOW", "MEDIUM", "HIGH", "CRITICAL"])))

    kev = pd.DataFrame(json.loads((RAW / "kev" / "kev.json").read_text())["vulnerabilities"])
    kev["dateAdded"] = pd.to_datetime(kev.dateAdded)

    kev_date = kev.set_index("cveID").dateAdded
    rng = np.random.default_rng(7)
    frames, monthly = [], []
    for f in sorted((RAW / "epss").glob("epss_20??-??-??.csv.gz")):
        t = pd.Timestamp(f.name[5:15])
        if t + pd.Timedelta(days=90) > pd.Timestamp(AS_OF):
            continue
        u = cves[(cves.published >= t - pd.Timedelta(days=365)) & (cves.published < t)][["cve_id", "score", "sev"]].copy()
        kd = u.cve_id.map(kev_date)
        u = u[~(kd < t)]
        kd = u.cve_id.map(kev_date)
        u["hit"] = ((kd >= t) & (kd < t + pd.Timedelta(days=90))).astype(int)
        ep = pd.read_csv(f, comment="#", usecols=["cve", "epss"]).rename(columns={"cve": "cve_id"})
        u = u.merge(ep, on="cve_id", how="left")
        u["r_cvss"] = pct_rank(u.score, rng)
        u["r_epss"] = pct_rank(u.epss, rng)
        u["t"] = t
        frames.append(u)
        monthly.append({"month": t, "open_cves": len(u), "exploited_next_90d": int(u.hit.sum())})
    allu = pd.concat(frames, ignore_index=True)
    h = allu[allu.hit == 1]
    hits = int(len(h))
    curves = pd.DataFrame({
        "effort": EFFORT,
        "CVSS score": [float((h.r_cvss <= e).mean()) for e in EFFORT],
        "EPSS that day": [float((h.r_epss <= e).mean()) for e in EFFORT],
        "Random": EFFORT,
    })

    def point(mask: pd.Series, name: str) -> dict:
        return {"rule": name, "effort": float(mask.mean()), "coverage": float(allu.hit[mask].sum() / hits), "rows": int(mask.sum()), "hits": int(allu.hit[mask].sum())}

    pts = [
        point(allu.sev == "CRITICAL", "All critical"),
        point(allu.sev.isin(["CRITICAL", "HIGH"]), "All critical and high"),
        point(allu.epss >= 0.1, "EPSS 10% or more"),
        point(allu.epss >= 0.01, "EPSS 1% or more"),
        point((allu.sev == "CRITICAL") | (allu.epss >= 0.01), "Critical, or EPSS 1% or more"),
    ]
    u = allu
    # median position of exploited CVEs under each rule, by year of snapshot
    by_year = h.assign(year=h.t.dt.year).groupby("year").agg(hits=("hit", "count"), top5_cvss=("r_cvss", lambda s: float((s <= 0.05).mean())),
                                                              top5_epss=("r_epss", lambda s: float((s <= 0.05).mean()))).reset_index()

    # Exploitation rate by severity band for the 2022-2025 cohorts (all KEV to date)
    kev_all = set(kev[kev.dateAdded <= pd.Timestamp(AS_OF)].cveID)
    coh = cves[(cves.published >= "2022-01-01") & (cves.published < "2026-01-01") & cves.sev.notna()].copy()
    coh["kev"] = coh.cve_id.isin(kev_all)
    band = coh.groupby("sev").agg(n=("cve_id", "count"), exploited=("kev", "sum")).reindex(["CRITICAL", "HIGH", "MEDIUM", "LOW"]).reset_index()
    band["rate"] = band.exploited / band.n
    band["share_of_exploited"] = band.exploited / band.exploited.sum()
    band["share_of_all"] = band.n / band.n.sum()

    write_clean_csv("triage_curves", curves)
    write_site_json("triage", {
        "universe": {"rows": int(len(u)), "months": len(monthly), "hits": hits, "distinct_hits": int(h.cve_id.nunique()),
                     "epss_coverage": float(u.epss.notna().mean()), "score_coverage": float(u.score.notna().mean()), "as_of": str(AS_OF)},
        "monthly": records(pd.DataFrame(monthly)),
        "by_year": records(by_year),
        "curves": records(curves),
        "points": pts,
        "bands": records(band),
    })
    print("   rows", len(u), "hits", hits, "months", len(monthly))
    print(by_year.round(3).to_string())
    print(curves.round(3).to_string())
    print(pd.DataFrame(pts).round(3).to_string())
    print(band.round(4).to_string())


if __name__ == "__main__":
    main()
