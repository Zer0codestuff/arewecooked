"""NVD enrichment backlog and NVD severity, from the fkie-cad NVD mirror.

Input : data/raw/nvd/CVE-YYYY.json.xz  (pipeline/fetch.py nvd)
Output: site/public/data/nvd.json, data/clean/nvd_status_monthly.csv,
        data/interim/nvd.parquet (per-CVE NVD status, severity, score and CWE for joins in later steps)
"""

from __future__ import annotations

import glob
import json
import lzma
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import AS_OF, INTERIM, RAW, records, write_clean_csv, write_site_json  # noqa: E402

STATUS_MAP = {
    "Analyzed": "Analyzed by NVD",
    "Modified": "Analyzed by NVD",
    "Awaiting Analysis": "Waiting",
    "Undergoing Analysis": "Waiting",
    "Received": "Waiting",
    "Deferred": "Not scheduled (lowest priority)",
    "Rejected": "Rejected",
}
ORDER = ["Analyzed by NVD", "Waiting", "Not scheduled (lowest priority)"]


def severity(metrics: dict) -> str | None:
    """Severity from the NVD's own (Primary) score, newest CVSS version first."""
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for m in metrics.get(key, []) or []:
            if m.get("type") == "Primary":
                d = m.get("cvssData", {})
                s = d.get("baseSeverity") or m.get("baseSeverity")
                if s:
                    return s.upper()
    return None


def score(metrics: dict) -> float | None:
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for m in metrics.get(key, []) or []:
            if m.get("type") == "Primary":
                v = (m.get("cvssData") or {}).get("baseScore")
                if v is not None:
                    return float(v)
    return None


def cwe(weak: list) -> str | None:
    """CWE IDs from NVD weaknesses, Primary (NVD's own) first, skipping noinfo/Other placeholders."""
    out: list[str] = []
    for w in sorted(weak or [], key=lambda w: w.get("type") != "Primary"):
        for d in w.get("description", []):
            v = d.get("value", "")
            if v.startswith("CWE-") and v not in out:
                out.append(v)
    return ";".join(out) or None


def cpe_vendor_product(configs: list) -> tuple[str | None, str | None]:
    """Vendor and product of the first vulnerable CPE match (cpe:2.3:part:vendor:product:...)."""
    for c in configs or []:
        for node in c.get("nodes", []):
            for m in node.get("cpeMatch", []):
                if m.get("vulnerable", True):
                    parts = m.get("criteria", "").split(":")
                    if len(parts) > 4:
                        return parts[3], parts[4]
    return None, None


def main():
    rows = []
    for f in sorted(glob.glob(str(RAW / "nvd" / "CVE-*.json.xz"))):
        data = json.load(lzma.open(f))
        for it in data.get("cve_items", []):
            rows.append({
                "id": it.get("id"),
                "published": it.get("published"),
                "status": STATUS_MAP.get(it.get("vulnStatus"), it.get("vulnStatus")),
                "nvd_sev": severity(it.get("metrics") or {}),
                "nvd_score": score(it.get("metrics") or {}),
                "nvd_cwe": cwe(it.get("weaknesses")),
                "has_cpe": bool(it.get("configurations")),
                "cpe": cpe_vendor_product(it.get("configurations")),
            })
    df = pd.DataFrame(rows)
    df["nvd_vendor"] = df.cpe.str[0]
    df["nvd_product"] = df.cpe.str[1]
    INTERIM.mkdir(parents=True, exist_ok=True)
    df[["id", "status", "nvd_sev", "nvd_score", "nvd_cwe", "has_cpe", "nvd_vendor", "nvd_product"]].rename(columns={"id": "cve_id"}).to_parquet(INTERIM / "nvd.parquet", index=False)
    df["published"] = pd.to_datetime(df.published, errors="coerce")
    df = df[df.published.notna() & (df.published <= pd.Timestamp(AS_OF) + pd.Timedelta(days=1)) & (df.status != "Rejected")]
    df["year"] = df.published.dt.year
    df["month"] = df.published.dt.to_period("M").dt.to_timestamp()

    yearly = df[df.year >= 2015].pivot_table(index="year", columns="status", values="id", aggfunc="count", fill_value=0)
    yearly = yearly.reindex(columns=ORDER, fill_value=0).reset_index()
    monthly = df[df.month >= "2023-01-01"].pivot_table(index="month", columns="status", values="id", aggfunc="count", fill_value=0)
    monthly = monthly.reindex(columns=ORDER, fill_value=0).reset_index()
    sev = df[(df.year >= 2015) & df.nvd_sev.notna()].pivot_table(index="year", columns="nvd_sev", values="id", aggfunc="count", fill_value=0).reset_index()
    cur = df[df.year == AS_OF.year]
    totals = {
        "cur_year": int(len(cur)),
        "analyzed_cur": int((cur.status == ORDER[0]).sum()),
        "waiting_cur": int((cur.status == ORDER[1]).sum()),
        "deferred_cur": int((cur.status == ORDER[2]).sum()),
        "analyzed_share_2023": float((df[df.year == 2023].status == ORDER[0]).mean()),
        "analyzed_share_cur": float((cur.status == ORDER[0]).mean()),
    }
    write_clean_csv("nvd_status_monthly", monthly)
    write_site_json("nvd", {"yearly": records(yearly), "monthly": records(monthly), "severity_nvd": records(sev), "order": ORDER, "totals": totals,
                            "mirror_release": (RAW / "nvd" / "RELEASE.txt").read_text().strip()})
    print("  ", totals)


if __name__ == "__main__":
    main()
