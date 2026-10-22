"""Vulnerability volume, severity, AI attribution and exploitation timing.

Inputs : data/interim/cves.parquet, data/raw/kev/kev.json, data/raw/epss,
         data/raw/anthropic_cves/cves.yaml, data/raw/berkeley/embedded.json
Outputs: site/public/data/vulns.json, data/clean/*.csv
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import duckdb
import numpy as np
import pandas as pd
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ai_patterns import AI_SOFTWARE, ai_finder  # noqa: E402
from common import AS_OF, INTERIM, RAW, records, write_clean_csv, write_site_json  # noqa: E402

BIG_VENDORS = {
    "microsoft", "oracle", "Chrome", "apple", "adobe", "cisco", "ibm", "redhat", "mozilla", "google_android",
    "Google", "dell", "hpe", "vmware", "intel", "nvidia", "sap", "siemens", "fortinet", "palo_alto", "juniper",
    "apache", "GitLab", "f5", "samsung_mobile", "qualcomm", "lenovo", "hp", "zdi", "Mattermost", "jetbrains",
    "Unisoc", "mediatek", "Hikvision", "huawei", "zte", "Synology", "QNAP", "schneider", "SonicWall", "Ivanti",
    "atlassian", "Zoom", "salesforce", "AMD", "Arm", "Canonical", "debian", "suse", "elastic", "OpenSSL", "curl",
}


def assigner_group(a: str | None) -> str:
    if a == "Linux":
        return "Linux kernel"
    if a in ("Patchstack", "Wordfence", "WPScan"):
        return "WordPress plugins"
    if a == "GitHub_M":
        return "Open source (GitHub)"
    if a == "VulDB":
        return "VulDB"
    if a == "VulnCheck":
        return "VulnCheck"
    if a == "mitre":
        return "MITRE"
    if a in BIG_VENDORS:
        return "Software vendors"
    return "Other CNAs"


GROUP_ORDER = ["Software vendors", "Open source (GitHub)", "Linux kernel", "WordPress plugins", "VulDB", "VulnCheck", "MITRE", "Other CNAs"]
SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "Not scored"]


def load() -> pd.DataFrame:
    df = pd.read_parquet(
        INTERIM / "cves.parquet",
        columns=["cve_id", "state", "assigner", "date_published", "date_reserved", "description", "credits", "vendor",
                 "product", "cwe", "adp_cwe", "cvss_score", "cvss_severity", "cvss_version", "ssvc_exploitation",
                 "ssvc_automatable", "ssvc_impact", "title"],
    )
    df = df[(df.state == "PUBLISHED") & df.date_published.notna()].copy()
    df["date_published"] = df.date_published.dt.tz_convert(None)
    df["year"] = df.date_published.dt.year
    df["month"] = df.date_published.dt.to_period("M").dt.to_timestamp()
    df["group"] = df.assigner.map(assigner_group)
    sev = df.cvss_severity.fillna("Not scored").replace({"NONE": "Not scored", "": "Not scored"})
    df["severity"] = sev.where(sev.isin(SEV_ORDER), "Not scored")
    return df


def tag_ai(df: pd.DataFrame) -> pd.DataFrame:
    df["ai_finder"] = [ai_finder(c, d) for c, d in zip(df.credits, df.description)]
    df["ai_source"] = np.where(df.ai_finder.notna(), "cve-record", None)
    tracker = pd.DataFrame(yaml.safe_load((RAW / "anthropic_cves" / "cves.yaml").read_text()))
    tracker = set(tracker.loc[tracker.status == "published", "cve"])
    extra = df.cve_id.isin(tracker) & df.ai_finder.isna()
    df.loc[extra, "ai_finder"] = "Anthropic (Claude)"
    df.loc[extra, "ai_source"] = "anthropic-cve-tracker"
    text = (df["vendor"].fillna("") + " " + df["product"].fillna("") + " " + df["title"].fillna("") + " " + df.description.fillna("").str[:600])
    df["ai_software"] = text.str.contains(AI_SOFTWARE) | df.cwe.fillna("").str.contains("CWE-1427")
    return df


def load_kev(df: pd.DataFrame) -> pd.DataFrame:
    kev = pd.DataFrame(json.loads((RAW / "kev" / "kev.json").read_text())["vulnerabilities"])
    kev["dateAdded"] = pd.to_datetime(kev.dateAdded)
    kev = kev.merge(df[["cve_id", "date_published", "date_reserved", "assigner", "ai_finder", "severity", "cvss_score"]],
                    left_on="cveID", right_on="cve_id", how="left")
    kev["days_to_kev"] = (kev.dateAdded - kev.date_published.dt.normalize()).dt.days
    return kev


def main():
    con = duckdb.connect()
    df = tag_ai(load())
    cur_year = AS_OF.year
    frac = (pd.Timestamp(AS_OF).day_of_year) / 365.0

    # ---------- volume ----------
    yearly = df.groupby("year").size().rename("cves").reset_index()
    yearly["partial"] = yearly.year == cur_year
    by_group = df[df.year >= 2015].pivot_table(index="year", columns="group", values="cve_id", aggfunc="count", fill_value=0)
    by_group = by_group.reindex(columns=GROUP_ORDER, fill_value=0).reset_index()
    monthly = df[df.month >= "2018-01-01"].groupby("month").size().rename("cves").reset_index()
    monthly_group = df[df.month >= "2023-01-01"].pivot_table(index="month", columns="group", values="cve_id", aggfunc="count", fill_value=0)
    monthly_group = monthly_group.reindex(columns=GROUP_ORDER, fill_value=0).reset_index()

    # Vendor CNAs that changed most from 2025 to 2026 (same-period comparison: Jan 1 to AS_OF)
    cutoff_md = (AS_OF.month, AS_OF.day)
    same = df[(df.date_published.dt.month < cutoff_md[0]) | ((df.date_published.dt.month == cutoff_md[0]) & (df.date_published.dt.day <= cutoff_md[1]))]
    ytd = same[same.year.isin([cur_year - 1, cur_year])].pivot_table(index="assigner", columns="year", values="cve_id", aggfunc="count", fill_value=0)
    ytd.columns = ["prev", "cur"]
    ytd = ytd[ytd.prev + ytd.cur >= 150].copy()
    ytd["ratio"] = (ytd.cur / ytd.prev.replace(0, np.nan)).round(2)
    ytd = ytd.sort_values("cur", ascending=False).head(25).reset_index()
    ytd_total = same[same.year.isin([cur_year - 1, cur_year])].groupby("year").size().to_dict()

    # ---------- severity ----------
    sev = df[df.year >= 2016].pivot_table(index="year", columns="severity", values="cve_id", aggfunc="count", fill_value=0)
    sev = sev.reindex(columns=SEV_ORDER, fill_value=0).reset_index()
    crit_high_monthly = df[df.month >= "2023-01-01"].assign(ch=df.severity.isin(["CRITICAL", "HIGH"])).groupby("month").ch.sum().rename("critical_high").reset_index()

    # CWE families for 2026 vs 2020
    def cwe_top(year):
        s = df[df.year == year].cwe.dropna().str.split(";").explode()
        return s.value_counts().head(12)

    from_cwe = {y: cwe_top(y) for y in (2020, 2025, cur_year)}

    # ---------- AI attribution ----------
    ai = df[df.ai_finder.notna()]
    ai_monthly = ai[ai.month >= "2024-07-01"].pivot_table(index="month", columns="ai_finder", values="cve_id", aggfunc="count", fill_value=0)
    top_orgs = ai.ai_finder.value_counts()
    ai_by_org = top_orgs.rename_axis("org").reset_index(name="cves")
    keep = list(top_orgs.index[:7])
    ai_monthly_slim = ai_monthly[keep].copy()
    ai_monthly_slim["Others"] = ai_monthly.drop(columns=keep).sum(axis=1)
    ai_monthly_slim = ai_monthly_slim.reset_index()
    all_monthly = df[df.month >= "2024-07-01"].groupby("month").size()
    ai_share = (ai.groupby("month").size() / all_monthly).dropna().rename("share").reset_index()
    ai_share = ai_share[ai_share.month >= "2024-07-01"]

    sev_cmp = []
    recent = df[df.year == cur_year]
    for label, sub in (("AI-attributed", recent[recent.ai_finder.notna()]), ("All other CVEs", recent[recent.ai_finder.isna()])):
        scored = sub[sub.severity != "Not scored"]
        row = {"cohort": label, "n": len(sub), "scored": len(scored)}
        for s in SEV_ORDER[:4]:
            row[s.lower()] = round(float((scored.severity == s).mean()), 4) if len(scored) else None
        row["median_cvss"] = float(scored.cvss_score.median()) if len(scored) else None
        sev_cmp.append(row)

    ai_vendors = ai[ai.year == cur_year]["vendor"].fillna("n/a").str.strip().value_counts().head(15).rename_axis("vendor").reset_index(name="cves")

    # ---------- vulnerabilities in AI software ----------
    ais = df[df.ai_software & (df.month >= "2022-01-01")]
    ai_soft_monthly = ais.groupby("month").size().rename("cves").reset_index()
    ai_soft_yearly = df[df.ai_software].groupby("year").size().rename("cves").reset_index()
    ai_soft_yearly = ai_soft_yearly[ai_soft_yearly.year >= 2018]
    ai_soft_products = ais[ais.year == cur_year]["product"].fillna("n/a").str.lower().str.strip().value_counts().head(20).rename_axis("product").reset_index(name="cves")

    # ---------- exploitation (KEV) ----------
    kev = load_kev(df)
    kev_year = kev.groupby(kev.dateAdded.dt.year).agg(added=("cveID", "count"), ransomware=("knownRansomwareCampaignUse", lambda s: (s == "Known").sum())).reset_index().rename(columns={"dateAdded": "year"})
    # Only CVEs published 2022+ give a fair 'time to exploitation' view (KEV started Nov 2021)
    k2 = kev[kev.date_published.notna() & (kev.date_published >= "2022-01-01")].copy()
    k2["pub_year"] = k2.date_published.dt.year
    tte = k2.groupby("pub_year").agg(
        n=("cveID", "count"),
        median_days=("days_to_kev", "median"),
        share_day0=("days_to_kev", lambda s: float((s <= 0).mean())),
        share_week=("days_to_kev", lambda s: float((s <= 7).mean())),
        share_month=("days_to_kev", lambda s: float((s <= 30).mean())),
    ).reset_index()
    bins = [-10_000, 0, 7, 30, 90, 365, 100_000]
    labels = ["Before or on disclosure day", "1 to 7 days", "8 to 30 days", "31 to 90 days", "91 to 365 days", "Over a year"]
    k2["bucket"] = pd.cut(k2.days_to_kev, bins=bins, labels=labels)
    tte_buckets = k2.groupby(["pub_year", "bucket"], observed=False).size().unstack(fill_value=0).reset_index()
    # Exploited share of CVEs by publication year
    kev_rate = (kev[kev.date_published.notna()].groupby(kev.date_published.dt.year).size() / df.groupby("year").size()).dropna()
    kev_rate = kev_rate[kev_rate.index >= 2018].rename("share").rename_axis("year").reset_index()
    kev_vendors = kev.vendorProject.value_counts().head(15).rename_axis("vendor").reset_index(name="kevs")
    recent_kev_vendors = kev[kev.dateAdded >= f"{cur_year-1}-01-01"].vendorProject.value_counts().head(15).rename_axis("vendor").reset_index(name="kevs")
    kev_ai = kev[kev.ai_finder.notna()][["cveID", "vendorProject", "product", "dateAdded", "ai_finder", "days_to_kev"]]

    # SSVC (CISA vulnrichment) exploitation status for recent CVEs
    ssvc = df[(df.year >= 2024) & df.ssvc_exploitation.notna()].pivot_table(index="year", columns="ssvc_exploitation", values="cve_id", aggfunc="count", fill_value=0).reset_index()

    # EPSS: share of CVEs with meaningful exploitation probability
    epss = pd.read_csv(RAW / "epss" / "epss_current.csv.gz", comment="#")
    epss = epss.merge(df[["cve_id", "year", "ai_finder"]], left_on="cve", right_on="cve_id", how="inner")
    epss_by_year = epss[epss.year >= 2018].groupby("year").agg(
        n=("cve", "count"),
        p10=("epss", lambda s: float((s >= 0.1).mean())),
        p50=("epss", lambda s: float((s >= 0.5).mean())),
        mean=("epss", "mean"),
    ).reset_index()
    epss_ai = {
        "ai": float(epss[epss.ai_finder.notna() & (epss.year == cur_year)].epss.mean()),
        "other": float(epss[epss.ai_finder.isna() & (epss.year == cur_year)].epss.mean()),
        "ai_p10": float((epss[epss.ai_finder.notna() & (epss.year == cur_year)].epss >= 0.1).mean()),
        "other_p10": float((epss[epss.ai_finder.isna() & (epss.year == cur_year)].epss >= 0.1).mean()),
    }

    # Berkeley tracker context
    berk = json.loads((RAW / "berkeley" / "embedded.json").read_text())
    berk_board = {}
    for m in berk["leaderboard"]["metrics"]:
        for r in m["rows"]:
            berk_board.setdefault(r["org"], {})[m["key"]] = r["val"]
    berkeley = {
        "total_cves": berk["footer_stats"]["catalog"]["total_cves"],
        "organizations": berk["footer_stats"]["catalog"]["organizations"],
        "start": berk["footer_stats"]["catalog"]["start_date"],
        "end": berk["footer_stats"]["catalog"]["end_date"],
        "pace": berk["headline_pace"]["counts"],
        "board": [{"org": k, **v} for k, v in sorted(berk_board.items(), key=lambda kv: -kv[1].get("count", 0))],
    }

    totals = {
        "all_time": int(len(df)),
        "cur_year": int((df.year == cur_year).sum()),
        "prev_year": int((df.year == cur_year - 1).sum()),
        "y2020": int((df.year == 2020).sum()),
        "ytd_prev": int(ytd_total.get(cur_year - 1, 0)),
        "ytd_cur": int(ytd_total.get(cur_year, 0)),
        "year_fraction": round(frac, 3),
        "peak_month": records(monthly.sort_values("cves").tail(1))[0],
        "ai_attributed": int(len(ai)),
        "ai_attributed_cur": int((ai.year == cur_year).sum()),
        "ai_from_tracker": int((ai.ai_source == "anthropic-cve-tracker").sum()),
        "ai_software_cur": int((df.ai_software & (df.year == cur_year)).sum()),
        "ai_software_prev": int((df.ai_software & (df.year == cur_year - 1)).sum()),
        "kev_total": int(len(kev)),
        "kev_cur_year": int((kev.dateAdded.dt.year == cur_year).sum()),
        "critical_cur": int(((df.year == cur_year) & (df.severity == "CRITICAL")).sum()),
        "critical_prev": int(((df.year == cur_year - 1) & (df.severity == "CRITICAL")).sum()),
    }

    write_site_json("vulns", {
        "totals": totals,
        "yearly": records(yearly),
        "by_group": records(by_group),
        "group_order": GROUP_ORDER,
        "monthly": records(monthly),
        "monthly_group": records(monthly_group),
        "ytd_assigners": records(ytd),
        "severity": records(sev),
        "crit_high_monthly": records(crit_high_monthly),
        "cwe_top": {str(y): [{"cwe": k, "n": int(v)} for k, v in s.items()] for y, s in from_cwe.items()},
        "ai_monthly": records(ai_monthly_slim),
        "ai_orgs": records(ai_by_org),
        "ai_share": records(ai_share),
        "ai_severity": sev_cmp,
        "ai_vendors": records(ai_vendors),
        "ai_epss": epss_ai,
        "ai_software_monthly": records(ai_soft_monthly),
        "ai_software_yearly": records(ai_soft_yearly),
        "ai_software_products": records(ai_soft_products),
        "kev_year": records(kev_year),
        "tte": records(tte),
        "tte_buckets": records(tte_buckets),
        "kev_rate": records(kev_rate),
        "kev_vendors": records(kev_vendors),
        "kev_vendors_recent": records(recent_kev_vendors),
        "kev_ai": records(kev_ai),
        "ssvc": records(ssvc),
        "epss_by_year": records(epss_by_year),
        "berkeley": berkeley,
    })

    # Clean, reusable tables
    write_clean_csv("cve_monthly_by_source", monthly_group.merge(monthly, on="month", how="left"))
    write_clean_csv("cve_yearly", yearly.merge(by_group, on="year", how="left"))
    write_clean_csv("cve_severity_yearly", sev)
    write_clean_csv(
        "ai_attributed_cves",
        ai[["cve_id", "date_published", "assigner", "vendor", "product", "severity", "cvss_score", "ai_finder", "ai_source", "credits"]]
        .sort_values("date_published"),
    )
    write_clean_csv("kev_enriched", kev[["cveID", "vendorProject", "product", "dateAdded", "date_published", "days_to_kev", "knownRansomwareCampaignUse", "severity", "cvss_score", "ai_finder"]])
    print("  totals:", totals)


if __name__ == "__main__":
    main()
