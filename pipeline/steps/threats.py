"""Attacker-side activity: ransomware leak-site victims, zero-days, public exploits, Patch Tuesday.

Outputs: site/public/data/threats.json, data/clean/ransomware_victims_monthly.csv, ...
"""

from __future__ import annotations

import glob
import json
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import AS_OF, INTERIM, RAW, records, write_clean_csv, write_site_json  # noqa: E402


def ransomware():
    rows = []
    for f in sorted(glob.glob(str(RAW / "ransomware_live" / "*.json"))):
        try:
            data = json.loads(Path(f).read_text())
        except json.JSONDecodeError:
            print(f"  ! bad json {f}")
            continue
        for r in data if isinstance(data, list) else []:
            rows.append({
                "victim": (r.get("victim") or r.get("post_title") or "").strip().lower(),
                "group": (r.get("group") or r.get("group_name") or "").strip().lower(),
                "date": r.get("attackdate") or r.get("discovered") or r.get("published"),
                "discovered": r.get("discovered"),
                "country": r.get("country") or None,
                "sector": r.get("activity") or None,
            })
    df = pd.DataFrame(rows)
    df["date"] = pd.to_datetime(df.date, errors="coerce", utc=True, format="mixed").dt.tz_convert(None)
    df["discovered"] = pd.to_datetime(df.discovered, errors="coerce", utc=True, format="mixed").dt.tz_convert(None)
    # attackdate is the leak-post date ransomware.live files the victim under (API month).
    df["when"] = df.date.fillna(df.discovered)
    df = df[df.when.notna() & (df.when >= "2020-01-01") & (df.when <= pd.Timestamp(AS_OF))]
    df = df.drop_duplicates(["victim", "group"])
    df["month"] = df.when.dt.to_period("M").dt.to_timestamp()
    df["year"] = df.when.dt.year
    monthly = df.groupby("month").agg(victims=("victim", "count"), groups=("group", "nunique")).reset_index()
    yearly = df.groupby("year").agg(victims=("victim", "count"), groups=("group", "nunique")).reset_index()
    top_groups = {}
    for y in range(2020, AS_OF.year + 1):
        s = df[df.year == y].group.value_counts().head(8)
        top_groups[str(y)] = [{"group": k, "victims": int(v)} for k, v in s.items()]
    # Share of victims claimed by the top 5 groups each year (market concentration)
    conc = []
    for y, sub in df.groupby("year"):
        vc = sub.group.value_counts()
        conc.append({"year": int(y), "top5_share": float(vc.head(5).sum() / vc.sum()), "groups": int(len(vc))})
    country = df[df.year == AS_OF.year].country.fillna("Unknown").value_counts().head(12).rename_axis("country").reset_index(name="victims")
    sector = df[(df.year >= AS_OF.year - 1) & df.sector.notna() & (df.sector != "Not Found")].sector.value_counts().head(12).rename_axis("sector").reset_index(name="victims")
    write_clean_csv("ransomware_victims_monthly", monthly)
    return {
        "monthly": records(monthly),
        "yearly": records(yearly),
        "top_groups": top_groups,
        "concentration": conc,
        "countries_cur": records(country),
        "sectors_recent": records(sector),
        "total": int(len(df)),
    }


def zerodays():
    frames = []
    for f in sorted(glob.glob(str(RAW / "p0" / "*.csv"))):
        d = pd.read_csv(f)
        d = d[d["CVE"].astype(str).str.startswith("CVE")]
        d["sheet_year"] = int(Path(f).stem)
        frames.append(d)
    df = pd.concat(frames).drop_duplicates("CVE")
    df["Vendor"] = df.Vendor.str.strip()
    yearly = df.groupby("sheet_year").size().rename("zero_days").reset_index().rename(columns={"sheet_year": "year"})
    vend = df.copy()
    top = vend.Vendor.value_counts().head(6).index
    vend["vendor"] = vend.Vendor.where(vend.Vendor.isin(top), "Other")
    by_vendor = vend.pivot_table(index="sheet_year", columns="vendor", values="CVE", aggfunc="count", fill_value=0).reset_index().rename(columns={"sheet_year": "year"})
    types = df[df.sheet_year >= 2019].Type.str.strip().value_counts().head(6).rename_axis("type").reset_index(name="n")
    write_clean_csv("p0_itw_zero_days", df[["CVE", "Vendor", "Product", "Type", "Date Discovered", "Date Patched", "sheet_year"]])
    return {"yearly": records(yearly), "by_vendor": records(by_vendor), "vendors": list(top) + ["Other"], "types": records(types)}


def exploits():
    edb = pd.read_csv(RAW / "exploitdb" / "files_exploits.csv", low_memory=False)
    edb["date"] = pd.to_datetime(edb.date_published, errors="coerce")
    edb_y = edb[edb.date.dt.year >= 2005].groupby(edb.date.dt.year).agg(
        exploits=("id", "count"), with_cve=("codes", lambda s: s.fillna("").str.contains("CVE-").sum())
    ).reset_index().rename(columns={"date": "year"})

    msf = json.loads((RAW / "metasploit" / "modules_metadata_base.json").read_text())
    m = pd.DataFrame([{"type": v.get("type"), "disclosure": v.get("disclosure_date"), "refs": v.get("references") or []} for v in msf.values()])
    m["year"] = pd.to_datetime(m.disclosure, errors="coerce").dt.year
    msf_y = m[(m.type == "exploit") & (m.year >= 2005)].groupby("year").size().rename("modules").reset_index()

    nuc = [json.loads(line) for line in (RAW / "nuclei" / "cves.json").read_text().splitlines() if line.strip()]
    n = pd.DataFrame([{"cve": x["ID"]} for x in nuc])
    n["year"] = n.cve.str.extract(r"CVE-(\d{4})-").astype(float)
    nuc_y = n[n.year >= 2005].groupby("year").size().rename("templates").reset_index()

    out = edb_y.merge(msf_y, on="year", how="outer").merge(nuc_y, on="year", how="outer").sort_values("year").fillna(0)
    write_clean_csv("public_exploits_yearly", out)
    return {"yearly": records(out)}


def patch_tuesday():
    cves = pd.read_parquet(INTERIM / "cves.parquet", columns=["cve_id", "assigner"])
    ms = set(cves.loc[cves.assigner == "microsoft", "cve_id"])
    rows = []
    for f in sorted(glob.glob(str(RAW / "msrc" / "*.json"))):
        if f.endswith("updates.json"):
            continue
        try:
            d = json.loads(Path(f).read_text())
        except json.JSONDecodeError:
            continue
        rel = (d.get("DocumentTracking") or {}).get("InitialReleaseDate")
        for v in d.get("Vulnerability") or []:
            cve = v.get("CVE")
            if cve not in ms:
                continue
            exploited = any("Exploited:Yes" in ((t.get("Description") or {}).get("Value") or "") for t in v.get("Threats") or [])
            rows.append({"cve": cve, "release": rel, "exploited": exploited})
    df = pd.DataFrame(rows).drop_duplicates("cve")
    df["release"] = pd.to_datetime(df.release, errors="coerce", utc=True, format="mixed").dt.tz_convert(None)
    df["month"] = df.release.dt.to_period("M").dt.to_timestamp()
    out = df[df.month >= "2017-01-01"].groupby("month").agg(cves=("cve", "count"), exploited=("exploited", "sum")).reset_index()
    yearly = df[df.month >= "2017-01-01"].groupby(df.month.dt.year).agg(cves=("cve", "count"), exploited=("exploited", "sum")).reset_index().rename(columns={"month": "year"})
    write_clean_csv("microsoft_patch_tuesday_monthly", out)
    return {"monthly": records(out), "yearly": records(yearly)}


def main():
    write_site_json("threats", {
        "ransomware": ransomware(),
        "zerodays": zerodays(),
        "exploits": exploits(),
        "patch_tuesday": patch_tuesday(),
    })


if __name__ == "__main__":
    main()
