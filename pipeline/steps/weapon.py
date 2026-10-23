"""From bug to weapon: public exploit code on GitHub and Exploit-DB, and what kind of products get exploited.

Inputs : data/raw/poc_github/repo/YYYY/CVE-*.json (nomi-sec/PoC-in-GitHub, shallow clone),
         data/raw/exploitdb/files_exploits.csv, data/raw/kev/kev.json,
         data/interim/cves.parquet, data/clean/ai_attributed_cves.csv
Outputs: site/public/data/weapon.json, data/clean/github_poc_first_seen.csv, data/clean/kev_product_category.csv
"""

from __future__ import annotations

import glob
import json
import re
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import AS_OF, CLEAN, INTERIM, RAW, records, write_clean_csv, write_site_json  # noqa: E402

END = pd.Timestamp(AS_OF) + pd.Timedelta(days=1)

# Product categories for CISA KEV entries (vendor + product text, first match wins).
CATEGORIES: list[tuple[str, str]] = [
    ("Developer and AI tools", r"litellm|mlflow|marimo|langflow|langchain|n8n|ollama|\bray\b|anyscale|comfyui|open webui|\bnx\b|nx console|tanstack|vite|prettier|"
     r"eslint|npm|pypi|trivy|jfrog|artifactory|gitea|gitlab|github|jenkins|teamcity|bitbucket|docker|kubernetes|argo|terraform|nexus|sonatype|"
     r"jupyter|gradio|hugging|pytorch|tensorflow|vllm|mcp|cline|cursor|copilot|openai|anthropic|claude"),
    ("Network edge and remote access", r"fortinet|forti|pan-os|globalprotect|palo alto|connect secure|pulse connect|policy secure|ivanti (cloud|neurons for zta|secure access)|"
     r"netscaler|citrix (adc|gateway)|big-ip|\bf5\b|sonicwall|sonicos|\bsma\b|cisco (asa|adaptive|firepower|ios|small business|rv|secure firewall|identity services|catalyst sd-wan|sd-wan)|"
     r"ios xe|ios xr|nx-os|zyxel|junos|juniper|sophos|check point|quantum security|barracuda|array networks|draytek|mikrotik|ubiquiti|router|gateway|"
     r"firewall|vpn|d-link|tp-link|netgear|linksys|tenda|totolink|edgerouter|watchguard|fireware|aruba|velocloud|versa|arista|sd-wan|lantronix"),
    ("IT admin and remote management", r"simplehelp|n-able|n-central|screenconnect|connectwise|kaseya|beyondtrust|remote support|sysaid|manageengine|zoho|"
     r"configuration manager|endpoint manager|\bepm\b|epmm|mobile device|mdm|solarwinds|veeam|backup|nakivo|commvault|ahsaycbs|recoverpoint|"
     r"defender|apex one|trend micro|threatsonar|anti-ransomware|vcenter|esxi|vmware|hyper-v|active directory|adfs"),
    ("Browsers", r"chrom|firefox|safari|webkit|internet explorer|\bedge\b|mshtml|\bv8\b|skia|dawn|angle"),
    ("Operating systems and mobile", r"windows|win32k|kernel|macos|\bios\b|ipados|android|linux|chrome os|smb|print spooler|ntlm|apple|qualcomm|"
     r"samsung mobile|mobile devices|pixel|arm mali|mali gpu|chipset|exynos|mediatek|unisoc"),
    ("Office, mail and documents", r"office|word|excel|outlook|powerpoint|acrobat|reader|exchange|roundcube|zimbra|mail|winrar|7-zip|notepad|telemessage|"
     r"mitel|switchvox|unified communications|trueconf|teams|zoom|webex"),
    ("Business and web apps", r"sharepoint|confluence|jira|atlassian|oracle|weblogic|\bsap\b|netweaver|moveit|goanywhere|cleo|crushftp|wing ftp|gladinet|centrestack|"
     r"apache|struts|log4j|tomcat|coldfusion|magento|commerce|joomla|wordpress|drupal|craft cms|sitecore|kentico|strapi|telerik|progress|"
     r"citrix|ivanti|hpe|ibm|php|laravel|papercut|qlik|servicenow|splunk|metabase|minio|geoserver|ownercloud|owncloud|zammad|plex|"
     r"windchill|delmia|apriso|veracore|wso2|cyberpanel|cpanel|litespeed|starlette|redis|elastic|grafana|\bcms\b|portal|server|manager"),
    ("Cameras, IoT and OT", r"camera|nvr|dvr|hikvision|dahua|avtech|scada|siemens|schneider|rockwell|plc|iot|realtek|"
     r"geovision|edimax|digiever|optilink|vacron|axis|zte|huawei|knx|magicinfo"),
]
CAT_RE = [(name, re.compile(rx, re.I)) for name, rx in CATEGORIES]
CAT_ORDER = [c for c, _ in CATEGORIES] + ["Other"]


def category(text: str) -> str:
    for name, rx in CAT_RE:
        if rx.search(text):
            return name
    return "Other"


def load_pocs() -> pd.DataFrame:
    rows = []
    for f in glob.glob(str(RAW / "poc_github" / "repo" / "*" / "CVE-*.json")):
        cve = Path(f).stem.upper()
        try:
            items = json.loads(Path(f).read_text())
        except Exception:
            continue
        for r in items:
            if r.get("fork"):
                continue
            rows.append({"cve_id": cve, "repo": r.get("full_name"), "created_at": r.get("created_at"), "stars": r.get("stargazers_count", 0)})
    df = pd.DataFrame(rows).drop_duplicates("repo")
    df["created_at"] = pd.to_datetime(df.created_at, utc=True, errors="coerce").dt.tz_convert(None)
    return df[df.created_at.notna() & (df.created_at < END)]


def main():
    cves = pd.read_parquet(INTERIM / "cves.parquet", columns=["cve_id", "state", "date_published", "vendor", "product", "assigner", "cvss_severity", "title"])
    cves = cves[cves.state == "PUBLISHED"].copy()
    cves["published"] = pd.to_datetime(cves.date_published, utc=True).dt.tz_convert(None)
    cves = cves[cves.published < END]

    poc = load_pocs()
    first = poc.groupby("cve_id").agg(first_poc=("created_at", "min"), repos=("repo", "count"), stars=("stars", "sum")).reset_index()
    j = cves[["cve_id", "published", "vendor", "product", "title"]].merge(first, on="cve_id", how="inner")
    j["lag_days"] = (j.first_poc - j.published).dt.total_seconds() / 86400
    j["pub_year"] = j.published.dt.year

    # 1) PoC repos created per month (and distinct CVEs that got their first PoC that month)
    poc["month"] = poc.created_at.dt.to_period("M").dt.to_timestamp()
    pm = poc[poc.month >= "2018-01-01"].groupby("month").agg(repos=("repo", "count"), cves=("cve_id", "nunique")).reset_index()

    # 2) speed: per publication year, CVEs that got a public PoC within 1 / 7 / 30 days (count and share of all CVEs)
    allc = cves.assign(pub_year=cves.published.dt.year).groupby("pub_year").size().rename("all_cves")
    speed = []
    for y in range(2018, AS_OF.year + 1):
        sub = j[j.pub_year == y]
        row = {"year": y, "all_cves": int(allc.get(y, 0)), "with_poc": int(len(sub))}
        for d in (1, 7, 30):
            row[f"within_{d}d"] = int(((sub.lag_days <= d)).sum())
        row["before_pub"] = int((sub.lag_days < 0).sum())
        row["median_lag_days"] = float(sub.lag_days.clip(lower=0).median()) if len(sub) else None
        speed.append(row)
    speed = pd.DataFrame(speed)
    speed["share_7d"] = speed.within_7d / speed.all_cves

    # median lag within a fixed 180-day window so recent years are comparable
    win = j[(j.lag_days <= 180)]
    lag_y = win.groupby("pub_year").lag_days.apply(lambda s: float(s.clip(lower=0).median())).rename("median_lag_180").reset_index()
    speed = speed.merge(lag_y, left_on="year", right_on="pub_year", how="left").drop(columns="pub_year")

    # 3) top PoC'd CVEs of the current year
    top = j[j.pub_year == AS_OF.year].sort_values("repos", ascending=False).head(12).copy()
    top["label"] = top.apply(lambda r: f"{r.cve_id} {(r.vendor or '').strip()} {(r['product'] or '').strip()}".strip()[:60], axis=1)

    # 4) Exploit-DB vs GitHub per year
    edb = pd.read_csv(RAW / "exploitdb" / "files_exploits.csv", usecols=["id", "date_published", "codes", "type"])
    edb["date_published"] = pd.to_datetime(edb.date_published, errors="coerce")
    edb = edb[edb.date_published.notna() & (edb.date_published < END)]
    edb["has_cve"] = edb.codes.fillna("").str.contains("CVE-")
    ev = edb.groupby(edb.date_published.dt.year).agg(edb_all=("id", "count"), edb_cve=("has_cve", "sum")).reset_index().rename(columns={"date_published": "year"})
    gh = poc.groupby(poc.created_at.dt.year).agg(gh_repos=("repo", "count"), gh_cves=("cve_id", "nunique")).reset_index().rename(columns={"created_at": "year"})
    venues = ev.merge(gh, on="year", how="outer").fillna(0)
    venues = venues[(venues.year >= 2010)].astype(int)

    # 5) KEV: product categories by CVE year, PoC-before-exploitation
    kev = pd.DataFrame(json.loads((RAW / "kev" / "kev.json").read_text())["vulnerabilities"])
    kev["dateAdded"] = pd.to_datetime(kev.dateAdded)
    kev["cve_year"] = kev.cveID.str.extract(r"CVE-(\d{4})").astype(int)
    kev["category"] = (kev.vendorProject.fillna("") + " " + kev["product"].fillna("") + " " + kev.vulnerabilityName.fillna("")).map(category)
    kcat = kev[kev.cve_year >= 2018].pivot_table(index="cve_year", columns="category", values="cveID", aggfunc="count", fill_value=0)
    kcat = kcat.reindex(columns=CAT_ORDER, fill_value=0).reset_index().rename(columns={"cve_year": "year"})
    kj = kev.merge(cves[["cve_id", "published"]], left_on="cveID", right_on="cve_id", how="left").merge(first[["cve_id", "first_poc"]], left_on="cveID", right_on="cve_id", how="left")
    kj["days_to_kev"] = (kj.dateAdded - kj.published).dt.total_seconds() / 86400
    cat_speed = kj[(kj.cve_year >= 2023) & kj.days_to_kev.notna() & (kj.days_to_kev >= -30)].groupby("category").agg(
        n=("cveID", "count"), median_days=("days_to_kev", "median"), within_7=("days_to_kev", lambda s: float((s <= 7).mean()))).reset_index()
    rec = kj[kj.cve_year >= 2024]
    poc_first = {
        "kev_recent": int(len(rec)),
        "with_poc": int(rec.first_poc.notna().sum()),
        "poc_before_kev": int((rec.first_poc < rec.dateAdded).sum()),
        "poc_after_kev": int((rec.first_poc >= rec.dateAdded).sum()),
        "no_poc": int(rec.first_poc.isna().sum()),
    }
    edge_share = (kcat.set_index("year")[CAT_ORDER[0]] / kcat.set_index("year")[CAT_ORDER].sum(axis=1)).round(3).to_dict()

    # 6) AI-credited CVEs: do they get public PoCs?
    ai_ids = set(pd.read_csv(CLEAN / "ai_attributed_cves.csv").cve_id)
    c26 = cves[cves.published.dt.year == AS_OF.year].merge(first, on="cve_id", how="left")
    c26["ai"] = c26.cve_id.isin(ai_ids)
    ai_poc = c26.groupby("ai").apply(lambda g: pd.Series({"n": len(g), "with_poc": int(g.first_poc.notna().sum())}), include_groups=False).reset_index()

    write_clean_csv("github_poc_first_seen", j[["cve_id", "published", "first_poc", "lag_days", "repos", "stars"]].sort_values("published"))
    write_clean_csv("kev_product_category", kev[["cveID", "vendorProject", "product", "dateAdded", "category"]])
    write_site_json("weapon", {
        "poc_monthly": records(pm),
        "speed": records(speed),
        "top_cur": records(top[["cve_id", "label", "vendor", "product", "title", "repos", "stars", "lag_days"]]),
        "venues": records(venues),
        "kev_categories": records(kcat),
        "kev_category_order": CAT_ORDER,
        "kev_category_speed": records(cat_speed),
        "edge_share": {str(k): v for k, v in edge_share.items()},
        "poc_vs_kev": poc_first,
        "ai_poc_cur": records(ai_poc),
        "totals": {"poc_repos": int(len(poc)), "poc_cves": int(poc.cve_id.nunique())},
    })
    print("   poc repos", len(poc), "cves", poc.cve_id.nunique())
    print(speed.to_string())
    print(venues.tail(8).to_string())
    print(kcat.to_string())
    print(cat_speed.to_string())
    print(poc_first, ai_poc.to_dict("records"))
    print(top[["label", "repos", "lag_days"]].to_string())


if __name__ == "__main__":
    main()
