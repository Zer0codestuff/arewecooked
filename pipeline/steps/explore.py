"""Vendor explorer: one profile per vendor for the interactive comparison on the site.

Vendor = NVD CPE vendor when available, else the vendor named in the CVE record, normalized so that
"Microsoft Corporation", "microsoft" and "Microsoft" are one key.

Inputs : data/interim/cves.parquet, data/interim/nvd.parquet, data/raw/kev/kev.json,
         data/clean/ai_attributed_cves.csv, data/clean/github_poc_first_seen.csv
Outputs: site/public/data/explore.json, data/clean/vendor_profiles.csv
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import AS_OF, CLEAN, INTERIM, RAW, write_clean_csv, write_site_json  # noqa: E402
from anatomy import family  # noqa: E402

TOP_N = 250
SUFFIX = re.compile(r"\b(inc|incorporated|corp|corporation|ltd|limited|llc|co|company|gmbh|se|ag|sa|bv|plc|technologies|technology|"
                    r"systems|software|foundation|project|networks|group|holdings|international|the)\b")
ALIAS = {
    "hewlettpackardenterprise": "hpe", "hewlettpackardenterprisehpe": "hpe", "hewlettpackard": "hp", "googleandroid": "google",
    "samsungmobile": "samsung", "qnapsystems": "qnap", "apachesoftware": "apache", "jenkinsci": "jenkins", "elasticsearch": "elastic",
    "paloaltonetworks": "paloaltonetworks", "fortinetinc": "fortinet", "dlinksystems": "dlink", "tplink": "tplink", "sun": "oracle",
    "wordpressorg": "wordpress", "foxitsoftware": "foxit", "hcltech": "hcl", "zohocorp": "zoho", "progresssoftware": "progress", "redhatinc": "redhat", "linuxfoundation": "linux", "gnu": "gnu", "sapse": "sap", "unisocshanghai": "unisoc",
}
DISPLAY = {
    "microsoft": "Microsoft", "google": "Google", "linux": "Linux kernel", "oracle": "Oracle", "ibm": "IBM", "apple": "Apple",
    "adobe": "Adobe", "cisco": "Cisco", "mozilla": "Mozilla", "apache": "Apache", "qualcomm": "Qualcomm", "huawei": "Huawei",
    "hp": "HP", "hpe": "HPE", "redhat": "Red Hat", "dell": "Dell", "tenda": "Tenda", "siemens": "Siemens", "jenkins": "Jenkins",
    "intel": "Intel", "dlink": "D-Link", "sap": "SAP", "samsung": "Samsung", "gitlab": "GitLab", "netgear": "Netgear",
    "fortinet": "Fortinet", "paloaltonetworks": "Palo Alto Networks", "ivanti": "Ivanti", "vmware": "VMware", "nvidia": "NVIDIA",
    "mediatek": "MediaTek", "juniper": "Juniper", "tplink": "TP-Link", "wordpress": "WordPress", "php": "PHP", "openssl": "OpenSSL",
    "sourcecodester": "SourceCodester", "codeprojects": "code-projects", "phpgurukul": "PHPGurukul", "zyxel": "Zyxel", "f5": "F5",
    "atlassian": "Atlassian", "jetbrains": "JetBrains", "elastic": "Elastic", "splunk": "Splunk", "drupal": "Drupal", "qnap": "QNAP",
    "unisoc": "Unisoc", "amd": "AMD", "lenovo": "Lenovo", "citrix": "Citrix", "sonicwall": "SonicWall", "zoom": "Zoom",
    "mattermost": "Mattermost", "foxit": "Foxit", "arubanetworks": "Aruba Networks", "zoho": "Zoho", "hcl": "HCL", "cpanel": "cPanel",
    "deltaww": "Delta Electronics", "progress": "Progress Software", "oretnom23": "oretnom23 (SourceCodester)", "debian": "Debian", "tensorflow": "TensorFlow", "openclaw": "OpenClaw", "langflow": "Langflow",
}
AXES = [
    ("volume", "Volume (2026)"),
    ("growth", "Growth vs 2025"),
    ("crit_share", "Critical share"),
    ("kev", "Exploited (KEV)"),
    ("poc", "Public exploit code"),
    ("ai", "Found by AI"),
    ("memsafety", "Memory bugs share"),
]


def norm(x) -> str | None:
    if not isinstance(x, str):
        return None
    s = x.strip().lower()
    if s in ("", "n/a", "na", "unknown", "none", "-", "*"):
        return None
    s = s.replace("_", " ")
    s = SUFFIX.sub(" ", s)
    s = re.sub(r"[^a-z0-9]", "", s)
    if not s or s in ("na", "unknown", "none", "vendor", "unspecified"):
        return None
    return ALIAS.get(s, s)


def main():
    cves = pd.read_parquet(INTERIM / "cves.parquet", columns=["cve_id", "state", "date_published", "vendor", "product", "cwe", "adp_cwe", "cvss_severity"])
    cves = cves[cves.state == "PUBLISHED"].copy()
    cves["published"] = pd.to_datetime(cves.date_published, utc=True).dt.tz_convert(None)
    cves = cves[(cves.published >= "2016-01-01") & (cves.published <= pd.Timestamp(AS_OF) + pd.Timedelta(days=1))]
    nvd = pd.read_parquet(INTERIM / "nvd.parquet", columns=["cve_id", "nvd_vendor", "nvd_product", "nvd_cwe", "nvd_sev"])
    df = cves.merge(nvd, on="cve_id", how="left")
    df["key"] = df.nvd_vendor.map(norm).fillna(df.vendor.map(norm))
    df = df[df.key.notna()]
    df["year"] = df.published.dt.year
    df["family"] = df.cwe.fillna(df.adp_cwe).fillna(df.nvd_cwe).map(family)
    sev = df.cvss_severity.str.upper().where(df.cvss_severity.str.upper().isin(["LOW", "MEDIUM", "HIGH", "CRITICAL"]))
    df["sev"] = sev.fillna(df.nvd_sev.where(df.nvd_sev.isin(["LOW", "MEDIUM", "HIGH", "CRITICAL"])))
    df["prod"] = df.nvd_product.fillna(df["product"]).astype(str).str.replace("_", " ")

    kev = set(pd.DataFrame(json.loads((RAW / "kev" / "kev.json").read_text())["vulnerabilities"]).cveID)
    ai = set(pd.read_csv(CLEAN / "ai_attributed_cves.csv").cve_id)
    poc = set(pd.read_csv(CLEAN / "github_poc_first_seen.csv").cve_id)
    df["is_kev"] = df.cve_id.isin(kev)
    df["is_ai"] = df.cve_id.isin(ai)
    df["is_poc"] = df.cve_id.isin(poc)

    top = df.key.value_counts().head(TOP_N).index
    frac = AS_OF.timetuple().tm_yday / 365
    def pick_name(g: pd.DataFrame) -> str:
        k = g.name
        if k in DISPLAY:
            return DISPLAY[k]
        cna = g.vendor.dropna()
        cna = cna[cna.map(norm) == k]
        if len(cna):
            return str(cna.mode().iloc[0]).strip()[:28]
        cpe = g.nvd_vendor.dropna()
        if len(cpe):
            return str(cpe.mode().iloc[0]).replace("_", " ").replace("\\", "").title()[:28]
        return k

    names = df[df.key.isin(df.key.value_counts().head(TOP_N).index)].groupby("key")[["vendor", "nvd_vendor"]].apply(pick_name)
    out = []
    for k in top:
        g = df[df.key == k]
        yearly = g.groupby("year").size().reindex(range(2016, AS_OF.year + 1), fill_value=0)
        cur, prev = int(yearly.get(AS_OF.year, 0)), int(yearly.get(AS_OF.year - 1, 0))
        recent = g[g.year >= 2024]
        scored = recent[recent.sev.notna()]
        fam = g[(g.year >= 2020) & g.family.notna()]
        prods = g[g.year >= 2024]["prod"].value_counts()
        prods = [p for p in prods.index if p not in ("n/a", "nan", "None", "*")][:3]
        out.append({
            "key": k,
            "name": names.get(k, k),
            "total": int(len(g)),
            "yearly": [int(v) for v in yearly.values],
            "cur": cur,
            "prev": prev,
            "growth": round((cur / frac) / prev, 2) if prev else None,
            "crit_share": round(float((scored.sev == "CRITICAL").mean()), 3) if len(scored) >= 10 else None,
            "kev": int(g.is_kev.sum()),
            "poc": int(g.is_poc.sum()),
            "ai": int(g.is_ai.sum()),
            "memsafety": round(float((fam.family == "Memory safety").mean()), 3) if len(fam) >= 10 else None,
            "products": prods,
        })
    prof = pd.DataFrame(out)
    dup = prof.name.duplicated(keep=False)
    prof.loc[dup, "name"] = prof.loc[dup, "name"] + " (" + prof.loc[dup, "key"] + ")"
    prof["volume"] = prof.cur
    # radar scores: percentile rank among the top vendors (0 to 100); missing values score 0
    for key, _ in AXES:
        prof[f"r_{key}"] = (prof[key].rank(pct=True, method="average") * 100).round(0).fillna(0)
    write_clean_csv("vendor_profiles", prof.drop(columns=["yearly", "products"]))
    write_site_json("explore", {
        "years": list(range(2016, AS_OF.year + 1)),
        "axes": [{"key": k, "label": lab} for k, lab in AXES],
        "vendors": prof.to_dict("records"),
        "year_fraction": frac,
        "top_n": TOP_N,
    })
    print(prof[["name", "total", "cur", "growth", "crit_share", "kev", "poc", "ai", "memsafety"]].head(30).to_string())


if __name__ == "__main__":
    main()
