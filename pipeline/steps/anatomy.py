"""What kinds of flaws: weakness families over time, AI-found vs other bugs, AI-era weaknesses, daily calendar.

Inputs : data/interim/cves.parquet (cve_extract), data/interim/nvd.parquet (nvd_status),
         data/clean/ai_attributed_cves.csv (vulns)
Outputs: site/public/data/anatomy.json, data/clean/cwe_family_yearly.csv, data/clean/ai_era_weaknesses_monthly.csv,
         data/clean/cve_daily_2025_2026.csv
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import AS_OF, CLEAN, INTERIM, RAW, records, write_clean_csv, write_site_json  # noqa: E402

# Weakness families. Each CWE maps to one family; a record takes the family of its first mappable CWE.
FAMILIES: dict[str, list[int]] = {
    "Memory safety": [119, 120, 121, 122, 123, 124, 125, 126, 127, 129, 131, 134, 170, 190, 191, 193, 415, 416, 456, 457,
                      466, 467, 476, 562, 587, 590, 680, 681, 704, 761, 762, 763, 786, 787, 788, 805, 806, 822, 823, 824,
                      825, 843, 908, 909, 1284, 1325, 1341],
    "Injection and code execution": [74, 75, 76, 77, 78, 88, 89, 90, 91, 93, 94, 95, 96, 97, 98, 99, 113, 116, 117, 138,
                                     470, 502, 564, 611, 643, 652, 776, 917, 943, 1236, 1321, 1336, 1427],
    "Web (XSS, CSRF, SSRF)": [79, 80, 83, 84, 85, 86, 87, 352, 441, 601, 918, 1021, 1385],
    "Files and paths": [22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 59, 61, 62, 64, 65, 66,
                        73, 377, 379, 425, 434, 538, 552, 706],
    "Access control and auth": [250, 254, 255, 256, 257, 258, 259, 260, 261, 262, 263, 264, 266, 267, 268, 269, 270, 271,
                                272, 273, 274, 275, 276, 277, 278, 279, 280, 281, 282, 283, 284, 285, 286, 287, 288, 289,
                                290, 291, 292, 293, 294, 302, 303, 304, 305, 306, 307, 308, 309, 345, 346, 347, 348, 350,
                                384, 419, 420, 471, 472, 521, 522, 523, 547, 565, 603, 613, 618, 620, 639, 640, 645, 648,
                                732, 749, 798, 807, 829, 830, 862, 863, 915, 923, 939, 940, 942, 1188, 1220, 1259, 1390,
                                1391, 1392, 1393],
    "Data exposure and crypto": [200, 201, 202, 203, 204, 208, 209, 210, 212, 213, 214, 215, 295, 296, 297, 299, 310, 311,
                                 312, 313, 314, 315, 316, 317, 318, 319, 320, 321, 322, 323, 324, 325, 326, 327, 328, 329,
                                 330, 331, 334, 335, 336, 337, 338, 340, 341, 342, 343, 344, 349, 354, 359, 497, 524, 525,
                                 526, 527, 528, 529, 530, 531, 532, 533, 534, 535, 536, 537, 539, 540, 541, 548, 549, 550,
                                 598, 614, 615, 757, 759, 760, 780, 916, 922, 1004, 1191, 1204, 1230, 1240, 1275],
    "Resource, logic and races": [362, 363, 364, 365, 366, 367, 368, 369, 370, 385, 386, 399, 400, 401, 402, 403, 404, 405,
                                  406, 407, 408, 409, 410, 412, 459, 460, 617, 662, 664, 665, 666, 667, 668, 669, 670, 672,
                                  674, 675, 680, 682, 691, 696, 697, 754, 755, 770, 771, 772, 773, 774, 775, 789, 799, 834,
                                  835, 840, 841, 1050, 1088, 1333],
}
FAMILY_OF = {f"CWE-{c}": fam for fam, cs in FAMILIES.items() for c in cs}
ORDER = list(FAMILIES) + ["Other weakness"]

PROMPT_INJ = re.compile(r"prompt[- ]injection", re.I)
MCP = re.compile(r"model context protocol|\bmcp\b", re.I)
SASHIKO = re.compile(r"\bsashiko\b", re.I)
KERNEL_AI = re.compile(r"ai[- ]assisted|\bai review|found by (?:an )?ai\b|\bllm\b|\blollm\b|\bclaude\b|\bgpt-\d|\bgemini\b|\bcodex\b|"
                       r"large language model|ai-generated|\bai tool|\bai agent", re.I)
LLM = re.compile(r"\b(?:LLM|LLMs|large language models?|AI agents?|agentic|generative AI)\b", re.I)


def family(cwes: str | None) -> str | None:
    if not isinstance(cwes, str) or not cwes:
        return None
    ids = [c.strip() for c in cwes.split(";") if c.strip().startswith("CWE-")]
    for c in ids:
        if c in FAMILY_OF:
            return FAMILY_OF[c]
    return "Other weakness" if ids else None


def load() -> pd.DataFrame:
    df = pd.read_parquet(INTERIM / "cves.parquet", columns=["cve_id", "state", "assigner", "date_published", "description", "cwe",
                                                           "adp_cwe", "cvss_severity", "cvss_score"])
    df = df[df.state == "PUBLISHED"].copy()
    df["date_published"] = pd.to_datetime(df.date_published, utc=True).dt.tz_convert(None)
    df = df[df.date_published <= pd.Timestamp(AS_OF) + pd.Timedelta(days=1)]
    nvd = pd.read_parquet(INTERIM / "nvd.parquet", columns=["cve_id", "nvd_sev", "nvd_cwe"])
    df = df.merge(nvd, on="cve_id", how="left")
    df["cwe_all"] = df.cwe.fillna(df.adp_cwe).fillna(df.nvd_cwe)
    df["cwe_src"] = df.cwe.notna().map({True: "CNA"}).fillna(df.adp_cwe.notna().map({True: "CISA ADP"})).fillna(df.nvd_cwe.notna().map({True: "NVD"}))
    df["family"] = df.cwe_all.map(family)
    sev = df.cvss_severity.str.upper().where(df.cvss_severity.str.upper().isin(["LOW", "MEDIUM", "HIGH", "CRITICAL"]))
    df["sev_all"] = sev.fillna(df.nvd_sev.where(df.nvd_sev.isin(["LOW", "MEDIUM", "HIGH", "CRITICAL"])))
    df["sev_src"] = sev.notna().map({True: "CVE record"}).fillna(df.nvd_sev.notna().map({True: "NVD"}))
    df["year"] = df.date_published.dt.year
    df["month"] = df.date_published.dt.to_period("M").dt.to_timestamp()
    return df


def main():
    df = load()
    yr = df[df.year >= 2015]

    # 1) families by year (share of records with a classifiable CWE) + coverage
    fam_y = yr[yr.family.notna()].pivot_table(index="year", columns="family", values="cve_id", aggfunc="count", fill_value=0)
    fam_y = fam_y.reindex(columns=ORDER, fill_value=0).reset_index()
    cov = yr.groupby("year").agg(n=("cve_id", "count"), with_cwe=("family", lambda s: int(s.notna().sum()))).reset_index()
    cov["coverage"] = cov.with_cwe / cov.n

    # 2) AI-found vs everything else, 2025-2026 records
    ai_ids = set(pd.read_csv(CLEAN / "ai_attributed_cves.csv").cve_id)
    rec = df[(df.year >= 2025) & df.family.notna()].copy()
    rec["who"] = rec.cve_id.isin(ai_ids).map({True: "AI-credited", False: "Everything else"})
    ai_mix = rec.pivot_table(index="family", columns="who", values="cve_id", aggfunc="count", fill_value=0)
    ai_n = ai_mix.sum()
    ai_share = (ai_mix / ai_n).reindex(ORDER).fillna(0).reset_index()
    ai_share_counts = {k: int(v) for k, v in ai_n.items()}

    # 3) memory-safety share for the big C/C++ codebases
    bases = {"microsoft": "Microsoft", "Chrome": "Google Chrome", "google_android": "Android", "apple": "Apple", "Linux": "Linux kernel", "mozilla": "Mozilla"}
    ms = df[(df.year >= 2019) & df.assigner.isin(bases) & df.family.notna()].copy()
    ms["base"] = ms.assigner.map(bases)
    ms_share = ms.groupby(["base", "year"]).apply(lambda g: pd.Series({"share": (g.family == "Memory safety").mean(), "n": len(g)}), include_groups=False).reset_index()
    ms_wide = ms_share.pivot(index="year", columns="base", values="share").reset_index()
    ms_n = ms_share.pivot(index="year", columns="base", values="n").reset_index()

    # 4) AI-era weaknesses per month
    recent = df[df.month >= "2023-01-01"].copy()
    desc = recent.description.fillna("")
    recent["prompt_injection"] = desc.str.contains(PROMPT_INJ) | recent.cwe_all.fillna("").str.contains("CWE-1427")
    recent["mcp"] = desc.str.contains(MCP)
    recent["llm_agents"] = desc.str.contains(LLM) & ~recent.mcp & ~recent.prompt_injection
    era = recent.groupby("month")[["prompt_injection", "mcp", "llm_agents"]].sum().astype(int).reset_index()
    era_year = df.assign(mcp=df.description.fillna("").str.contains(MCP), pi=df.description.fillna("").str.contains(PROMPT_INJ))
    era_tot = {
        "mcp_cur": int(era_year[(era_year.year == AS_OF.year)].mcp.sum()),
        "mcp_prev": int(era_year[(era_year.year == AS_OF.year - 1)].mcp.sum()),
        "pi_cur": int(era_year[(era_year.year == AS_OF.year)].pi.sum()),
        "pi_prev": int(era_year[(era_year.year == AS_OF.year - 1)].pi.sum()),
    }
    mcp_sev = era_year[(era_year.year == AS_OF.year) & era_year.mcp].sev_all.value_counts(normalize=True).to_dict()

    # 4b) Linux kernel fixes that credit an AI reviewer (Sashiko or another LLM tool)
    kern = df[(df.assigner == "Linux") & (df.month >= "2025-01-01")].copy()
    kd = kern.description.fillna("")
    kern["sashiko"] = kd.str.contains(SASHIKO)
    kern["other_ai"] = kd.str.contains(KERNEL_AI) & ~kern.sashiko
    kernel_ai = kern.groupby("month").agg(kernel_cves=("cve_id", "count"), sashiko=("sashiko", "sum"), other_ai=("other_ai", "sum")).reset_index()
    kernel_ai[["sashiko", "other_ai"]] = kernel_ai[["sashiko", "other_ai"]].astype(int)
    kernel_tot = {"sashiko": int(kern.sashiko.sum()), "other_ai": int(kern.other_ai.sum()),
                  "since_apr": int(kern[kern.month >= "2026-04-01"][["sashiko", "other_ai"]].any(axis=1).sum()),
                  "kernel_since_apr": int((kern.month >= "2026-04-01").sum())}

    # 4c) research output (OpenAlex, title and abstract search)
    research = []
    for name in ("llm_security", "llm_all", "ml_vuln"):
        f = RAW / "openalex" / f"{name}.json"
        if f.exists():
            for g in json.loads(f.read_text())["group_by"]:
                research.append({"series": name, "year": int(g["key"]), "papers": int(g["count"])})
    research = pd.DataFrame(research)
    research_w = research.pivot(index="year", columns="series", values="papers").fillna(0).astype(int).reset_index() if len(research) else research

    # 5) daily calendar 2025-2026
    daily = df[df.year >= 2025].groupby(df.date_published.dt.date).size().rename("cves").reset_index().rename(columns={"date_published": "date"})
    daily["date"] = pd.to_datetime(daily.date)
    full = pd.DataFrame({"date": pd.date_range("2025-01-01", pd.Timestamp(AS_OF))})
    daily = full.merge(daily, on="date", how="left").fillna({"cves": 0})
    daily["cves"] = daily.cves.astype(int)
    daily["dow"] = daily.date.dt.day_of_week
    dow = daily[daily.date.dt.year == AS_OF.year].groupby("dow").cves.mean().round(1).tolist()
    top_days = daily.sort_values("cves", ascending=False).head(5)

    # 6) severity with NVD fallback (fills the pre-2022 gap)
    sev = yr[yr.sev_all.notna()].pivot_table(index="year", columns="sev_all", values="cve_id", aggfunc="count", fill_value=0)
    sev = sev.reindex(columns=["LOW", "MEDIUM", "HIGH", "CRITICAL"], fill_value=0).reset_index()
    sev_cov = yr.groupby("year").agg(n=("cve_id", "count"), scored=("sev_all", lambda s: int(s.notna().sum())), from_nvd=("sev_src", lambda s: int((s == "NVD").sum()))).reset_index()

    write_clean_csv("cwe_family_yearly", fam_y.merge(cov, on="year"))
    write_clean_csv("ai_era_weaknesses_monthly", era)
    write_clean_csv("cve_daily_2025_2026", daily[["date", "cves"]])
    write_site_json("anatomy", {
        "families": ORDER,
        "family_yearly": records(fam_y),
        "coverage": records(cov),
        "ai_vs_rest": records(ai_share),
        "ai_vs_rest_n": ai_share_counts,
        "memsafety": records(ms_wide),
        "memsafety_n": records(ms_n),
        "era_monthly": records(era),
        "era_totals": era_tot,
        "mcp_severity_cur": mcp_sev,
        "daily": records(daily[["date", "cves"]]),
        "dow_mean_cur": dow,
        "top_days": records(top_days[["date", "cves"]]),
        "severity_all": records(sev),
        "kernel_ai": records(kernel_ai),
        "kernel_ai_totals": kernel_tot,
        "research": records(research_w[research_w.year >= 2018]) if len(research) else [],
        "severity_cov": records(sev_cov),
    })
    print("   coverage:", cov.tail(4).to_dict("records"))
    print("   ai mix:", ai_share.round(3).to_dict("records"))
    print("   era:", era_tot, "mcp sev", {k: round(v, 2) for k, v in mcp_sev.items()})
    print("   memsafety:", ms_wide.round(2).to_string())
    print("   kernel:", kernel_tot, kernel_ai.tail(8).to_dict("records"))
    print("   dow:", dow, "top days:", top_days.to_dict("records"))


if __name__ == "__main__":
    main()
