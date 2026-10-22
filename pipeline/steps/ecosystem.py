"""Open-source supply chain (OSV), breaches (Have I Been Pwned) and markets (Yahoo Finance).

Outputs: site/public/data/supplychain.json, breaches.json, markets.json
"""

from __future__ import annotations

import json
import sys
import zipfile
from pathlib import Path

import orjson
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ai_patterns import AI_FINDERS  # noqa: E402
from _common import AS_OF, RAW, records, write_clean_csv, write_site_json  # noqa: E402

ECOS = ["npm", "PyPI", "crates.io", "Go", "Maven", "RubyGems", "NuGet", "Packagist"]


def supply_chain():
    rows = []
    for eco in ECOS:
        with zipfile.ZipFile(RAW / "osv" / f"{eco}.zip") as z:
            for n in z.namelist():
                if not n.endswith(".json"):
                    continue
                d = orjson.loads(z.read(n))
                vid = d.get("id", "")
                credits = " | ".join(c.get("name", "") for c in d.get("credits") or [])
                rows.append({
                    "id": vid,
                    "eco": eco,
                    "malicious": vid.startswith("MAL-"),
                    "published": d.get("published"),
                    "withdrawn": d.get("withdrawn"),
                    "aliases": ";".join(d.get("aliases") or []),
                    "credits": credits or None,
                    "summary": (d.get("summary") or "")[:200],
                })
    df = pd.DataFrame(rows)
    df = df[df.withdrawn.isna()].copy()
    df["published"] = pd.to_datetime(df.published, errors="coerce", utc=True, format="mixed").dt.tz_convert(None)
    df = df[df.published.notna() & (df.published <= pd.Timestamp(AS_OF))]
    df["month"] = df.published.dt.to_period("M").dt.to_timestamp()
    df["year"] = df.published.dt.year
    mal = df[df.malicious]
    mal_monthly = mal[mal.month >= "2022-01-01"].pivot_table(index="month", columns="eco", values="id", aggfunc="count", fill_value=0)
    mal_monthly = mal_monthly.reindex(columns=[e for e in ["npm", "PyPI"] if e in mal_monthly.columns], fill_value=0)
    mal_monthly["Other"] = mal[mal.month >= "2022-01-01"].query("eco not in ['npm','PyPI']").groupby("month").size().reindex(mal_monthly.index, fill_value=0)
    mal_monthly = mal_monthly.reset_index()
    mal_yearly = mal.groupby(["year", "eco"]).size().unstack(fill_value=0).reset_index()
    vulns = df[~df.malicious & df.id.str.startswith("GHSA")]
    vuln_yearly = vulns[vulns.year >= 2017].pivot_table(index="year", columns="eco", values="id", aggfunc="count", fill_value=0).reset_index()

    # AI credited open-source advisories (GHSA credits)
    def ai_label(c):
        if not isinstance(c, str):
            return None
        for label, pat in AI_FINDERS:
            if pat.search(c):
                return label
        return None

    vulns = vulns.assign(ai=vulns.credits.map(ai_label))
    ghsa_ai_monthly = vulns[vulns.month >= "2024-07-01"].groupby("month").agg(advisories=("id", "count"), ai=("ai", lambda s: s.notna().sum())).reset_index()
    write_clean_csv("osv_malicious_packages_monthly", mal_monthly)
    write_clean_csv("ghsa_advisories_yearly_by_ecosystem", vuln_yearly)
    write_site_json("supplychain", {
        "malicious_monthly": records(mal_monthly),
        "malicious_yearly": records(mal_yearly),
        "malicious_total": int(len(mal)),
        "malicious_cur_year": int((mal.year == AS_OF.year).sum()),
        "malicious_prev_year": int((mal.year == AS_OF.year - 1).sum()),
        "advisories_yearly": records(vuln_yearly),
        "ghsa_ai_monthly": records(ghsa_ai_monthly),
    })


def breaches():
    b = pd.DataFrame(json.loads((RAW / "hibp" / "breaches.json").read_text()))
    b = b[~b.IsFabricated & ~b.IsSpamList & ~b.IsRetired].copy()
    b["breach_date"] = pd.to_datetime(b.BreachDate, errors="coerce")
    b["added"] = pd.to_datetime(b.AddedDate, errors="coerce", utc=True).dt.tz_convert(None)
    b["year"] = b.breach_date.dt.year
    yearly = b[(b.year >= 2010)].groupby("year").agg(breaches=("Name", "count"), accounts=("PwnCount", "sum")).reset_index()
    # what kind of data leaks: share of breaches exposing each data class, recent vs older
    def classes(sub):
        s = sub.DataClasses.explode().value_counts() / len(sub)
        return s

    old = classes(b[(b.year >= 2015) & (b.year <= 2019)])
    new = classes(b[b.year >= 2023])
    keys = [k for k in new.sort_values(ascending=False).index[:14]]
    data_classes = [{"cls": k, "y2015_19": float(old.get(k, 0)), "y2023_26": float(new.get(k, 0))} for k in keys]
    top = b.sort_values("PwnCount", ascending=False).head(25)[["Title", "Domain", "BreachDate", "PwnCount", "IsStealerLog", "IsMalware"]]
    recent = b[b.breach_date >= f"{AS_OF.year - 1}-01-01"].sort_values("PwnCount", ascending=False).head(15)[["Title", "BreachDate", "PwnCount", "Domain"]]
    stealer = b[b.IsStealerLog].groupby("year").PwnCount.sum().rename("stealer_accounts").reset_index()
    write_clean_csv("hibp_breaches_yearly", yearly)
    write_site_json("breaches", {
        "yearly": records(yearly),
        "data_classes": data_classes,
        "top": records(top),
        "recent_top": records(recent),
        "stealer": records(stealer),
        "total_breaches": int(len(b)),
        "total_accounts": int(b.PwnCount.sum()),
    })


TICKER_NAMES = {
    "CIBR": "First Trust Nasdaq Cybersecurity ETF", "HACK": "Amplify Cybersecurity ETF", "BUG": "Global X Cybersecurity ETF",
    "IHAK": "iShares Cybersecurity and Tech ETF", "QQQ": "Nasdaq-100", "SPY": "S&P 500", "CRWD": "CrowdStrike",
    "PANW": "Palo Alto Networks", "FTNT": "Fortinet", "ZS": "Zscaler", "NET": "Cloudflare", "S": "SentinelOne",
    "OKTA": "Okta", "CHKP": "Check Point", "TENB": "Tenable", "RPD": "Rapid7", "QLYS": "Qualys",
}


def markets():
    series = {}
    for t in TICKER_NAMES:
        p = RAW / "prices" / f"{t}.json"
        if not p.exists():
            continue
        r = json.loads(p.read_text())["chart"]["result"][0]
        ts = pd.to_datetime(r["timestamp"], unit="s")
        adj = r["indicators"].get("adjclose", [{}])[0].get("adjclose") or r["indicators"]["quote"][0]["close"]
        s = pd.Series(adj, index=ts).dropna()
        s.index = s.index.to_period("M").to_timestamp()
        series[t] = s.groupby(level=0).last()
    px = pd.DataFrame(series)
    base = "2020-01-01"
    idx = px[px.index >= base]
    idx = (idx / idx.iloc[0] * 100).round(1)
    idx = idx.reset_index().rename(columns={"index": "month"})
    perf = []
    for t in TICKER_NAMES:
        if t not in px:
            continue
        s = px[t].dropna()
        def ret(start):
            s2 = s[s.index >= start]
            return float(s2.iloc[-1] / s2.iloc[0] - 1) if len(s2) > 1 else None
        perf.append({"ticker": t, "name": TICKER_NAMES[t], "since_2020": ret("2020-01-01"), "ytd": ret(f"{AS_OF.year}-01-01"), "one_year": ret(str(pd.Timestamp(AS_OF) - pd.DateOffset(years=1))[:10])})
    write_clean_csv("cyber_stocks_indexed_2020", idx)
    write_site_json("markets", {"indexed": records(idx), "perf": perf, "names": TICKER_NAMES})


def main():
    supply_chain()
    breaches()
    markets()


if __name__ == "__main__":
    main()
