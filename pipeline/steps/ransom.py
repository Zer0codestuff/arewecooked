"""Ransomware deep dive: where victims are (per capita), which brands lead each year, how fast the market churns, sectors.

Inputs : data/raw/ransomware_live/YYYY-MM.json, data/raw/worldbank/pop_2024.json, data/raw/worldbank/gdp_2024.json
Outputs: site/public/data/ransom.json, data/clean/ransomware_countries_2026.csv, data/clean/ransomware_group_ranks.csv
"""

from __future__ import annotations

import glob
import json
import sys
from pathlib import Path

import pandas as pd
import pycountry

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import AS_OF, RAW, records, write_clean_csv, write_site_json  # noqa: E402

# Brand families: rebrands and versions of the same operation are merged.
FAMILY = {
    "lockbit2": "LockBit", "lockbit3": "LockBit", "lockbit5": "LockBit", "lockbit": "LockBit",
    "alphv": "ALPHV/BlackCat", "blackcat": "ALPHV/BlackCat",
    "clop": "Cl0p", "cl0p": "Cl0p", "incransom": "INC Ransom", "inc ransom": "INC Ransom", "lynx": "Lynx",
    "ransomhub": "RansomHub", "blackbasta": "Black Basta", "bianlian": "BianLian", "8base": "8Base", "akira": "Akira",
    "qilin": "Qilin", "play": "Play", "hunters": "Hunters Intl.", "medusa": "Medusa", "safepay": "SafePay",
    "dragonforce": "DragonForce", "thegentlemen": "The Gentlemen", "nightspire": "NightSpire", "conti": "Conti",
    "hive": "Hive", "vicesociety": "Vice Society", "pysa": "Pysa", "avaddon": "Avaddon", "revil": "REvil", "maze": "Maze",
    "dispossessor": "Dispossessor", "royal": "Royal", "blacksuit": "BlackSuit", "noescape": "NoEscape", "rhysida": "Rhysida",
    "cactus": "Cactus", "funksec": "FunkSec", "sinobi": "Sinobi", "devman": "Devman", "worldleaks": "World Leaks",
    "everest": "Everest", "spook": "Spook", "blackbyte": "BlackByte", "ragnarlocker": "RagnarLocker", "netwalker": "NetWalker",
}


def load() -> pd.DataFrame:
    rows = []
    for f in sorted(glob.glob(str(RAW / "ransomware_live" / "*.json"))):
        try:
            data = json.loads(Path(f).read_text())
        except json.JSONDecodeError:
            continue
        for r in data if isinstance(data, list) else []:
            rows.append({
                "victim": (r.get("victim") or "").strip().lower(),
                "group": (r.get("group") or "").strip().lower(),
                "date": r.get("attackdate") or r.get("discovered"),
                "discovered": r.get("discovered"),
                "country": (r.get("country") or "").strip().upper() or None,
                "sector": r.get("activity") or None,
            })
    df = pd.DataFrame(rows)
    df["date"] = pd.to_datetime(df.date, errors="coerce", utc=True, format="mixed").dt.tz_convert(None)
    df["discovered"] = pd.to_datetime(df.discovered, errors="coerce", utc=True, format="mixed").dt.tz_convert(None)
    df["when"] = df.date.fillna(df.discovered)
    df = df[df.when.notna() & (df.when >= "2020-01-01") & (df.when <= pd.Timestamp(AS_OF))]
    df = df.drop_duplicates(["victim", "group"])
    df["year"] = df.when.dt.year
    df["family"] = df.group.map(lambda g: FAMILY.get(g, g))
    return df


def worldbank(name: str) -> pd.DataFrame:
    data = json.loads((RAW / "worldbank" / name).read_text())[1]
    return pd.DataFrame([{"iso2": d["country"]["id"], "iso3": d["countryiso3code"], "value": d["value"]} for d in data if d["value"] is not None])


def iso_numeric(a2: str) -> str | None:
    c = pycountry.countries.get(alpha_2=a2)
    return c.numeric if c else None


def main():
    df = load()
    cur = df[df.year == AS_OF.year]
    prev = df[df.year == AS_OF.year - 1]

    # 1) countries, per million people and per US$100B of GDP
    pop = worldbank("pop_2024.json").rename(columns={"value": "pop"})
    gdp = worldbank("gdp_2024.json").rename(columns={"value": "gdp"})
    cc = cur[cur.country.notna() & (cur.country.str.len() == 2)].country.value_counts().rename_axis("iso2").reset_index(name="victims")
    cp = prev[prev.country.notna() & (prev.country.str.len() == 2)].country.value_counts().rename_axis("iso2").reset_index(name="victims_prev")
    cc = cc.merge(cp, on="iso2", how="left").merge(pop[["iso2", "pop"]], on="iso2", how="left").merge(gdp[["iso2", "gdp"]], on="iso2", how="left")
    cc["per_million"] = cc.victims / (cc["pop"] / 1e6)
    cc["per_100b_gdp"] = cc.victims / (cc.gdp / 1e11)
    cc["id"] = cc.iso2.map(iso_numeric)
    cc["name"] = cc.iso2.map(lambda a: (pycountry.countries.get(alpha_2=a).name if pycountry.countries.get(alpha_2=a) else a))
    cc["name"] = cc.name.replace({"United States": "United States", "United Kingdom": "United Kingdom", "Korea, Republic of": "South Korea",
                                  "Taiwan, Province of China": "Taiwan", "Russian Federation": "Russia", "Viet Nam": "Vietnam",
                                  "Türkiye": "Turkey", "Iran, Islamic Republic of": "Iran"})
    known = int(cc.victims.sum())
    unknown = int(len(cur) - known)
    big = cc[cc["pop"] >= 1e6].sort_values("per_million", ascending=False)
    italy = cc[cc.iso2 == "IT"].to_dict("records")
    rank_count = cc.sort_values("victims", ascending=False).reset_index(drop=True)
    it_rank = int(rank_count.index[rank_count.iso2 == "IT"][0]) + 1 if (rank_count.iso2 == "IT").any() else None

    # 2) brand ranks per year (bump chart), top 6 each year since 2021
    ranks = []
    years = list(range(2021, AS_OF.year + 1))
    for y in years:
        vc = df[df.year == y].family.value_counts()
        for i, (g, v) in enumerate(vc.items()):
            ranks.append({"year": y, "group": g, "victims": int(v), "rank": i + 1, "share": float(v / vc.sum())})
    ranks = pd.DataFrame(ranks)
    keep = set(ranks[ranks["rank"] <= 5].group)
    bump = ranks[ranks.group.isin(keep)]

    # 3) churn: share of each year's victims claimed by brands first seen that year or the year before
    first = df.groupby("family").when.min().dt.year.rename("first_year")
    d2 = df.merge(first, left_on="family", right_index=True)
    d2["age"] = (d2.year - d2.first_year).clip(upper=3)
    age_lab = {0: "New this year", 1: "1 year old", 2: "2 years old", 3: "3+ years old"}
    churn = d2[d2.year >= 2022].pivot_table(index="year", columns="age", values="victim", aggfunc="count", fill_value=0)
    churn = churn.rename(columns=age_lab).reset_index()
    life = df.groupby("family").agg(first=("when", "min"), last=("when", "max"), victims=("victim", "count"))
    life = life[life.victims >= 50]
    life["months"] = (life["last"] - life["first"]).dt.days / 30.44
    gone = life[life["last"] < pd.Timestamp(AS_OF) - pd.Timedelta(days=90)]

    # 4) sectors, current vs previous year
    sec = df[(df.year >= AS_OF.year - 1) & df.sector.notna() & ~df.sector.isin(["Not Found", ""])]
    st = sec.pivot_table(index="sector", columns="year", values="victim", aggfunc="count", fill_value=0)
    st.columns = ["prev", "cur"]
    st = st.sort_values("cur", ascending=False).head(12).reset_index()
    frac = AS_OF.timetuple().tm_yday / 365
    st["cur_pace"] = st.cur / frac

    write_clean_csv("ransomware_countries_2026", cc.sort_values("victims", ascending=False))
    write_clean_csv("ransomware_group_ranks", ranks[ranks["rank"] <= 20])
    write_site_json("ransom", {
        "countries": records(cc.sort_values("victims", ascending=False)),
        "country_known": known,
        "country_unknown": unknown,
        "per_million_top": records(big.head(12)[["iso2", "name", "victims", "per_million", "pop"]]),
        "italy": italy[0] if italy else None,
        "italy_rank": it_rank,
        "bump": records(bump),
        "bump_years": years,
        "churn": records(churn),
        "churn_order": [age_lab[k] for k in range(4)],
        "lifespan_median_months": float(gone.months.median()),
        "brands_50plus": int(len(life)),
        "brands_gone": int(len(gone)),
        "sectors": records(st),
        "year_fraction": frac,
    })
    print(cc.sort_values("victims", ascending=False).head(12)[["iso2", "name", "victims", "per_million"]].round(1).to_string())
    print("per million top:", big.head(10)[["name", "victims", "per_million"]].round(1).to_string())
    print("italy", italy, it_rank, "unknown", unknown)
    print(bump.pivot(index="group", columns="year", values="rank").to_string())
    print(churn.to_string())
    print("lifespan", gone.months.median(), len(life), len(gone))
    print(st.round(0).to_string())


if __name__ == "__main__":
    main()
