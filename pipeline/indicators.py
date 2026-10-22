"""The "cooked index": how fast threats grew compared with how fast defenses grew.

For every indicator we compare its latest complete year with a baseline (the
average of BASELINE_YEARS, or the earliest available year when the series starts
later) and get a growth multiple. Pressure indicators measure the threat side,
response indicators measure money and people. The verdict is the ratio of the
geometric means:

    cooked ratio = geomean(pressure multiples) / geomean(response multiples)

A ratio of 1 means defenses kept pace. Above 1, threats outgrew defenses. This
is a deliberately simple, transparent heuristic, not a forecast.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import date

import pandas as pd

from pipeline.common import BASELINE_YEARS

# Gartner widened its security market definition in 2018; earlier values are not comparable.
SPENDING_SERIES_START = 2018

# (upper bound of ratio, level, label, one-line explanation)
VERDICTS = [
    (1.0, 0, "Raw", "Defenses grew at least as fast as threats."),
    (1.5, 1, "Simmering", "Threats are growing a bit faster than defenses."),
    (2.5, 2, "Cooking", "Threats are clearly outgrowing the money and people defending against them."),
    (4.0, 3, "Well done", "Threats grew several times faster than defenses."),
    (math.inf, 4, "Burnt", "Defense has lost track of the threat curve."),
]


@dataclass
class Indicator:
    id: str
    label: str
    group: str  # "pressure" or "response"
    series: pd.DataFrame  # columns: year, value
    partial_current_year: bool = True  # running counts: drop the unfinished year
    source: str = ""


def growth(ind: Indicator, as_of: date) -> dict | None:
    s = ind.series.dropna().sort_values("year")
    if ind.partial_current_year:
        s = s[s["year"] < as_of.year]
    s = s[s["value"] > 0]
    if len(s) < 2:
        return None
    base = s[s["year"].isin(BASELINE_YEARS)]
    if base.empty:
        first = int(s["year"].iloc[0])
        base = s[s["year"] == first]
        baseline_label = str(first)
    else:
        years = sorted(base["year"].astype(int))
        baseline_label = f"{years[0]}-{years[-1]}" if len(years) > 1 else str(years[0])
    baseline_value = float(base["value"].mean())
    latest = s.iloc[-1]
    if int(latest["year"]) <= int(base["year"].max()):
        return None
    return {
        "id": ind.id,
        "label": ind.label,
        "group": ind.group,
        "source": ind.source,
        "baseline_label": baseline_label,
        "baseline_value": round(baseline_value, 4),
        "latest_year": int(latest["year"]),
        "latest_value": round(float(latest["value"]), 4),
        "multiple": round(float(latest["value"]) / baseline_value, 4),
    }


def geomean(values: list[float]) -> float | None:
    vals = [v for v in values if v and v > 0]
    if not vals:
        return None
    return math.exp(sum(math.log(v) for v in vals) / len(vals))


def verdict(ratio: float) -> dict:
    for bound, level, label, text in VERDICTS:
        if ratio < bound:
            return {"level": level, "label": label, "text": text}
    raise AssertionError("unreachable")  # pragma: no cover


def compute(indicators: list[Indicator], as_of: date) -> tuple[pd.DataFrame, dict]:
    rows = [r for r in (growth(i, as_of) for i in indicators) if r]
    table = pd.DataFrame(
        rows,
        columns=["id", "label", "group", "source", "baseline_label", "baseline_value", "latest_year", "latest_value", "multiple"],
    )
    pressure = geomean(table[table["group"] == "pressure"]["multiple"].tolist())
    response = geomean(table[table["group"] == "response"]["multiple"].tolist())
    summary: dict = {"pressure_multiple": None, "response_multiple": None, "ratio": None, "verdict": None}
    if pressure and response:
        ratio = pressure / response
        summary = {
            "pressure_multiple": round(pressure, 3),
            "response_multiple": round(response, 3),
            "ratio": round(ratio, 3),
            "verdict": verdict(ratio),
        }
    return table, summary


def default_indicators(tables: dict[str, pd.DataFrame], metrics: pd.DataFrame) -> list[Indicator]:
    """Build the indicator list from clean tables and manual metrics (skips anything missing)."""
    out: list[Indicator] = []

    def table_series(name: str, column: str) -> pd.DataFrame | None:
        df = tables.get(name)
        if df is None or column not in df.columns:
            return None
        return df[["year", column]].rename(columns={column: "value"})

    def manual_series(metric: str, min_year: int | None = None) -> pd.DataFrame | None:
        """Reported values only: forecasts and derived values never enter the index."""
        if metrics is None or metrics.empty:
            return None
        df = metrics[metrics["metric"] == metric]
        if "kind" in df.columns:
            df = df[~df["kind"].isin(["forecast", "derived"])]
        if min_year is not None:
            df = df[df["year"] >= min_year]
        df = df[["year", "value"]]
        return df if not df.empty else None

    specs = [
        ("cves", "CVEs published", "pressure", table_series("cve_by_year", "cves"), True, "NVD"),
        ("zero_days", "Zero-days exploited in the wild", "pressure", table_series("zeroday_by_year", "zero_days"), True, "Project Zero"),
        ("ransomware", "Ransomware leak-site victims", "pressure", table_series("ransomware_by_year", "victims"), True, "ransomware.live"),
        ("ic3_losses", "Cybercrime losses reported to the FBI", "pressure", manual_series("ic3_losses"), False, "FBI IC3"),
        ("breach_cost", "Average cost of a data breach", "pressure", manual_series("ibm_breach_cost"), False, "IBM"),
        ("spending", "Security spending", "response", manual_series("gartner_security_spend", SPENDING_SERIES_START), False, "Gartner"),
        ("workforce", "Security workforce", "response", manual_series("isc2_workforce"), False, "ISC2"),
    ]
    sev = tables.get("cve_severity_year")
    if sev is not None and {"critical", "high"} <= set(sev.columns):
        crit = pd.DataFrame({"year": sev["year"], "value": sev["critical"] + sev["high"]})
        specs.insert(1, ("severe_cves", "Critical and high severity CVEs", "pressure", crit, True, "NVD"))
    for ident, label, group, series, partial, source in specs:
        if series is not None and not series.empty:
            out.append(Indicator(ident, label, group, series.reset_index(drop=True), partial, source))
    return out
