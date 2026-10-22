"""Tests for manual-table validation, the cooked index and the story export."""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import pandas as pd
import pytest

from pipeline import build, export, indicators, manual
from pipeline.common import MANUAL

HEADER = "metric,year,value,unit,kind,source,source_url,note\n"
MILESTONE_HEADER = "date,side,title,detail,figure,source,source_url\n"


def write_manual(folder: Path, rows: str, milestones: str = "") -> None:
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "metrics.csv").write_text(HEADER + rows)
    (folder / "ai_milestones.csv").write_text(MILESTONE_HEADER + milestones)


# ---------------------------------------------------------------- manual tables


def test_committed_manual_tables_are_valid():
    metrics, milestones, problems = manual.load(MANUAL)
    assert problems == []
    assert not metrics.empty and not milestones.empty
    assert metrics["source_url"].str.startswith("http").all()
    assert milestones["source_url"].str.startswith("http").all()


def test_no_em_dashes_in_project_text():
    root = Path(__file__).resolve().parents[1]
    offenders = []
    for pattern in ("data/manual/*.csv", "pipeline/**/*.py", "site/src/**/*", "site/index.html", "README.md"):
        for path in root.glob(pattern):
            if path.is_file() and "\u2014" in path.read_text(encoding="utf-8", errors="ignore"):
                offenders.append(str(path.relative_to(root)))
    assert offenders == []


def test_manual_validation_reports_problems(tmp_path):
    write_manual(
        tmp_path,
        "a,2020,1,x,reported,Src,https://example.org,\n"
        "b,20x0,1,x,reported,Src,https://example.org,\n"
        "c,2020,abc,x,reported,Src,ftp://example.org,\n",
        "2025-01-01,sideways,T,D,,S,https://example.org\n",
    )
    _, _, problems = manual.load(tmp_path)
    text = "\n".join(problems)
    assert "year is not an integer" in text
    assert "value is not numeric" in text
    assert "source_url must be an http(s) URL" in text
    assert "side must be one of" in text


def test_manual_series():
    metrics = pd.DataFrame({"metric": ["m", "m", "n"], "year": [2021, 2020, 2020], "value": [2.0, 1.0, 5.0]})
    assert manual.series(metrics, "m")["year"].tolist() == [2020, 2021]


# ---------------------------------------------------------------- indicators


def series(pairs):
    return pd.DataFrame(pairs, columns=["year", "value"])


def test_growth_uses_baseline_average_and_drops_partial_year():
    ind = indicators.Indicator("x", "X", "pressure", series([(2017, 10), (2018, 20), (2019, 30), (2025, 60), (2026, 999)]))
    g = indicators.growth(ind, date(2026, 10, 1))
    assert g["baseline_label"] == "2017-2019" and g["baseline_value"] == 20
    assert g["latest_year"] == 2025 and g["multiple"] == 3


def test_growth_falls_back_to_first_year_and_keeps_reported_year():
    ind = indicators.Indicator("x", "X", "response", series([(2022, 4), (2026, 6)]), partial_current_year=False)
    g = indicators.growth(ind, date(2026, 10, 1))
    assert g["baseline_label"] == "2022" and g["latest_year"] == 2026 and g["multiple"] == 1.5


def test_growth_needs_two_points():
    ind = indicators.Indicator("x", "X", "pressure", series([(2025, 4)]))
    assert indicators.growth(ind, date(2026, 1, 1)) is None


@pytest.mark.parametrize("ratio,label", [(0.8, "Raw"), (1.2, "Simmering"), (2.0, "Cooking"), (3.0, "Well done"), (9.0, "Burnt")])
def test_verdict_levels(ratio, label):
    assert indicators.verdict(ratio)["label"] == label


def test_compute_ratio_is_geomean_ratio():
    inds = [
        indicators.Indicator("a", "A", "pressure", series([(2018, 1), (2025, 4)])),
        indicators.Indicator("b", "B", "pressure", series([(2018, 1), (2025, 1)])),
        indicators.Indicator("c", "C", "response", series([(2018, 1), (2025, 2)])),
    ]
    table, summary = indicators.compute(inds, date(2026, 1, 1))
    assert len(table) == 3
    assert summary["pressure_multiple"] == 2.0
    assert summary["response_multiple"] == 2.0
    assert summary["ratio"] == 1.0 and summary["verdict"]["label"] == "Simmering"


def test_default_indicators_skip_forecasts_and_old_gartner_values():
    metrics = pd.DataFrame(
        {
            "metric": ["gartner_security_spend"] * 4,
            "year": [2017, 2018, 2025, 2026],
            "value": [50.0, 100.0, 200.0, 400.0],
            "kind": ["estimate", "estimate", "estimate", "forecast"],
        }
    )
    inds = {i.id: i for i in indicators.default_indicators({}, metrics)}
    assert inds["spending"].series["year"].tolist() == [2018, 2025]


# ---------------------------------------------------------------- export and build


def test_build_and_export_end_to_end(tmp_path, monkeypatch):
    raw, clean, man, site = tmp_path / "raw", tmp_path / "clean", tmp_path / "manual", tmp_path / "site"
    (raw / "hibp").mkdir(parents=True)
    (raw / "hibp" / "breaches.json").write_text(
        json.dumps([{"Name": "A", "Title": "A", "BreachDate": "2019-01-01", "PwnCount": 10, "IsVerified": True}])
    )
    (raw / "p0").mkdir()
    (raw / "p0" / "2018.csv").write_text("CVE,Vendor\nCVE-2018-1001,Microsoft\n")
    (raw / "p0" / "2025.csv").write_text("CVE,Vendor\nCVE-2025-1001,Microsoft\nCVE-2025-1002,Apple\n")
    write_manual(
        man,
        "isc2_workforce,2019,2,people m,survey estimate,ISC2,https://example.org/isc2,\n"
        "isc2_workforce,2024,3,people m,survey estimate,ISC2,https://example.org/isc2,\n",
        "2025-08-08,defense,AIxCC,Finals,18,DARPA,https://example.org/darpa\n",
    )
    written = build.run(["hibp", "p0", "kev"], date(2026, 10, 1), raw_dir=raw, clean_dir=clean)
    assert set(written) == {"hibp", "p0"}  # kev skipped: no raw file
    build.update_meta(clean, date(2026, 10, 1), written)
    monkeypatch.setattr(export, "SITE_DATA", site)
    story, table, problems = export.build_story(clean_dir=clean, manual_dir=man)
    assert problems == []
    assert story["meta"]["as_of"] == "2026-10-01" and story["meta"]["partial_year"] == 2026
    assert story["datasets"]["zeroday_by_year"] == [{"year": 2018, "zero_days": 1}, {"year": 2025, "zero_days": 2}]
    assert story["manual"]["isc2_workforce"][0]["source_url"] == "https://example.org/isc2"
    assert story["milestones"][0]["title"] == "AIxCC"
    assert story["index"]["summary"]["ratio"] == round(2 / 1.5, 3)
    json.dumps(story, allow_nan=False)  # strict JSON, no NaN


def test_build_keeps_existing_tables_when_raw_missing(tmp_path):
    clean = tmp_path / "clean"
    clean.mkdir()
    (clean / "cve_by_year.csv").write_text("year,cves,rejected\n2025,1,0\n")
    written = build.run(["nvd"], date(2026, 1, 1), raw_dir=tmp_path / "raw", clean_dir=clean)
    assert written == {}
    assert (clean / "cve_by_year.csv").read_text().startswith("year,cves")


def test_cli_rejects_unknown_source():
    with pytest.raises(SystemExit):
        build.main(["--only", "nope"])


def test_committed_story_matches_schema():
    path = Path(__file__).resolve().parents[1] / "site" / "public" / "data" / "story.json"
    story = json.loads(path.read_text())
    assert {"meta", "sources", "datasets", "manual", "milestones", "index"} <= set(story)
    for name in ("cve_by_year", "kev_by_year", "ai_credits_month", "ransomware_by_month", "exploits_by_year"):
        assert story["datasets"][name], name
    assert story["index"]["summary"]["verdict"]["label"]
