"""Unit tests for the per-source processors, using small synthetic inputs."""

from __future__ import annotations

import gzip
import io
import json
import lzma
import zipfile
from collections import Counter
from datetime import date

import pandas as pd
import pytest

from pipeline.common import median_or_none, month_key, parse_date
from pipeline.sources import cvelist, epss, exploits, hibp, kev, nvd, p0, ransomware


# ---------------------------------------------------------------- common


@pytest.mark.parametrize(
    "value,expected",
    [
        ("2024-03-05T10:00:00.000", date(2024, 3, 5)),
        ("2024/3/5", date(2024, 3, 5)),
        ("2024-02-30", None),
        ("", None),
        (None, None),
        (date(2020, 1, 1), date(2020, 1, 1)),
    ],
)
def test_parse_date(value, expected):
    assert parse_date(value) == expected


def test_month_key_and_median():
    assert month_key(date(2026, 3, 9)) == "2026-03"
    assert median_or_none([3, 1, 2]) == 2
    assert median_or_none([1, 2, 3, 4]) == 2.5
    assert median_or_none([]) is None


# ---------------------------------------------------------------- NVD


def nvd_cve(cve_id, published, status="Analyzed", severity="HIGH", key="cvssMetricV31"):
    metrics = {key: [{"type": "Primary", "cvssData": {"baseSeverity": severity}}]} if severity else {}
    return {"cve": {"id": cve_id, "published": published, "vulnStatus": status, "metrics": metrics}}


def test_nvd_process(tmp_path):
    folder = tmp_path / "nvd"
    folder.mkdir()
    items = [
        nvd_cve("CVE-2024-0001", "2024-01-10T00:00:00", severity="CRITICAL"),
        nvd_cve("CVE-2024-0002", "2024-02-10T00:00:00", status="Deferred", severity=None),
        nvd_cve("CVE-2024-0003", "2024-02-11T00:00:00", status="Rejected"),
        nvd_cve("CVE-2025-0001", "2025-05-01T00:00:00", status="Awaiting Analysis", severity="LOW", key="cvssMetricV40"),
        nvd_cve("CVE-2014-0001", "2014-05-01T00:00:00"),
        nvd_cve("CVE-2026-0001", "2026-12-01T00:00:00"),
    ]
    with lzma.open(folder / "CVE-2024.json.xz", "wt", encoding="utf-8") as fh:
        json.dump({"cve_items": [i["cve"] for i in items]}, fh)
    result = nvd.build(tmp_path, as_of=date(2026, 6, 1))
    by_year = result.tables["cve_by_year"].set_index("year")
    assert list(by_year.index) == [2024, 2025]  # 2014 before start, 2026 after as_of
    assert by_year.loc[2024, "cves"] == 2 and by_year.loc[2024, "rejected"] == 1
    sev = result.tables["cve_severity_year"].set_index("year")
    assert sev.loc[2024, "critical"] == 1 and sev.loc[2024, "unscored"] == 1
    assert sev.loc[2025, "low"] == 1
    status = result.tables["nvd_status_year"].set_index("year")
    assert status.loc[2024, "deferred"] == 1 and status.loc[2025, "waiting"] == 1
    assert result.published["CVE-2026-0001"] == date(2026, 12, 1)  # dates kept for KEV lag
    assert list(result.tables["cve_by_month"]["month"]) == ["2024-01", "2024-02", "2025-05"]


def test_nvd_best_severity_prefers_v31_primary():
    metrics = {
        "cvssMetricV31": [
            {"type": "Secondary", "cvssData": {"baseSeverity": "LOW"}},
            {"type": "Primary", "cvssData": {"baseSeverity": "HIGH"}},
        ],
        "cvssMetricV2": [{"type": "Primary", "baseSeverity": "MEDIUM"}],
    }
    assert nvd.best_severity(metrics) == "HIGH"
    assert nvd.best_severity({"cvssMetricV2": [{"type": "Primary", "baseSeverity": "MEDIUM"}]}) == "MEDIUM"
    assert nvd.best_severity({}) is None


def test_nvd_missing_dir(tmp_path):
    assert nvd.build(tmp_path) is None


# ---------------------------------------------------------------- CVE List / AI credits


@pytest.mark.parametrize(
    "text,label",
    [
        ("Google Big Sleep", "Google Big Sleep"),
        ("Claude Opus 5 (1M context)", "Anthropic Claude"),
        ("This vulnerability was discovered by XBOW.", "XBOW"),
        ("Joshua Rogers (AISLE Research)", "AISLE"),
        ("Zhenpeng (Leo) Lin at depthfirst", "depthfirst"),
        ("openai/gpt-5.5-cyber-preview", "OpenAI"),
        ("found with an AI-assisted fuzzer", "Other AI mention"),
        ("Jane Doe of Example Corp", None),
        ("Bilishim Cyber Security and Artificial Intelligence Ltd", None),
        ("aisle seat", None),  # AISLE match is case sensitive
    ],
)
def test_classify_credit(text, label):
    assert cvelist.classify_credit(text) == label


def cve5(cve_id, published, credits=(), state="PUBLISHED", adp_credits=()):
    doc = {
        "cveMetadata": {"cveId": cve_id, "state": state, "datePublished": published},
        "containers": {"cna": {"credits": [{"lang": "en", "value": c} for c in credits]}},
    }
    if adp_credits:
        doc["containers"]["adp"] = [{"credits": [{"value": c} for c in adp_credits]}]
    return json.dumps(doc).encode()


def test_cvelist_process():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("cves/2025/0xxx/CVE-2025-0001.json", cve5("CVE-2025-0001", "2025-07-01T00:00:00", ["Google Big Sleep"]))
        z.writestr("cves/2025/0xxx/CVE-2025-0002.json", cve5("CVE-2025-0002", "2025-07-02T00:00:00", ["Jane Doe"]))
        z.writestr("cves/2025/0xxx/CVE-2025-0003.json", cve5("CVE-2025-0003", "2025-08-02T00:00:00"))
        z.writestr("cves/2026/0xxx/CVE-2026-0001.json", cve5("CVE-2026-0001", "2026-01-05T00:00:00", adp_credits=["XBOW"]))
        z.writestr("cves/2026/0xxx/CVE-2026-0002.json", cve5("CVE-2026-0002", "2026-01-06T00:00:00", ["XBOW"], state="REJECTED"))
        z.writestr("cves/delta.json", b"{}")
    buf.seek(0)
    tables = cvelist.process(zipfile.ZipFile(buf))
    month = tables["ai_credits_month"].set_index("month")
    assert month.loc["2025-07", "published"] == 2
    assert month.loc["2025-07", "with_credits"] == 2
    assert month.loc["2025-07", "ai_credited"] == 1
    assert month.loc["2026-01", "ai_credited"] == 1  # ADP credits count, rejected record does not
    tools = tables["ai_credits_tool"].set_index("system")
    assert tools.loc["XBOW", "cves"] == 1 and tools.loc["Google Big Sleep", "first_month"] == "2025-07"
    assert tables["ai_credits_recent"].iloc[0]["cve"] == "CVE-2026-0001"


def test_cvelist_nested_zip(tmp_path):
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as z:
        z.writestr("cves/2025/CVE-2025-0001.json", cve5("CVE-2025-0001", "2025-07-01T00:00:00", ["Big Sleep"]))
    folder = tmp_path / "cvelist"
    folder.mkdir()
    with zipfile.ZipFile(folder / "cvelist.zip.zip", "w") as outer:
        outer.writestr("cves.zip", inner.getvalue())
    tables = cvelist.build(tmp_path)
    assert int(tables["ai_credits_month"]["ai_credited"].sum()) == 1


# ---------------------------------------------------------------- KEV


def test_kev_process():
    entries = [
        {"cveID": "CVE-2022-1", "dateAdded": "2022-01-10", "vendorProject": "Microsoft", "knownRansomwareCampaignUse": "Known"},
        {"cveID": "CVE-2022-2", "dateAdded": "2022-03-01", "vendorProject": "Microsoft", "knownRansomwareCampaignUse": "Unknown"},
        {"cveID": "CVE-2010-1", "dateAdded": "2022-03-01", "vendorProject": "Adobe", "knownRansomwareCampaignUse": "Unknown"},
        {"cveID": "CVE-2023-1", "dateAdded": "2023-05-01", "vendorProject": "Ivanti", "knownRansomwareCampaignUse": "Known"},
    ]
    published = {
        "CVE-2022-1": date(2022, 1, 10),  # same day
        "CVE-2022-2": date(2022, 2, 1),  # 28 days
        "CVE-2010-1": date(2010, 1, 1),  # before KEV launch, excluded from lag
        "CVE-2023-1": date(2023, 4, 28),  # 3 days
    }
    t = kev.process(entries, published)
    by_year = t["kev_by_year"].set_index("year")
    assert by_year.loc[2022, "added"] == 3 and by_year.loc[2022, "ransomware_known"] == 1
    lag = t["kev_lag_year"].set_index("year")
    assert lag.loc[2022, "fresh_cves"] == 2
    assert lag.loc[2022, "median_days"] == 14
    assert lag.loc[2022, "share_within_7d"] == 0.5
    assert lag.loc[2023, "share_same_day_or_before"] == 0.0
    vendors = t["kev_vendors"].set_index("vendor")
    assert vendors.loc["Microsoft", "all_time"] == 2
    assert vendors.loc["Adobe", "last_3_years"] == 1


# ---------------------------------------------------------------- EPSS


def test_epss_buckets(tmp_path):
    folder = tmp_path / "epss"
    folder.mkdir()
    text = "#model_version:v2025.03.14,score_date:2026-10-22T12:55:00Z\ncve,epss,percentile\n"
    rows = [("CVE-1", 0.0005), ("CVE-2", 0.005), ("CVE-3", 0.05), ("CVE-4", 0.2), ("CVE-5", 0.9), ("CVE-6", 1.0)]
    text += "".join(f"{c},{s},0.5\n" for c, s in rows)
    with gzip.open(folder / "epss_current.csv.gz", "wt") as fh:
        fh.write(text)
    t = epss.build(tmp_path)
    assert t["epss_buckets"]["cves"].tolist() == [1, 1, 1, 1, 2]
    s = t["epss_summary"].iloc[0]
    assert s["model_version"] == "v2025.03.14" and s["score_date"] == "2026-10-22"
    assert s["above_10pct"] == 3 and s["above_50pct"] == 2


# ---------------------------------------------------------------- exploits


def test_exploits_process():
    edb = (Counter({2014: 5, 2020: 3}), Counter({2020: 1}))
    df = exploits.process(edb, Counter({2020: 2, 2021: 1}), None)
    assert df["year"].tolist() == [2020, 2021]
    assert df.set_index("year").loc[2021, "exploitdb"] == 0
    assert df["nuclei_cve_templates"].isna().all()


def test_exploit_readers(tmp_path):
    edb = tmp_path / "files_exploits.csv"
    edb.write_text("id,date_published,codes\n1,2020-01-01,CVE-2020-1;OSVDB-2\n2,2020-02-01,\n3,bad,\n")
    total, with_cve = exploits.exploitdb_counts(edb)
    assert total[2020] == 2 and with_cve[2020] == 1
    msf = tmp_path / "msf.json"
    msf.write_text(json.dumps({"a": {"type": "exploit", "disclosure_date": "2019-04-01"}, "b": {"type": "auxiliary", "disclosure_date": "2019-04-01"}}))
    assert exploits.metasploit_counts(msf)[2019] == 1
    nuc = tmp_path / "cves.json"
    nuc.write_text('{"ID":"CVE-2021-44228"}\n\nnot json\n{"ID":"CVE-2023-1"}\n')
    assert exploits.nuclei_counts(nuc) == Counter({2021: 1, 2023: 1})


# ---------------------------------------------------------------- Project Zero


def test_p0(tmp_path):
    folder = tmp_path / "p0"
    folder.mkdir()
    (folder / "2021.csv").write_text("CVE,Vendor,Product\nCVE-2021-1001,Microsoft,Windows\nCVE-2021-1002,Apple,iOS\nCVE-2021-1001,Microsoft,Windows\n,,\n")
    (folder / "2014.csv").write_text("CVE,Vendor\nCVE-2014-1001,Adobe\n")
    t = p0.build(tmp_path)
    assert t["zeroday_by_year"].to_dict("records") == [{"year": 2021, "zero_days": 2}]
    assert t["zeroday_vendors"].iloc[0]["vendor"] == "Microsoft"


# ---------------------------------------------------------------- HIBP


def test_hibp():
    breaches = [
        {"Name": "A", "Title": "A", "BreachDate": "2019-01-01", "PwnCount": 100, "IsVerified": True},
        {"Name": "B", "Title": "B", "BreachDate": "2019-06-01", "PwnCount": 50, "IsVerified": True},
        {"Name": "C", "Title": "C", "BreachDate": "2019-06-01", "PwnCount": 999, "IsVerified": True, "IsFabricated": True},
        {"Name": "D", "Title": "D", "BreachDate": "2019-06-01", "PwnCount": 999, "IsVerified": False},
        {"Name": "E", "Title": "E", "BreachDate": "2010-06-01", "PwnCount": 999, "IsVerified": True},
    ]
    t = hibp.process(breaches)
    assert t["breaches_by_year"].to_dict("records") == [{"year": 2019, "breaches": 2, "accounts": 150}]
    assert t["breaches_largest"].iloc[0]["name"] == "A"


# ---------------------------------------------------------------- ransomware.live


def test_ransomware_dedupe_and_coverage(tmp_path):
    folder = tmp_path / "ransomwarelive"
    folder.mkdir()
    posts = [
        {"victim": "Acme", "group": "lockbit3", "discovered": "2024-01-02 10:00:00"},
        {"victim": "ACME ", "group": "lockbit3", "discovered": "2024-01-05 10:00:00"},  # duplicate
        {"victim": "Acme", "group": "akira", "discovered": "2024-02-01 10:00:00"},  # same victim, other group
        {"victim": "Old", "group": "conti", "discovered": "2021-09-01 10:00:00"},  # before coverage start
        {"victim": "Future", "group": "akira", "discovered": "2026-11-01"},  # after as_of
        {"victim": "", "group": "akira", "discovered": "2024-02-01"},
        {"victim": "Beta", "group": "akira", "discovered": "2025-03-01"},
    ]
    (folder / "2024-01.json").write_text(json.dumps(posts))
    (folder / "2024-02.json").write_text("not json")
    t = ransomware.build(tmp_path, as_of=date(2026, 10, 1))
    assert t["ransomware_by_month"].to_dict("records") == [
        {"month": "2024-01", "victims": 1},
        {"month": "2024-02", "victims": 1},
        {"month": "2025-03", "victims": 1},
    ]
    by_year = t["ransomware_by_year"].set_index("year")
    assert by_year.loc[2024, "victims"] == 2 and by_year.loc[2024, "active_groups"] == 2
    groups = t["ransomware_groups"]
    assert set(groups["year"]) == {2025}  # latest full year before as_of


def test_missing_sources_return_none(tmp_path):
    assert kev.build(tmp_path) is None
    assert epss.build(tmp_path) is None
    assert exploits.build(tmp_path) is None
    assert p0.build(tmp_path) is None
    assert hibp.build(tmp_path) is None
    assert ransomware.build(tmp_path) is None
    assert cvelist.build(tmp_path) is None


def test_frames_have_expected_columns():
    t = kev.process([], {})
    assert list(t["kev_lag_year"].columns) == ["year", "fresh_cves", "median_days", "share_within_7d", "share_same_day_or_before"]
    assert isinstance(t["kev_vendors"], pd.DataFrame)
