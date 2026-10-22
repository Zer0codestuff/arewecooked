"""Flatten every CVE JSON 5 record from the CVE List into one parquet table.

Input : data/raw/cvelist/cves.zip (inner zip of the cvelistV5 release)
Output: data/interim/cves.parquet  (one row per CVE ID, including REJECTED)
"""

from __future__ import annotations

import sys
import zipfile
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import orjson
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import INTERIM, RAW  # noqa: E402

ZIP = RAW / "cvelist" / "cves.zip"
SEV_ORDER = ["cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"]


def _first_en(items, key="value"):
    for it in items or []:
        if str(it.get("lang", "")).lower().startswith("en"):
            return it.get(key) or ""
    return (items[0].get(key) or "") if items else ""


def _cvss(metrics):
    """Return (version, base_score, severity) for the newest CVSS version present."""
    best = None
    for m in metrics or []:
        for ver in SEV_ORDER:
            if ver in m and isinstance(m[ver], dict):
                rank = SEV_ORDER.index(ver)
                if best is None or rank < best[0]:
                    d = m[ver]
                    best = (rank, ver, d.get("baseScore"), d.get("baseSeverity"))
    if best is None:
        return None, None, None
    return best[1], best[2], best[3]


def _ssvc(metrics):
    for m in metrics or []:
        other = m.get("other") or {}
        if other.get("type") == "ssvc":
            opts = {}
            for o in (other.get("content") or {}).get("options", []):
                opts.update(o)
            return opts.get("Exploitation"), opts.get("Automatable"), opts.get("Technical Impact")
    return None, None, None


def parse(raw: bytes) -> dict | None:
    d = orjson.loads(raw)
    meta = d.get("cveMetadata", {})
    cid = meta.get("cveId")
    if not cid:
        return None
    cont = d.get("containers", {})
    cna = cont.get("cna", {}) or {}
    adps = cont.get("adp", []) or []

    cwes = set()
    for pt in cna.get("problemTypes", []) or []:
        for desc in pt.get("descriptions", []) or []:
            if desc.get("cweId"):
                cwes.add(desc["cweId"])
    adp_cwes = set()
    for adp in adps:
        for pt in adp.get("problemTypes", []) or []:
            for desc in pt.get("descriptions", []) or []:
                if desc.get("cweId"):
                    adp_cwes.add(desc["cweId"])

    ver, score, sev = _cvss(cna.get("metrics"))
    score_src = "cna" if score is not None else None
    if score is None:
        for adp in adps:
            ver, score, sev = _cvss(adp.get("metrics"))
            if score is not None:
                score_src = "adp"
                break
    ssvc = (None, None, None)
    for adp in adps:
        s = _ssvc(adp.get("metrics"))
        if s[0] is not None:
            ssvc = s
            break

    affected = cna.get("affected", []) or []
    vendor = product = None
    if affected:
        vendor = affected[0].get("vendor")
        product = affected[0].get("product")

    credits = cna.get("credits", []) or []
    credit_txt = " | ".join(f"{c.get('value','')} [{c.get('type','')}]" for c in credits if c.get("value"))

    refs = cna.get("references", []) or []
    ref_urls = " ".join(r.get("url", "") for r in refs)[:2000]
    ref_tags = sorted({t for r in refs for t in (r.get("tags") or [])})

    desc = _first_en(cna.get("descriptions")) or _first_en(cna.get("rejectedReasons"))

    return {
        "cve_id": cid,
        "id_year": int(cid.split("-")[1]),
        "state": meta.get("state"),
        "assigner": meta.get("assignerShortName"),
        "date_reserved": meta.get("dateReserved"),
        "date_published": meta.get("datePublished"),
        "date_updated": meta.get("dateUpdated"),
        "date_rejected": meta.get("dateRejected"),
        "title": cna.get("title"),
        "description": (desc or "")[:1500],
        "vendor": vendor,
        "product": product,
        "n_affected": len(affected),
        "cwe": ";".join(sorted(cwes)) or None,
        "adp_cwe": ";".join(sorted(adp_cwes)) or None,
        "cvss_version": ver,
        "cvss_score": score,
        "cvss_severity": (sev or "").upper() or None,
        "cvss_source": score_src,
        "ssvc_exploitation": ssvc[0],
        "ssvc_automatable": ssvc[1],
        "ssvc_impact": ssvc[2],
        "credits": credit_txt or None,
        "n_credits": len(credits),
        "ref_urls": ref_urls,
        "ref_tags": ";".join(ref_tags) or None,
        "has_adp_cisa": any((a.get("providerMetadata") or {}).get("shortName") == "CISA-ADP" for a in adps),
    }


def _work(names: list[str]) -> list[dict]:
    out = []
    with zipfile.ZipFile(ZIP) as z:
        for n in names:
            try:
                r = parse(z.read(n))
            except Exception as exc:  # malformed record: keep going
                print(f"  ! {n}: {exc}")
                continue
            if r:
                out.append(r)
    return out


def main():
    with zipfile.ZipFile(ZIP) as z:
        names = [n for n in z.namelist() if n.endswith(".json") and "/CVE-" in n]
    print(f"  {len(names):,} records")
    chunks = [names[i : i + 5000] for i in range(0, len(names), 5000)]
    rows = []
    with ProcessPoolExecutor() as ex:
        for part in ex.map(_work, chunks):
            rows.extend(part)
    df = pd.DataFrame(rows)
    for c in ("date_reserved", "date_published", "date_updated", "date_rejected"):
        df[c] = pd.to_datetime(df[c], utc=True, errors="coerce", format="mixed")
    df.to_parquet(INTERIM / "cves.parquet", index=False)
    print(f"  wrote data/interim/cves.parquet ({len(df):,} rows)")


if __name__ == "__main__":
    main()
