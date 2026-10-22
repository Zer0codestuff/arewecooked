"""CVE List (CVE JSON 5 records from the CVE Program) and AI-credited findings.

Input:  ``data/raw/cvelist/cvelist.zip.zip`` (release asset, a zip inside a zip) or
        ``data/raw/cvelist/cves.zip`` (the inner zip, extracted).
Output tables:
    ai_credits_month   per month: published CVEs, CVEs with credits, CVEs whose
                       credits name an AI system
    ai_credits_tool    per AI system: number of credited CVEs, first and last month
    ai_credits_recent  the 40 most recent AI-credited CVEs (id, date, system, credit)

Method: a CVE counts as "AI-credited" when one of its ``credits`` entries matches
one of the patterns in ``AI_PATTERNS``: either an AI system by name (Big Sleep,
Claude, XBOW, Aardvark, ...) or an AI lab / AI-native security research team
(Anthropic, OpenAI, AISLE, depthfirst, Xint, ZeroPath, AIxCC teams). This is a lower bound: most AI-assisted
findings are not labelled as such, and credits are free text chosen by the CNA.
"""

from __future__ import annotations

import io
import re
import zipfile
from collections import Counter, defaultdict
from datetime import date
from pathlib import Path
from typing import Iterator

import pandas as pd

from pipeline.common import START_YEAR, get_logger, month_key, parse_date

try:  # orjson is much faster on 400k small documents; fall back to stdlib
    import orjson as _json

    _loads = _json.loads
except ImportError:  # pragma: no cover
    import json as _json

    _loads = _json.loads

log = get_logger("cvelist")

# (label, regex). Order matters: the first match labels the credit.
AI_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("Google Big Sleep", re.compile(r"big\s?sleep", re.I)),
    ("Anthropic Claude", re.compile(r"\bmythos\b|glasswing|\banthropic\b|\bclaude\s+(opus|sonnet|haiku|code)\b", re.I)),
    ("XBOW", re.compile(r"\bxbow\b", re.I)),
    ("OpenAI", re.compile(r"\baardvark\b|\bopenai\b|\bchatgpt\b|\bgpt-?[345o]", re.I)),
    ("Google Gemini / CodeMender", re.compile(r"\bcodemender\b|\bgemini\b", re.I)),
    ("AIxCC systems", re.compile(r"\baixcc\b|ai cyber challenge|team atlanta|buttercup|shellphish|42-b3yond|fuzzing brain", re.I)),
    ("ZeroPath", re.compile(r"\bzeropath\b", re.I)),
    ("AISLE", re.compile(r"\bAISLE\b")),
    ("depthfirst", re.compile(r"\bdepthfirst\b", re.I)),
    ("Theori Xint", re.compile(r"\bxint\b", re.I)),
    ("Microsoft Security Copilot", re.compile(r"security\s+copilot", re.I)),
    (
        "Other AI mention",
        re.compile(
            r"\b(llm|large language model|ai[- ]assisted|ai[- ]powered|ai[- ]driven|ai[- ]based|ai agents?|"
            r"ai tools?|using ai|with ai|autonomous (ai|agent)|agentic|security ai agent)\b",
            re.I,
        ),
    ),
]

_STATE_RE = re.compile(rb'"state"\s*:\s*"(PUBLISHED|REJECTED)"')
_PUB_RE = re.compile(rb'"datePublished"\s*:\s*"([0-9T:\-\.Z]+)"')


def classify_credit(text: str) -> str | None:
    for label, pattern in AI_PATTERNS:
        if pattern.search(text or ""):
            return label
    return None


def credit_texts(record: dict) -> list[str]:
    """All credit strings of a CVE record (CNA container plus ADP containers)."""
    containers = record.get("containers") or {}
    out: list[str] = []
    blocks = [containers.get("cna") or {}] + list(containers.get("adp") or [])
    for block in blocks:
        for credit in block.get("credits") or []:
            value = credit.get("value")
            if value:
                out.append(str(value))
    return out


def _open_inner(path: Path) -> zipfile.ZipFile:
    outer = zipfile.ZipFile(path)
    names = outer.namelist()
    if any(n.endswith(".json") for n in names[:50]):
        return outer
    inner_name = next(n for n in names if n.endswith(".zip"))
    # Reading the inner archive into memory keeps random access fast (~700 MB).
    return zipfile.ZipFile(io.BytesIO(outer.read(inner_name)))


def find_archive(raw_dir: Path) -> Path | None:
    base = raw_dir / "cvelist"
    for name in ("cves.zip", "cvelist.zip.zip"):
        if (base / name).exists():
            return base / name
    return None


def iter_documents(archive: zipfile.ZipFile) -> Iterator[bytes]:
    for info in archive.infolist():
        name = info.filename.rsplit("/", 1)[-1]
        if name.startswith("CVE-") and name.endswith(".json"):
            yield archive.read(info)


def process(archive: zipfile.ZipFile, start_year: int = START_YEAR, as_of: date | None = None) -> dict[str, pd.DataFrame]:
    published: Counter = Counter()
    with_credits: Counter = Counter()
    ai_month: Counter = Counter()
    tool_counts: Counter = Counter()
    tool_months: dict[str, list[str]] = defaultdict(list)
    recent: list[dict] = []
    seen = 0
    for raw in iter_documents(archive):
        seen += 1
        state = _STATE_RE.search(raw)
        if not state or state.group(1) != b"PUBLISHED":
            continue
        pub_match = _PUB_RE.search(raw)
        pub = parse_date(pub_match.group(1).decode()) if pub_match else None
        if pub is None or pub.year < start_year or (as_of and pub > as_of):
            continue
        month = month_key(pub)
        published[month] += 1
        if b'"credits"' not in raw:
            continue
        record = _loads(raw)
        texts = credit_texts(record)
        if not texts:
            continue
        with_credits[month] += 1
        label = None
        matched_text = ""
        for text in texts:
            label = classify_credit(text)
            if label:
                matched_text = text
                break
        if not label:
            continue
        cve_id = record.get("cveMetadata", {}).get("cveId", "")
        ai_month[month] += 1
        tool_counts[label] += 1
        tool_months[label].append(month)
        recent.append({"cve": cve_id, "published": pub.isoformat(), "system": label, "credit": matched_text[:160]})
    log.info("scanned %d CVE documents", seen)

    months = sorted(published)
    month_df = pd.DataFrame(
        {
            "month": months,
            "published": [published[m] for m in months],
            "with_credits": [with_credits[m] for m in months],
            "ai_credited": [ai_month[m] for m in months],
        }
    )
    tool_df = pd.DataFrame(
        [
            {"system": label, "cves": n, "first_month": min(tool_months[label]), "last_month": max(tool_months[label])}
            for label, n in tool_counts.most_common()
        ],
        columns=["system", "cves", "first_month", "last_month"],
    )
    recent_df = pd.DataFrame(
        sorted(recent, key=lambda r: (r["published"], r["cve"]), reverse=True)[:40],
        columns=["cve", "published", "system", "credit"],
    )
    return {"ai_credits_month": month_df, "ai_credits_tool": tool_df, "ai_credits_recent": recent_df}


def build(raw_dir: Path, as_of: date | None = None) -> dict[str, pd.DataFrame] | None:
    path = find_archive(raw_dir)
    if path is None:
        log.warning("no CVE List archive in %s, skipping", raw_dir / "cvelist")
        return None
    log.info("reading %s", path)
    return process(_open_inner(path), as_of=as_of)
