import type { Data } from "../main";
import { columns } from "../lib/charts";
import { figure } from "../lib/figure";
import { fmtInt, pct } from "../lib/format";
import { C, callout, chapter, grid2, link, prose } from "../lib/page";

export function renderNoise(main: HTMLElement, d: Data) {
  const v = d.vulns;
  const sec = chapter(main, {
    id: "noise",
    num: "02",
    title: "Signal or noise?",
    kicker: "More bugs is not the same as more danger. Two questions: are they serious, and does anyone use them?",
  });

  const sev = (v.severity as any[]).filter((r) => r.year >= 2022);
  const s26 = sev.find((r) => r.year === 2026);
  const scored26 = s26.CRITICAL + s26.HIGH + s26.MEDIUM + s26.LOW;
  prose(
    sec,
    `<p>A common objection to scary CVE charts is that most of the growth is trivia: tiny plugin bugs, theoretical crashes, duplicate filings. Severity scores (CVSS, from 0 to 10) let us test that. If the flood were mostly noise, the share of serious flaws would shrink. It did not.</p>
     <p>In 2026, <strong>${pct((s26.CRITICAL + s26.HIGH) / scored26)}</strong> of scored CVEs are rated high or critical, the highest share since 2022, when most CVE records started to carry a score. The count of critical flaws alone (${fmtInt(s26.CRITICAL)}) is more than double 2025.</p>`,
  );

  const keys = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
  const names: Record<string, string> = { LOW: "Low", MEDIUM: "Medium", HIGH: "High", CRITICAL: "Critical" };
  const f1 = figure(sec, {
    title: "Severity mix of scored CVEs, by year published",
    sub: "Share of CVEs with a CVSS score (over 59% of records from 2022 on; earlier years are too sparsely scored to compare).",
    source: `CVE Program cvelistV5 (CNA score, or CISA's ${link("https://github.com/cisagov/vulnrichment", "Vulnrichment")} score when the CNA gave none)`,
    legend: [...keys].reverse().map((k) => ({ label: names[k], color: C.sev[k] })),
    table: {
      columns: [{ key: "year", label: "Year" }, ...[...keys].reverse().map((k) => ({ key: k, label: names[k], fmt: fmtInt })), { key: "Not scored", label: "Not scored", fmt: fmtInt }],
      rows: sev,
    },
  });
  columns(f1, {
    data: sev,
    x: "year",
    series: keys.map((k) => ({ key: k, label: names[k], color: C.sev[k] })),
    stacked: true,
    percent: true,
    height: 300,
  });

  const kr = (v.kev_rate as any[]).filter((r) => r.year >= 2018);
  const kr26 = kr.find((r) => r.year === 2026);
  const kev = v.kev_year as any[];
  prose(
    sec,
    `<h3>Does anyone actually use them?</h3>
     <p>The US Cybersecurity and Infrastructure Security Agency (CISA) keeps a list of vulnerabilities with confirmed attacks in the wild, the ${link("https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "Known Exploited Vulnerabilities")} (KEV) catalog. It is the best public signal of what attackers really use.</p>
     <p>Compared to the flood, it barely moves. Only <strong>${pct(kr26.share, 2)}</strong> of 2026 CVEs are on it so far, about 1 in ${Math.round(1 / kr26.share)}. Google's threat intelligence group measured almost exactly the same rate (0.23%) with its own data. The odds that any single new bug gets used in an attack keep falling.</p>
     <p>But the absolute number keeps rising. CISA added ${kev.find((r) => r.year === 2026).added} entries in 2026 to date, already more than in any full year since 2022, and Google counted 141 exploited vulnerabilities in the first eight months of 2026 against 127 in all of 2025. A smaller share of a much bigger pile is still a bigger pile.</p>`,
  );

  const g = grid2(sec);
  const f2 = figure(g, {
    title: "Share of each year's CVEs that ended up exploited",
    sub: "CVEs on CISA's KEV list, by CVE publication year.",
    source: "CISA KEV, CVE Program",
    table: { columns: [{ key: "year", label: "Year" }, { key: "share", label: "Exploited share", fmt: (x) => pct(x, 2) }], rows: kr },
  });
  columns(f2, {
    data: kr,
    x: "year",
    series: [{ key: "share", label: "Exploited share", color: C.s2 }],
    colorFn: () => C.s2,
    yFormat: (x) => pct(x, 1),
    valueFormat: (x) => pct(x, 2),
    labelBars: (r) => r.year === 2021 || r.year === 2026,
    height: 260,
    partial: (r) => r.year === 2026,
  });
  const f3 = figure(g, {
    title: "Exploited vulnerabilities added to KEV per year",
    sub: "Bottom segment: flagged by CISA as used in ransomware campaigns.",
    source: "CISA KEV (2021 includes the catalog's initial backlog)",
    legend: [
      { label: "Ransomware-linked", color: C.s7 },
      { label: "Other", color: C.s2 },
    ],
    table: { columns: [{ key: "year", label: "Year" }, { key: "added", label: "Added", fmt: fmtInt }, { key: "ransomware", label: "Ransomware-linked", fmt: fmtInt }], rows: kev },
  });
  columns(f3, {
    data: kev.map((r) => ({ ...r, other: r.added - r.ransomware })),
    x: "year",
    series: [
      { key: "ransomware", label: "Ransomware-linked", color: C.s7 },
      { key: "other", label: "Other", color: C.s2 },
    ],
    stacked: true,
    labelBars: () => true,
    height: 260,
    partial: (r) => r.year === 2026,
  });

  callout(
    sec,
    "reading the numbers",
    `Two things are true at once. <b>Most new CVEs will never be exploited</b>, and defenders who try to patch everything drown. <b>The few that are exploited are used faster than ever</b> (next chapters). The hard problem in 2026 is not finding bugs. It is picking the right 0.2% and fixing them in time.`,
  );
}
