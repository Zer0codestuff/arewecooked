import type { Data } from "../main";
import { columns } from "../lib/charts";
import { figure } from "../lib/figure";
import { fmtInt, monthLabel, pct, shortMonth } from "../lib/format";
import { C, callout, chapter, grid2, link, prose } from "../lib/page";

export function renderNoise(main: HTMLElement, d: Data) {
  const v = d.vulns;
  const sec = chapter(main, {
    id: "noise",
    num: "02",
    title: "Signal or noise?",
    kicker: "More bugs is not the same as more danger. Two questions: are they serious, and does anyone use them?",
  });

  const cov = d.anatomy.severity_cov as any[];
  const sev = (d.anatomy.severity_all as any[]).filter((r) => r.year >= 2016).map((r) => {
    const c = cov.find((x) => x.year === r.year);
    return { ...r, nvd_share: c ? c.from_nvd / c.n : null };
  });
  const s26 = sev.find((r) => r.year === 2026);
  const s25 = sev.find((r) => r.year === 2025);
  const s22 = sev.find((r) => r.year === 2022);
  const hiShare = (r: any) => (r.CRITICAL + r.HIGH) / (r.CRITICAL + r.HIGH + r.MEDIUM + r.LOW);
  prose(
    sec,
    `<p>A common objection to scary CVE charts is that most of the growth is trivia: tiny plugin bugs, theoretical crashes, duplicate filings. Severity scores (CVSS, from 0 to 10) let us test that. If the flood were mostly noise, the share of serious flaws would shrink. It did not.</p>
     <p>In 2026, <strong>${pct(hiShare(s26))}</strong> of scored CVEs are rated high or critical, up from ${pct(hiShare(s25))} in 2025 and back to the level of 2022 (${pct(hiShare(s22))}). The count of critical flaws alone (${fmtInt(s26.CRITICAL)}) is more than double 2025. Where a CVE record has no score we use the one from the US National Vulnerability Database, which fills almost every gap before 2022.</p>`,
  );

  const keys = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
  const names: Record<string, string> = { LOW: "Low", MEDIUM: "Medium", HIGH: "High", CRITICAL: "Critical" };
  const f1 = figure(sec, {
    title: "Severity mix of scored CVEs, by year published",
    sub: "Share of scored CVEs. Until 2021 most scores come from NIST's NVD; from 2023 almost all come from the vendor or CISA, which partly explains the 2023 to 2025 dip.",
    source: `CVE Program cvelistV5 (CNA score, else CISA ${link("https://github.com/cisagov/vulnrichment", "Vulnrichment")}), NIST NVD as fallback via the ${link("https://github.com/fkie-cad/nvd-json-data-feeds", "fkie-cad mirror")}`,
    legend: [...keys].reverse().map((k) => ({ label: names[k], color: C.sev[k] })),
    table: {
      columns: [{ key: "year", label: "Year" }, ...[...keys].reverse().map((k) => ({ key: k, label: names[k], fmt: fmtInt })), { key: "nvd_share", label: "Scored by NVD", fmt: (x: number) => pct(x) }],
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
    partial: (r) => r.year === 2026,
    tipExtra: (r) => [{ label: "scored by NVD", value: pct(r.nvd_share) }],
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

  // NVD backlog
  const nv = d.nvd;
  const nt = nv.totals;
  const order: string[] = nv.order;
  const NV_COLORS = [C.s1, C.s5, C.other];
  prose(
    sec,
    `<h3>The referee is overwhelmed</h3>
     <p>For twenty years the US National Vulnerability Database (NVD), run by NIST, has "enriched" every CVE: it adds a standard severity score and a precise list of affected products, which is what most corporate vulnerability scanners rely on. Until 2023 it analyzed essentially every CVE. In 2026 it has analyzed <strong>${pct(nt.analyzed_share_cur)}</strong> of them. ${fmtInt(nt.deferred_cur)} of this year's CVEs are marked "not scheduled" and ${fmtInt(nt.waiting_cur)} are still waiting.</p>
     <p>This is a policy, not an accident. In ${link("https://www.nist.gov/news-events/news/2026/04/nist-updates-nvd-operations-address-record-cve-growth", "April 2026")} NIST announced it would only prioritize exploited vulnerabilities, software used by the federal government and critical software, and ${link("https://www.infosecurity-magazine.com/news/nvd-enrichment-premarch-2026/", "moved about 29,000 backlogged CVEs")} to the lowest priority. The public database most of the industry leans on has, in effect, started triaging too.</p>`,
  );
  const nm = nv.monthly as any[];
  const f4 = figure(sec, {
    title: "What the NVD did with each month's new CVEs",
    sub: "CVEs by publication month and current NVD status (Oct 2026). October covers 1 to 22 Oct.",
    source: `NIST NVD via the ${link("https://github.com/fkie-cad/nvd-json-data-feeds", "fkie-cad NVD JSON mirror")} (release ${nv.mirror_release})`,
    legend: order.map((o, i) => ({ label: o, color: NV_COLORS[i] })),
    table: { columns: [{ key: "month", label: "Month", fmt: (x: string) => monthLabel(x) }, ...order.map((o) => ({ key: o, label: o, fmt: fmtInt }))], rows: nm },
  });
  columns(f4, {
    data: nm,
    x: "month",
    xLabel: shortMonth,
    xTickEvery: (m: string) => new Date(m).getUTCMonth() % 6 === 0,
    series: order.map((o, i) => ({ key: o, label: o, color: NV_COLORS[i] })),
    stacked: true,
    height: 300,
    tipHead: (r) => monthLabel(r.month),
    annotations: [{ x: "2026-04-01T00:00:00.000Z", text: "NIST triage policy", dy: 0, align: "end" }],
    releases: true,
  });

  callout(
    sec,
    "reading the numbers",
    `Two things are true at once. <b>Most new CVEs will never be exploited</b>, and defenders who try to patch everything drown. <b>The few that are exploited are used faster than ever</b> (next chapters). The hard problem in 2026 is not finding bugs. It is picking the right 0.2% and fixing them in time.`,
  );
}
