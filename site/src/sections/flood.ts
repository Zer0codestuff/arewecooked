import type { Data } from "../main";
import { GREEN_RAMP, calendar } from "../lib/charts2";
import { columns, hbars, lines } from "../lib/charts";
import { figure } from "../lib/figure";
import { fmtInt, monthLabel, shortMonth, times } from "../lib/format";
import { C, callout, chapter, link, prose } from "../lib/page";

const GROUP_COLORS: Record<string, string> = {
  "Software vendors": C.s1,
  "Open source (GitHub)": C.s2,
  "Linux kernel": C.s3,
  "WordPress plugins": C.s4,
  VulDB: C.s5,
  VulnCheck: C.s6,
  MITRE: C.s7,
  "Other CNAs": C.other,
};

const CNA_NAMES: Record<string, string> = {
  GitHub_M: "GitHub (open source)",
  VulnCheck: "VulnCheck",
  Linux: "Linux kernel",
  VulDB: "VulDB",
  Patchstack: "Patchstack (WordPress)",
  microsoft: "Microsoft",
  oracle: "Oracle",
  mitre: "MITRE",
  Chrome: "Google Chrome",
  Wordfence: "Wordfence (WordPress)",
  WPScan: "WPScan (WordPress)",
  ibm: "IBM",
  redhat: "Red Hat",
  apache: "Apache",
  adobe: "Adobe",
  apple: "Apple",
  mozilla: "Mozilla",
  cisco: "Cisco",
  dell: "Dell",
  icscert: "CISA ICS",
  GitLab: "GitLab",
  nvidia: "NVIDIA",
  Joomla: "Joomla",
  CPANSec: "CPAN (Perl)",
  "TR-CERT": "TR-CERT",
};

export function renderFlood(main: HTMLElement, d: Data) {
  const v = d.vulns;
  const t = v.totals;
  const sec = chapter(main, {
    id: "flood",
    num: "01",
    title: "The flood",
    kicker: "Vulnerability disclosures doubled in a single year. Here is where they come from.",
  });

  prose(
    sec,
    `<p>Every publicly known software flaw gets an ID called a <strong>CVE</strong> (for example CVE-2026-109618, the PHP bug that made headlines this week). Counting CVEs is the closest thing the industry has to a census of software weakness.</p>
     <p>The census just broke. Between 1 January and 22 October 2026, <strong>${fmtInt(t.ytd_cur)}</strong> CVEs were published, against ${fmtInt(t.ytd_prev)} in the same days of 2025. That is more than in all of 2025 (${fmtInt(t.prev_year)}) and <strong>${times(t.cur_year, t.y2020)}</strong> the total for 2020.</p>`,
  );

  const yearly = (v.yearly as any[]).filter((r) => r.year >= 2005);
  const f1 = figure(sec, {
    title: "CVEs published per year",
    sub: "2026 counts only up to 22 October and is already the biggest year on record.",
    source: `CVE Program, ${link("https://github.com/CVEProject/cvelistV5", "cvelistV5")} (published records, by publication date)`,
    table: { columns: [{ key: "year", label: "Year" }, { key: "cves", label: "CVEs", fmt: fmtInt }], rows: yearly },
  });
  columns(f1, {
    data: yearly,
    x: "year",
    series: [{ key: "cves", label: "CVEs", color: C.s1 }],
    colorFn: (r) => (r.year === 2026 ? C.s1 : C.dim),
    labelBars: (r) => [2005, 2020, 2024, 2025, 2026].includes(r.year),
    xTickEvery: (yv: number) => yv % 5 === 0 || yv === 2026,
    height: 320,
    annotations: [{ x: 2017, text: "2017: CNA program expands", dy: 60, align: "end" }],
  });

  prose(
    sec,
    `<h3>Who is filing them</h3>
     <p>CVEs are issued by more than 400 "numbering authorities" (CNAs): software vendors, bug-bounty platforms, national CERTs, and a few databases. Part of the long-term growth is bookkeeping: the Linux kernel became its own CNA in 2024 and now files a CVE for almost every bug fix, and WordPress plugin security firms file thousands of small plugin bugs a year.</p>
     <p>But 2026 is different. The fastest-growing source is not new bookkeeping: it is <strong>established software vendors</strong> reporting far more flaws in their own products, plus a wave of open-source advisories through GitHub.</p>`,
  );

  const groups: string[] = v.group_order;
  const mg = v.monthly_group as any[];
  const f2 = figure(sec, {
    title: "CVEs published per month, by who filed them",
    sub: "January 2023 to October 2026 (October covers 1 to 22 Oct).",
    source: `CVE Program cvelistV5, assigner field; grouping by the author`,
    legend: groups.map((g) => ({ label: g, color: GROUP_COLORS[g] })),
    table: {
      columns: [{ key: "month", label: "Month", fmt: (x) => monthLabel(x) }, ...groups.map((g) => ({ key: g, label: g, fmt: fmtInt }))],
      rows: mg,
    },
  });
  columns(f2, {
    data: mg,
    x: "month",
    xLabel: shortMonth,
    xTickEvery: (m: string) => new Date(m).getUTCMonth() % 6 === 0,
    series: groups.map((g) => ({ key: g, label: g, color: GROUP_COLORS[g] })),
    stacked: true,
    height: 340,
    tipHead: (r) => monthLabel(r.month),
    releases: true,
  });

  const vm = v.vendor_monthly as any[];
  const vendors = [
    { key: "Microsoft", color: C.s3 },
    { key: "Oracle", color: C.s2 },
    { key: "Google Chrome", color: C.s1 },
    { key: "Mozilla", color: C.s4 },
  ];
  prose(
    sec,
    `<p>Look at four of the biggest software makers month by month. For years each published a steady trickle. Then, from spring 2026, the lines bend upward together. Microsoft went from roughly 100 CVEs a month to more than 1,400 in October. Google Chrome went from a dozen in January to several hundred a month.</p>
     <p>The CVE records do not say why. The timing matches the 7 April launch of ${link("https://www.constellationr.com/insights/news/anthropic-launches-project-glasswing-claude-mythos-preview-ai-cybersecurity-push", "Project Glasswing")}, in which Anthropic gave an unreleased model, Claude Mythos Preview, to Microsoft, Google, Apple, AWS, the Linux Foundation and others to scan their own code. Google's own analysts ${link("https://cloud.google.com/blog/topics/threat-intelligence/vulnerability-discovery-and-exploitation-trends-in-the-ai-era", "caution")} that part of the surge also reflects quarterly patch cycles and how vendors count. Both can be true: <strong>vendors are finding and fixing more of their own bugs, faster, and AI is a big reason they can.</strong></p>`,
  );
  const f3 = figure(sec, {
    title: "Monthly CVEs filed by four large vendors",
    sub: "Each vendor files CVEs for its own products. January 2024 to October 2026 (October covers 1 to 22 Oct).",
    source: "CVE Program cvelistV5, by assigner",
    legend: vendors.map((s) => ({ label: s.key, color: s.color, shape: "line" })),
    table: { columns: [{ key: "month", label: "Month", fmt: (x) => monthLabel(x) }, ...vendors.map((s) => ({ key: s.key, label: s.key, fmt: fmtInt }))], rows: vm },
  });
  lines(f3, {
    data: vm,
    x: "month",
    time: true,
    series: vendors.map((s) => ({ key: s.key, label: s.key, color: s.color })),
    height: 320,
    endLabels: true,
    xFormat: (m) => monthLabel(m),
    releases: true,
  });

  const ytd = (v.ytd_assigners as any[]).slice(0, 16).map((r) => ({ ...r, name: CNA_NAMES[r.assigner] ?? r.assigner }));
  const f4 = figure(sec, {
    title: "Same calendar window, 2025 vs 2026",
    sub: "CVEs filed 1 Jan to 22 Oct by the 16 busiest numbering authorities. Gray dot: 2025, green dot: 2026.",
    source: "CVE Program cvelistV5",
    legend: [
      { label: "2025", color: C.other },
      { label: "2026", color: C.s1 },
    ],
    table: {
      columns: [
        { key: "name", label: "Filed by" },
        { key: "prev", label: "2025", fmt: fmtInt },
        { key: "cur", label: "2026", fmt: fmtInt },
        { key: "ratio", label: "Change", fmt: (x) => (x ? `${x}x` : "new") },
      ],
      rows: ytd,
    },
  });
  hbars(f4, {
    data: ytd,
    label: "name",
    value: "cur",
    value2: "prev",
    color: C.s1,
    color2: C.other,
    labelWidth: 180,
    tip: (r) => ({
      head: r.name,
      rows: [
        { label: "2026", value: fmtInt(r.cur), color: C.s1 },
        { label: "2025", value: fmtInt(r.prev), color: C.other },
        { label: "change", value: r.ratio ? `${r.ratio}x` : "new" },
      ],
    }),
  });

  const pt = d.threats.patch_tuesday.yearly as any[];
  const pt25 = pt.find((r) => r.year === 2025);
  const pt26 = pt.find((r) => r.year === 2026);
  callout(
    sec,
    "patch tuesday",
    `Microsoft's monthly security update used to fix 70 to 120 of its own CVEs. In 2026 it has fixed <b>${fmtInt(pt26.cves)}</b> so far, against <b>${fmtInt(pt25.cves)}</b> in all of 2025. Only ${pt26.exploited} of this year's were already being exploited when the fix shipped. Source: ${link("https://api.msrc.microsoft.com/cvrf/v3.0/updates", "MSRC CVRF API")}.`,
  );

  // Daily calendar
  const an = d.anatomy;
  const dowMean: number[] = an.dow_mean_cur;
  const top = an.top_days as any[];
  prose(
    sec,
    `<h3>The weekly heartbeat</h3>
     <p>Day by day, the flood has a rhythm. In 2026 an average Tuesday brings <strong>${fmtInt(dowMean[1])}</strong> new CVEs, a Sunday ${fmtInt(dowMean[6])}. The five busiest days of the year were all Tuesdays: Microsoft's Patch Tuesday (second Tuesday of the month) and Oracle's quarterly Critical Patch Update (third Tuesday of January, April, July and October). On 13 October Microsoft alone published 1,407 CVEs, more than it used to publish in a year.</p>`,
  );
  const secondTue = (dt: Date) => dt.getUTCDay() === 2 && dt.getUTCDate() >= 8 && dt.getUTCDate() <= 14;
  const oracleCpu = (dt: Date) => dt.getUTCDay() === 2 && dt.getUTCDate() >= 15 && dt.getUTCDate() <= 21 && [0, 3, 6, 9].includes(dt.getUTCMonth());
  const fc = figure(sec, {
    title: "Every day of 2025 and 2026, by CVEs published",
    source: "CVE Program cvelistV5, publication date (UTC)",
    table: {
      columns: [{ key: "date", label: "Date", fmt: (x: string) => x.slice(0, 10) }, { key: "cves", label: "CVEs", fmt: fmtInt }],
      rows: [...top, ...(an.daily as any[]).slice(-30).reverse()],
    },
  });
  calendar(fc, {
    data: an.daily,
    value: "cves",
    thresholds: [50, 150, 300, 600, 1000],
    colors: GREEN_RAMP,
    label: "CVEs per day",
    marked: (dt) => (secondTue(dt) ? "Microsoft Patch Tuesday" : oracleCpu(dt) ? "Oracle Critical Patch Update" : null),
  });
}
