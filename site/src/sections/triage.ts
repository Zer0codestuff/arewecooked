import type { Data } from "../main";
import { columns, hbars, lines } from "../lib/charts";
import { figure } from "../lib/figure";
import { fmtInt, pct } from "../lib/format";
import { C, callout, chapter, grid2, link, prose, stats } from "../lib/page";

export function renderTriage(main: HTMLElement, d: Data) {
  const t = d.triage;
  const u = t.universe;
  const sec = chapter(main, {
    id: "triage",
    num: "07",
    title: "The triage game",
    kicker: "Nobody can patch 85,000 bugs a year. So which ones first? We replayed three and a half years of decisions to find out.",
  });

  prose(
    sec,
    `<p>Every security team runs the same game. A list of open vulnerabilities, a limited patching budget, and an attacker who will use only a handful of them. Two scores dominate the decision. <strong>CVSS</strong> (0 to 10) rates how bad a bug would be if exploited. <strong>EPSS</strong>, from the ${link("https://www.first.org/epss/", "FIRST")} forum, estimates the probability it will be exploited in the next 30 days, updated daily from signals like public exploit code and attack traffic.</p>
     <p>We tested both, out of sample. On the first day of each month from January 2023 to July 2026 (${u.months} months), we took every CVE published in the previous year that was not yet known to be exploited, ranked it by its CVSS score and by <em>that day's</em> EPSS score, then checked which ones CISA added to its exploited list in the following 90 days. That gives ${fmtInt(u.hits)} real attacks to catch, over ${fmtInt(u.rows)} vulnerability-months.</p>`,
  );

  const curves = (t.curves as any[]).filter((r) => r.effort <= 0.5);
  const at = (k: string, e: number) => (t.curves as any[]).find((r) => Math.abs(r.effort - e) < 1e-9)?.[k];
  const pts = t.points as any[];
  const P = (name: string) => pts.find((p) => p.rule === name);
  const pColor: Record<string, string> = { "All critical": C.s2, "All critical and high": C.s2, "EPSS 10% or more": C.s3, "EPSS 1% or more": C.s3, "Critical, or EPSS 1% or more": C.s5 };
  const pLabel: Record<string, { anchor?: "start" | "end"; dx?: number; dy?: number }> = {
    "All critical": { anchor: "start", dx: 9, dy: 16 },
    "All critical and high": { anchor: "end", dy: -10 },
    "EPSS 10% or more": { anchor: "start", dx: 9, dy: 4 },
    "EPSS 1% or more": { anchor: "start", dx: 9, dy: 4 },
    "Critical, or EPSS 1% or more": { anchor: "start", dx: 9, dy: -6 },
  };
  const f1 = figure(sec, {
    title: "Share of next-90-day exploits caught, by share of open CVEs patched",
    source: `CVE Program, NVD, ${link("https://www.first.org/epss/data_stats", "EPSS daily snapshots")} (${u.months} monthly), ${link("https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "CISA KEV")}; backtest by the author`,
    legend: [
      { label: "Rank by EPSS (that day)", color: C.s3, shape: "line" },
      { label: "Rank by CVSS score", color: C.s2, shape: "line" },
      { label: "Random order", color: C.other, shape: "line" },
    ],
    table: {
      columns: [
        { key: "effort", label: "Patched (top x%)", fmt: (x: number) => pct(x, 1) },
        { key: "EPSS that day", label: "Caught, EPSS", fmt: (x: number) => pct(x) },
        { key: "CVSS score", label: "Caught, CVSS", fmt: (x: number) => pct(x) },
        { key: "Random", label: "Caught, random", fmt: (x: number) => pct(x) },
      ],
      rows: t.curves,
    },
  });
  lines(f1, {
    data: [{ effort: 0, "CVSS score": 0, "EPSS that day": 0, Random: 0 }, ...curves],
    x: "effort",
    xDomain: [0, 0.5],
    xTicks: [0, 0.05, 0.1, 0.2, 0.3, 0.4, 0.5],
    series: [
      { key: "EPSS that day", label: "EPSS", color: C.s3 },
      { key: "CVSS score", label: "CVSS", color: C.s2 },
      { key: "Random", label: "Random", color: C.other },
    ],
    height: 360,
    yMin: 0,
    yFormat: (v) => `${Math.round(v * 100)}%`,
    valueFormat: (v) => pct(v),
    tickFormat: (v) => `${Math.round(v * 100)}%`,
    xFormat: (v) => `patch the top ${pct(v, 1)}`,
    points: pts.map((p) => ({ x: p.effort, y: p.coverage, label: p.rule, color: pColor[p.rule], ...pLabel[p.rule] })),
  });

  stats(sec, [
    [pct(at("EPSS that day", 0.05)), "of upcoming exploits caught by patching the top 5% by EPSS"],
    [pct(at("CVSS score", 0.05)), "caught by the top 5% by CVSS score"],
    [pct(P("Critical, or EPSS 1% or more").coverage), `caught by "critical, or EPSS 1% or more", which means patching ${pct(P("Critical, or EPSS 1% or more").effort)} of the list`],
    [pct(1 - P("All critical and high").coverage), `of exploits missed even after patching every high and critical CVE (${pct(P("All critical and high").effort)} of the list)`],
  ]);

  prose(
    sec,
    `<p>The lesson is not "one score wins". <strong>EPSS is much better at the very top</strong>: if you can only patch a few percent of your backlog, ranking by EPSS catches far more of what attackers will use. Past about 10% of the list, CVSS catches up and then pulls ahead, because EPSS gives near-zero scores to many bugs that are later exploited without warning. A simple combined rule beats either alone at a sensible budget. And no rule is safe: patching every high and critical CVE, almost half the list, still misses about one exploited bug in five.</p>`,
  );

  // Severity bands
  const bands = (t.bands as any[]).map((r) => ({ ...r, label: r.sev[0] + r.sev.slice(1).toLowerCase() }));
  const crit = bands.find((r) => r.sev === "CRITICAL");
  const med = bands.find((r) => r.sev === "MEDIUM");
  const g = grid2(sec);
  const f2 = figure(g, {
    title: "Share of all CVEs vs share of exploited CVEs, by severity",
    source: "CVEs published 2022 to 2025; exploited = on CISA KEV by 22 Oct 2026",
    legend: [
      { label: "Share of all CVEs", color: C.other },
      { label: "Share of exploited", color: C.s7 },
    ],
    table: {
      columns: [
        { key: "label", label: "Severity" },
        { key: "n", label: "CVEs", fmt: fmtInt },
        { key: "exploited", label: "Exploited", fmt: fmtInt },
        { key: "rate", label: "Exploited rate", fmt: (x: number) => pct(x, 2) },
        { key: "share_of_all", label: "Share of all", fmt: (x: number) => pct(x) },
        { key: "share_of_exploited", label: "Share of exploited", fmt: (x: number) => pct(x) },
      ],
      rows: bands,
    },
  });
  hbars(f2, {
    data: bands,
    label: "label",
    value: "share_of_exploited",
    value2: "share_of_all",
    color: C.s7,
    color2: C.other,
    labelWidth: 90,
    rowHeight: 40,
    valueFormat: (x) => pct(x),
    tip: (r) => ({
      head: r.label,
      rows: [
        { label: "share of all CVEs", value: pct(r.share_of_all), color: C.other },
        { label: "share of exploited", value: pct(r.share_of_exploited), color: C.s7 },
        { label: "chance of being exploited", value: pct(r.rate, 2) },
      ],
    }),
  });
  const by = (t.by_year as any[]).map((r) => ({ ...r, ys: String(r.year) }));
  const f3 = figure(g, {
    title: "Exploits caught by patching the top 5%, by year",
    source: "Same backtest, grouped by snapshot year (2026: January to July)",
    legend: [
      { label: "EPSS", color: C.s3 },
      { label: "CVSS", color: C.s2 },
    ],
    table: { columns: [{ key: "year", label: "Year" }, { key: "hits", label: "Exploits", fmt: fmtInt }, { key: "top5_epss", label: "EPSS top 5%", fmt: (x: number) => pct(x) }, { key: "top5_cvss", label: "CVSS top 5%", fmt: (x: number) => pct(x) }], rows: by },
  });
  columns(f3, {
    data: by,
    x: "ys",
    series: [
      { key: "top5_epss", label: "EPSS", color: C.s3 },
      { key: "top5_cvss", label: "CVSS", color: C.s2 },
    ],
    percent: false,
    yMax: 0.6,
    yFormat: (v) => `${Math.round(v * 100)}%`,
    valueFormat: (v) => pct(v),
    labelBars: () => true,
    height: 240,
    tipExtra: (r) => [{ label: "exploits in sample", value: fmtInt(r.hits) }],
  });
  prose(
    sec,
    `<p class="dim">Critical bugs are ${pct(crit.share_of_all)} of all CVEs but ${pct(crit.share_of_exploited)} of exploited ones: severity does carry signal. Medium bugs are half the pile and still ${pct(med.share_of_exploited)} of what gets used. EPSS's lead at the top has narrowed since 2023 (from 32 points to 4); with only a few hundred exploits per year the trend is noisy, but it fits a world where more attacks land within days, before any outside signal appears.</p>`,
  );
  callout(
    sec,
    "if you run a patch queue",
    `Patch everything on CISA's KEV list first: that is confirmed exploitation, not a prediction. Then <b>rank the rest by EPSS for the urgent slice</b> and by severity for the long tail. Watch the edge devices and developer tools from the previous chapter, the two categories attackers reach for fastest.`,
  );
}
