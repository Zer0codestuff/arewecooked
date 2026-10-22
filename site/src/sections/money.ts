import type { Data } from "../main";
import { columns, lines } from "../lib/charts";
import { figure } from "../lib/figure";
import { monthLabel, pct } from "../lib/format";
import { C, callout, chapter, grid2, link, prose } from "../lib/page";

export function renderMoney(main: HTMLElement, d: Data) {
  const s = d.context.series;
  const sec = chapter(main, {
    id: "money",
    num: "07",
    title: "Follow the money",
    kicker: "Companies are not cutting security budgets. They are spending more than ever.",
  });
  const srm = s.gartner_spend_srm.points as any[];
  const inf = s.gartner_spend_infosec.points as any[];
  const rows = [
    ...srm.map((p: any) => ({ year: String(p.year), srm: p.value, infosec: null, note: p.note })),
    ...inf.map((p: any) => ({ year: p.year === 2030 ? "2030 (f)" : p.year === 2026 ? "2026 (f)" : String(p.year), srm: null, infosec: p.value, note: p.note })),
  ];
  const v26 = inf.find((p: any) => p.year === 2026).value;
  const v25 = inf.find((p: any) => p.year === 2025).value;
  prose(
    sec,
    `<p>If AI were replacing security spending, it would show up here first. It does not. Gartner estimates worldwide end-user spending on information security at <strong>$${v26} billion in 2026</strong>, up ${pct((v26 - v25) / v25, 1)} on 2025, and forecasts about $373 billion by 2030. The fastest-growing slice is "securing AI" itself: around $3 billion in 2026, projected to reach $16 billion by 2030.</p>`,
  );
  const f1 = figure(sec, {
    title: "Worldwide security spending",
    sub: "US$ billions. Gartner changed its market definition in 2024, so the two colors are not strictly comparable. (f) = forecast.",
    source: `Gartner press releases ${link("https://www.gartner.com/en/newsroom/press-releases/2021-05-17-gartner-forecasts-worldwide-security-and-risk-managem", "2021")}, ${link("https://gartner.com/en/newsroom/press-releases/2022-10-13-gartner-identifies-three-factors-influencing-growth-i", "2022")}, ${link("https://www.gartner.com/en/newsroom/press-releases/2023-09-28-gartner-forecasts-global-security-and-risk-management-spending-to-grow-14-percent-in-2024", "2023")}; 3Q26 forecast via ${link("https://softwarestrategiesblog.com/2026/10/05/gartner-3q26-information-security-forecast-post-quantum-firewalls-2030/", "Software Strategies Blog")}`,
    legend: [
      { label: "Security and risk management (old scope)", color: C.other },
      { label: "Information security (current scope)", color: C.s1 },
    ],
    table: { columns: [{ key: "year", label: "Year" }, { key: "srm", label: "Old scope $B" }, { key: "infosec", label: "Current scope $B" }, { key: "note", label: "Note" }], rows },
  });
  columns(f1, {
    data: rows,
    x: "year",
    series: [
      { key: "srm", label: "Old scope", color: C.other },
      { key: "infosec", label: "Current scope", color: C.s1 },
    ],
    stacked: true,
    labelBars: () => true,
    valueFormat: (x) => `$${x.toFixed(0)}B`,
    yFormat: (x) => `$${x}B`,
    height: 280,
    partial: (r) => r.year.includes("(f)"),
  });

  const idx = d.markets.indexed as any[];
  const perf = d.markets.perf as any[];
  const p = (t: string) => perf.find((r) => r.ticker === t);
  prose(
    sec,
    `<h3>Wall Street's vote</h3>
     <p>Investors read the AI era as good news for security vendors. The First Trust Nasdaq Cybersecurity ETF (ticker CIBR), a basket of listed security companies, is up <strong>${pct(p("CIBR").ytd)}</strong> in 2026 so far, against ${pct(p("QQQ").ytd)} for the Nasdaq-100 and ${pct(p("SPY").ytd)} for the S&P 500. Market commentators ${link("https://finance.yahoo.com/markets/article/cybersecurity-stocks-are-hitting-records-again-as-chips-play-catch-up-chart-of-the-day-130252672.html", "tied the rally")} to demand for AI-era security and consolidation into a few big platforms. CrowdStrike, Palo Alto Networks and Fortinet roughly doubled this year.</p>`,
  );
  const ser = [
    { key: "CIBR", label: "Cyber ETF (CIBR)", color: C.s1 },
    { key: "QQQ", label: "Nasdaq-100", color: C.s3 },
    { key: "SPY", label: "S&P 500", color: C.s5 },
  ];
  const f2 = figure(sec, {
    title: "Cybersecurity stocks vs the market",
    sub: "Monthly total return, indexed to January 2020 = 100.",
    source: "Yahoo Finance adjusted monthly closes (author's calculation)",
    legend: ser.map((x) => ({ label: x.label, color: x.color, shape: "line" })),
    table: { columns: [{ key: "month", label: "Month", fmt: (x) => monthLabel(x) }, ...ser.map((x) => ({ key: x.key, label: x.label }))], rows: idx },
  });
  lines(f2, {
    data: idx,
    x: "month",
    time: true,
    series: ser,
    height: 320,
    baseline: 100,
    endLabels: true,
    marginRight: 150,
    valueFormat: (x) => x.toFixed(0),
    yFormat: (x) => x.toFixed(0),
    xFormat: (m) => monthLabel(m),
  });

  const vc = s.cyber_vc.points as any[];
  const vch = s.cyber_vc_h1.points as any[];
  const vrp = s.google_vrp.points as any[];
  const g = grid2(sec);
  const vcRows = [
    { label: "FY 2024", value: vc.find((x: any) => x.year === 2024).value },
    { label: "FY 2025", value: vc.find((x: any) => x.year === 2025).value },
    { label: "H1 2025", value: vch.find((x: any) => x.year === 2025).value },
    { label: "H1 2026", value: vch.find((x: any) => x.year === 2026).value },
  ];
  const f3 = figure(g, {
    title: "Venture funding for security startups",
    sub: "US$ billions, seed to growth stage. FY = full year, H1 = January to June.",
    source: `${link("https://news.crunchbase.com/venture/cybersecurity-startup-investment-up-ye-2025/", "Crunchbase News")} (2024 implied from +26% growth)`,
    table: { columns: [{ key: "label", label: "Period" }, { key: "value", label: "US$ billion" }], rows: vcRows },
  });
  columns(f3, {
    data: vcRows,
    x: "label",
    series: [{ key: "value", label: "Funding ($B)", color: C.s3 }],
    colorFn: (r) => (r.label.includes("2026") ? C.s3 : "#2b4a72"),
    labelBars: () => true,
    valueFormat: (x) => `$${x.toFixed(1)}B`,
    yFormat: (x) => `$${x}B`,
    height: 240,
  });
  callout(
    g,
    "bug bounties",
    `Paying outsiders to find bugs is also at record levels. Google paid <b>$${vrp[0].value} million</b> through its Vulnerability Reward Program in 2025, ${link("https://blog.google/security/vrp-2025-year-in-review/", "more than 40% above 2024")}, and launched a dedicated AI bug bounty. HackerOne ${link("https://www.hackerone.com/report/hacker-powered-security", "reports")} valid AI-related vulnerability reports up 210% in a year and prompt-injection reports up 540%, while autonomous "hackbots" now submit reports alongside humans.`,
  );
}
