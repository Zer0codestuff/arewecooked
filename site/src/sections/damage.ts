import type { Data } from "../main";
import { RED_RAMP, bump, choropleth } from "../lib/charts2";
import { columns, hbars, lines } from "../lib/charts";
import { el, figure } from "../lib/figure";
import { fmtInt, monthLabel, pct, shortMonth } from "../lib/format";
import { C, callout, chapter, grid2, link, prose } from "../lib/page";

export function renderDamage(main: HTMLElement, d: Data) {
  const rw = d.threats.ransomware;
  const sec = chapter(main, {
    id: "damage",
    num: "06",
    title: "The damage",
    kicker: "Ransomware, fraud and breaches: what all of this costs in the real world.",
  });
  const y = rw.yearly as any[];
  const y25 = y.find((r) => r.year === 2025);
  const y26 = y.find((r) => r.year === 2026);
  const y22 = y.find((r) => r.year === 2022);
  prose(
    sec,
    `<p>Modern ransomware gangs steal data before encrypting it, then publish the victim's name on a "leak site" to pressure them into paying. Those sites are public, and ${link("https://www.ransomware.live/", "ransomware.live")} has archived these posts since 2021 (complete coverage from 2022). They undercount (victims who pay quickly are never posted), but they are the most consistent public measure of ransomware activity.</p>
     <p>In 2026 the gangs have named <strong>${fmtInt(y26.victims)}</strong> victims so far, already above the ${fmtInt(y25.victims)} of all 2025 and almost ${Math.round(y26.victims / y22.victims)} times 2022. The market has also fragmented: ${y26.groups} different groups posted victims this year, against ${y22.groups} in 2022. When police take down a big brand, its affiliates simply rebrand.</p>`,
  );
  const mon = (rw.monthly as any[]).filter((r) => r.month >= "2022-01");
  const f1 = figure(sec, {
    title: "Ransomware victims named on leak sites, per month",
    sub: "January 2022 to October 2026 (October covers 1 to 22 Oct).",
    source: `${link("https://www.ransomware.live/", "ransomware.live")} API (deduplicated by victim and group)`,
    table: { columns: [{ key: "month", label: "Month", fmt: (x) => monthLabel(x) }, { key: "victims", label: "Victims", fmt: fmtInt }, { key: "groups", label: "Active groups", fmt: fmtInt }], rows: mon },
  });
  columns(f1, {
    data: mon,
    x: "month",
    xLabel: shortMonth,
    xTickEvery: (m: string) => new Date(m).getUTCMonth() === 0,
    series: [{ key: "victims", label: "Victims", color: C.s7 }],
    colorFn: () => C.s7,
    height: 280,
    tipHead: (r) => monthLabel(r.month),
    tipExtra: (r) => [{ label: "active groups", value: fmtInt(r.groups) }],
    releases: true,
  });

  renderRansomGeo(sec, d);

  const pay = d.context.series.ransom_payments.points as any[];
  const rate = d.context.series.ransom_pay_rate.points as any[];
  prose(
    sec,
    `<h3>More attacks, fewer payments</h3>
     <p>The good news hides in the money. Blockchain analysts at Chainalysis estimate ransom payments at about <strong>$${(pay.find((p) => p.year === 2025).value * 1000).toFixed(0)} million</strong> in 2025, down from a peak of $1.25 billion in 2023, even as attacks rose. Only <strong>${rate.find((p) => p.year === 2025).value}%</strong> of victims paid in 2025, a record low (${rate.find((p) => p.year === 2024).value}% in 2024). Better backups, law enforcement pressure and a growing refusal to pay are eroding the business model, which is one reason gangs now go after more, smaller victims.</p>`,
  );
  const g = grid2(sec);
  const f2 = figure(g, {
    title: "Ransom payments tracked on-chain",
    sub: "US$ billions per year, lower-bound estimates (revised upward as more wallets are identified).",
    source: `Chainalysis Crypto Crime Reports, via ${link("https://www.bleepingcomputer.com/news/security/ransomware-payment-rate-drops-to-record-low-as-attacks-surge/amp/", "BleepingComputer")} and ${link("https://www.techtarget.com/cybersecurity/news/252529391/Chainalysis-Ransomware-payments-down-fewer-victims-paying", "TechTarget")}`,
    table: { columns: [{ key: "year", label: "Year" }, { key: "value", label: "US$ billion" }, { key: "note", label: "Note" }], rows: pay },
  });
  columns(f2, {
    data: pay,
    x: "year",
    series: [{ key: "value", label: "Payments ($B)", color: C.s5 }],
    colorFn: () => C.s5,
    labelBars: () => true,
    valueFormat: (x) => `$${x.toFixed(2)}B`,
    yFormat: (x) => `$${x}B`,
    height: 240,
  });
  const ic3 = d.context.series.ic3_losses.points as any[];
  const f3 = figure(g, {
    title: "Cybercrime losses reported to the FBI",
    sub: "US$ billions per year, all internet crime types (mostly fraud).",
    source: `${link("https://www.ic3.gov/AnnualReport/Reports/2025_IC3Report.pdf", "FBI IC3 annual reports")} 2019 and 2025`,
    table: { columns: [{ key: "year", label: "Year" }, { key: "value", label: "US$ billion" }], rows: ic3 },
  });
  columns(f3, {
    data: ic3,
    x: "year",
    series: [{ key: "value", label: "Losses ($B)", color: C.s7 }],
    colorFn: () => C.s7,
    labelBars: (r) => r.year === 2015 || r.year === 2020 || r.year === 2025,
    valueFormat: (x) => `$${x.toFixed(1)}B`,
    yFormat: (x) => `$${x}B`,
    height: 240,
  });

  const ibm = d.context.series.ibm_breach_cost.points as any[];
  prose(
    sec,
    `<p>Reported cybercrime losses grew from $1.1 billion in 2015 to <strong>$20.9 billion</strong> in 2025, nearly 20 times. Most of that is fraud (investment scams, business email compromise) rather than hacking in the narrow sense, but the techniques overlap. For companies that do get breached, IBM's annual study puts the average cost at <strong>$${ibm.find((p) => p.year === 2026).value} million</strong> in 2026, a record. In 2026 IBM also ${link("https://www.varonis.com/blog/ibm-cost-of-a-data-breach-report-2026", "found")} that 43% of breached organizations had incidents involving "shadow AI", staff using AI tools the security team did not approve.</p>`,
  );
  const f4 = figure(sec, {
    title: "Average cost of a data breach",
    sub: "Global average, US$ millions, IBM / Ponemon study year.",
    source: `${link("https://www.ibm.com/reports/data-breach", "IBM Cost of a Data Breach")} reports 2015 to 2026`,
    narrow: true,
    table: { columns: [{ key: "year", label: "Year" }, { key: "value", label: "US$ million" }], rows: ibm },
  });
  lines(f4, {
    data: ibm,
    x: "year",
    series: [{ key: "value", label: "Average cost", color: C.s7 }],
    height: 240,
    yMin: 3,
    dots: true,
    yFormat: (x) => `$${x.toFixed(1)}M`,
    valueFormat: (x) => `$${x.toFixed(2)}M`,
    tickFormat: (x) => String(x),
    xFormat: (x) => String(x),
  });

  // Timeline
  prose(sec, `<h3>Six years in ${(d.context.timeline as any[]).length} moments</h3><p>The incidents and AI milestones behind the numbers. Use the filters to separate attacks from AI developments.</p>`);
  const wrap = el("div", "figure narrow");
  const card = el("div", "card");
  wrap.appendChild(card);
  const filt = el("div", "tl-filter");
  const kinds: [string, string][] = [
    ["all", "all"],
    ["incident", "incidents"],
    ["ai", "AI milestones"],
  ];
  const list = el("ol", "timeline");
  const items = (d.context.timeline as any[]).slice().reverse();
  const draw = (k: string) => {
    list.replaceChildren();
    for (const it of items.filter((x) => k === "all" || x.kind === k)) {
      const li = el("li");
      const dt = el("div", "d");
      dt.textContent = it.date.slice(0, 7);
      const dot = el("div", "dot");
      dot.style.background = it.kind === "ai" ? C.s1 : C.s7;
      const body = el("div");
      const tt = el("div", "t");
      tt.textContent = it.title;
      const x = el("div", "x");
      x.textContent = it.detail;
      const a = el("a");
      a.href = it.source_url;
      a.target = "_blank";
      a.rel = "noopener";
      a.textContent = "source";
      x.appendChild(a);
      body.append(tt, x);
      li.append(dt, dot, body);
      list.appendChild(li);
    }
  };
  for (const [k, label] of kinds) {
    const b = el("button");
    b.type = "button";
    b.textContent = label;
    if (k === "all") b.classList.add("on");
    b.addEventListener("click", () => {
      filt.querySelectorAll("button").forEach((x) => x.classList.remove("on"));
      b.classList.add("on");
      draw(k);
    });
    filt.appendChild(b);
  }
  card.append(filt, list);
  draw("all");
  sec.appendChild(wrap);

  callout(
    sec,
    "pattern",
    `Look at the incident column: most of the biggest events of the last six years were not exotic hacks. They were <b>supply chains</b> (SolarWinds, MOVEit, XZ, Shai-Hulud, Railway), <b>help desks talked into resetting a password</b> (MGM, M&S) and <b>internet-facing boxes left unpatched</b>. AI accelerates all three.`,
  );
}

const BRAND_COLORS: Record<string, string> = {
  Qilin: "#e66767",
  "The Gentlemen": "#c98500",
  Akira: "#3987e5",
  LockBit: "#9085e9",
  RansomHub: "#d55181",
  "ALPHV/BlackCat": "#34a870",
};

function renderRansomGeo(sec: HTMLElement, d: Data) {
  const r = d.ransom;
  const it = r.italy;
  const us = (r.countries as any[]).find((c) => c.iso2 === "US");
  const known = r.country_known as number;
  prose(
    sec,
    `<h3>Where the victims are</h3>
     <p>Ransomware is a business, and it goes where the money is. American organizations are ${pct(us.victims / known)} of the 2026 victims whose country is known. Per person the picture spreads out: rich, highly digitized economies such as Singapore, Switzerland, Hong Kong, Canada and the United Arab Emirates rank close to the US. <strong>Italy</strong> is the ${it ? ordinal(r.italy_rank) : ""} most-hit country in absolute terms, with ${it ? fmtInt(it.victims) : ""} victims named so far in 2026, already ${it ? pct(it.victims / it.victims_prev - 1) : ""} more than in all of 2025.</p>`,
  );
  const fig = figure(sec, {
    title: "Ransomware victims named in 2026, by country",
    source: `${link("https://www.ransomware.live/", "ransomware.live")}; population and GDP from the ${link("https://data.worldbank.org/", "World Bank")} (2024)`,
    table: {
      columns: [
        { key: "name", label: "Country" },
        { key: "victims", label: "Victims 2026", fmt: fmtInt },
        { key: "victims_prev", label: "Victims 2025", fmt: (x: number) => (x ? fmtInt(x) : "") },
        { key: "per_million", label: "Per million people", fmt: (x: number) => (x ? x.toFixed(1) : "") },
      ],
      rows: r.countries,
    },
  });
  const toggle = el("div", "seg-toggle");
  const modes = [
    { key: "victims", label: "victims", thresholds: [5, 20, 50, 100, 300], fmt: (x: number) => fmtInt(x), title: "Victims named" },
    { key: "per_million", label: "per million people", thresholds: [0.2, 0.5, 1, 2.5, 5], fmt: (x: number) => (x < 1 ? x.toFixed(1) : x.toFixed(x < 10 ? 1 : 0)), title: "Victims per million people" },
  ];
  fig.chart.before(toggle);
  import("world-atlas/countries-110m.json").then(async (topo: any) => {
    const { feature } = await import("topojson-client");
    const features = (feature(topo.default ?? topo, (topo.default ?? topo).objects.countries) as any).features;
    const draw = (i: number) => {
      toggle.querySelectorAll("button").forEach((b, j) => b.classList.toggle("on", j === i));
      const m = modes[i];
      choropleth(fig, {
        features,
        data: r.countries,
        value: m.key,
        thresholds: m.thresholds,
        colors: RED_RAMP,
        label: m.title,
        format: m.fmt,
        extra: (c) => [
          { label: "victims", value: fmtInt(c.victims) },
          { label: "per million people", value: c.per_million ? c.per_million.toFixed(1) : "n/a" },
          { label: "2025, full year", value: c.victims_prev ? fmtInt(c.victims_prev) : "0" },
        ],
      });
    };
    modes.forEach((m, i) => {
      const b = el("button");
      b.type = "button";
      b.textContent = m.label;
      b.addEventListener("click", () => draw(i));
      toggle.appendChild(b);
    });
    draw(0);
  });
  prose(sec, `<p class="dim">${fmtInt(r.country_unknown)} of the year's victims have no country attached. Small states such as Singapore and Hong Kong are too small to see on the map; they are in the table view.</p>`);

  // Brands
  const bumpRows = r.bump as any[];
  const yrs: number[] = r.bump_years;
  // ransomware.live coverage starts in 2020, so brand age is only meaningful from 2023 on
  const ch = (r.churn as any[]).filter((x) => x.year >= 2023);
  const ch26 = ch.find((x) => x.year === 2026);
  const chTot = (x: any) => (r.churn_order as string[]).reduce((s, k) => s + (x[k] ?? 0), 0);
  prose(
    sec,
    `<h3>Brands come and go, the business stays</h3>
     <p>Police takedowns work, briefly. LockBit led the market for three years until an international operation seized its servers in February 2024; ALPHV/BlackCat vanished after an apparent exit scam the same spring; RansomHub rose to first place in 2024 and went dark in April 2025. Each time, the affiliates who actually break into networks moved to the next brand. Of the ${r.brands_50plus} brands that ever named 50 or more victims, ${r.brands_gone} have gone quiet; their median lifespan was about <strong>${Math.round(r.lifespan_median_months)} months</strong>. In 2026, ${pct(ch26["New this year"] / chTot(ch26))} of victims were claimed by brands that did not exist a year earlier.</p>`,
  );
  const fb = figure(sec, {
    title: "Ransomware brands ranked by victims named, per year",
    source: `${link("https://www.ransomware.live/", "ransomware.live")}; versions of the same brand merged (LockBit 2/3/5)`,
    legend: Object.entries(BRAND_COLORS).map(([k, c]) => ({ label: k, color: c, shape: "line" as const })),
    table: {
      columns: [{ key: "year", label: "Year" }, { key: "rank", label: "Rank" }, { key: "group", label: "Brand" }, { key: "victims", label: "Victims", fmt: fmtInt }, { key: "share", label: "Share", fmt: (x: number) => pct(x, 1) }],
      rows: [...bumpRows].filter((x) => x.rank <= 10).sort((a, b) => a.year - b.year || a.rank - b.rank),
    },
  });
  bump(fb, { data: bumpRows, years: yrs, highlight: BRAND_COLORS, maxRank: 10, height: 340 });

  // Sectors
  const st = (r.sectors as any[]).filter((x) => x.sector !== "Other").slice(0, 10).map((x) => ({ ...x, prev: x.prev, pace: Math.round(x.cur_pace) }));
  const g = grid2(sec);
  const f2 = figure(g, {
    title: "Victims by sector: 2025 vs 2026 full-year pace",
    source: "ransomware.live sector labels; 2026 scaled from 1 Jan to 22 Oct",
    legend: [
      { label: "2025", color: C.other },
      { label: "2026 pace", color: C.s7 },
    ],
    table: { columns: [{ key: "sector", label: "Sector" }, { key: "prev", label: "2025", fmt: fmtInt }, { key: "cur", label: "2026 to date", fmt: fmtInt }, { key: "pace", label: "2026 pace", fmt: fmtInt }], rows: st },
  });
  hbars(f2, {
    data: st,
    label: "sector",
    value: "pace",
    value2: "prev",
    color: C.s7,
    color2: C.other,
    labelWidth: 170,
    tip: (x: any) => ({
      head: x.sector,
      rows: [
        { label: "2026 to date", value: fmtInt(x.cur), color: "transparent" },
        { label: "2026 full-year pace", value: fmtInt(x.pace), color: C.s7 },
        { label: "2025", value: fmtInt(x.prev), color: C.other },
      ],
    }),
  });
  const order: string[] = r.churn_order;
  const AGE = [C.s7, C.s5, C.s3, C.other];
  const f3 = figure(g, {
    title: "Victims by age of the brand that claimed them",
    source: "ransomware.live; brand age = years since its first leak-site post",
    legend: order.map((o, i) => ({ label: o, color: AGE[i] })),
    table: { columns: [{ key: "year", label: "Year" }, ...order.map((o) => ({ key: o, label: o, fmt: fmtInt }))], rows: ch },
  });
  columns(f3, {
    data: ch,
    x: "year",
    series: order.map((o, i) => ({ key: o, label: o, color: AGE[i] })),
    stacked: true,
    percent: true,
    height: 260,
  });
}

function ordinal(n: number): string {
  const s = ["th", "st", "nd", "rd"];
  const v = n % 100;
  return n + (s[(v - 20) % 10] || s[v] || s[0]);
}
