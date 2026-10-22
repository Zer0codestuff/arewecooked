import type { Data } from "../main";
import { radar } from "../lib/charts";
import { el, figure } from "../lib/figure";
import { fmtInt } from "../lib/format";
import { C, chapter, grid2, prose } from "../lib/page";

interface Axis {
  key: string;
  label: string;
  then: number;
  now: number;
  thenLabel: string;
  nowLabel: string;
  fmt: (x: number) => string;
  inverse?: boolean; // smaller is worse (e.g. days to exploitation)
}

export function renderVerdict(main: HTMLElement, d: Data) {
  const v = d.vulns;
  const t = v.totals;
  const s = d.context.series;
  const frac = t.year_fraction; // share of 2026 elapsed on the snapshot date
  const pace = (x: number) => x / frac;
  const pt = (name: string, y: number) => (s[name].points as any[]).find((p) => p.year === y).value;
  const yr = (arr: any[], y: number, k: string) => arr.find((r) => r.year === y || r.pub_year === y)[k];
  const sev = v.severity as any[];
  const rwy = d.threats.ransomware.yearly as any[];
  const ays = v.ai_software_yearly as any[];
  const aiYear = (y: number) => (v.ai_monthly as any[]).filter((r) => r.month.startsWith(String(y))).reduce((a, r) => a + Object.entries(r).filter(([k]) => k !== "month").reduce((b, [, x]) => b + (x as number), 0), 0);
  const ms = d.threats.patch_tuesday.yearly as any[];

  const threat: Axis[] = [
    { key: "cves", label: "New vulnerabilities", then: yr(v.yearly, 2020, "cves"), now: pace(t.cur_year), thenLabel: "2020", nowLabel: "2026 pace", fmt: fmtInt },
    { key: "crit", label: "Critical vulnerabilities", then: yr(sev, 2023, "CRITICAL"), now: pace(t.critical_cur), thenLabel: "2023", nowLabel: "2026 pace", fmt: fmtInt },
    { key: "speed", label: "Exploitation speed", then: yr(v.tte, 2022, "median_days"), now: yr(v.tte, 2026, "median_days"), thenLabel: "2022 CVEs", nowLabel: "2026 CVEs", fmt: (x) => `${x} days`, inverse: true },
    { key: "rw", label: "Ransomware victims", then: yr(rwy, 2022, "victims"), now: pace(yr(rwy, 2026, "victims")), thenLabel: "2022", nowLabel: "2026 pace", fmt: fmtInt },
    { key: "loss", label: "Cybercrime losses", then: pt("ic3_losses", 2020), now: pt("ic3_losses", 2025), thenLabel: "2020", nowLabel: "2025", fmt: (x) => `$${x.toFixed(1)}B` },
    { key: "cost", label: "Cost per breach", then: pt("ibm_breach_cost", 2020), now: pt("ibm_breach_cost", 2026), thenLabel: "2020", nowLabel: "2026", fmt: (x) => `$${x.toFixed(2)}M` },
    { key: "aisw", label: "Bugs in AI software", then: yr(ays, 2022, "cves"), now: pace(yr(ays, 2026, "cves")), thenLabel: "2022", nowLabel: "2026 pace", fmt: fmtInt },
  ];
  const defense: Axis[] = [
    { key: "spend", label: "Security spending", then: pt("gartner_spend_srm", 2021), now: pt("gartner_spend_infosec", 2026), thenLabel: "2021", nowLabel: "2026", fmt: (x) => `$${x.toFixed(0)}B` },
    { key: "people", label: "Security workforce", then: pt("isc2_workforce", 2020), now: pt("isc2_workforce", 2024), thenLabel: "2020", nowLabel: "2024", fmt: (x) => `${x}M` },
    { key: "aifound", label: "Bugs found by AI for defenders", then: aiYear(2025), now: pace(aiYear(2026)), thenLabel: "2025", nowLabel: "2026 pace", fmt: fmtInt },
    { key: "refuse", label: "Victims refusing to pay", then: 100 - pt("ransom_pay_rate", 2024), now: 100 - pt("ransom_pay_rate", 2025), thenLabel: "2024", nowLabel: "2025", fmt: (x) => `${x.toFixed(0)}%` },
    { key: "fixes", label: "Microsoft flaws fixed", then: yr(ms, 2020, "cves"), now: pace(yr(ms, 2026, "cves")), thenLabel: "2020", nowLabel: "2026 pace", fmt: fmtInt },
    { key: "vc", label: "Startup funding", then: pt("cyber_vc", 2024), now: pt("cyber_vc", 2025), thenLabel: "2024", nowLabel: "2025", fmt: (x) => `$${x.toFixed(1)}B` },
  ];

  const mult = (a: Axis) => (a.inverse ? a.then / a.now : a.now / a.then);
  const toSeries = (axes: Axis[], color: string) => {
    const now: Record<string, number> = {};
    const then: Record<string, number> = {};
    const rawNow: Record<string, string> = {};
    const rawThen: Record<string, string> = {};
    for (const a of axes) {
      now[a.key] = 100;
      then[a.key] = Math.max(2, 100 / mult(a));
      rawNow[a.key] = `${a.nowLabel}: ${a.fmt(a.now)}`;
      rawThen[a.key] = `${a.thenLabel}: ${a.fmt(a.then)}`;
    }
    return [
      { label: "Then", color: C.other, values: then, raw: rawThen },
      { label: "Now", color, values: now, raw: rawNow },
    ];
  };
  const geo = (axes: Axis[]) => Math.exp(axes.reduce((a, x) => a + Math.log(mult(x)), 0) / axes.length);
  const gT = geo(threat);
  const gD = geo(defense);

  const sec = chapter(main, {
    id: "verdict",
    num: "09",
    title: "So... are we cooked?",
    kicker: "Two radars, one question: did the threats grow faster than the defenses?",
  });
  prose(
    sec,
    `<p>To pull everything together we picked seven measures of <strong>threat pressure</strong> and six of <strong>defensive capacity</strong>, each compared between an earlier year and today. On each radar, "now" sits on the outer ring and "then" shows how far back things were. A small gray shape means that dimension has grown a lot. Hover any point for the raw numbers and years.</p>`,
  );
  const g = grid2(sec);
  const f1 = figure(g, {
    title: "Threat pressure, then vs now",
    sub: `Typical threat measure grew ${gT.toFixed(1)}x (geometric mean).`,
    source: "CVE Program, CISA KEV, ransomware.live, FBI IC3, IBM (see chapters above)",
    legend: [
      { label: "Then", color: C.other },
      { label: "Now", color: C.s7 },
    ],
    table: {
      columns: [{ key: "label", label: "Measure" }, { key: "thenS", label: "Then" }, { key: "nowS", label: "Now" }, { key: "m", label: "Change" }],
      rows: threat.map((a) => ({ label: a.label, thenS: `${a.fmt(a.then)} (${a.thenLabel})`, nowS: `${a.fmt(a.now)} (${a.nowLabel})`, m: `${mult(a).toFixed(1)}x` })),
    },
  });
  radar(f1, { axes: threat.map((a) => ({ key: a.key, label: a.label })), series: toSeries(threat, C.s7), height: 420 });
  const f2 = figure(g, {
    title: "Defensive capacity, then vs now",
    sub: `Typical defense measure grew ${gD.toFixed(1)}x (geometric mean).`,
    source: "Gartner, ISC2, CVE Program, Chainalysis, MSRC, Crunchbase (see chapters above)",
    legend: [
      { label: "Then", color: C.other },
      { label: "Now", color: C.s1 },
    ],
    table: {
      columns: [{ key: "label", label: "Measure" }, { key: "thenS", label: "Then" }, { key: "nowS", label: "Now" }, { key: "m", label: "Change" }],
      rows: defense.map((a) => ({ label: a.label, thenS: `${a.fmt(a.then)} (${a.thenLabel})`, nowS: `${a.fmt(a.now)} (${a.nowLabel})`, m: `${mult(a).toFixed(1)}x` })),
    },
  });
  radar(f2, { axes: defense.map((a) => ({ key: a.key, label: a.label })), series: toSeries(defense, C.s1), height: 420 });

  // ASCII doneness meter
  const ratio = gT / gD;
  const levels = ["RAW", "RARE", "MEDIUM-RARE", "MEDIUM", "MEDIUM-WELL", "WELL DONE", "BURNT"];
  const cuts = [0.75, 1, 1.5, 2, 3, 4];
  const pos = cuts.findIndex((c) => ratio < c) === -1 ? levels.length - 1 : cuts.findIndex((c) => ratio < c);
  const width = Math.max(16, Math.min(42, Math.floor((Math.min(window.innerWidth, 820) - 160) / 8)));
  const filled = Math.round(((pos + 0.5) / levels.length) * width);
  const wrap = el("div", "figure narrow");
  const card = el("div", "card");
  wrap.appendChild(card);
  const title = el("h4", "fig-title");
  title.textContent = "The doneness meter";
  card.appendChild(title);
  const sub = el("p", "fig-sub");
  sub.textContent = `Threat growth divided by defense growth: ${gT.toFixed(1)}x / ${gD.toFixed(1)}x = ${ratio.toFixed(2)}. Below 1 the defenses are winning (rare); 4 or more means burnt.`;
  card.appendChild(sub);
  const pre = el("pre", "meter");
  const bar = "█".repeat(filled) + "░".repeat(width - filled);
  pre.innerHTML = `<span class="lab">  heat  </span>[<span class="fill">${bar.slice(0, filled)}</span>${bar.slice(filled)}]\n<span class="lab">  level </span> ${levels.map((l, i) => (i === pos ? `<b style="color:#fff">&gt;${l}&lt;</b>` : l)).join(" · ")}`;
  card.appendChild(pre);
  sec.appendChild(wrap);

  prose(
    sec,
    `<h3>Our answer: ${levels[pos].toLowerCase()}, not cooked</h3>
     <p>Threats grew about ${gT.toFixed(1)} times over the periods we compared; defenses about ${gD.toFixed(1)} times. The heat is rising faster than the cooling. But the picture is less bleak than the CVE chart alone suggests, for three reasons the data supports:</p>
     <ul>
       <li><strong>Most of the new bugs are found by defenders first.</strong> The 2026 surge is largely vendors, open-source projects and AI labs cleaning up code before attackers get there. A bug found and fixed is a bug that cannot hurt anyone.</li>
       <li><strong>Attackers still use a tiny fraction.</strong> About 0.2% of 2026 CVEs are known to be exploited, and that share keeps falling. Knowing which ones matter is a solvable problem.</li>
       <li><strong>The money is there.</strong> Record spending, record bug bounties, fewer ransom payments.</li>
     </ul>
     <p>What would make us cooked is the gap the data keeps pointing to: <strong>fixing</strong>. Exploitation now takes days, while patches for AI-found bugs in volunteer-run projects can take months, and the security workforce has stopped growing. The next two years will be decided less by who finds bugs fastest, and more by who can fix them fastest. AI will have to do that part too.</p>
     <p class="dim">Method note: this composite is a rough summary, not a scientific index. Measures use different years depending on data availability (labeled in each tooltip and table), partial 2026 values are scaled to a full-year pace, and Gartner's spending definition changed in 2024. Every input is shown in the chapters above.</p>`,
  );
}
