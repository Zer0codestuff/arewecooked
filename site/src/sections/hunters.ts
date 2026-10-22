import type { Data } from "../main";
import { columns, hbars, lines, radar } from "../lib/charts";
import { el, figure } from "../lib/figure";
import { fmtInt, monthLabel, pct, shortMonth } from "../lib/format";
import { C, callout, chapter, link, prose } from "../lib/page";

const ORG_COLORS = [C.s1, C.s2, C.s3, C.s4, C.s5, C.s6, C.s7];

export function renderHunters(main: HTMLElement, d: Data) {
  const v = d.vulns;
  const t = v.totals;
  const gw = d.glasswing;
  const sec = chapter(main, {
    id: "hunters",
    num: "03",
    title: "The machines are hunting",
    kicker: "How many vulnerabilities are now found by AI? More than the records admit.",
  });

  prose(
    sec,
    `<p>Until 2024, an AI finding a real, exploitable bug in widely used software was news. Google's Big Sleep agent found one in SQLite in late 2024; in 2025 a researcher used OpenAI's o3 to find a Linux kernel flaw, and an autonomous pentester called XBOW topped HackerOne's US leaderboard. In 2026 it became routine.</p>
     <p>Measuring it is harder than it sounds. A CVE record has a "credits" field, but there is no standard way to say "found by AI", and many vendors credit no one at all. So we built a classifier: it reads the credits and descriptions of all ${fmtInt(412863)} CVE records and flags those that name an AI system or an AI-native research team (the list follows Berkeley's ${link("https://vuln.cs.berkeley.edu/", "Agentic Vulnerability Coverage Map")}), then adds CVEs from a community ${link("https://github.com/patrickmgarrity/Anthropic-Credited-CVEs", "tracker of Anthropic-credited CVEs")} that are only credited in vendor advisories.</p>
     <p>Result: <strong>${fmtInt(t.ai_attributed)}</strong> CVEs publicly credited to AI finders, ${fmtInt(t.ai_attributed_cur)} of them in 2026. That is a floor, not an estimate. The real number is far higher, as the next chart shows.</p>`,
  );

  const am = v.ai_monthly as any[];
  const orgs = Object.keys(am[0]).filter((k) => k !== "month");
  const colorOf = (o: string, i: number) => (o === "Others" ? C.other : ORG_COLORS[i % ORG_COLORS.length]);
  const f1 = figure(sec, {
    title: "CVEs credited to AI vulnerability finders, per month",
    sub: "July 2024 to October 2026. Lower bound: only records that name an AI system or AI-native team.",
    source: `CVE Program cvelistV5 credits (author's classifier), ${link("https://github.com/patrickmgarrity/Anthropic-Credited-CVEs", "Anthropic-Credited-CVEs")}`,
    legend: orgs.map((o, i) => ({ label: o, color: colorOf(o, i) })),
    table: { columns: [{ key: "month", label: "Month", fmt: (x) => monthLabel(x) }, ...orgs.map((o) => ({ key: o, label: o, fmt: fmtInt }))], rows: am },
  });
  columns(f1, {
    data: am,
    x: "month",
    xLabel: shortMonth,
    xTickEvery: (m: string) => new Date(m).getUTCMonth() % 3 === 0,
    series: orgs.map((o, i) => ({ key: o, label: o, color: colorOf(o, i) })),
    stacked: true,
    height: 320,
    tipHead: (r) => monthLabel(r.month),
    annotations: [{ x: "2026-04-01T00:00:00.000", text: "Glasswing", dy: 0, align: "end" }],
  });

  const share = (v.ai_share as any[]).filter((r) => r.month >= "2025-01");
  const last = share[share.length - 1];
  prose(
    sec,
    `<p>As a share of all CVEs the credited part is still small: <strong>${pct(last.share, 1)}</strong> in October 2026, up from almost zero in early 2025. VulnCheck, using a broader dataset, counts ${link("https://www.vulncheck.com/blog/state-of-exploitation-1h-2026", "1,061 AI-attributed vulnerabilities")} by mid-2026; Berkeley's tracker counts ${fmtInt(v.berkeley.total_cves)} across ${v.berkeley.organizations} organizations.</p>`,
  );

  // Glasswing funnel
  const fn = gw.funnel as any[];
  prose(
    sec,
    `<h3>The iceberg: one company's ledger</h3>
     <p>Anthropic publishes a ${link("https://red.anthropic.com/2026/cvd/", "coordinated disclosure dashboard")} for bugs its Claude models found in open-source software. It is the clearest view of what sits under the waterline. Between November 2025 and October 2026, Claude models flagged <strong>${fmtInt(fn[0].n)}</strong> potential vulnerabilities in ${gw.projects} projects. Human reviewers at outside security firms confirmed ${pct(gw.true_positive_rate, 1)} of a large sample as real. ${fmtInt(fn[1].n)} were reported to maintainers. Only <strong>${fmtInt(fn[3].n)}</strong> are known to be fixed, and ${fmtInt(fn[4].n)} have a public ID (CVE or GitHub advisory).</p>`,
  );
  const f2 = figure(sec, {
    title: "From AI finding to public fix: Anthropic's disclosure funnel",
    sub: `Findings by Claude models (including Mythos Preview) in open-source projects, as of ${gw.dashboard_as_of}.`,
    source: `${link("https://red.anthropic.com/2026/cvd/", "Anthropic coordinated vulnerability disclosure dashboard")}`,
    narrow: true,
    table: { columns: [{ key: "stage", label: "Stage" }, { key: "n", label: "Findings", fmt: fmtInt }], rows: fn },
  });
  hbars(f2, {
    data: fn,
    label: "stage",
    value: "n",
    color: (r) => (r.stage.startsWith("Patched") ? C.s2 : C.s1),
    labelWidth: 210,
    rowHeight: 34,
  });

  callout(
    sec,
    "the real bottleneck",
    `Finding bugs is no longer the slow step. <b>Fixing them is.</b> An open-source library is often maintained by one or two volunteers. Anthropic says human triage is now its "rate limiting step"; by mid-2026 VulnCheck counted ${link("https://www.vulncheck.com/blog/state-of-exploitation-1h-2026", "more than 150 Glasswing findings")} already past their disclosure deadline. Meanwhile the curl project ${link("https://www.bleepingcomputer.com/news/security/curl-ending-bug-bounty-program-after-flood-of-ai-slop-reports/", "shut down its bug bounty")} in January because of a flood of fake, AI-generated reports. AI has made bug reports both far better and far worse.`,
  );

  // AI vs other severity
  const sv = v.ai_severity as any[];
  const ai = sv[0];
  const oth = sv[1];
  prose(
    sec,
    `<h3>Are AI-found bugs worse?</h3>
     <p>By the standard severity score, no: in 2026, ${pct(ai.critical + ai.high)} of AI-credited CVEs are high or critical, against ${pct(oth.critical + oth.high)} for everything else, with the same median score (${ai.median_cvss} vs ${oth.median_cvss}). Exploitation forecasts (${link("https://www.first.org/epss/", "EPSS")}) are also about the same. VulnCheck found that only 1.3% of AI-attributed CVEs have been exploited, roughly the base rate.</p>
     <p>Google sees it differently: grading by its own risk model, ${link("https://cloud.google.com/blog/topics/threat-intelligence/vulnerability-discovery-and-exploitation-trends-in-the-ai-era", "half of likely AI-discovered vulnerabilities allow remote code execution, against 26% of all CVEs")}. AI hunters go after deep memory bugs in C code, exactly the kind attackers prize. The fair summary: AI is not finding a different kind of bug yet, but it is finding a lot of the expensive kind.</p>`,
  );

  // Radar: profile of three AI finders (Berkeley)
  const board = v.berkeley.board as any[];
  const pick = ["AISLE Research Team", "Anthropic", "XBOW"];
  const metrics = [
    { key: "count", label: "Volume" },
    { key: "critical", label: "Critical finds" },
    { key: "avg_cvss", label: "Avg severity" },
    { key: "avg_epss", label: "Exploit odds" },
    { key: "breadth", label: "Bug-type breadth" },
    { key: "tempo", label: "Last 90 days" },
  ];
  const max: Record<string, number> = {};
  for (const m of metrics) max[m.key] = Math.max(...board.map((b) => +b[m.key] || 0));
  const fmtRaw = (k: string, x: number) => (k === "avg_cvss" ? x.toFixed(1) : k === "avg_epss" ? pct(x, 1) : fmtInt(x));
  const ser = pick.map((p, i) => {
    const b = board.find((x) => x.org === p) ?? {};
    const values: Record<string, number> = {};
    const raw: Record<string, string> = {};
    for (const m of metrics) {
      values[m.key] = m.key === "avg_cvss" ? ((+b[m.key] || 0) / 10) * 100 : ((+b[m.key] || 0) / max[m.key]) * 100;
      raw[m.key] = fmtRaw(m.key, +b[m.key] || 0);
    }
    return { label: p.replace(" Research Team", ""), color: [C.s1, C.s2, C.s3][i], values, raw };
  });
  const f3 = figure(sec, {
    title: "Three AI bug hunters, three styles",
    sub: "Each axis is scaled to the leader among 22 tracked AI finders (severity on its 0 to 10 scale). Hover a point for raw values.",
    source: `${link("https://vuln.cs.berkeley.edu/", "Berkeley Vulnerability Initiative, Agentic Vulnerability Coverage Map")} (snapshot 19 Oct 2026)`,
    narrow: true,
    legend: ser.map((s) => ({ label: s.label, color: s.color })),
    table: {
      columns: [{ key: "org", label: "Finder" }, ...metrics.map((m) => ({ key: m.key, label: m.label, fmt: (x: number) => fmtRaw(m.key, +x) }))],
      rows: board.slice(0, 12),
    },
  });
  radar(f3, { axes: metrics, series: ser });
  prose(
    sec,
    `<p class="dim">AISLE is the volume player (hundreds of CVEs across many bug types, including every flaw in OpenSSL's January 2026 release). Anthropic leads on critical findings. XBOW, which attacks running web applications like a human pentester, finds fewer bugs, but they carry about five times the predicted exploitation odds of the other two (the overall leader on that axis, Hacktron AI, found the BeyondTrust flaw that was exploited within days).</p>`,
  );

  const sh = figure(sec, {
    title: "AI-credited share of all CVEs",
    sub: "Monthly, January 2025 to October 2026.",
    source: "Author's classifier on cvelistV5",
    narrow: true,
    table: { columns: [{ key: "month", label: "Month", fmt: (x) => monthLabel(x) }, { key: "share", label: "Share", fmt: (x) => pct(x, 2) }], rows: share },
  });
  lines(sh, {
    data: share,
    x: "month",
    time: true,
    series: [{ key: "share", label: "AI-credited share", color: C.s1 }],
    area: true,
    height: 220,
    yFormat: (x) => pct(x, 1),
    valueFormat: (x) => pct(x, 2),
    xFormat: (m) => monthLabel(m),
  });

  const note = el("div", "prose");
  note.innerHTML = `<p class="dim">The bump in mid-2025 is a single AI scanner (ZAST.AI) filing batches of web-application bugs through VulDB. The steady climb starts in early 2026. Most vendors still list no finder at all, so treat this line as the visible tip.</p>`;
  sec.appendChild(note);
}
