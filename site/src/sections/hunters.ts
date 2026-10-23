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
    releases: true,
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
    releases: true,
  });

  const note = el("div", "prose");
  note.innerHTML = `<p class="dim">The bump in mid-2025 is a single AI scanner (ZAST.AI) filing batches of web-application bugs through VulDB. The steady climb starts in early 2026. Most vendors still list no finder at all, so treat this line as the visible tip.</p>`;
  sec.appendChild(note);

  // AI review inside the Linux kernel
  const an = d.anatomy;
  const ka = (an.kernel_ai as any[]).map((r) => ({ ...r }));
  const kt = an.kernel_ai_totals;
  prose(
    sec,
    `<h3>The reviewer that never sleeps</h3>
     <p>The clearest sign that AI is now part of ordinary maintenance comes from the Linux kernel, the most scrutinized codebase on earth. On 17 March 2026 Google engineers ${link("https://lkml.iu.edu/hypermail/linux/kernel/2603.2/03802.html", "announced Sashiko")}, an AI system that reviews every patch posted to the kernel mailing lists (it runs on Gemini; the project is moving to the Linux Foundation). Kernel fixes are published as CVEs, and their descriptions say who spotted the bug.</p>
     <p>Since April, <strong>${fmtInt(kt.since_apr)}</strong> kernel CVE fixes credit an AI reviewer: ${fmtInt(kt.sashiko)} name Sashiko, the rest Claude or other LLM tools. That is ${pct(kt.since_apr / kt.kernel_since_apr, 1)} of all kernel CVEs in the period, up from almost none a year earlier. These records have no "credits" entry at all, the AI shows up only in the text of the fix, which is why our classifier reads descriptions too.</p>`,
  );
  const fk = figure(sec, {
    title: "Linux kernel CVE fixes that credit an AI reviewer, per month",
    source: `Linux kernel CNA records in cvelistV5 (text of the fix description); ${link("https://www.theregister.com/2026/03/20/sashiko_code_review_linux/", "Sashiko background")}`,
    narrow: true,
    legend: [
      { label: "Sashiko (Google, Gemini)", color: C.s3 },
      { label: "Other AI or LLM review", color: C.s1 },
    ],
    table: { columns: [{ key: "month", label: "Month", fmt: (x) => monthLabel(x) }, { key: "sashiko", label: "Sashiko", fmt: fmtInt }, { key: "other_ai", label: "Other AI", fmt: fmtInt }, { key: "kernel_cves", label: "All kernel CVEs", fmt: fmtInt }], rows: ka },
  });
  columns(fk, {
    data: ka,
    x: "month",
    xLabel: shortMonth,
    xTickEvery: (m: string) => new Date(m).getUTCMonth() % 3 === 0,
    series: [
      { key: "sashiko", label: "Sashiko", color: C.s3 },
      { key: "other_ai", label: "Other AI", color: C.s1 },
    ],
    stacked: true,
    height: 240,
    tipHead: (r) => monthLabel(r.month),
    tipExtra: (r) => [{ label: "all kernel CVEs", value: fmtInt(r.kernel_cves) }],
    annotations: [{ x: "2026-03-01T00:00:00.000Z", text: "Sashiko launch", dy: 0, align: "end" }],
  });

  // Research boom
  const rs = (an.research as any[]).filter((r) => r.year >= 2019);
  const r22 = rs.find((r) => r.year === 2022);
  const r26 = rs.find((r) => r.year === 2026);
  prose(
    sec,
    `<p>Behind the tools sits a research boom. Papers that pair large language models with vulnerabilities, exploits, fuzzing, malware or penetration testing went from ${fmtInt(r22.llm_security)} in 2022 to <strong>${fmtInt(r26.llm_security)}</strong> in 2026 so far, according to the OpenAlex scholarly index. In 2026, about ${pct(r26.llm_security / r26.llm_all)} of all LLM papers are about security.</p>`,
  );
  const fr = figure(sec, {
    title: "Research papers on LLMs and software security, per year",
    source: `${link("https://openalex.org/", "OpenAlex")} title and abstract search ("large language model" and vulnerability, exploit, fuzzing, malware or penetration testing); 2026 to 22 Oct`,
    narrow: true,
    table: { columns: [{ key: "year", label: "Year" }, { key: "llm_security", label: "LLM + security papers", fmt: fmtInt }, { key: "llm_all", label: "All LLM papers", fmt: fmtInt }], rows: rs },
  });
  columns(fr, {
    data: rs,
    x: "year",
    series: [{ key: "llm_security", label: "Papers", color: C.s6 }],
    colorFn: () => C.s6,
    labelBars: (r) => r.year >= 2022,
    partial: (r) => r.year === 2026,
    height: 230,
    tipExtra: (r) => [{ label: "share of all LLM papers", value: r.llm_all ? pct(r.llm_security / r.llm_all, 1) : "" }],
  });
}
