import type { Data } from "../main";
import { columns, hbars, lines } from "../lib/charts";
import { figure } from "../lib/figure";
import { fmtInt, pct } from "../lib/format";
import { C, callout, chapter, grid2, link, prose } from "../lib/page";

export function renderPeople(main: HTMLElement, d: Data) {
  const s = d.context.series;
  const sec = chapter(main, {
    id: "people",
    num: "08",
    title: "Are robots taking the jobs?",
    kicker: "Not yet. But the entry-level ladder is getting shorter.",
  });
  const wf = s.isc2_workforce.points as any[];
  const gap = s.isc2_gap.points as any[];
  const rows = wf.map((p: any) => ({ year: p.year, workforce: p.value, gap: gap.find((g: any) => g.year === p.year)?.value }));
  const cyb = s.cybersn_postings.points[0];
  prose(
    sec,
    `<p>Security has been "short of people" for a decade. ISC2, the largest professional body, estimated the global workforce at <strong>5.5 million</strong> people in 2024, and the gap (jobs organizations say they need but cannot fill) at <strong>4.8 million</strong>. Two things changed after that.</p>
     <p>First, the workforce stopped growing: +0.1% in 2024. Second, in its ${link("https://www.isc2.org/Insights/2025/12/2025-ISC2-Cybersecurity-Workforce-Study", "2025 study")} ISC2 stopped publishing a gap number altogether, saying the real shortage is <em>skills</em>, not headcount: 95% of teams report at least one skills gap, and 59% call it critical or significant.</p>`,
  );
  const f1 = figure(sec, {
    title: "Cybersecurity workforce vs. unfilled demand",
    sub: "Global estimates, millions of people. ISC2 published no gap estimate for 2025.",
    source: `${link("https://www.isc2.org/research", "ISC2 Cybersecurity Workforce Studies")} 2019 to 2024`,
    legend: [
      { label: "Workforce", color: C.s1, shape: "line" },
      { label: "Workforce gap", color: C.s2, shape: "line" },
    ],
    narrow: true,
    table: { columns: [{ key: "year", label: "Year" }, { key: "workforce", label: "Workforce (M)" }, { key: "gap", label: "Gap (M)" }], rows },
  });
  lines(f1, {
    data: rows,
    x: "year",
    series: [
      { key: "workforce", label: "Workforce", color: C.s1 },
      { key: "gap", label: "Gap", color: C.s2 },
    ],
    height: 260,
    dots: true,
    endLabels: true,
    yFormat: (x) => (x ? `${x}M` : "0"),
    valueFormat: (x) => `${x}M`,
    tickFormat: (x) => String(x),
    xFormat: (x) => String(x),
  });

  prose(
    sec,
    `<h3>What AI is doing to the jobs</h3>
     <p>The clearest signal comes from job ads. CyberSN, which tracks US security postings, counted <strong>${fmtInt(cyb.value)}</strong> ads in January to September 2026, <strong>26.4% fewer</strong> than a year earlier. The cut is uneven: postings for security analysts, security engineers and DevSecOps fell by more than 20%, while ads for AI security engineers and security data scientists ${link("https://www.esecurityplanet.com/cybersecurity/news-us-cybersecurity-job-postings-decline-ai-roles/", "more than tripled")}.</p>
     <p>That is the shape of the change: <strong>AI is absorbing the repetitive first tier of work</strong> (sorting alerts, first-pass triage, routine scanning) and companies are hiring fewer juniors to do it, while demand grows for people who can secure and supervise AI systems. CrowdStrike cut ${link("https://www.csoonline.com/article/3981182/crowdstrike-cuts-500-jobs-in-ai-pivot-but-flags-risks.html", "about 500 jobs (5%) in May 2025")} calling AI a "force multiplier", and security leaders describe plans to replace outsourced entry-level analysts with AI agents overseen by fewer senior staff.</p>
     <p>Layoffs, though, are not accelerating. In ISC2's 2025 survey, 24% of professionals reported layoffs on their team, down from 25%, and 72% said that cutting security staff significantly raises breach risk. Only 28% of organizations had fully integrated AI security tools.</p>`,
  );
  // Bug hunters: people vs AI in CVE credits
  const cr = d.credits.yearly as any[];
  const c23 = cr.find((r) => r.year === 2023);
  const c25 = cr.find((r) => r.year === 2025);
  const c26 = cr.find((r) => r.year === 2026);
  prose(
    sec,
    `<h3>The bug hunters are multiplying, not disappearing</h3>
     <p>One job AI was supposed to take first is finding vulnerabilities. The CVE credits say otherwise, at least so far. Since 2023, when most numbering authorities began recording who found each bug, the number of different people credited as finders has grown every year: ${fmtInt(c23.distinct_people)} in 2023, ${fmtInt(c25.distinct_people)} in 2025 and <strong>${fmtInt(c26.distinct_people)}</strong> in 2026 so far, ${fmtInt(c26.new_people)} of them credited for the first time.</p>
     <p>AI systems were credited on ${fmtInt(c26.ai_credited)} CVEs this year against ${fmtInt(c26.person_credited)} credited to people. Many of those people now use AI tools without saying so, and bug-bounty platforms make it easier than ever to start. The data fits a world where <strong>AI is lowering the bar to entry for human hunters</strong> as much as it competes with them.</p>`,
  );
  const gc = grid2(sec);
  const fc1 = figure(gc, {
    title: "Different people credited as vulnerability finders",
    source: "cvelistV5 credit entries (finder, reporter, tool types); names normalized, organizations and AI systems excluded; counts only",
    legend: [
      { label: "Credited before", color: C.s3 },
      { label: "First time", color: C.s1 },
    ],
    table: { columns: [{ key: "year", label: "Year" }, { key: "distinct_people", label: "People", fmt: fmtInt }, { key: "new_people", label: "First time", fmt: fmtInt }], rows: cr },
  });
  columns(fc1, {
    data: cr.map((r) => ({ ...r, returning: r.distinct_people - r.new_people })),
    x: "year",
    series: [
      { key: "returning", label: "Credited before", color: C.s3 },
      { key: "new_people", label: "First time", color: C.s1 },
    ],
    stacked: true,
    labelBars: () => true,
    partial: (r) => r.year === 2026,
    height: 250,
  });
  const fc2 = figure(gc, {
    title: "CVEs credited to people vs to AI systems",
    source: "cvelistV5 credits; AI attribution by the author's classifier (chapter 04)",
    legend: [
      { label: "Credited to a person", color: C.s3 },
      { label: "Attributed to AI", color: C.s1 },
    ],
    table: { columns: [{ key: "year", label: "Year" }, { key: "person_credited", label: "Person", fmt: fmtInt }, { key: "ai_credited", label: "AI", fmt: fmtInt }, { key: "credited_share", label: "CVEs with any credit", fmt: (x: number) => pct(x) }], rows: cr },
  });
  columns(fc2, {
    data: cr,
    x: "year",
    series: [
      { key: "person_credited", label: "Person", color: C.s3 },
      { key: "ai_credited", label: "AI", color: C.s1 },
    ],
    labelBars: () => true,
    partial: (r) => r.year === 2026,
    height: 250,
  });

  const lay = s.isc2_layoffs.points as any[];
  const bud = s.isc2_budget_cuts.points as any[];
  const hir = s.isc2_hiring_freeze.points as any[];
  const pr = [
    { label: "Hiring freezes", y24: hir[0].value, y25: hir[1].value },
    { label: "Budget cuts", y24: bud[0].value, y25: bud[1].value },
    { label: "Layoffs", y24: lay[0].value, y25: lay[1].value },
  ];
  const g = grid2(sec);
  const f2 = figure(g, {
    title: "Pressure on security teams, 2025",
    sub: "Share of professionals reporting each on their team. All three are within one point of the 2024 survey: stable, not accelerating.",
    source: `${link("https://www.isc2.org/Insights/2025/12/2025-ISC2-Cybersecurity-Workforce-Study", "ISC2 2025 Workforce Study")} (16,029 respondents)`,
    table: { columns: [{ key: "label", label: "Measure" }, { key: "y24", label: "2024 %" }, { key: "y25", label: "2025 %" }], rows: pr },
  });
  hbars(f2, {
    data: pr,
    label: "label",
    value: "y25",
    color: C.s2,
    max: 50,
    valueFormat: (x) => `${x}%`,
    labelWidth: 120,
    rowHeight: 34,
    tip: (r) => ({ head: r.label, rows: [{ label: "2025", value: `${r.y25}%`, color: C.s1 }, { label: "2024", value: `${r.y24}%`, color: C.other }] }),
  });
  callout(
    g,
    "verdict on jobs",
    `<b>Replaced: no. Reshaped: yes.</b> Spending is at a record, layoffs are flat, but entry-level hiring is shrinking and the skills in demand are moving toward AI. The people most exposed are those whose job was to look at alerts all day. The ones in demand can tell a real finding from an AI hallucination, and fix it.`,
  );
}
