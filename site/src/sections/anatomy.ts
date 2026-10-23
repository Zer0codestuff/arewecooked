import type { Data } from "../main";
import { columns, hbars } from "../lib/charts";
import { multiples } from "../lib/charts2";
import { figure } from "../lib/figure";
import { fmtInt, pct } from "../lib/format";
import { C, callout, chapter, link, prose } from "../lib/page";

const FAM_COLORS = [C.s1, C.s2, C.s3, C.s4, C.s5, C.s6, C.s7, C.other];

export function renderAnatomy(main: HTMLElement, d: Data) {
  const a = d.anatomy;
  const fams: string[] = a.families;
  const sec = chapter(main, {
    id: "anatomy",
    num: "03",
    title: "Anatomy of a flaw",
    kicker: "What kinds of bugs are these, which ones are going away, and does AI find different ones?",
  });

  const rows = (a.family_yearly as any[]).filter((r) => r.year >= 2016);
  const share = (r: any, f: string) => r[f] / fams.reduce((s, k) => s + r[k], 0);
  const r16 = rows.find((r) => r.year === 2016);
  const r25 = rows.find((r) => r.year === 2025);
  const r26 = rows.find((r) => r.year === 2026);
  const cov26 = (a.coverage as any[]).find((r) => r.year === 2026);
  prose(
    sec,
    `<p>Every CVE can be tagged with a weakness type from MITRE's Common Weakness Enumeration (CWE), a catalog of about 900 kinds of programming mistakes: "use after free", "SQL injection", "missing authorization" and so on. We grouped them into seven families. Combining the tag from the CVE record, from CISA and from the NVD gives a family for <strong>${pct(cov26.coverage)}</strong> of 2026 CVEs.</p>
     <p>Three shifts stand out. <strong>Memory-safety bugs</strong>, the classic C and C++ mistakes behind most serious exploits, fell from ${pct(share(r16, fams[0]))} of classified CVEs in 2016 to ${pct(share(r25, fams[0]))} in 2025. <strong>Web bugs</strong> rose with the WordPress plugin flood, then fell back in 2026 as vendors filed so much else. And <strong>access-control mistakes</strong> (missing permission checks, broken logins, hardcoded passwords) are the biggest family in 2026 at ${pct(share(r26, fams[4]))}: the bugs that let an attacker simply walk in.</p>`,
  );
  const f1 = figure(sec, {
    title: "What kind of flaw: weakness families by year",
    source: `CWE tags from cvelistV5 (CNA), CISA ADP and ${link("https://github.com/fkie-cad/nvd-json-data-feeds", "NVD")}; family grouping by the author (${link("https://github.com/Zer0codestuff/arewecooked/blob/main/pipeline/steps/anatomy.py", "mapping")})`,
    legend: fams.map((f, i) => ({ label: f, color: FAM_COLORS[i] })),
    table: {
      columns: [{ key: "year", label: "Year" }, ...fams.map((f) => ({ key: f, label: f, fmt: fmtInt }))],
      rows,
    },
  });
  columns(f1, {
    data: rows,
    x: "year",
    series: fams.map((f, i) => ({ key: f, label: f, color: FAM_COLORS[i] })),
    stacked: true,
    percent: true,
    height: 320,
    partial: (r) => r.year === 2026,
  });

  // Memory safety in big C/C++ codebases
  const ms = a.memsafety as any[];
  const msn = a.memsafety_n as any[];
  const at = (base: string, y: number) => ms.find((r) => r.year === y)?.[base];
  prose(
    sec,
    `<h3>The memory-safety experiment</h3>
     <p>Memory bugs are not fading everywhere. They are fading where code is written in memory-safe languages. Google moved new Android code to Rust and Kotlin from 2019 and ${link("https://security.googleblog.com/2024/09/eliminating-memory-safety-vulnerabilities-Android.html", "reported")} memory-safety bugs falling from 76% of Android vulnerabilities to 24%. The CVE records show the same thing independently: <strong>${pct(at("Android", 2019))} in 2019, ${pct(at("Android", 2026))} in 2026</strong>.</p>
     <p>Elsewhere 2026 runs the other way. Memory bugs are ${pct(at("Microsoft", 2026))} of Microsoft's CVEs (${pct(at("Microsoft", 2022))} in 2022) and ${pct(at("Mozilla", 2026))} of Mozilla's. These are the old C++ codebases that AI models are now combing through: Mozilla ${link("https://hacks.mozilla.org/2026/05/behind-the-scenes-hardening-firefox/", "fixed 271 bugs")} found by Claude Mythos Preview in a single Firefox release. When the hunters get better, the oldest kind of bug comes back into view.</p>`,
  );
  const panels = [
    { key: "Android", label: "Android" },
    { key: "Google Chrome", label: "Google Chrome" },
    { key: "Microsoft", label: "Microsoft" },
    { key: "Mozilla", label: "Mozilla" },
    { key: "Apple", label: "Apple" },
    { key: "Linux kernel", label: "Linux kernel" },
  ];
  const f2 = figure(sec, {
    title: "Share of each vendor's CVEs that are memory-safety bugs",
    source: "cvelistV5 by assigner (CNA), CWE tags as above",
    table: {
      columns: [{ key: "year", label: "Year" }, ...panels.map((p) => ({ key: p.key, label: p.label, fmt: (x: number) => (x == null ? "" : pct(x)) }))],
      rows: ms,
    },
  });
  multiples(f2, {
    data: ms,
    x: "year",
    panels,
    color: C.s1,
    yMax: 1,
    yFormat: (v) => `${Math.round(v * 100)}%`,
    valueFormat: (v) => pct(v),
    tipExtra: (key, r) => {
      const n = msn.find((x) => x.year === r.year)?.[key];
      return n ? [{ label: "classified CVEs", value: fmtInt(n) }] : [];
    },
  });

  // AI vs everyone else
  const av = (a.ai_vs_rest as any[]).map((r) => ({ ...r, ai: r["AI-credited"], rest: r["Everything else"] }));
  const ms_ai = av.find((r) => r.family === fams[0]);
  const inj = av.find((r) => r.family === fams[1]);
  prose(
    sec,
    `<h3>Do AI hunters find different bugs?</h3>
     <p>Yes, measurably. Among the ${fmtInt(a.ai_vs_rest_n["AI-credited"])} AI-credited CVEs of 2025 and 2026, <strong>${pct(ms_ai.ai)}</strong> are memory-safety bugs, against ${pct(ms_ai.rest)} for everything else. They find fewer injection bugs (${pct(inj.ai)} vs ${pct(inj.rest)}), the easy web flaws that scanners have caught for years. AI models are being pointed at the hard, old C and C++ code, and that is where they find the most.</p>`,
  );
  const f3 = figure(sec, {
    title: "Weakness mix: AI-credited CVEs vs all others, 2025 to 2026",
    source: "Author's AI-attribution classifier (chapter 04) and CWE families above",
    narrow: true,
    legend: [
      { label: "AI-credited", color: C.s1 },
      { label: "Everything else", color: C.other },
    ],
    table: {
      columns: [{ key: "family", label: "Family" }, { key: "ai", label: "AI-credited", fmt: (x: number) => pct(x) }, { key: "rest", label: "Everything else", fmt: (x: number) => pct(x) }],
      rows: av,
    },
  });
  hbars(f3, {
    data: av,
    label: "family",
    value: "ai",
    value2: "rest",
    color: C.s1,
    color2: C.other,
    labelWidth: 200,
    valueFormat: (x) => pct(x),
    tip: (r) => ({
      head: r.family,
      rows: [
        { label: "AI-credited", value: pct(r.ai), color: C.s1 },
        { label: "Everything else", value: pct(r.rest), color: C.other },
      ],
    }),
  });
  callout(
    sec,
    "why it matters",
    `Memory bugs are the raw material of the most valuable exploits: browser and phone zero-days, kernel privilege escalation. A tool that finds them cheaply helps whoever runs it first. That is why vendors are racing to scan their own C++ before attackers do, and why the long-term fix is still the boring one: <b>write new code in memory-safe languages</b>, as Android did.`,
  );
}
