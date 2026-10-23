import type { Data } from "../main";
import { columns, hbars, lines } from "../lib/charts";
import { figure } from "../lib/figure";
import { fmtInt, monthLabel, pct, shortMonth } from "../lib/format";
import { C, callout, chapter, link, prose, stats } from "../lib/page";

const NICE: Record<string, string> = { "CVE-2026-109618": "php2shell (PHP)" };
const CAT_COLORS = [C.s4, C.s2, C.s5, C.s3, C.s1, C.s6, C.s7, C.other];

function friendly(r: any): string {
  if (NICE[r.cve_id]) return NICE[r.cve_id];
  const v = (r.vendor || "").trim();
  const p = (r.product || "").trim();
  if (v === "Linux") {
    const sub = String(r.title || "").split(":")[0].trim();
    return sub && sub.length < 18 ? `Linux kernel (${sub})` : "Linux kernel";
  }
  if (!p || p.toLowerCase() === v.toLowerCase()) return v || r.cve_id;
  return p.length > 22 ? p.slice(0, 21) + "…" : p;
}

export function renderWeapon(main: HTMLElement, d: Data) {
  const w = d.weapon;
  const sec = chapter(main, {
    id: "weapon",
    num: "06",
    title: "From bug to weapon",
    kicker: "A vulnerability becomes dangerous when someone publishes working attack code. That now happens in hours, and mostly on GitHub.",
  });

  const venues = (w.venues as any[]).filter((r) => r.year >= 2012);
  const v19 = venues.find((r) => r.year === 2019);
  const v26 = venues.find((r) => r.year === 2026);
  prose(
    sec,
    `<p>Between a bug and an attack sits the exploit: code that actually triggers the flaw. For twenty years the reference shelf for public exploits was ${link("https://www.exploit-db.com/", "Exploit-DB")}, a curated archive that checks submissions by hand. It is drying up. Exploit code now appears on GitHub first, often within hours, in repositories named after the CVE. A community project, ${link("https://github.com/nomi-sec/PoC-in-GitHub", "PoC-in-GitHub")}, has been indexing them since 2019; we took its full archive (${fmtInt(w.totals.poc_repos)} repositories for ${fmtInt(w.totals.poc_cves)} CVEs).</p>
     <p>In 2019 Exploit-DB published ${fmtInt(v19.edb_all)} exploits and GitHub saw ${fmtInt(v19.gh_repos)} new proof-of-concept repositories. In 2026 so far: <strong>${fmtInt(v26.edb_all)}</strong> on Exploit-DB, <strong>${fmtInt(v26.gh_repos)}</strong> on GitHub.</p>`,
  );
  const f1 = figure(sec, {
    title: "Where public exploit code is published, per year",
    source: `${link("https://gitlab.com/exploit-database/exploitdb", "Exploit-DB files_exploits.csv")}; ${link("https://github.com/nomi-sec/PoC-in-GitHub", "nomi-sec/PoC-in-GitHub")} (non-fork repositories, by creation date)`,
    legend: [
      { label: "GitHub proof-of-concept repositories", color: C.s1, shape: "line" },
      { label: "Exploit-DB entries", color: C.s5, shape: "line" },
    ],
    narrow: true,
    table: {
      columns: [{ key: "year", label: "Year" }, { key: "gh_repos", label: "GitHub PoC repos", fmt: fmtInt }, { key: "gh_cves", label: "CVEs with a new GitHub PoC", fmt: fmtInt }, { key: "edb_all", label: "Exploit-DB entries", fmt: fmtInt }, { key: "edb_cve", label: "Exploit-DB with CVE", fmt: fmtInt }],
      rows: venues,
    },
  });
  lines(f1, {
    data: venues,
    x: "year",
    series: [
      { key: "gh_repos", label: "GitHub", color: C.s1 },
      { key: "edb_all", label: "Exploit-DB", color: C.s5 },
    ],
    height: 260,
    dots: true,
    endLabels: true,
    marginRight: 112,
    tickFormat: (x) => String(x),
    xFormat: (x) => (x === 2026 ? "2026 (to 22 Oct)" : String(x)),
  });

  // monthly PoC repos with model releases
  const pm = (w.poc_monthly as any[]).filter((r) => r.month >= "2022-01");
  const f2 = figure(sec, {
    title: "New exploit repositories on GitHub, per month",
    source: `${link("https://github.com/nomi-sec/PoC-in-GitHub", "nomi-sec/PoC-in-GitHub")}`,
    table: { columns: [{ key: "month", label: "Month", fmt: (x) => monthLabel(x) }, { key: "repos", label: "Repositories", fmt: fmtInt }, { key: "cves", label: "CVEs covered", fmt: fmtInt }], rows: pm },
  });
  columns(f2, {
    data: pm,
    x: "month",
    xLabel: shortMonth,
    xTickEvery: (m: string) => new Date(m).getUTCMonth() % 6 === 0,
    series: [{ key: "repos", label: "Repositories", color: C.s1 }],
    colorFn: () => C.s1,
    height: 260,
    tipHead: (r) => monthLabel(r.month),
    tipExtra: (r) => [{ label: "CVEs covered", value: fmtInt(r.cves) }],
    partial: (r) => r.month.startsWith("2026-10"),
    releases: true,
  });

  // speed
  const sp = (w.speed as any[]).filter((r) => r.year >= 2018);
  const s18 = sp.find((r) => r.year === 2018);
  const s26 = sp.find((r) => r.year === 2026);
  prose(
    sec,
    `<h3>Hours, not months</h3>
     <p>Only about 2% of CVEs ever get public exploit code on GitHub, a share that has hardly moved. What changed is the speed and the volume. In 2018, ${fmtInt(s18.within_7d)} CVEs had exploit code on GitHub within a week of disclosure. In 2026 so far, <strong>${fmtInt(s26.within_7d)}</strong>, and ${fmtInt(s26.within_1d)} of them within a day (often the code appears before the CVE record, because the researcher's write-up or the vendor's patch lands first). When exploit code exists at all, the median wait is now ${s26.median_lag_days < 3 ? "under three days" : `${Math.round(s26.median_lag_days)} days`}.</p>`,
  );
  const f3 = figure(sec, {
    title: "CVEs with public exploit code on GitHub within 7 days of disclosure",
    source: "PoC-in-GitHub first repository date vs CVE publication date (cvelistV5)",
    narrow: true,
    table: {
      columns: [
        { key: "year", label: "CVE year" },
        { key: "within_1d", label: "Within 1 day", fmt: fmtInt },
        { key: "within_7d", label: "Within 7 days", fmt: fmtInt },
        { key: "within_30d", label: "Within 30 days", fmt: fmtInt },
        { key: "with_poc", label: "Any PoC", fmt: fmtInt },
        { key: "all_cves", label: "All CVEs", fmt: fmtInt },
      ],
      rows: sp,
    },
  });
  columns(f3, {
    data: sp,
    x: "year",
    series: [{ key: "within_7d", label: "Within 7 days", color: C.s2 }],
    colorFn: () => C.s2,
    labelBars: () => true,
    partial: (r) => r.year === 2026,
    height: 240,
    tipExtra: (r) => [
      { label: "within 1 day", value: fmtInt(r.within_1d) },
      { label: "share of all CVEs", value: pct(r.share_7d, 1) },
    ],
  });

  // top PoC'd CVEs
  const seen = new Map<string, number>();
  const top = (w.top_cur as any[]).map((r) => {
    let name = friendly(r);
    const k = (seen.get(name) ?? 0) + 1;
    seen.set(name, k);
    if (k > 1) name = `${name} (${r.cve_id.slice(-5)})`;
    return { ...r, name };
  });
  const php = top[0];
  prose(
    sec,
    `<p>Some bugs draw a crowd. The PHP flaw that made headlines this week, <strong>php2shell</strong> (${php.cve_id}), already has <strong>${fmtInt(php.repos)}</strong> exploit repositories, the most of any 2026 CVE. Several of the top twelve are AI tools: an MCP inspector, the marimo notebook and Langflow, an AI workflow builder. Treat these repositories with care: a ${link("https://arxiv.org/abs/2210.08374", "Leiden University study")} found that about 1 in 10 GitHub "exploits" it analyzed was itself malicious, a trap for the defenders and researchers who download them.</p>`,
  );
  const f4 = figure(sec, {
    title: "2026 CVEs with the most exploit repositories on GitHub",
    source: "PoC-in-GitHub (non-fork repositories), cvelistV5",
    narrow: true,
    table: { columns: [{ key: "cve_id", label: "CVE" }, { key: "name", label: "Product" }, { key: "repos", label: "Repositories", fmt: fmtInt }, { key: "title", label: "Title" }], rows: top },
  });
  hbars(f4, {
    data: top,
    label: "name",
    value: "repos",
    color: (r) => (r.cve_id === php.cve_id ? C.s2 : C.s1),
    labelWidth: 180,
    tip: (r) => ({
      head: `${r.cve_id}, ${r.name}`,
      rows: [
        { label: "repositories", value: fmtInt(r.repos), color: C.s1 },
        { label: "first one", value: r.lag_days < 0 ? `${Math.round(-r.lag_days)} days before the CVE` : `${r.lag_days < 1 ? "<1" : Math.round(r.lag_days)} days after the CVE` },
        ...(r.title ? [{ label: String(r.title).slice(0, 60), value: "" }] : []),
      ],
    }),
  });

  const pk = w.poc_vs_kev;
  const ai = (w.ai_poc_cur as any[]).find((r) => r.ai);
  const rest = (w.ai_poc_cur as any[]).find((r) => !r.ai);
  stats(sec, [
    [pct(pk.poc_before_kev / pk.kev_recent), "of exploited 2024 to 2026 CVEs had exploit code on GitHub before CISA confirmed the attacks"],
    [pct(pk.no_poc / pk.kev_recent), "were exploited with no public exploit code at all: private tools, zero-days"],
    [`${(ai.with_poc / ai.n / (rest.with_poc / rest.n)).toFixed(1)}x`, `more likely: public exploit code for AI-credited 2026 CVEs (${pct(ai.with_poc / ai.n, 1)}) vs others (${pct(rest.with_poc / rest.n, 1)})`],
  ]);

  // KEV categories
  // Cameras/IoT/OT is about one CVE a year: fold it into Other to stay within the 8-slot palette
  const order: string[] = (w.kev_category_order as string[]).filter((c) => !c.startsWith("Cameras"));
  const kc = (w.kev_categories as any[]).filter((r) => r.year >= 2019).map((r) => ({ ...r, Other: r.Other + (r["Cameras, IoT and OT"] ?? 0) }));
  const k26 = kc.find((r) => r.year === 2026);
  const tot26 = order.reduce((s, k) => s + k26[k], 0);
  const dev = (y: number) => kc.find((r) => r.year === y)?.[order[0]] ?? 0;
  prose(
    sec,
    `<h3>What gets exploited</h3>
     <p>Sorting CISA's exploited list by product type shows where attackers aim. The steady leader is the <strong>network edge</strong>: VPNs, firewalls, gateways and remote-access boxes that sit on the internet by design and often run old, unmonitored code. They are ${pct(k26[order[1]] / tot26)} of exploited 2026 CVEs. The newcomer is <strong>developer and AI tooling</strong>: ${dev(2023)} exploited CVEs from 2023, ${dev(2024)} from 2024, ${dev(2025)} from 2025 and <strong>${dev(2026)}</strong> from 2026 so far (LiteLLM, Langflow, MLflow, marimo, build tools and package managers).</p>`,
  );
  const f5 = figure(sec, {
    title: "Exploited CVEs by product type, by CVE year",
    source: `${link("https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "CISA KEV")}; product taxonomy by the author`,
    legend: order.map((o, i) => ({ label: o, color: CAT_COLORS[i] })),
    table: { columns: [{ key: "year", label: "CVE year" }, ...order.map((o) => ({ key: o, label: o, fmt: fmtInt }))], rows: kc },
  });
  columns(f5, {
    data: kc,
    x: "year",
    series: order.map((o, i) => ({ key: o, label: o, color: CAT_COLORS[i] })),
    stacked: true,
    height: 300,
    partial: (r) => r.year === 2026,
  });
  const cs = (w.kev_category_speed as any[]).filter((r) => r.category !== "Other" && r.n >= 20).sort((a, b) => a.median_days - b.median_days).map((r) => ({ ...r, md: Math.max(0, r.median_days) }));
  const f6 = figure(sec, {
    title: "Median days from CVE to confirmed exploitation",
    narrow: true,
    source: "CISA KEV date added minus CVE publication date, CVEs from 2023 on",
    table: { columns: [{ key: "category", label: "Product type" }, { key: "n", label: "Exploited CVEs", fmt: fmtInt }, { key: "median_days", label: "Median days", fmt: (x: number) => x.toFixed(1) }, { key: "within_7", label: "Within 7 days", fmt: (x: number) => pct(x) }], rows: cs },
  });
  hbars(f6, {
    data: cs,
    label: "category",
    value: "md",
    color: (r) => CAT_COLORS[order.indexOf(r.category)] ?? C.other,
    labelWidth: 240,
    valueFormat: (x) => (x < 1 ? "<1 day" : `${Math.round(x)} days`),
    tip: (r) => ({
      head: r.category,
      rows: [
        { label: "median days", value: r.median_days < 1 ? "<1" : r.median_days.toFixed(1), color: CAT_COLORS[order.indexOf(r.category)] },
        { label: "exploited within 7 days", value: pct(r.within_7) },
        { label: "exploited CVEs", value: fmtInt(r.n) },
      ],
    }),
  });
  callout(
    sec,
    "reading it",
    `Browser and operating-system bugs show near-zero medians because they are usually <b>zero-days</b>: attacked before the fix exists, so the CVE and the exploitation report arrive together. Edge devices are typically hit <b>within days of a patch</b>, the window when attackers compare old and new code. Business software is slower but bigger: one bug in a file-transfer server can expose thousands of companies at once.`,
  );
}
