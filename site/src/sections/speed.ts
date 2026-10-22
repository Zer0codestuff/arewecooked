import type { Data } from "../main";
import { columns, hbars } from "../lib/charts";
import { figure } from "../lib/figure";
import { fmtInt, pct } from "../lib/format";
import { C, callout, chapter, grid2, link, prose } from "../lib/page";

const BUCKETS = ["Before or on disclosure day", "1 to 7 days", "8 to 30 days", "31 to 90 days", "91 to 365 days", "Over a year"];
// hottest = fastest; validated ordinal ramp, extended with muted greys for the slow tail
const BUCKET_COLORS = ["#f59a6e", "#e0662f", "#b54a20", "#8a3d1d", "#4f5652", "#353b38"];

export function renderSpeed(main: HTMLElement, d: Data) {
  const v = d.vulns;
  const sec = chapter(main, {
    id: "speed",
    num: "04",
    title: "Faster than the patch",
    kicker: "The window between a flaw going public and attacks starting has collapsed to days.",
  });
  const tte = v.tte as any[];
  const t22 = tte.find((r) => r.pub_year === 2022);
  const t26 = tte.find((r) => r.pub_year === 2026);
  prose(
    sec,
    `<p>For every vulnerability on CISA's exploited list we measured the gap between the day the CVE was published and the day CISA confirmed attacks. For CVEs published in 2022 the median gap was <strong>${t22.median_days} days</strong>. For 2026 CVEs it is <strong>${t26.median_days} days</strong>, and <strong>${pct(t26.share_month)}</strong> of them were confirmed exploited within a month (against ${pct(t22.share_month)} for 2022).</p>
     <p>About a quarter are exploited <strong>before or on the day</strong> the CVE appears: these are zero-days, used by attackers before the vendor could warn anyone.</p>`,
  );
  const rows = (v.tte_buckets as any[]).map((r) => ({ ...r, year: r.pub_year }));
  const f1 = figure(sec, {
    title: "How fast exploited CVEs get exploited",
    sub: "Days from CVE publication to CISA KEV listing, for exploited CVEs, by CVE publication year. 2026 is partial and skews fast: slow cases have not had time to appear.",
    source: "CISA KEV, CVE Program cvelistV5 (author's calculation)",
    legend: BUCKETS.map((b, i) => ({ label: b, color: BUCKET_COLORS[i] })),
    table: {
      columns: [{ key: "year", label: "CVE year" }, ...BUCKETS.map((b) => ({ key: b, label: b, fmt: fmtInt }))],
      rows,
    },
  });
  columns(f1, {
    data: rows,
    x: "year",
    series: [...BUCKETS].reverse().map((b) => ({ key: b, label: b, color: BUCKET_COLORS[BUCKETS.indexOf(b)] })),
    stacked: true,
    percent: true,
    height: 300,
    partial: (r) => r.year === 2026,
  });

  callout(
    sec,
    "caveat",
    `The 2026 bar is biased toward speed: a CVE published in September cannot yet appear as "exploited after 90 days". The 2022 to 2025 bars are fair comparisons, and they already show the shift. ${link("https://www.vulncheck.com/blog/state-of-exploitation-1h-2026", "VulnCheck")} independently measured the median time from CVE to exploitation evidence falling from 120 days in 2025 to 80 days in early 2026, and Google observed a BeyondTrust flaw found by an AI agent being exploited by six separate groups within a week of disclosure.`,
  );

  const zd = d.threats.zerodays.yearly as any[];
  const dbir = d.context.series.dbir_exploit_share.points as any[];
  const dbirCred = d.context.series.dbir_cred_share.points as any[];
  prose(
    sec,
    `<h3>Exploits beat passwords</h3>
     <p>For the first time in its 19 editions, Verizon's ${link("https://www.techrepublic.com/article/news-verizon-dbir-vulnerability-exploitation-2026/", "2026 Data Breach Investigations Report")} found that exploiting a software flaw is the most common way attackers break in: <strong>${dbir.find((p) => p.year === 2026).value}%</strong> of breaches, up from ${dbir.find((p) => p.year === 2024).value}% two editions earlier, while stolen credentials fell to ${dbirCred.find((p) => p.year === 2026).value}%.</p>`,
  );
  const g = grid2(sec);
  const dbRows = [2024, 2025, 2026].map((y) => ({ year: `DBIR ${y}`, exploit: dbir.find((p) => p.year === y)?.value, cred: dbirCred.find((p) => p.year === y)?.value }));
  const f2 = figure(g, {
    title: "How attackers got in: exploited flaw vs stolen login",
    sub: "Share of breaches by initial access vector, by report edition.",
    source: `${link("https://www.verizon.com/business/resources/reports/dbir/", "Verizon DBIR")} 2024 to 2026`,
    legend: [
      { label: "Exploited vulnerability", color: C.s2 },
      { label: "Credential abuse", color: C.s3 },
    ],
    table: { columns: [{ key: "year", label: "Edition" }, { key: "exploit", label: "Exploit %" }, { key: "cred", label: "Credentials %" }], rows: dbRows },
  });
  columns(f2, {
    data: dbRows,
    x: "year",
    series: [
      { key: "exploit", label: "Exploited vulnerability", color: C.s2 },
      { key: "cred", label: "Credential abuse", color: C.s3 },
    ],
    height: 240,
    yFormat: (x) => `${x}%`,
    valueFormat: (x) => `${x}%`,
    labelBars: () => true,
  });

  const f3 = figure(g, {
    title: "Zero-days caught in the wild per year",
    sub: "Flaws exploited before a patch existed, as tracked by Google Project Zero. 2026 to 22 Oct.",
    source: `${link("https://googleprojectzero.blogspot.com/p/0day.html", "Google Project Zero, 0day In the Wild")}`,
    table: { columns: [{ key: "year", label: "Year" }, { key: "zero_days", label: "Zero-days", fmt: fmtInt }], rows: zd },
  });
  columns(f3, {
    data: zd.filter((r) => r.year >= 2015),
    x: "year",
    series: [{ key: "zero_days", label: "Zero-days", color: C.s2 }],
    colorFn: () => C.s2,
    height: 240,
    labelBars: (r) => r.year === 2021 || r.year >= 2025,
    partial: (r) => r.year === 2026,
    xTickEvery: (y: number) => y % 2 === 1 || y === 2026,
  });

  const kv = (v.kev_vendors_recent as any[]).slice(0, 12);
  prose(
    sec,
    `<p>What gets hit? Since January 2025 the exploited list is dominated by the same names: Microsoft Windows and Office, and then a long line of <strong>network edge devices</strong> (VPNs, firewalls, remote-access gateways from Cisco, Fortinet, Ivanti, Citrix, SonicWall). These boxes sit on the internet by design, often run old code, and give an attacker the keys to the whole network. Google puts edge and security appliances at 14% of all exploited flaws in 2026.</p>`,
  );
  const f4 = figure(sec, {
    title: "Most-exploited vendors since January 2025",
    sub: "New entries in CISA's Known Exploited Vulnerabilities catalog, 1 Jan 2025 to 21 Oct 2026.",
    source: "CISA KEV",
    narrow: true,
    table: { columns: [{ key: "vendor", label: "Vendor" }, { key: "kevs", label: "KEV entries" }], rows: kv },
  });
  hbars(f4, { data: kv, label: "vendor", value: "kevs", color: C.s2, labelWidth: 120 });
}
