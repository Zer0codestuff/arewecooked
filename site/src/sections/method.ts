import type { Data } from "../main";
import { el } from "../lib/figure";
import { chapter, link, prose } from "../lib/page";

const REPO = "https://github.com/Zer0codestuff/arewecooked";

const SOURCES: [string, string, string][] = [
  ["CVE List (cvelistV5)", "https://github.com/CVEProject/cvelistV5", "All 412,863 CVE records (JSON 5), release of 22 Oct 2026. Publication dates, assigners, severity, credits."],
  ["CISA KEV", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "Vulnerabilities with confirmed exploitation, 1,754 entries as of 21 Oct 2026."],
  ["CISA Vulnrichment", "https://github.com/cisagov/vulnrichment", "CVSS and SSVC scores CISA adds to CVE records."],
  ["FIRST EPSS", "https://www.first.org/epss/", "Daily exploitation probability for every CVE."],
  ["Berkeley Agentic Vulnerability Coverage Map", "https://vuln.cs.berkeley.edu/", "List of AI vulnerability finders and their statistics."],
  ["Anthropic-Credited-CVEs", "https://github.com/patrickmgarrity/Anthropic-Credited-CVEs", "Community tracker of CVEs crediting Anthropic researchers."],
  ["Anthropic CVD dashboard", "https://red.anthropic.com/2026/cvd/", "Findings, disclosures and fixes from Claude models in open source."],
  ["Google Project Zero 0day In the Wild", "https://googleprojectzero.blogspot.com/p/0day.html", "Zero-days exploited in the wild since 2014."],
  ["MSRC CVRF API", "https://api.msrc.microsoft.com/cvrf/v3.0/updates", "Every Microsoft security update, with exploitation flags."],
  ["Exploit-DB, Metasploit, Nuclei", "https://gitlab.com/exploit-database/exploitdb", "Public exploits and detection templates (in the clean data files)."],
  ["ransomware.live", "https://www.ransomware.live/", "Victims posted on ransomware leak sites, 2020 to 2026."],
  ["OSV.dev", "https://osv.dev/", "Malicious packages and advisories for npm, PyPI and six other registries."],
  ["Have I Been Pwned", "https://haveibeenpwned.com/api/v3/breaches", "Catalog of 1,000+ verified data breaches (in the clean data files)."],
  ["Yahoo Finance", "https://finance.yahoo.com/quote/CIBR/", "Monthly prices for security ETFs, vendors and benchmarks."],
  ["Reports", "#", "FBI IC3, Gartner, Chainalysis, IBM, ISC2, Verizon DBIR, Crunchbase, GitGuardian, Google GTIG, VulnCheck, HackerOne, CyberSN: transcribed in data/manual/series.csv with a source link on every row."],
];

const CLEAN = [
  "cve_yearly.csv",
  "cve_monthly_by_source.csv",
  "cve_severity_yearly.csv",
  "ai_attributed_cves.csv",
  "kev_enriched.csv",
  "ransomware_victims_monthly.csv",
  "p0_itw_zero_days.csv",
  "public_exploits_yearly.csv",
  "microsoft_patch_tuesday_monthly.csv",
  "osv_malicious_packages_monthly.csv",
  "hibp_breaches_yearly.csv",
  "cyber_stocks_indexed_2020.csv",
  "anthropic_cvd_ledger_weekly.csv",
];

export function renderMethod(main: HTMLElement, _d: Data) {
  const sec = chapter(main, {
    id: "method",
    num: "10",
    title: "Data and method",
    kicker: "Everything here is reproducible from public data with one command.",
  });
  prose(
    sec,
    `<h3>How it was built</h3>
     <p>A Python pipeline downloads about 2 GB of public data, flattens every CVE record into one table, joins it with exploitation, scoring and credit data, and writes small JSON files that this page reads. Report figures that only exist as PDFs or press releases were transcribed by hand, each with a link. Code: ${link(REPO, "github.com/Zer0codestuff/arewecooked")}.</p>
     <h3>Caveats worth knowing</h3>
     <ul>
       <li><strong>Counting is policy.</strong> How many CVEs exist depends on who files them and how. The Linux kernel and WordPress security firms file many small bugs; some vendors bundle several flaws into one ID. We show who files what so you can judge.</li>
       <li><strong>"Found by AI" is a lower bound.</strong> It relies on public credits. Many vendors credit nobody, and AI-assisted human researchers rarely say so.</li>
       <li><strong>2026 is partial</strong> (to 22 October). Where we compare with full years we say so, or scale to a full-year pace.</li>
       <li><strong>Leak sites undercount ransomware</strong>: victims who pay quickly are never posted.</li>
       <li><strong>Exploitation is measured by CISA KEV</strong>, which focuses on vulnerabilities relevant to US government networks and requires solid evidence. It misses many attacks.</li>
       <li>Some 2026 report figures (IBM 2026, Gartner 3Q26, Verizon 2026) come from press coverage of the report rather than the report itself; they are labeled as such in the data file.</li>
     </ul>`,
  );
  const p = prose(sec, `<h3>Sources</h3>`);
  const list = el("div", "sources");
  for (const [name, url, desc] of SOURCES) {
    const para = el("p");
    const b = el("b");
    if (url !== "#") {
      const a = el("a");
      a.href = url;
      a.target = "_blank";
      a.rel = "noopener";
      a.textContent = name;
      b.appendChild(a);
    } else b.textContent = name;
    para.appendChild(b);
    para.appendChild(document.createTextNode(` ${desc}`));
    list.appendChild(para);
  }
  p.appendChild(list);
  const dl = prose(sec, `<h3>Download the clean data</h3><p>Tidy CSV files produced by the pipeline (free to reuse, please cite the original sources):</p>`);
  const ul = el("ul");
  for (const f of CLEAN) {
    const li = el("li");
    const a = el("a");
    a.href = `${REPO}/blob/main/data/clean/${f}`;
    a.target = "_blank";
    a.rel = "noopener";
    a.textContent = f;
    li.appendChild(a);
    ul.appendChild(li);
  }
  dl.appendChild(ul);
}
