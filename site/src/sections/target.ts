import type { Data } from "../main";
import { columns, hbars, lines } from "../lib/charts";
import { figure } from "../lib/figure";
import { compact, fmtInt, monthLabel, times } from "../lib/format";
import { C, callout, chapter, grid2, link, prose } from "../lib/page";

const PRODUCT_NAMES: Record<string, string> = {
  n8n: "n8n (workflows)",
  "open-webui": "Open WebUI",
  "langflow oss": "Langflow",
  langflow: "Langflow",
  flowise: "Flowise",
  vllm: "vLLM",
  sglang: "SGLang",
  maxkb: "MaxKB",
  "mcp-atlassian": "MCP Atlassian server",
  "triton inference server": "NVIDIA Triton",
  fastgpt: "FastGPT",
  litellm: "LiteLLM",
  praisonai: "PraisonAI",
  autogpt: "AutoGPT",
};

export function renderTarget(main: HTMLElement, d: Data) {
  const v = d.vulns;
  const t = v.totals;
  const sec = chapter(main, {
    id: "target",
    num: "05",
    title: "AI is also the target",
    kicker: "The tools companies rushed to adopt are now one of the fastest-growing sources of vulnerabilities.",
  });

  prose(
    sec,
    `<p>AI does not only find bugs, it ships them. Agent frameworks, chat front-ends, model servers and the new "MCP" connectors that let AI agents use other software were mostly written in the last two years, fast, by small teams. They also tend to hold the most valuable secrets in a company: API keys, database passwords, customer data.</p>
     <p>We tagged every CVE whose product or description points to AI software (LLM apps, agent frameworks, inference servers, ML platforms, MCP servers). In 2026 there are <strong>${fmtInt(t.ai_software_cur)}</strong> of them so far, <strong>${times(t.ai_software_cur, t.ai_software_prev)}</strong> the count for all of 2025. Google, with a different method, counts ${link("https://cloud.google.com/blog/topics/threat-intelligence/vulnerability-discovery-and-exploitation-trends-in-the-ai-era", "more than 1,500 AI-stack CVEs")} in the first eight months of 2026, half of them in agent orchestration frameworks.</p>`,
  );
  const g = grid2(sec);
  const ay = v.ai_software_yearly as any[];
  const f1 = figure(g, {
    title: "CVEs in AI software, per year",
    sub: "Keyword match on product, vendor and description. 2026 to 22 Oct.",
    source: "CVE Program cvelistV5 (author's classifier)",
    table: { columns: [{ key: "year", label: "Year" }, { key: "cves", label: "CVEs", fmt: fmtInt }], rows: ay },
  });
  columns(f1, {
    data: ay.filter((r) => r.year >= 2019),
    x: "year",
    series: [{ key: "cves", label: "CVEs in AI software", color: C.s4 }],
    colorFn: (r) => (r.year === 2026 ? C.s4 : C.dim),
    labelBars: (r) => r.year >= 2024,
    partial: (r) => r.year === 2026,
    height: 260,
  });
  const merged = new Map<string, number>();
  for (const r of v.ai_software_products as any[]) {
    if (r.product === "n/a") continue;
    const name = PRODUCT_NAMES[r.product] ?? r.product;
    merged.set(name, (merged.get(name) ?? 0) + r.cves);
  }
  const prods = [...merged.entries()].map(([name, cves]) => ({ name, cves })).sort((a, b) => b.cves - a.cves).slice(0, 10);
  const f2 = figure(g, {
    title: "Most-affected AI products in 2026",
    sub: "CVEs published in 2026, by product.",
    source: "CVE Program cvelistV5",
    table: { columns: [{ key: "name", label: "Product" }, { key: "cves", label: "CVEs" }], rows: prods },
  });
  hbars(f2, { data: prods, label: "name", value: "cves", color: C.s4, labelWidth: 150, rowHeight: 24 });

  // Secrets
  const sl = d.context.series.secrets_leaked.points as any[];
  prose(
    sec,
    `<h3>The keys to the kingdom are lying around</h3>
     <p>On 21 October 2026, the developer platform Railway ${link("https://thehackernews.com/2026/10/railway-says-intruder-may-have-accessed.html", "disclosed")} that an intruder may have decrypted the environment variables its customers store: API keys, database passwords, tokens. It paused every deployment and told all customers to rotate everything. Railway linked the attack to a wider campaign against hosting platforms, aimed at stealing the AI provider keys that customers keep there.</p>
     <p>Leaked secrets are a fast-growing problem on their own. GitGuardian scans every public commit on GitHub; the number of hardcoded secrets it finds has grown every year, to <strong>${sl.find((p) => p.year === 2025).value} million</strong> in 2025. Of those, 1.28 million were keys for AI services, up 81% in one year.</p>`,
  );
  const f3 = figure(sec, {
    title: "Secrets leaked in public GitHub commits, per year",
    sub: "API keys, passwords and tokens found by GitGuardian's scanners, in millions.",
    source: `${link("https://www.gitguardian.com/state-of-secrets-sprawl-report-2025", "GitGuardian, State of Secrets Sprawl")} reports 2021 to 2026`,
    narrow: true,
    table: { columns: [{ key: "year", label: "Year" }, { key: "value", label: "Million secrets" }], rows: sl },
  });
  columns(f3, {
    data: sl,
    x: "year",
    series: [{ key: "value", label: "Secrets (millions)", color: C.s5 }],
    colorFn: () => C.s5,
    labelBars: () => true,
    valueFormat: (x) => `${x}M`,
    yFormat: (x) => (x ? `${x}M` : "0"),
    height: 240,
  });

  // Supply chain
  const mm = d.supplychain.malicious_monthly as any[];
  const mm2 = mm.filter((r) => r.month >= "2023-01").map((r) => ({ month: r.month, npm: Math.max(1, r.npm), rest: Math.max(1, r.PyPI + r.Other) }));
  prose(
    sec,
    `<h3>Poisoned packages</h3>
     <p>Modern software is assembled from thousands of open-source packages, which makes the package registries a favorite target. The Open Source Vulnerabilities database lists <strong>${fmtInt(d.supplychain.malicious_total)}</strong> malicious packages in npm, PyPI and six other registries. The log-scale chart below shows a steady background of a few hundred to a few thousand per month, plus huge spikes: about 34,000 junk packages from a single npm account flagged on one day in August 2025, the self-spreading <em>Shai-Hulud</em> worm that stole developer secrets in September 2025, and the <em>IndonesianFoods</em> spam campaign that pushed more than 100,000 packages in November 2025. Spam packages are not all dangerous, but they bury the real threats and overload the tools that scan for them.</p>`,
  );
  const f4 = figure(sec, {
    title: "Malicious packages reported per month",
    sub: "Log scale: each gridline is ten times the one below. January 2023 to October 2026.",
    source: `${link("https://osv.dev/", "OSV.dev")} (MAL- advisories, incl. ${link("https://github.com/ossf/malicious-packages", "OpenSSF malicious-packages")})`,
    legend: [
      { label: "npm (JavaScript)", color: C.s5, shape: "line" },
      { label: "PyPI and six other registries", color: C.s3, shape: "line" },
    ],
    table: { columns: [{ key: "month", label: "Month", fmt: (x) => monthLabel(x) }, { key: "npm", label: "npm", fmt: fmtInt }, { key: "PyPI", label: "PyPI", fmt: fmtInt }, { key: "Other", label: "Other", fmt: fmtInt }], rows: mm },
  });
  lines(f4, {
    data: mm2,
    x: "month",
    time: true,
    log: true,
    yMin: 1,
    series: [
      { key: "npm", label: "npm", color: C.s5 },
      { key: "rest", label: "PyPI and others", color: C.s3 },
    ],
    height: 300,
    yFormat: compact,
    xFormat: (m) => monthLabel(m),
    annotations: [
      { x: "2025-09-01", text: "Shai-Hulud", dy: 30, align: "end" },
      { x: "2025-11-01", text: "IndonesianFoods", dy: 0, align: "start" },
    ],
  });

  // AI as a weapon
  const ic3 = d.context.series.ic3_losses.points as any[];
  prose(
    sec,
    `<h3>AI on the attacking side</h3>
     <p>Criminals use the same tools. The FBI received ${link("https://www.ic3.gov/AnnualReport/Reports/2025_IC3Report.pdf", "22,364 complaints involving AI in 2025, with $893 million in losses")}, mostly from deepfake voices and videos, fake personas and AI-polished phishing. Three firsts mark the shift from "AI helps a criminal write an email" to "AI runs the operation":</p>
     <ul>
       <li><strong>Nov 2025.</strong> Anthropic ${link("https://www.anthropic.com/news/disrupting-AI-espionage", "reports")} a state-sponsored group that used Claude Code to carry out 80 to 90% of an espionage campaign against about 30 organizations, with humans stepping in only at a few decision points.</li>
       <li><strong>Jul 2026.</strong> Sysdig ${link("https://www.theregister.com/security/2026/07/02/smooth-ai-criminal-drives-first-end-to-end-agentic-ransomware-attack/5266073", "documents")} the first ransomware attack run end to end by an AI agent (JadePuffer): it found an exposed Langflow server, broke in, moved through the network, encrypted data and left the ransom note.</li>
       <li><strong>Oct 2026.</strong> The PHP flaw "php2shell", credited in part to OpenAI, is exploited in the wild ${link("https://www.helpnetsecurity.com/2026/10/21/php2shell-php-vulnerabilities-patched-cve-2026-109618-cve-2026-109619/", "on the day the patch ships")}. Amazon saw an exploitation attempt four days before disclosure.</li>
     </ul>`,
  );
  callout(
    sec,
    "context",
    `Total reported cybercrime losses to the FBI were $${ic3.find((p) => p.year === 2025).value.toFixed(1)}B in 2025, so losses in AI-tagged complaints are still about 4% of the total. The AI share is small but growing, and the FBI notes that many victims never know AI was involved.`,
  );
}
