import type { Data } from "../main";
import { el } from "../lib/figure";
import { fmtInt, times } from "../lib/format";

const TITLE = String.raw`
 █████╗ ██████╗ ███████╗    ██╗    ██╗███████╗     ██████╗ ██████╗  ██████╗ ██╗  ██╗███████╗██████╗ ██████╗
██╔══██╗██╔══██╗██╔════╝    ██║    ██║██╔════╝    ██╔════╝██╔═══██╗██╔═══██╗██║ ██╔╝██╔════╝██╔══██╗╚════██╗
███████║██████╔╝█████╗      ██║ █╗ ██║█████╗      ██║     ██║   ██║██║   ██║█████╔╝ █████╗  ██║  ██║  ▄███╔╝
██╔══██║██╔══██╗██╔══╝      ██║███╗██║██╔══╝      ██║     ██║   ██║██║   ██║██╔═██╗ ██╔══╝  ██║  ██║  ▀▀══╝
██║  ██║██║  ██║███████╗    ╚███╔███╔╝███████╗    ╚██████╗╚██████╔╝╚██████╔╝██║  ██╗███████╗██████╔╝  ██╗
╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝     ╚══╝╚══╝ ╚══════╝     ╚═════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═════╝   ╚═╝`.slice(1);

export function renderHero(main: HTMLElement, d: Data) {
  const v = d.vulns.totals;
  const tte = d.vulns.tte as any[];
  const rw = d.threats.ransomware.yearly as any[];
  const rwCur = rw.find((r) => r.year === 2026)?.victims;
  const rwPrev = rw.find((r) => r.year === 2025)?.victims;
  const spend = d.context.series.gartner_spend_infosec.points as any[];
  const s26 = spend.find((p) => p.year === 2026).value;
  const s25 = spend.find((p) => p.year === 2025).value;
  const t22 = tte.find((r) => r.pub_year === 2022);
  const t26 = tte.find((r) => r.pub_year === 2026);

  const hero = el("header", "hero");
  hero.id = "top";
  const pre = el("pre", "ascii-title");
  pre.setAttribute("aria-label", "Are we cooked?");
  pre.textContent = TITLE;
  hero.appendChild(pre);
  hero.appendChild(el("p", "prompt", `<span>$</span> <span class="cmd">./are-we-cooked --sector=cybersecurity --year=2026</span><span class="caret"></span>`));
  hero.appendChild(
    el(
      "p",
      "lede",
      `This year the world will publish more software vulnerabilities than in any year on record: about <strong>${times(v.ytd_cur, v.ytd_prev)}</strong> the pace of 2025. AI now finds bugs by the thousand, attackers turn fresh flaws into working attacks in days, and companies are spending more on security than ever. This is a data story about whether defenders can keep up.`,
    ),
  );
  hero.appendChild(
    el(
      "p",
      "meta",
      `data as of 22 Oct 2026 · ${fmtInt(412863)} CVE records parsed · 15+ public datasets · every number links to its source`,
    ),
  );
  main.appendChild(hero);

  const kpis = el("div", "kpis");
  const tile = (label: string, value: string, delta: string) => {
    const k = el("div", "kpi");
    k.appendChild(el("div", "label", label));
    k.appendChild(el("div", "value", value));
    k.appendChild(el("div", "delta", delta));
    kpis.appendChild(k);
  };
  tile("CVEs published in 2026 so far", fmtInt(v.cur_year), `<span class="up">▲ ${times(v.ytd_cur, v.ytd_prev)}</span> vs same days of 2025`);
  tile("critical-severity CVEs in 2026", fmtInt(v.critical_cur), `<span class="up">▲</span> ${fmtInt(v.critical_prev)} in all of 2025`);
  tile("2026 CVEs credited to AI finders", fmtInt(v.ai_attributed_cur), `at least · ${((v.ai_attributed_cur / v.cur_year) * 100).toFixed(1)}% of all · see ch. 03`);
  tile("median days, CVE to confirmed attack", String(t26.median_days), `<span class="up">▼</span> ${t22.median_days} days for 2022 CVEs (CISA KEV)`);
  tile("ransomware victims named in 2026", fmtInt(rwCur), `${fmtInt(rwPrev)} in all of 2025 (leak sites)`);
  tile("global security spending, 2026", `$${s26}B`, `<span class="good">▲ ${(((s26 - s25) / s25) * 100).toFixed(1)}%</span> vs 2025 (Gartner)`);
  main.appendChild(kpis);
}
