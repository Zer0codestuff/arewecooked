import type { Data } from "../main";
import { lines, radar } from "../lib/charts";
import { el, figure } from "../lib/figure";
import { fmtInt, pct } from "../lib/format";
import { C, chapter, grid2, prose } from "../lib/page";

const COLORS = [C.s1, C.s3];

export function renderExplore(main: HTMLElement, d: Data) {
  const x = d.explore;
  const vendors = x.vendors as any[];
  const axes = x.axes as { key: string; label: string }[];
  const years: number[] = x.years;
  const sec = chapter(main, {
    id: "explore",
    num: "13",
    title: "Explore: compare two vendors",
    kicker: `Pick any two of the ${x.top_n} vendors with the most CVEs since 2016.`,
  });
  prose(
    sec,
    `<p>Each axis ranks the vendor against the other ${x.top_n - 1} (100 = highest). Volume and growth are about 2026; critical share covers 2024 to 2026; exploited, public exploit code and AI-found are counts since 2016; memory bugs share covers 2020 on. Hover a point for the raw number.</p>`,
  );

  // controls
  const byName = new Map(vendors.map((v) => [v.name.toLowerCase(), v]));
  const ctl = el("div", "compare-ctl");
  const list = el("datalist");
  list.id = "vendor-list";
  for (const v of [...vendors].sort((a, b) => a.name.localeCompare(b.name))) {
    const o = el("option");
    o.value = v.name;
    list.appendChild(o);
  }
  const inputs = ["Microsoft", "Google"].map((def, i) => {
    const wrap = el("label", "cmp");
    const sw = el("i");
    sw.style.background = COLORS[i];
    const inp = el("input") as HTMLInputElement;
    inp.type = "text";
    inp.value = def;
    inp.setAttribute("list", "vendor-list");
    inp.setAttribute("aria-label", `Vendor ${i + 1}`);
    inp.spellcheck = false;
    wrap.append(sw, inp);
    return { wrap, inp };
  });
  const vs = el("span", "vs");
  vs.textContent = "vs";
  ctl.append(inputs[0].wrap, vs, inputs[1].wrap, list);
  const quick = el("div", "quick");
  for (const [a, b] of [["Microsoft", "Google"], ["Apple", "Linux kernel"], ["Fortinet", "Palo Alto Networks"], ["Mozilla", "Oracle"], ["Ivanti", "Cisco"]]) {
    const btn = el("button") as HTMLButtonElement;
    btn.type = "button";
    btn.textContent = `${a} / ${b}`;
    btn.addEventListener("click", () => {
      inputs[0].inp.value = a;
      inputs[1].inp.value = b;
      update();
    });
    quick.appendChild(btn);
  }
  const ctlWrap = el("div", "compare");
  ctlWrap.append(ctl, quick);
  sec.appendChild(ctlWrap);

  const g = grid2(sec);
  const fr = figure(g, { title: "Profile, ranked against the top vendors", source: "CVE Program, NVD CPE vendors, CISA KEV, PoC-in-GitHub, author's AI classifier" });
  const fl = figure(g, { title: "CVEs per year", source: "CVE Program cvelistV5 and NVD (vendor from NVD CPE, else the CVE record); 2026 to 22 Oct" });
  const statWrap = el("div", "cmp-table");
  sec.appendChild(statWrap);

  const raw = (v: any, k: string) => {
    const val = v[k];
    if (val == null) return "n/a";
    if (k === "crit_share" || k === "memsafety") return pct(val);
    if (k === "growth") return `${val}x`;
    return fmtInt(val);
  };

  function update() {
    const pick = inputs.map((i) => byName.get(i.inp.value.trim().toLowerCase()));
    inputs.forEach((i, j) => i.wrap.classList.toggle("bad", !pick[j]));
    if (!pick[0] || !pick[1]) return;
    const [a, b] = pick as any[];
    fr.reset();
    radar(fr, {
      axes,
      series: [a, b].map((v, i) => ({
        label: v.name,
        color: COLORS[i],
        values: Object.fromEntries(axes.map((ax) => [ax.key, Math.max(2, v[`r_${ax.key}`])])),
        raw: Object.fromEntries(axes.map((ax) => [ax.key, raw(v, ax.key)])),
      })),
      height: 400,
    });
    const rows = years.map((y, i) => ({ year: y, a: a.yearly[i], b: b.yearly[i] }));
    fl.reset();
    lines(fl, {
      data: rows,
      x: "year",
      series: [
        { key: "a", label: a.name, color: COLORS[0] },
        { key: "b", label: b.name, color: COLORS[1] },
      ],
      height: 300,
      dots: true,
      endLabels: true,
      marginRight: 120,
      tickFormat: (t) => String(t),
      xFormat: (t) => (t === 2026 ? "2026 (to 22 Oct)" : String(t)),
    });
    // comparison table
    const t = el("table");
    const head = el("tr");
    for (const h of ["", a.name, b.name]) {
      const th = el("th");
      th.textContent = h;
      head.appendChild(th);
    }
    t.appendChild(head);
    const line = (label: string, fa: string, fb: string) => {
      const tr = el("tr");
      for (const [i, txt] of [label, fa, fb].entries()) {
        const td = el(i === 0 ? "th" : "td");
        td.textContent = txt;
        tr.appendChild(td);
      }
      t.appendChild(tr);
    };
    line("CVEs since 2016", fmtInt(a.total), fmtInt(b.total));
    line("CVEs in 2026 (to 22 Oct)", fmtInt(a.cur), fmtInt(b.cur));
    line("2025", fmtInt(a.prev), fmtInt(b.prev));
    for (const ax of axes.slice(1)) line(ax.label, raw(a, ax.key), raw(b, ax.key));
    line("Top products since 2024", (a.products || []).join(", "), (b.products || []).join(", "));
    statWrap.replaceChildren(t);
  }
  for (const i of inputs) {
    i.inp.addEventListener("change", update);
    i.inp.addEventListener("input", () => {
      if (byName.has(i.inp.value.trim().toLowerCase())) update();
    });
  }
  update();
}
