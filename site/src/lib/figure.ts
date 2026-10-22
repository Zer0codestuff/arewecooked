// Figure shell: title, subtitle, legend, chart area, source line, table view, tooltip.

export type Row = Record<string, any>;

export interface LegendItem {
  label: string;
  color: string;
  shape?: "rect" | "line";
}

export interface FigureOpts {
  title: string;
  sub?: string;
  source: string; // HTML allowed (links)
  legend?: LegendItem[];
  table?: { columns: { key: string; label: string; fmt?: (v: any, r: Row) => string }[]; rows: Row[] };
  narrow?: boolean;
  id?: string;
}

export interface Figure {
  root: HTMLElement;
  chart: HTMLDivElement;
  width: () => number;
  onResize: (fn: () => void) => void;
}

export function el<K extends keyof HTMLElementTagNameMap>(tag: K, cls?: string, html?: string): HTMLElementTagNameMap[K] {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (html !== undefined) e.innerHTML = html;
  return e;
}

export function figure(parent: HTMLElement, o: FigureOpts): Figure {
  const root = el("div", "figure" + (o.narrow ? " narrow" : ""));
  if (o.id) root.id = o.id;
  const card = el("div", "card");
  root.appendChild(card);
  const t = el("h4", "fig-title");
  t.textContent = o.title;
  card.appendChild(t);
  if (o.sub) {
    const s = el("p", "fig-sub");
    s.textContent = o.sub;
    card.appendChild(s);
  }
  if (o.legend && o.legend.length > 1) {
    const lg = el("div", "legend");
    for (const it of o.legend) {
      const sp = el("span");
      const i = el("i", it.shape === "line" ? "line" : "");
      i.style.background = it.color;
      sp.appendChild(i);
      sp.appendChild(document.createTextNode(it.label));
      lg.appendChild(sp);
    }
    card.appendChild(lg);
  }
  const chart = el("div", "chart");
  card.appendChild(chart);
  const foot = el("div", "foot");
  const src = el("div", "src", "Source: " + o.source);
  foot.appendChild(src);
  card.appendChild(foot);
  if (o.table) {
    const btn = el("button");
    btn.type = "button";
    btn.textContent = "[ table ]";
    btn.setAttribute("aria-expanded", "false");
    foot.appendChild(btn);
    const wrap = el("div", "table-wrap");
    const tbl = el("table");
    const thead = el("thead");
    const htr = el("tr");
    for (const c of o.table.columns) {
      const th = el("th");
      th.textContent = c.label;
      htr.appendChild(th);
    }
    thead.appendChild(htr);
    tbl.appendChild(thead);
    const tb = el("tbody");
    for (const r of o.table.rows) {
      const tr = el("tr");
      for (const c of o.table.columns) {
        const td = el("td");
        const v = r[c.key];
        td.textContent = c.fmt ? c.fmt(v, r) : v == null ? "" : String(v);
        tr.appendChild(td);
      }
      tb.appendChild(tr);
    }
    tbl.appendChild(tb);
    wrap.appendChild(tbl);
    card.appendChild(wrap);
    btn.addEventListener("click", () => {
      const open = wrap.classList.toggle("open");
      btn.setAttribute("aria-expanded", String(open));
      btn.textContent = open ? "[ hide table ]" : "[ table ]";
    });
  }
  parent.appendChild(root);

  const handlers: (() => void)[] = [];
  let last = 0;
  const ro = new ResizeObserver(() => {
    const w = Math.round(chart.clientWidth);
    if (w && Math.abs(w - last) > 2) {
      last = w;
      handlers.forEach((h) => h());
    }
  });
  ro.observe(chart);
  return {
    root,
    chart,
    width: () => Math.max(280, chart.clientWidth),
    onResize: (fn) => {
      handlers.push(fn);
      last = Math.round(chart.clientWidth);
      fn();
    },
  };
}

// ---------- tooltip ----------
let tt: HTMLDivElement | null = null;
function tip(): HTMLDivElement {
  if (!tt) {
    tt = el("div", "tooltip");
    tt.setAttribute("role", "status");
    document.body.appendChild(tt);
  }
  return tt;
}

export interface TipRow {
  label: string;
  value: string;
  color?: string;
}

export function showTip(ev: { clientX: number; clientY: number }, head: string, rows: TipRow[]) {
  const t = tip();
  t.replaceChildren();
  const h = el("div", "tt-head");
  h.textContent = head;
  t.appendChild(h);
  for (const r of rows) {
    const row = el("div", "tt-row");
    const k = el("span", "k");
    if (r.color) {
      const i = el("i");
      i.style.background = r.color;
      k.appendChild(i);
    }
    k.appendChild(document.createTextNode(r.label));
    const b = el("b");
    b.textContent = r.value;
    row.appendChild(b);
    row.appendChild(k);
    row.style.flexDirection = "row-reverse";
    t.appendChild(row);
  }
  t.classList.add("on");
  const pad = 14;
  const rect = t.getBoundingClientRect();
  let x = ev.clientX + pad;
  let y = ev.clientY + pad;
  if (x + rect.width > window.innerWidth - 8) x = ev.clientX - rect.width - pad;
  if (y + rect.height > window.innerHeight - 8) y = ev.clientY - rect.height - pad;
  t.style.left = `${Math.max(8, x)}px`;
  t.style.top = `${Math.max(8, y)}px`;
}

export function hideTip() {
  tip().classList.remove("on");
}
