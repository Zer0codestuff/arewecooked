// Additional chart forms: calendar heatmap, bump chart, choropleth, small multiples.
import * as d3 from "d3";
import { Figure, Row, hideTip, showTip } from "./figure";
import { compact, fmtInt } from "./format";

const SURFACE = "#0b0c0c";
const MONO = "var(--mono)";

function svgFor(fig: Figure, height: number) {
  d3.select(fig.chart).selectAll("svg").remove();
  const w = fig.width();
  const svg = d3.select(fig.chart).append("svg").attr("width", w).attr("height", height).attr("viewBox", `0 0 ${w} ${height}`).attr("role", "img");
  return { svg, w };
}

const tipAt = (ev: any) => {
  if (ev.clientX) return ev;
  const r = (ev.target as Element).getBoundingClientRect();
  return { clientX: r.right, clientY: r.top + r.height / 2 };
};

/** Discrete sequential ramp, one hue, from near-surface to bright (dark mode). */
export function ramp(from: string, to: string, n: number): string[] {
  return d3.quantize(d3.interpolateLab(from, to), n);
}
export const GREEN_RAMP = ramp("#17301f", "#7be0ac", 6);
export const RED_RAMP = ramp("#3a1b18", "#ff8f78", 6);

/** Legend strip for a binned sequential scale, appended under the chart. */
function binLegend(fig: Figure, colors: string[], labels: string[], title: string) {
  const old = fig.chart.parentElement!.querySelector(".bin-legend");
  old?.remove();
  const lg = document.createElement("div");
  lg.className = "bin-legend";
  const t = document.createElement("span");
  t.className = "bl-title";
  t.textContent = title;
  lg.appendChild(t);
  colors.forEach((c, i) => {
    const s = document.createElement("span");
    const sw = document.createElement("i");
    sw.style.background = c;
    s.append(sw, document.createTextNode(labels[i]));
    lg.appendChild(s);
  });
  fig.chart.after(lg);
}

// ---------------------------------------------------------------------------
// Calendar heatmap: one block per year, weeks as columns, weekdays as rows
// ---------------------------------------------------------------------------
export interface CalendarOpts {
  data: Row[]; // {date: ISO string, cves: number}
  value: string;
  thresholds: number[]; // upper bounds of each bin except the last
  colors: string[];
  label: string;
  marked?: (d: Date) => string | null; // optional note for a day (e.g. Patch Tuesday)
}

export function calendar(fig: Figure, o: CalendarOpts) {
  const scale = d3.scaleThreshold<number, string>().domain(o.thresholds).range(o.colors);
  const labels = o.colors.map((_, i) => (i === 0 ? `<${o.thresholds[0]}` : i === o.colors.length - 1 ? `${compact(o.thresholds[i - 1])}+` : `${compact(o.thresholds[i - 1])}+`));
  binLegend(fig, o.colors, labels, o.label);
  const rows: any[] = o.data.map((r) => ({ ...r, d: new Date(r.date) }));
  const years = [...new Set(rows.map((r) => r.d.getUTCFullYear()))];
  const render = () => {
    const w = fig.width();
    const lw = 30;
    const cell = Math.max(5, Math.min(16, Math.floor((w - lw - 4) / 53)));
    const gap = cell > 8 ? 2 : 1;
    const blockH = cell * 7 + 34;
    const height = years.length * (blockH + 10);
    const { svg } = svgFor(fig, height);
    years.forEach((yr, yi) => {
      const g = svg.append("g").attr("transform", `translate(${lw},${yi * (blockH + 10) + 30})`);
      g.append("text").attr("x", -lw).attr("y", -20).attr("class", "lbl strong").text(String(yr));
      const start = Date.UTC(yr, 0, 1);
      const startDow = (new Date(start).getUTCDay() + 6) % 7; // Monday = 0
      const col = (d: Date) => Math.floor(((+d - start) / 864e5 + startDow) / 7);
      const dow = (d: Date) => (d.getUTCDay() + 6) % 7;
      ["Mon", "", "Wed", "", "Fri", "", "Sun"].forEach((t, i) => t && g.append("text").attr("class", "lbl muted").attr("x", -6).attr("y", i * cell + cell / 2).attr("dy", "0.32em").attr("text-anchor", "end").style("font-size", "9.5px").text(t));
      for (let m = 0; m < 12; m++) {
        const d = new Date(Date.UTC(yr, m, 1));
        g.append("text").attr("class", "lbl muted").attr("x", col(d) * cell).attr("y", -6).style("font-size", "9.5px").text(d3.utcFormat("%b")(d));
      }
      const yrRows = rows.filter((r) => r.d.getUTCFullYear() === yr);
      g.selectAll("rect.day")
        .data(yrRows)
        .join("rect")
        .attr("class", "day")
        .attr("x", (r) => col(r.d) * cell)
        .attr("y", (r) => dow(r.d) * cell)
        .attr("width", cell - gap)
        .attr("height", cell - gap)
        .attr("rx", Math.min(2, cell / 5))
        .attr("fill", (r) => scale(+r[o.value]))
        .attr("tabindex", 0)
        .on("pointermove focus", function (ev: any, r: any) {
          d3.select(this).attr("stroke", "var(--text)").attr("stroke-width", 1);
          const note = o.marked?.(r.d);
          const rowsT = [{ label: "CVEs published", value: fmtInt(+r[o.value]), color: scale(+r[o.value]) }];
          if (note) rowsT.push({ label: note, value: "", color: "transparent" });
          showTip(tipAt(ev), d3.utcFormat("%a %d %b %Y")(r.d), rowsT);
        })
        .on("pointerleave blur", function () {
          d3.select(this).attr("stroke", null);
          hideTip();
        });
    });
  };
  fig.onResize(render);
}

// ---------------------------------------------------------------------------
// Bump chart: rank per year, highlighted entities in color, the rest gray
// ---------------------------------------------------------------------------
export interface BumpOpts {
  data: Row[]; // {year, group, rank, victims, share}
  years: number[];
  highlight: Record<string, string>;
  maxRank: number;
  height?: number;
}

export function bump(fig: Figure, o: BumpOpts) {
  const groups = [...new Set(o.data.map((r) => r.group))];
  const render = () => {
    const height = o.height ?? 360;
    const { svg, w } = svgFor(fig, height);
    const narrow = w < 640;
    const m = { t: 24, r: narrow ? 104 : 118, b: 10, l: narrow ? 14 : 118 };
    const iw = w - m.l - m.r;
    const ih = height - m.t - m.b;
    const g = svg.append("g").attr("transform", `translate(${m.l},${m.t})`);
    const x = d3.scalePoint<number>().domain(o.years).range([0, iw]);
    const y = d3.scaleLinear().domain([1, o.maxRank]).range([0, ih]);
    o.years.forEach((yr) => {
      g.append("line").attr("class", "gridline").attr("x1", x(yr)!).attr("x2", x(yr)!).attr("y1", -6).attr("y2", ih);
      g.append("text").attr("class", "tick").attr("x", x(yr)!).attr("y", -12).attr("text-anchor", "middle").style("font-family", MONO).style("font-size", "11px").style("fill", "var(--muted)").text(String(yr));
    });
    const order = [...groups].sort((a, b) => (o.highlight[a] ? 1 : 0) - (o.highlight[b] ? 1 : 0));
    for (const grp of order) {
      const pts = o.data.filter((r) => r.group === grp).sort((a, b) => a.year - b.year);
      const col = o.highlight[grp] ?? "#4b524e";
      const hi = !!o.highlight[grp];
      // split into runs of consecutive in-range years
      let run: Row[] = [];
      const runs: Row[][] = [];
      for (const p of pts) {
        if (p.rank <= o.maxRank && (!run.length || p.year === run[run.length - 1].year + 1)) run.push(p);
        else {
          if (run.length) runs.push(run);
          run = p.rank <= o.maxRank ? [p] : [];
        }
      }
      if (run.length) runs.push(run);
      const grpG = g.append("g").attr("class", "bump-grp").style("opacity", hi ? 1 : 0.9);
      for (const rr of runs) {
        grpG.append("path").datum(rr).attr("fill", "none").attr("stroke", col).attr("stroke-width", hi ? 2.5 : 1.5).attr("stroke-linecap", "round")
          .attr("d", d3.line<Row>().x((r) => x(r.year)!).y((r) => y(r.rank)).curve(d3.curveMonotoneX) as any);
        grpG.selectAll(null).data(rr).join("circle").attr("cx", (r) => x(r.year)!).attr("cy", (r) => y(r.rank)).attr("r", hi ? 5 : 3.5).attr("fill", col).attr("stroke", SURFACE).attr("stroke-width", 2)
          .attr("tabindex", 0)
          .on("pointermove focus", (ev: any, r: any) => {
            grpG.raise().selectAll("path").attr("stroke-width", 3.5);
            showTip(tipAt(ev), `${grp}, ${r.year}`, [
              { label: "rank", value: `#${r.rank}`, color: col },
              { label: "victims named", value: fmtInt(r.victims), color: "transparent" },
              { label: "share of all victims", value: `${(r.share * 100).toFixed(1)}%`, color: "transparent" },
            ]);
          })
          .on("pointerleave blur", () => {
            grpG.selectAll("path").attr("stroke-width", hi ? 2.5 : 1.5);
            hideTip();
          });
      }
      // end labels: first and last in-range point
      const inR = pts.filter((p) => p.rank <= o.maxRank);
      if (!inR.length) continue;
      const last = inR[inR.length - 1];
      const firstP = inR[0];
      const lblCls = hi ? "lbl strong" : "lbl muted";
      const maxC = Math.floor((m.r - 12) / 6.8);
      const endTxt = `${last.rank}. ${grp}`;
      if (last.year === o.years[o.years.length - 1]) g.append("text").attr("class", lblCls).attr("x", iw + 10).attr("y", y(last.rank)).attr("dy", "0.32em").text(endTxt.length > maxC ? endTxt.slice(0, maxC - 1) + "…" : endTxt);
      if (firstP.year === o.years[0] && !narrow) g.append("text").attr("class", lblCls).attr("x", -10).attr("y", y(firstP.rank)).attr("dy", "0.32em").attr("text-anchor", "end").text(grp);
      else if (hi && last.year !== o.years[o.years.length - 1]) {
        // brand that enters and exits mid-chart: label it at its exit point
        const p = last;
        g.append("text").attr("class", lblCls).attr("x", x(p.year)!).attr("y", y(p.rank) + 15).attr("text-anchor", "middle").style("font-size", "10.5px").text(grp);
      }
    }
  };
  fig.onResize(render);
}

// ---------------------------------------------------------------------------
// Choropleth (world, Natural Earth projection), binned sequential fill
// ---------------------------------------------------------------------------
export interface ChoroOpts {
  features: any[]; // GeoJSON features with numeric string ids
  data: Row[]; // rows with {id, name}
  value: string;
  thresholds: number[];
  colors: string[];
  label: string;
  format: (v: number) => string;
  extra?: (r: Row) => { label: string; value: string }[];
}

export function choropleth(fig: Figure, o: ChoroOpts) {
  const byId = new Map(o.data.filter((r) => r.id).map((r) => [String(r.id).padStart(3, "0"), r]));
  const scale = d3.scaleThreshold<number, string>().domain(o.thresholds).range(o.colors);
  const labels = o.colors.map((_, i) => (i === 0 ? `<${o.format(o.thresholds[0])}` : `${o.format(o.thresholds[i - 1])}+`));
  binLegend(fig, o.colors, labels, o.label);
  const feats = o.features.filter((f) => f.id !== "010"); // drop Antarctica
  const render = () => {
    const w = fig.width();
    const height = Math.round(w * 0.5);
    const { svg } = svgFor(fig, height);
    const proj = d3.geoNaturalEarth1().fitExtent([[0, 4], [w, height - 4]], { type: "FeatureCollection", features: feats } as any);
    const path = d3.geoPath(proj);
    svg.append("g").selectAll("path").data(feats).join("path")
      .attr("d", path as any)
      .attr("fill", (f: any) => {
        const r = byId.get(String(f.id));
        return r && r[o.value] != null ? scale(+r[o.value]) : "#1a1f1d";
      })
      .attr("stroke", SURFACE)
      .attr("stroke-width", 0.6)
      .attr("tabindex", 0)
      .on("pointermove focus", function (ev: any, f: any) {
        d3.select(this).attr("stroke", "var(--text)").attr("stroke-width", 1.2).raise();
        const r = byId.get(String(f.id));
        const rows = r && r[o.value] != null
          ? [{ label: o.label, value: o.format(+r[o.value]), color: scale(+r[o.value]) }, ...(o.extra?.(r) ?? []).map((e) => ({ ...e, color: "transparent" }))]
          : [{ label: "no victims named in 2026", value: "", color: "transparent" }];
        showTip(tipAt(ev), r?.name ?? f.properties?.name ?? "", rows);
      })
      .on("pointerleave blur", function () {
        d3.select(this).attr("stroke", SURFACE).attr("stroke-width", 0.6);
        hideTip();
      });
  };
  fig.onResize(render);
}

// ---------------------------------------------------------------------------
// Small multiples: one mini line chart per panel, shared y scale
// ---------------------------------------------------------------------------
export interface MultiplesOpts {
  data: Row[];
  x: string;
  panels: { key: string; label: string }[];
  color: string;
  yMax?: number;
  yFormat: (v: number) => string;
  valueFormat: (v: number) => string;
  reference?: string; // optional key of a gray reference series drawn in every panel
  referenceLabel?: string;
  tipExtra?: (key: string, r: Row) => { label: string; value: string }[];
}

export function multiples(fig: Figure, o: MultiplesOpts) {
  const render = () => {
    const w = fig.width();
    const cols = w < 520 ? 2 : 3;
    const pw = (w - (cols - 1) * 18) / cols;
    const ph = 150;
    const rowsN = Math.ceil(o.panels.length / cols);
    const height = rowsN * (ph + 34);
    const { svg } = svgFor(fig, height);
    const xs = o.data.map((r) => +r[o.x]);
    const yMax = o.yMax ?? d3.max(o.data, (r) => d3.max(o.panels, (p) => +r[p.key] || 0))!;
    o.panels.forEach((p, i) => {
      const cx = (i % cols) * (pw + 18);
      const cy = Math.floor(i / cols) * (ph + 34) + 18;
      const m = { l: 34, r: 10, t: 6, b: 20 };
      const iw = pw - m.l - m.r;
      const ih = ph - m.t - m.b;
      const g = svg.append("g").attr("transform", `translate(${cx + m.l},${cy + m.t})`);
      svg.append("text").attr("class", "lbl strong").attr("x", cx).attr("y", cy - 4).text(p.label);
      const x = d3.scaleLinear().domain(d3.extent(xs) as [number, number]).range([0, iw]);
      const y = d3.scaleLinear().domain([0, yMax]).nice().range([ih, 0]);
      for (const t of y.ticks(3)) {
        g.append("line").attr("class", "gridline").attr("x1", 0).attr("x2", iw).attr("y1", y(t)).attr("y2", y(t));
        g.append("text").attr("class", "tick").attr("x", -6).attr("y", y(t)).attr("dy", "0.32em").attr("text-anchor", "end").style("font-family", MONO).style("font-size", "10px").style("fill", "var(--muted)").text(o.yFormat(t));
      }
      const ext = d3.extent(xs) as [number, number];
      [ext[0], ext[1]].forEach((t) => g.append("text").attr("class", "tick").attr("x", x(t)).attr("y", ih + 14).attr("text-anchor", t === ext[0] ? "start" : "end").style("font-family", MONO).style("font-size", "10px").style("fill", "var(--muted)").text(String(t)));
      if (o.reference) {
        const rp = o.data.filter((r) => r[o.reference!] != null);
        g.append("path").datum(rp).attr("fill", "none").attr("stroke", "#5d6561").attr("stroke-width", 1.5).attr("stroke-dasharray", "3 3").attr("d", d3.line<Row>().x((r) => x(+r[o.x])).y((r) => y(+r[o.reference!])) as any);
      }
      const pts = o.data.filter((r) => r[p.key] != null);
      g.append("path").datum(pts).attr("fill", o.color).attr("fill-opacity", 0.1).attr("d", d3.area<Row>().x((r) => x(+r[o.x])).y0(ih).y1((r) => y(+r[p.key])) as any);
      g.append("path").datum(pts).attr("fill", "none").attr("stroke", o.color).attr("stroke-width", 2).attr("stroke-linejoin", "round").attr("d", d3.line<Row>().x((r) => x(+r[o.x])).y((r) => y(+r[p.key])) as any);
      const last = pts[pts.length - 1];
      if (last) {
        g.append("circle").attr("cx", x(+last[o.x])).attr("cy", y(+last[p.key])).attr("r", 4).attr("fill", o.color).attr("stroke", SURFACE).attr("stroke-width", 2);
        g.append("text").attr("class", "lbl strong").attr("x", x(+last[o.x]) - 6).attr("y", y(+last[p.key]) - 9).attr("text-anchor", "end").text(o.valueFormat(+last[p.key]));
      }
      const cross = g.append("line").attr("y1", 0).attr("y2", ih).attr("stroke", "var(--text-2)").attr("stroke-opacity", 0.4).style("display", "none");
      const dot = g.append("circle").attr("r", 4).attr("fill", o.color).attr("stroke", SURFACE).attr("stroke-width", 2).style("display", "none");
      g.append("rect").attr("width", iw).attr("height", ih).attr("fill", "transparent")
        .on("pointermove", (ev: PointerEvent) => {
          const [px] = d3.pointer(ev);
          const xv = Math.round(x.invert(px));
          const r = pts.find((d) => +d[o.x] === xv);
          if (!r) return;
          cross.attr("x1", x(xv)).attr("x2", x(xv)).style("display", null);
          dot.attr("cx", x(xv)).attr("cy", y(+r[p.key])).style("display", null);
          const rows = [{ label: p.label, value: o.valueFormat(+r[p.key]), color: o.color }];
          if (o.reference && r[o.reference] != null) rows.push({ label: o.referenceLabel ?? o.reference, value: o.valueFormat(+r[o.reference]), color: "#5d6561" });
          for (const e of o.tipExtra?.(p.key, r) ?? []) rows.push({ ...e, color: "transparent" });
          showTip(ev, String(xv), rows);
        })
        .on("pointerleave", () => {
          cross.style("display", "none");
          dot.style("display", "none");
          hideTip();
        });
    });
  };
  fig.onResize(render);
}

// ---------------------------------------------------------------------------
// Matrix heatmap (e.g. confusion matrix): cells shaded by share of the row
// ---------------------------------------------------------------------------
export interface MatrixOpts {
  rows: string[];
  cols: string[];
  value: (r: string, c: string) => number;
  rowTitle: string;
  colTitle: string;
  colors: string[]; // binned sequential ramp
  thresholds: number[]; // on row share, 0..1
  diagonal?: boolean; // outline the agreement cells
}

export function matrix(fig: Figure, o: MatrixOpts) {
  const scale = d3.scaleThreshold<number, string>().domain(o.thresholds).range(o.colors);
  const render = () => {
    const w = fig.width();
    const lw = 78;
    const cell = Math.min(64, Math.floor((w - lw - 8) / o.cols.length));
    const height = cell * o.rows.length + 44;
    const { svg } = svgFor(fig, height);
    const g = svg.append("g").attr("transform", `translate(${lw},34)`);
    svg.append("text").attr("class", "lbl muted").attr("x", lw).attr("y", 11).text(o.colTitle + " ->");
    o.cols.forEach((c, j) => g.append("text").attr("class", "lbl").attr("x", j * cell + cell / 2).attr("y", -8).attr("text-anchor", "middle").text(c));
    o.rows.forEach((r, i) => {
      const tot = d3.sum(o.cols, (c) => o.value(r, c)) || 1;
      g.append("text").attr("class", "lbl").attr("x", -10).attr("y", i * cell + cell / 2).attr("dy", "0.32em").attr("text-anchor", "end").text(r);
      o.cols.forEach((c, j) => {
        const v = o.value(r, c);
        const share = v / tot;
        const rect = g.append("rect").attr("x", j * cell).attr("y", i * cell).attr("width", cell - 2).attr("height", cell - 2).attr("rx", 3)
          .attr("fill", v ? scale(share) : "#151917").attr("tabindex", 0);
        if (o.diagonal && i === j) g.append("rect").attr("x", j * cell + 0.5).attr("y", i * cell + 0.5).attr("width", cell - 3).attr("height", cell - 3).attr("rx", 3).attr("fill", "none").attr("stroke", "var(--text-2)").attr("stroke-width", 1).attr("stroke-dasharray", "2 2").style("pointer-events", "none");
        g.append("text").attr("class", share >= o.thresholds[o.thresholds.length - 2] ? "lbl strong" : "lbl").attr("x", j * cell + cell / 2 - 1).attr("y", i * cell + cell / 2).attr("dy", "0.32em").attr("text-anchor", "middle").style("pointer-events", "none")
          .style("fill", share >= o.thresholds[o.thresholds.length - 2] ? "#0b0d0c" : "var(--text-2)").text(v ? fmtInt(v) : "");
        rect.on("pointermove focus", (ev: any) => showTip(tipAt(ev), `${o.rowTitle}: ${r}`, [
          { label: o.colTitle, value: c, color: "transparent" },
          { label: "findings", value: fmtInt(v), color: v ? scale(share) : "transparent" },
          { label: `share of "${r}" row`, value: `${(share * 100).toFixed(0)}%`, color: "transparent" },
        ])).on("pointerleave blur", hideTip);
      });
    });
    svg.append("text").attr("class", "lbl muted").attr("x", 0).attr("y", 11).text(o.rowTitle);
  };
  fig.onResize(render);
}
