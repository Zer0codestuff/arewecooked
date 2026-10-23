import * as d3 from "d3";
import { Figure, Row, hideTip, showTip } from "./figure";
import { compact, fmtInt } from "./format";

export interface Series {
  key: string;
  label: string;
  color: string;
}

export interface Annotation {
  x: any; // category value or date
  text: string;
  dy?: number; // vertical offset in px from top of plot
  align?: "start" | "end" | "middle";
}

const SURFACE = "#101312";

// ---------------------------------------------------------------------------
// AI model release markers ("release rail"), shared by time-based charts
// ---------------------------------------------------------------------------
export interface Release {
  date: string; // YYYY-MM-DD
  label: string;
  model: string;
  lab: string;
  note?: string;
  priority?: number;
}

let RELEASES: Release[] = [];
export function setReleases(r: Release[]) {
  RELEASES = [...r].sort((a, b) => a.date.localeCompare(b.date));
}

const RAIL_ROWS = 3;
const RAIL_ROW_H = 13;
export const RAIL_H = RAIL_ROWS * RAIL_ROW_H + 8;
const CHAR_W = 6.2; // approx width of one 10.5px mono glyph

function addRailLegend(fig: Figure) {
  const card = fig.root.querySelector(".card")!;
  if (card.querySelector(".legend .rel")) return;
  let lg = card.querySelector<HTMLDivElement>(".legend");
  if (!lg) {
    lg = document.createElement("div");
    lg.className = "legend";
    card.insertBefore(lg, fig.chart);
  }
  const sp = document.createElement("span");
  sp.className = "rel";
  const i = document.createElement("i");
  i.className = "rel-mark";
  sp.append(i, document.createTextNode("AI model release"));
  lg.appendChild(sp);
}

/** Draw release markers. `pos` maps a release date to an x pixel, or null when out of range.
 *  Labels are placed by priority (1 first) in up to RAIL_ROWS rows; markers that do not fit stay unlabeled but keep a tooltip. */
function drawRail(g: d3.Selection<SVGGElement, unknown, null, undefined>, pos: (d: Date) => number | null, iw: number, ih: number) {
  const items = RELEASES.map((r) => ({ r, x: pos(new Date(r.date + "T12:00:00Z")) })).filter((d): d is { r: Release; x: number } => d.x != null && d.x >= 0 && d.x <= iw);
  const rows: [number, number][][] = Array.from({ length: RAIL_ROWS }, () => []);
  const free = (k: number, a: number, b: number) => rows[k].every(([c, d]) => b + 6 < c || a > d + 6);
  // also keep other markers' diamonds clear of a label's text
  const placed = new Map<Release, { row: number; right: boolean }>();
  for (const it of [...items].sort((a, b) => (a.r.priority ?? 3) - (b.r.priority ?? 3) || a.r.date.localeCompare(b.r.date))) {
    const w = it.r.label.length * CHAR_W;
    const opts = [
      { right: true, a: it.x - 3, b: it.x + w + 4 },
      { right: false, a: it.x - w - 4, b: it.x + 3 },
    ].filter((o) => o.a >= -40 && o.b <= iw + 8);
    let done = false;
    for (let k = 0; k < RAIL_ROWS && !done; k++) {
      for (const o of opts) {
        if (free(k, o.a, o.b)) {
          rows[k].push([o.a, o.b]);
          placed.set(it.r, { row: k, right: o.right });
          done = true;
          break;
        }
      }
    }
  }
  const layer = g.append("g").attr("class", "rail");
  for (const it of items) {
    const p = placed.get(it.r);
    const ty = -RAIL_H + 4 + (p ? p.row : RAIL_ROWS - 1) * RAIL_ROW_H;
    const w = it.r.label.length * CHAR_W;
    const mk = layer.append("g").attr("class", "rel-item");
    mk.append("line").attr("class", "rel-line").attr("x1", it.x).attr("x2", it.x).attr("y1", p ? ty + 2 : -6).attr("y2", ih);
    mk.append("path").attr("class", "rel-dot").attr("d", `M${it.x},-7l3.5,3.5l-3.5,3.5l-3.5,-3.5Z`);
    if (p) mk.append("text").attr("class", "rel-lbl").attr("x", p.right ? it.x + 4 : it.x - 4).attr("y", ty + 7).attr("text-anchor", p.right ? "start" : "end").text(it.r.label);
    const hx = p ? (p.right ? it.x - 6 : it.x - w - 6) : it.x - 6;
    const hw = p ? w + 12 : 12;
    mk.append("rect").attr("x", hx).attr("y", p ? ty - 4 : -12).attr("width", hw).attr("height", p ? -ty + 4 : 12).attr("fill", "transparent").attr("tabindex", 0)
      .on("pointermove focus", (ev: any) => {
        mk.classed("on", true);
        const rect = (ev.target as Element).getBoundingClientRect();
        const d = new Date(it.r.date + "T12:00:00Z").toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric", timeZone: "UTC" });
        const rows2 = [{ label: it.r.lab, value: d, color: "transparent" }];
        if (it.r.note) rows2.push({ label: it.r.note, value: "", color: "transparent" });
        showTip(ev.clientX ? ev : { clientX: rect.left + rect.width / 2, clientY: rect.bottom }, it.r.model, rows2);
      })
      .on("pointerleave blur", () => {
        mk.classed("on", false);
        hideTip();
      });
  }
  return items.length > 0;
}

function hasReleasesIn(lo: Date, hi: Date) {
  return RELEASES.some((r) => {
    const d = new Date(r.date + "T12:00:00Z");
    return d >= lo && d <= hi;
  });
}

function svgFor(fig: Figure, height: number) {
  d3.select(fig.chart).selectAll("svg").remove();
  const w = fig.width();
  const svg = d3
    .select(fig.chart)
    .append("svg")
    .attr("width", w)
    .attr("height", height)
    .attr("viewBox", `0 0 ${w} ${height}`)
    .attr("role", "img");
  return { svg, w };
}

/** Path for a bar with a 4px rounded data-end and a square baseline. */
function barPath(x: number, y: number, w: number, h: number, r = 4, roundTop = true): string {
  if (h <= 0 || w <= 0) return "";
  const rr = roundTop ? Math.min(r, w / 2, h) : 0;
  return `M${x},${y + h}V${y + rr}Q${x},${y} ${x + rr},${y}H${x + w - rr}Q${x + w},${y} ${x + w},${y + rr}V${y + h}Z`;
}

function hbarPath(x: number, y: number, w: number, h: number, r = 4): string {
  if (h <= 0 || w <= 0) return "";
  const rr = Math.min(r, h / 2, w);
  return `M${x},${y}H${x + w - rr}Q${x + w},${y} ${x + w},${y + rr}V${y + h - rr}Q${x + w},${y + h} ${x + w - rr},${y + h}H${x}Z`;
}

function yGrid(g: d3.Selection<SVGGElement, unknown, null, undefined>, y: d3.ScaleLinear<number, number>, w: number, fmt: (v: number) => string, ticks = 5) {
  const t = y.ticks(ticks);
  g.selectAll("line.gridline").data(t).join("line").attr("class", "gridline").attr("x1", 0).attr("x2", w).attr("y1", (d) => Math.round(y(d)) + 0.5).attr("y2", (d) => Math.round(y(d)) + 0.5);
  g.selectAll("text.ytick").data(t).join("text").attr("class", "ytick tick").attr("x", -8).attr("y", (d) => y(d)).attr("dy", "0.32em").attr("text-anchor", "end").style("font-family", "var(--mono)").style("font-size", "11px").style("fill", "var(--muted)").text((d) => fmt(d));
}

// ---------------------------------------------------------------------------
// Columns (single, grouped by color function, or stacked)
// ---------------------------------------------------------------------------
export interface ColumnsOpts {
  data: Row[];
  x: string;
  xLabel?: (v: any) => string;
  xTickEvery?: number | ((v: any, i: number) => boolean);
  series: Series[];
  stacked?: boolean;
  percent?: boolean;
  height?: number;
  colorFn?: (r: Row) => string; // single-series emphasis
  yFormat?: (v: number) => string;
  valueFormat?: (v: number) => string;
  labelBars?: (r: Row, i: number) => boolean;
  annotations?: Annotation[];
  partial?: (r: Row) => boolean;
  tipHead?: (r: Row) => string;
  tipExtra?: (r: Row) => { label: string; value: string }[];
  marginLeft?: number;
  yMax?: number;
  releases?: boolean; // x values are month-start dates
}

export function columns(fig: Figure, o: ColumnsOpts) {
  const render = () => {
    const months = o.releases ? o.data.map((r) => new Date(r[o.x])) : [];
    const rail = !!o.releases && months.length > 0 && hasReleasesIn(months[0], new Date(Date.UTC(months[months.length - 1].getUTCFullYear(), months[months.length - 1].getUTCMonth() + 1, 0)));
    const height = (o.height ?? 300) + (rail ? RAIL_H : 0);
    const { svg, w } = svgFor(fig, height);
    const m = { t: 22 + (rail ? RAIL_H : 0), r: 8, b: 26, l: o.marginLeft ?? 44 };
    const iw = w - m.l - m.r;
    const ih = height - m.t - m.b;
    const g = svg.append("g").attr("transform", `translate(${m.l},${m.t})`);
    const xs = o.data.map((d) => d[o.x]);
    const x = d3.scaleBand<any>().domain(xs).range([0, iw]).paddingInner(o.data.length > 30 ? 0.18 : 0.28).paddingOuter(0.1);
    const total = (r: Row) => d3.sum(o.series, (s) => +r[s.key] || 0);
    const yMax = o.percent ? 1 : o.yMax ?? (o.stacked ? d3.max(o.data, total)! : d3.max(o.data, (r) => d3.max(o.series, (s) => +r[s.key] || 0))!);
    const y = d3.scaleLinear().domain([0, yMax * (o.percent ? 1 : 1.08)]).nice().range([ih, 0]);
    const yf = o.yFormat ?? ((v: number) => (o.percent ? `${Math.round(v * 100)}%` : compact(v)));
    yGrid(g, y, iw, yf);
    const bw = Math.min(o.stacked || o.series.length === 1 ? 24 : 24 * o.series.length, x.bandwidth());
    const off = (x.bandwidth() - bw) / 2;

    // x labels
    const every = o.xTickEvery ?? Math.ceil(xs.length / Math.max(4, Math.floor(iw / 64)));
    const show = (v: any, i: number) => (typeof every === "function" ? every(v, i) : i % every === 0 || i === xs.length - 1);
    g.append("g")
      .selectAll("text")
      .data(xs.filter((v, i) => show(v, i)))
      .join("text")
      .attr("class", "tick")
      .attr("x", (v) => x(v)! + x.bandwidth() / 2)
      .attr("y", ih + 18)
      .attr("text-anchor", "middle")
      .style("font-family", "var(--mono)")
      .style("font-size", "11px")
      .style("fill", "var(--muted)")
      .text((v) => (o.xLabel ? o.xLabel(v) : String(v)));
    g.append("line").attr("x1", 0).attr("x2", iw).attr("y1", ih + 0.5).attr("y2", ih + 0.5).attr("stroke", "var(--axis)");

    const bars = g.append("g");
    o.data.forEach((r, i) => {
      const x0 = x(r[o.x])! + off;
      const tot = total(r) || 1;
      let acc = 0;
      const n = o.series.length;
      const grp = bars.append("g").attr("class", "col");
      const partial = o.partial?.(r);
      if (o.stacked || n === 1) {
        const visible = o.series.filter((s) => (+r[s.key] || 0) > 0);
        o.series.forEach((s) => {
          const v = +r[s.key] || 0;
          if (v <= 0) return;
          const val = o.percent ? v / tot : v;
          const y1 = y(acc + val);
          const y0 = y(acc);
          acc += val;
          const isTop = s === visible[visible.length - 1];
          const hgt = Math.max(0, y0 - y1 - (isTop ? 0 : 2));
          grp.append("path")
            .attr("d", barPath(x0, y1 + (isTop ? 0 : 2), bw, isTop ? y0 - y1 : hgt, 4, isTop))
            .attr("fill", n === 1 && o.colorFn ? o.colorFn(r) : s.color)
            .attr("opacity", partial && n === 1 ? 0.72 : 1);
        });
        if (partial) {
          const top = y(o.percent ? 1 : acc);
          grp.append("path").attr("d", barPath(x0 - 0.5, top - 0.5, bw + 1, y(0) - top + 1, 4, true)).attr("fill", "none").attr("stroke", "var(--text-2)").attr("stroke-dasharray", "2 2").attr("stroke-width", 1).attr("opacity", 0.7);
        }
      } else {
        const sub = bw / n;
        o.series.forEach((s, j) => {
          const v = +r[s.key] || 0;
          grp.append("path").attr("d", barPath(x0 + j * sub, y(v), sub - 2, y(0) - y(v))).attr("fill", s.color);
          if (o.labelBars?.(r, i) && r[s.key] != null) {
            g.append("text").attr("class", "lbl strong").attr("x", x0 + j * sub + (sub - 2) / 2).attr("y", y(v) - 7).attr("text-anchor", "middle").text((o.valueFormat ?? fmtInt)(v));
          }
        });
      }
      if (o.labelBars?.(r, i) && (o.stacked || n === 1)) {
        const v = o.stacked || n === 1 ? total(r) : d3.max(o.series, (s) => +r[s.key] || 0)!;
        g.append("text").attr("class", "lbl strong").attr("x", x0 + bw / 2).attr("y", y(o.percent ? 1 : v) - 7).attr("text-anchor", "middle").text((o.valueFormat ?? fmtInt)(v));
      }
      // hit target: whole column band
      grp.append("rect")
        .attr("x", x(r[o.x])!)
        .attr("y", 0)
        .attr("width", x.bandwidth())
        .attr("height", ih)
        .attr("fill", "transparent")
        .attr("tabindex", 0)
        .on("pointermove focus", (ev: any) => {
          grp.selectAll("path").attr("filter", "brightness(1.25)");
          const rows = [...o.series].reverse().filter((s) => r[s.key] != null).map((s) => ({
            label: s.label,
            value: o.percent ? `${(((+r[s.key] || 0) / tot) * 100).toFixed(1)}% (${(o.valueFormat ?? fmtInt)(+r[s.key] || 0)})` : (o.valueFormat ?? fmtInt)(+r[s.key] || 0),
            color: n === 1 && o.colorFn ? o.colorFn(r) : s.color,
          }));
          if (o.series.length > 1 && !o.percent) rows.push({ label: "Total", value: (o.valueFormat ?? fmtInt)(total(r)), color: "transparent" });
          for (const e of o.tipExtra?.(r) ?? []) rows.push({ ...e, color: "transparent" });
          const rect = (ev.target as Element).getBoundingClientRect();
          const pt = ev.clientX ? ev : { clientX: rect.right, clientY: rect.top + rect.height / 2 };
          showTip(pt, o.tipHead ? o.tipHead(r) : String(o.xLabel ? o.xLabel(r[o.x]) : r[o.x]), rows);
        })
        .on("pointerleave blur", () => {
          grp.selectAll("path").attr("filter", null);
          hideTip();
        });
    });

    for (const a of o.annotations ?? []) {
      const ax = x(a.x);
      if (ax == null) continue;
      const cx = ax + x.bandwidth() / 2;
      const ty = a.dy ?? 4;
      g.append("line").attr("class", "annot-line").attr("x1", cx).attr("x2", cx).attr("y1", ty + 6).attr("y2", ih).attr("stroke-opacity", 0.35);
      const anchor = a.align ?? (cx > iw * 0.7 ? "end" : "start");
      g.append("text").attr("class", "annot").attr("x", cx + (anchor === "end" ? -6 : anchor === "start" ? 6 : 0)).attr("y", ty + 4).attr("text-anchor", anchor).text(a.text);
    }
    if (rail) {
      const byMonth = new Map(o.data.map((r) => [String(new Date(r[o.x]).toISOString().slice(0, 7)), r[o.x]]));
      drawRail(g, (d) => {
        const key = byMonth.get(d.toISOString().slice(0, 7));
        if (key == null) return null;
        const days = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth() + 1, 0)).getUTCDate();
        return x(key)! + off + (bw * (d.getUTCDate() - 0.5)) / days;
      }, iw, ih);
    }
  };
  if (o.releases) addRailLegend(fig);
  fig.onResize(render);
}

// ---------------------------------------------------------------------------
// Lines (multi-series, crosshair tooltip)
// ---------------------------------------------------------------------------
export interface LinesOpts {
  data: Row[];
  x: string; // date string or number
  time?: boolean;
  series: Series[];
  height?: number;
  yFormat?: (v: number) => string;
  valueFormat?: (v: number) => string;
  xFormat?: (d: any) => string;
  tickFormat?: (d: any) => string;
  area?: boolean;
  endLabels?: boolean;
  annotations?: Annotation[];
  baseline?: number; // draw a reference line (e.g. 100 for indexed)
  yMin?: number;
  log?: boolean;
  marginLeft?: number;
  marginRight?: number;
  dots?: boolean;
  releases?: boolean; // requires time: true
  xDomain?: [number, number];
  points?: { x: number; y: number; label: string; color?: string; dx?: number; dy?: number; anchor?: "start" | "end" | "middle" }[];
  xTicks?: number[];
}

export function lines(fig: Figure, o: LinesOpts) {
  const render = () => {
    const ext = o.time ? (d3.extent(o.data, (r) => new Date(r[o.x])) as [Date, Date]) : null;
    const rail = !!o.releases && !!ext && hasReleasesIn(ext[0], ext[1]);
    const height = (o.height ?? 300) + (rail ? RAIL_H : 0);
    const { svg, w } = svgFor(fig, height);
    const m = { t: 16 + (rail ? RAIL_H : 0), r: o.marginRight ?? (o.endLabels ? 96 : 12), b: 26, l: o.marginLeft ?? 44 };
    const iw = w - m.l - m.r;
    const ih = height - m.t - m.b;
    const g = svg.append("g").attr("transform", `translate(${m.l},${m.t})`);
    const xv = (r: Row) => (o.time ? new Date(r[o.x]) : +r[o.x]);
    const x: any = o.time ? d3.scaleUtc().domain(d3.extent(o.data, xv) as [Date, Date]).range([0, iw]) : d3.scaleLinear().domain(o.xDomain ?? (d3.extent(o.data, (r) => +xv(r)) as [number, number])).range([0, iw]);
    const vals = o.data.flatMap((r) => o.series.map((s) => r[s.key]).filter((v) => v != null)) as number[];
    const lo = o.yMin ?? (o.log ? d3.min(vals)! * 0.8 : Math.min(0, d3.min(vals)!));
    const y = (o.log ? d3.scaleLog().domain([lo, d3.max(vals)! * 1.1]) : d3.scaleLinear().domain([lo, d3.max(vals)! * 1.06]).nice()).range([ih, 0]) as d3.ScaleLinear<number, number>;
    const yf = o.yFormat ?? compact;
    if (o.log) {
      const t = (y as any).ticks(5).filter((v: number) => [1, 2, 5].includes(+String(v)[0]));
      g.selectAll("line.gridline").data(t).join("line").attr("class", "gridline").attr("x1", 0).attr("x2", iw).attr("y1", (d: any) => y(d)).attr("y2", (d: any) => y(d));
      g.selectAll("text.ytick").data(t).join("text").attr("class", "tick").attr("x", -8).attr("y", (d: any) => y(d)).attr("dy", "0.32em").attr("text-anchor", "end").style("font-family", "var(--mono)").style("font-size", "11px").style("fill", "var(--muted)").text((d: any) => yf(d));
    } else yGrid(g, y, iw, yf);
    const xa = d3.axisBottom(x).ticks(Math.max(3, Math.floor(iw / 90))).tickSizeOuter(0);
    if (o.xTicks) xa.tickValues(o.xTicks as any);
    if (o.tickFormat) xa.tickFormat(o.tickFormat as any);
    const ax = g.append("g").attr("class", "axis").attr("transform", `translate(0,${ih})`).call(xa);
    ax.select(".domain").attr("stroke", "var(--axis)");
    ax.selectAll(".tick line").attr("stroke", "var(--axis)");
    if (o.baseline != null) g.append("line").attr("x1", 0).attr("x2", iw).attr("y1", y(o.baseline)).attr("y2", y(o.baseline)).attr("stroke", "var(--muted)").attr("stroke-opacity", 0.6);

    for (const s of o.series) {
      const pts = o.data.filter((r) => r[s.key] != null);
      if (o.area) {
        g.append("path").datum(pts).attr("fill", s.color).attr("fill-opacity", 0.1).attr("d", d3.area<Row>().x((r) => x(xv(r))).y0(y(Math.max(lo, o.log ? lo : 0))).y1((r) => y(r[s.key])).curve(d3.curveMonotoneX) as any);
      }
      g.append("path").datum(pts).attr("fill", "none").attr("stroke", s.color).attr("stroke-width", 2).attr("stroke-linejoin", "round").attr("stroke-linecap", "round").attr("d", d3.line<Row>().x((r) => x(xv(r))).y((r) => y(r[s.key])).curve(d3.curveMonotoneX) as any);
      if (o.dots) {
        g.selectAll(null).data(pts).join("circle").attr("cx", (r) => x(xv(r))).attr("cy", (r) => y(r[s.key])).attr("r", 4).attr("fill", s.color).attr("stroke", SURFACE).attr("stroke-width", 2);
      }
      if (o.endLabels && pts.length) {
        const last = pts[pts.length - 1];
        g.append("circle").attr("cx", x(xv(last))).attr("cy", y(last[s.key])).attr("r", 4).attr("fill", s.color).attr("stroke", SURFACE).attr("stroke-width", 2);
      }
    }
    if (o.endLabels) {
      // place labels, nudge apart to avoid overlap
      const items = o.series.map((s) => {
        const pts = o.data.filter((r) => r[s.key] != null);
        const last = pts[pts.length - 1];
        return { s, y: y(last[s.key]), v: last[s.key] };
      }).sort((a, b) => a.y - b.y);
      for (let i = 1; i < items.length; i++) if (items[i].y - items[i - 1].y < 14) items[i].y = items[i - 1].y + 14;
      for (const it of items) {
        g.append("text").attr("class", "lbl").attr("x", iw + 10).attr("y", it.y).attr("dy", "0.32em").text(`${it.s.label} ${(o.valueFormat ?? fmtInt)(it.v)}`);
      }
    }
    for (const a of o.annotations ?? []) {
      const cx = x(o.time ? new Date(a.x) : +a.x);
      const ty = a.dy ?? 4;
      g.append("line").attr("class", "annot-line").attr("x1", cx).attr("x2", cx).attr("y1", ty + 6).attr("y2", ih).attr("stroke-opacity", 0.35);
      const anchor = a.align ?? (cx > iw * 0.65 ? "end" : "start");
      g.append("text").attr("class", "annot").attr("x", cx + (anchor === "end" ? -6 : 6)).attr("y", ty + 4).attr("text-anchor", anchor).text(a.text);
    }

    if (rail) drawRail(g, (d) => (d >= ext![0] && d <= ext![1] ? x(d) : null), iw, ih);
    for (const p of o.points ?? []) {
      const px = x(p.x);
      const py = y(p.y);
      g.append("circle").attr("cx", px).attr("cy", py).attr("r", 5).attr("fill", p.color ?? "var(--text)").attr("stroke", SURFACE).attr("stroke-width", 2);
      const anchor = p.anchor ?? (px > iw * 0.6 ? "end" : "start");
      g.append("text").attr("class", "annot").attr("x", px + (p.dx ?? (anchor === "end" ? -9 : 9))).attr("y", py + (p.dy ?? 4)).attr("text-anchor", anchor).text(p.label);
    }

    // crosshair
    const cross = g.append("line").attr("y1", 0).attr("y2", ih).attr("stroke", "var(--text-2)").attr("stroke-opacity", 0.4).style("display", "none");
    const marks = g.append("g");
    const bis = d3.bisector((r: Row) => xv(r) as any).center;
    g.append("rect").attr("width", iw).attr("height", ih).attr("fill", "transparent")
      .on("pointermove", (ev: PointerEvent) => {
        const [px] = d3.pointer(ev);
        const i = bis(o.data, x.invert(px));
        const r = o.data[i];
        if (!r) return;
        const cx = x(xv(r));
        cross.attr("x1", cx).attr("x2", cx).style("display", null);
        marks.selectAll("circle").data(o.series.filter((s) => r[s.key] != null)).join("circle").attr("cx", cx).attr("cy", (s) => y(r[s.key])).attr("r", 4).attr("fill", (s) => s.color).attr("stroke", SURFACE).attr("stroke-width", 2);
        const rows = o.series.filter((s) => r[s.key] != null).map((s) => ({ label: s.label, value: (o.valueFormat ?? fmtInt)(r[s.key]), color: s.color })).sort((a, b) => (+b.value.replace(/[^0-9.-]/g, "") || 0) - (+a.value.replace(/[^0-9.-]/g, "") || 0));
        showTip(ev, o.xFormat ? o.xFormat(r[o.x]) : String(r[o.x]), rows);
      })
      .on("pointerleave", () => {
        cross.style("display", "none");
        marks.selectAll("circle").remove();
        hideTip();
      });
  };
  if (o.releases) addRailLegend(fig);
  fig.onResize(render);
}

// ---------------------------------------------------------------------------
// Horizontal bars (ranking) and dumbbells (before -> after)
// ---------------------------------------------------------------------------
export interface HBarsOpts {
  data: Row[];
  label: string;
  value: string;
  value2?: string; // dumbbell: from value2 to value
  color?: string | ((r: Row) => string);
  color2?: string;
  valueFormat?: (v: number) => string;
  rowHeight?: number;
  labelWidth?: number;
  tip?: (r: Row) => { head: string; rows: { label: string; value: string; color?: string }[] };
  log?: boolean;
  max?: number;
}

export function hbars(fig: Figure, o: HBarsOpts) {
  const render = () => {
    const rh = o.rowHeight ?? 26;
    const height = o.data.length * rh + 24;
    const { svg, w } = svgFor(fig, height);
    const lw = Math.min(o.labelWidth ?? 170, w * 0.42);
    const m = { t: 4, r: 64, b: 20, l: lw };
    const iw = w - m.l - m.r;
    const g = svg.append("g").attr("transform", `translate(${m.l},${m.t})`);
    const mx = o.max ?? d3.max(o.data, (r) => Math.max(+r[o.value] || 0, o.value2 ? +r[o.value2] || 0 : 0))!;
    const x = (o.log ? d3.scaleLog().domain([1, mx * 1.05]) : d3.scaleLinear().domain([0, mx * 1.02])).range([0, iw]).nice() as d3.ScaleLinear<number, number>;
    const ticks = o.log ? [1, 10, 100, 1000, 10000, 100000].filter((t) => t <= mx * 1.05) : x.ticks(Math.max(2, Math.floor(iw / 90)));
    g.selectAll("line.gridline").data(ticks).join("line").attr("class", "gridline").attr("x1", (d) => x(d)).attr("x2", (d) => x(d)).attr("y1", 0).attr("y2", o.data.length * rh);
    g.selectAll("text.xt").data(ticks).join("text").attr("class", "tick").attr("x", (d) => x(d)).attr("y", o.data.length * rh + 14).attr("text-anchor", "middle").style("font-family", "var(--mono)").style("font-size", "11px").style("fill", "var(--muted)").text((d) => compact(d));
    const vf = o.valueFormat ?? fmtInt;
    o.data.forEach((r, i) => {
      const yy = i * rh;
      const bh = Math.min(16, rh - 8);
      const cy = yy + rh / 2;
      const row = g.append("g");
      const name = String(r[o.label]);
      const maxChars = Math.floor((lw - 12) / 7);
      g.append("text").attr("class", "lbl").attr("x", -10).attr("y", cy).attr("dy", "0.32em").attr("text-anchor", "end").text(name.length > maxChars ? name.slice(0, maxChars - 1) + "…" : name).append("title").text(name);
      const v = +r[o.value] || 0;
      const col = typeof o.color === "function" ? o.color(r) : o.color ?? "var(--s1)";
      if (o.value2) {
        const v2 = +r[o.value2] || 0;
        const a = x(Math.max(o.log ? 1 : 0, v2));
        const b = x(Math.max(o.log ? 1 : 0, v));
        row.append("line").attr("x1", a).attr("x2", b).attr("y1", cy).attr("y2", cy).attr("stroke", "var(--axis)").attr("stroke-width", 2);
        row.append("circle").attr("cx", a).attr("cy", cy).attr("r", 5).attr("fill", o.color2 ?? "var(--other)").attr("stroke", SURFACE).attr("stroke-width", 2);
        row.append("circle").attr("cx", b).attr("cy", cy).attr("r", 5).attr("fill", col).attr("stroke", SURFACE).attr("stroke-width", 2);
        row.append("text").attr("class", "lbl strong").attr("x", Math.max(a, b) + 10).attr("y", cy).attr("dy", "0.32em").text(vf(v));
      } else {
        const x0 = o.log ? x(1) : 0;
        row.append("path").attr("d", hbarPath(x0, cy - bh / 2, Math.max(1, x(Math.max(o.log ? 1 : 0, v)) - x0), bh)).attr("fill", col);
        row.append("text").attr("class", "lbl strong").attr("x", x(Math.max(o.log ? 1 : 0, v)) + 8).attr("y", cy).attr("dy", "0.32em").text(vf(v));
      }
      row.append("rect").attr("x", -lw).attr("y", yy).attr("width", iw + lw + m.r).attr("height", rh).attr("fill", "transparent").attr("tabindex", 0)
        .on("pointermove focus", (ev: any) => {
          row.attr("filter", "brightness(1.25)");
          const t = o.tip ? o.tip(r) : { head: name, rows: [{ label: o.value, value: vf(v), color: col }] };
          const rect = (ev.target as Element).getBoundingClientRect();
          showTip(ev.clientX ? ev : { clientX: rect.left + rect.width / 2, clientY: rect.top }, t.head, t.rows);
        })
        .on("pointerleave blur", () => {
          row.attr("filter", null);
          hideTip();
        });
    });
  };
  fig.onResize(render);
}

// ---------------------------------------------------------------------------
// Radar (spider) chart
// ---------------------------------------------------------------------------
export interface RadarOpts {
  axes: { key: string; label: string; detail?: string }[];
  series: { label: string; color: string; values: Record<string, number>; raw?: Record<string, string> }[];
  height?: number;
}

export function radar(fig: Figure, o: RadarOpts) {
  const render = () => {
    const w = fig.width();
    const height = o.height ?? Math.min(520, Math.max(360, w * 0.8));
    const { svg } = svgFor(fig, height);
    const r = Math.min(w, height) / 2 - (w < 480 ? 64 : 92);
    const g = svg.append("g").attr("transform", `translate(${w / 2},${height / 2 + 6})`);
    const n = o.axes.length;
    const ang = (i: number) => (Math.PI * 2 * i) / n - Math.PI / 2;
    const rs = d3.scaleLinear().domain([0, 100]).range([0, r]);
    for (const lv of [25, 50, 75, 100]) {
      g.append("polygon").attr("points", o.axes.map((_, i) => [Math.cos(ang(i)) * rs(lv), Math.sin(ang(i)) * rs(lv)].join(",")).join(" ")).attr("fill", "none").attr("stroke", "var(--grid)");
    }
    o.axes.forEach((a, i) => {
      const xx = Math.cos(ang(i)) * r;
      const yy = Math.sin(ang(i)) * r;
      g.append("line").attr("x1", 0).attr("y1", 0).attr("x2", xx).attr("y2", yy).attr("stroke", "var(--grid)");
      const lx = Math.cos(ang(i)) * (r + 14);
      const ly = Math.sin(ang(i)) * (r + 14);
      const anchor = Math.abs(lx) < 8 ? "middle" : lx > 0 ? "start" : "end";
      const words = a.label.split(" ");
      const lines: string[] = [];
      for (const wd of words) {
        if (lines.length && (lines[lines.length - 1] + " " + wd).length <= 14) lines[lines.length - 1] += " " + wd;
        else lines.push(wd);
      }
      const t = g.append("text").attr("class", "lbl").attr("x", lx).attr("y", ly + (ly < -4 ? -(lines.length - 1) * 13 : ly > 4 ? 6 : 0)).attr("text-anchor", anchor);
      lines.forEach((ln, k) => t.append("tspan").attr("x", lx).attr("dy", k ? 13 : "0.32em").text(ln));
    });
    o.series.forEach((s) => {
      const pts = o.axes.map((a, i) => [Math.cos(ang(i)) * rs(s.values[a.key]), Math.sin(ang(i)) * rs(s.values[a.key])]);
      g.append("polygon").attr("points", pts.map((p) => p.join(",")).join(" ")).attr("fill", s.color).attr("fill-opacity", 0.12).attr("stroke", s.color).attr("stroke-width", 2).attr("stroke-linejoin", "round");
      pts.forEach((p, i) => {
        const a = o.axes[i];
        g.append("circle").attr("cx", p[0]).attr("cy", p[1]).attr("r", 4).attr("fill", s.color).attr("stroke", SURFACE).attr("stroke-width", 2);
        g.append("circle").attr("cx", p[0]).attr("cy", p[1]).attr("r", 12).attr("fill", "transparent").attr("tabindex", 0)
          .on("pointermove focus", (ev: any) => {
            const rect = (ev.target as Element).getBoundingClientRect();
            showTip(ev.clientX ? ev : { clientX: rect.right, clientY: rect.top }, a.label, o.series.map((ss) => ({ label: ss.label, value: `${Math.round(ss.values[a.key])}/100${ss.raw?.[a.key] ? "  (" + ss.raw[a.key] + ")" : ""}`, color: ss.color })));
          })
          .on("pointerleave blur", hideTip);
      });
    });
  };
  fig.onResize(render);
}
