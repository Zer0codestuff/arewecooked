const intFmt = new Intl.NumberFormat("en-US");

export const fmtInt = (v: number) => (v == null || Number.isNaN(v) ? "n/a" : intFmt.format(Math.round(v)));

export function compact(v: number): string {
  if (v == null || Number.isNaN(v)) return "";
  const a = Math.abs(v);
  if (a >= 1e9) return `${+(v / 1e9).toFixed(a >= 1e10 ? 0 : 1)}B`;
  if (a >= 1e6) return `${+(v / 1e6).toFixed(a >= 1e7 ? 0 : 1)}M`;
  if (a >= 1e3) return `${+(v / 1e3).toFixed(a >= 1e4 ? 0 : 1)}K`;
  if (a > 0 && a < 1) return `${+v.toFixed(2)}`;
  return `${+v.toFixed(1)}`;
}

export const pct = (v: number, d = 0) => (v == null ? "n/a" : `${(v * 100).toFixed(d)}%`);

export const usdB = (v: number) => `$${v >= 100 ? v.toFixed(0) : v.toFixed(1)}B`;
export const usdM = (v: number) => `$${v.toFixed(2)}M`;

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

export function monthLabel(iso: string, withYear = true): string {
  const d = new Date(iso);
  return withYear ? `${MONTHS[d.getUTCMonth()]} ${d.getUTCFullYear()}` : MONTHS[d.getUTCMonth()];
}

export function shortMonth(iso: string): string {
  const d = new Date(iso);
  return d.getUTCMonth() === 0 ? String(d.getUTCFullYear()) : MONTHS[d.getUTCMonth()];
}

export const ratio = (a: number, b: number) => (b ? a / b : NaN);

export function times(a: number, b: number): string {
  const r = a / b;
  return r >= 10 ? `${Math.round(r)}x` : `${r.toFixed(1)}x`;
}
