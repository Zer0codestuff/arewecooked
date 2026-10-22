// Building blocks for the long-form page.
import { el } from "./figure";

export const C = {
  s1: "#34a870",
  s2: "#d95926",
  s3: "#3987e5",
  s4: "#d55181",
  s5: "#c98500",
  s6: "#9085e9",
  s7: "#e66767",
  other: "#4b524e",
  dim: "#2b3a33",
  // ordinal ramps (validated, dark surface)
  sev: { LOW: "#8a3d1d", MEDIUM: "#b54a20", HIGH: "#e0662f", CRITICAL: "#f59a6e" } as Record<string, string>,
  green: ["#1f6e47", "#2a8a5a", "#34a870", "#62c995"],
};

export interface ChapterOpts {
  id: string;
  num: string;
  title: string;
  kicker: string;
}

export function chapter(main: HTMLElement, o: ChapterOpts): HTMLElement {
  const sec = el("section", "chapter");
  sec.id = o.id;
  const head = el("div", "chapter-head");
  const num = el("div", "num");
  num.textContent = `[${o.num}] ${o.id.toUpperCase()}`;
  const h = el("h2");
  h.textContent = o.title;
  const k = el("p", "kicker");
  k.textContent = o.kicker;
  head.append(num, h, k);
  sec.appendChild(head);
  main.appendChild(sec);
  return sec;
}

/** Trusted, author-written HTML only (no data strings). */
export function prose(parent: HTMLElement, html: string): HTMLElement {
  const d = el("div", "prose", html);
  parent.appendChild(d);
  return d;
}

export function callout(parent: HTMLElement, tag: string, html: string) {
  const w = el("div", "callout");
  const inner = el("div", "", `<span class="tag">${tag}</span>${html}`);
  w.appendChild(inner);
  parent.appendChild(w);
}

export function divider(parent: HTMLElement, text = "") {
  const pat = "─".repeat(28);
  const d = el("div", "divider");
  d.textContent = text ? `${pat}[ ${text} ]${pat}` : `${pat}${"─".repeat(10)}${pat}`;
  parent.appendChild(d);
}

export function grid2(parent: HTMLElement): HTMLElement {
  const g = el("div", "grid-2");
  parent.appendChild(g);
  return g;
}

export const link = (url: string, text: string) => `<a href="${url}" target="_blank" rel="noopener">${text}</a>`;
