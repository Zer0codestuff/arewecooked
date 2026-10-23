import "./style.css";
import { renderHero } from "./sections/hero";
import { renderFlood } from "./sections/flood";
import { renderNoise } from "./sections/noise";
import { renderHunters } from "./sections/hunters";
import { renderSpeed } from "./sections/speed";
import { renderTarget } from "./sections/target";
import { renderDamage } from "./sections/damage";
import { renderMoney } from "./sections/money";
import { renderPeople } from "./sections/people";
import { renderVerdict } from "./sections/verdict";
import { renderMethod } from "./sections/method";
import { setReleases } from "./lib/charts";

export interface Data {
  vulns: any;
  threats: any;
  supplychain: any;
  breaches: any;
  markets: any;
  context: any;
  glasswing: any;
  nvd: any;
}

const FILES = ["vulns", "threats", "supplychain", "breaches", "markets", "context", "glasswing", "nvd"] as const;

async function load(): Promise<Data> {
  const out: any = {};
  await Promise.all(
    FILES.map(async (f) => {
      const r = await fetch(`./data/${f}.json`);
      out[f] = await r.json();
    }),
  );
  return out as Data;
}

function navSpy() {
  const links = [...document.querySelectorAll<HTMLAnchorElement>(".topbar nav a")];
  const io = new IntersectionObserver(
    (entries) => {
      for (const e of entries) {
        if (e.isIntersecting) {
          links.forEach((a) => a.classList.toggle("active", a.getAttribute("href") === `#${e.target.id}`));
        }
      }
    },
    { rootMargin: "-40% 0px -55% 0px" },
  );
  document.querySelectorAll("section.chapter").forEach((s) => io.observe(s));
}

function progress() {
  const bar = document.querySelector<HTMLElement>(".progress i");
  if (!bar) return;
  let queued = false;
  const update = () => {
    queued = false;
    const max = document.documentElement.scrollHeight - innerHeight;
    bar.style.transform = `scaleX(${max > 0 ? Math.min(1, scrollY / max) : 0})`;
  };
  addEventListener("scroll", () => {
    if (!queued) {
      queued = true;
      requestAnimationFrame(update);
    }
  }, { passive: true });
  update();
}

function reveal() {
  if (matchMedia("(prefers-reduced-motion: reduce)").matches || !("IntersectionObserver" in window)) return;
  const io = new IntersectionObserver(
    (entries) => {
      for (const e of entries) {
        if (e.isIntersecting) {
          e.target.classList.add("in");
          io.unobserve(e.target);
        }
      }
    },
    { rootMargin: "0px 0px -8% 0px" },
  );
  document.querySelectorAll(".figure").forEach((f) => {
    if (f.getBoundingClientRect().top > innerHeight) {
      f.classList.add("reveal");
      io.observe(f);
    }
  });
}

load().then((d) => {
  const main = document.getElementById("app")!;
  main.replaceChildren();
  setReleases(d.context.releases ?? []);
  renderHero(main, d);
  renderFlood(main, d);
  renderNoise(main, d);
  renderHunters(main, d);
  renderSpeed(main, d);
  renderTarget(main, d);
  renderDamage(main, d);
  renderMoney(main, d);
  renderPeople(main, d);
  renderVerdict(main, d);
  renderMethod(main, d);
  navSpy();
  progress();
  reveal();
});
