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

load().then((d) => {
  const main = document.getElementById("app")!;
  main.replaceChildren();
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
});
