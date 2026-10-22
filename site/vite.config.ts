import { defineConfig } from "vite";

// Served from https://zer0codestuff.github.io/arewecooked/ on GitHub Pages
export default defineConfig({
  base: "./",
  build: { outDir: "dist", assetsInlineLimit: 0 },
});
