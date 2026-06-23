import { defineConfig } from "vite";
import { svelte, vitePreprocess } from "@sveltejs/vite-plugin-svelte";

const ORCHESTRATOR = process.env.DEMO_SERVER_URL ?? "http://localhost:4040";

// Dev: Vite serves the SPA and proxies the API + Proof callback to the
// orchestrator (so the browser only ever talks to one origin — no CORS).
// Build: emits to ./dist, which the orchestrator serves in production.
export default defineConfig({
  plugins: [svelte({ preprocess: vitePreprocess({ script: true }) })],
  server: {
    port: 5173,
    proxy: {
      "/api": ORCHESTRATOR,
      "/proof": ORCHESTRATOR,
    },
  },
  build: { outDir: "dist", emptyOutDir: true },
});
