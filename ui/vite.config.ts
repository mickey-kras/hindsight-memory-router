import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { defineConfig } from "vite";

// Dev proxy mirrors the production nginx shape: the UI is same-origin with the
// router admin API, so no CORS and no router changes are required.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    proxy: {
      "/admin": "http://127.0.0.1:8899",
      "/health": "http://127.0.0.1:8899",
      "/version": "http://127.0.0.1:8899",
    },
  },
});
