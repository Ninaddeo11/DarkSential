/// <reference types="vitest/config" />
import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig(({ mode }) => {
  // DSN_API_PROXY lets the dev server target a backend on a non-default port
  // (e.g. the virtual lab on 8010: DSN_API_PROXY=http://127.0.0.1:8010).
  const env = loadEnv(mode, ".", "DSN_");
  const target = env.DSN_API_PROXY ?? "http://127.0.0.1:8000";
  return {
    plugins: [react(), tailwindcss()],
    server: {
      host: "127.0.0.1",
      port: 5173,
      strictPort: true,
      proxy: {
        "/api/socket.io": { target, ws: true },
        "/api": target,
      },
    },
    build: {
      chunkSizeWarningLimit: 1200, // three.js lives in its own lazily loaded chunk
    },
    test: {
      environment: "node",
      include: ["src/**/*.test.ts"],
    },
  };
});
