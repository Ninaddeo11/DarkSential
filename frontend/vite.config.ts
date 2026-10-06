import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig(({ mode }) => {
  // DSN_API_PROXY lets the dev server target a backend on a non-default port.
  const env = loadEnv(mode, ".", "DSN_");
  return {
    plugins: [react()],
    server: {
      host: "127.0.0.1",
      port: 5173,
      strictPort: true,
      proxy: {
        "/api": env.DSN_API_PROXY ?? "http://127.0.0.1:8000",
      },
    },
  };
});
