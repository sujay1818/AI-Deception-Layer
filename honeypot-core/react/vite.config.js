import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "path";

export default defineConfig({
  plugins: [react()],
  base: "/dashboard/",
  build: {
    outDir: path.resolve(__dirname, "../static/dashboard"),
    emptyOutDir: true,
  },
  server: {
    proxy: {
      "/dashboard/api": {
        target: "http://localhost:8080",
        changeOrigin: true,
      },
    },
  },
});
