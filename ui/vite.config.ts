import { defineConfig } from "vite";
import solid from "vite-plugin-solid";

// The contents of dist/ are embedded into the server binary.
export default defineConfig({
  plugins: [solid()],
  build: {
    outDir: "dist",
    emptyOutDir: true,
    target: "es2022",
  },
});
