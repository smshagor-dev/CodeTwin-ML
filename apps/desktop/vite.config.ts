import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  // Use a fixed IPv4 loopback address so Tauri and Vite agree on Windows.
  server: { host: "127.0.0.1", port: 5173, strictPort: true },
});
