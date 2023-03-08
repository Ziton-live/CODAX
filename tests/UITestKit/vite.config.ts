import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

function CustomHmr() {
  return {
    name: "custom-hmr",
    enforce: "post",
    // HMR
    handleHotUpdate({ file, server }) {
      if (file.endsWith(".json")) {
        console.log("reloading json file...");

        server.ws.send({
          type: "full-reload",
          path: "*",
        });
      }
    },
  };
}
// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react(), CustomHmr()],
});
