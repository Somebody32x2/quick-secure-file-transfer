import { defineConfig } from 'vite';

const API = 'http://127.0.0.1:8080';

export default defineConfig({
  root: 'client',
  build: {
    outDir: '../dist/public',
    emptyOutDir: true,
    target: 'es2022',
    sourcemap: true,
  },
  server: {
    // host:true so phones on the LAN can reach the dev server (the untrusted-host case)
    host: true,
    port: 5173,
    proxy: {
      '/api': { target: API, changeOrigin: false },
      '/socket.io': { target: API, ws: true, changeOrigin: false },
    },
  },
});
