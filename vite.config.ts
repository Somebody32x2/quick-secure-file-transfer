import { defineConfig } from 'vite';

const API = 'http://127.0.0.1:8080';

/**
 * Mount point, e.g. BASE_PATH=/filetransfer to serve from a subpath. Vite bakes
 * this into asset URLs and exposes it as import.meta.env.BASE_URL, which
 * client/src/config.ts reads. Must match the server's BASE_PATH.
 */
function basePath(): string {
  const raw = (process.env.BASE_PATH ?? '').trim().replace(/\/+$/, '');
  if (!raw) return '/';
  return `${raw.startsWith('/') ? raw : `/${raw}`}/`;
}

export default defineConfig({
  base: basePath(),
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
