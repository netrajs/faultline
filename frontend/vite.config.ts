import { fileURLToPath, URL } from 'node:url';
import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';

// Transport wiring only. Nothing here describes anything the interface displays.
//
// VITE_API_BASE_URL   path or origin the browser calls          (default: /api)
// VITE_API_PROXY      origin the dev server forwards /api to    (default: http://127.0.0.1:8000)
// VITE_DEV_PORT       port the dev server listens on            (default: 5173)
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), 'VITE_');
  const proxyTarget = env.VITE_API_PROXY || 'http://127.0.0.1:8000';
  const devPort = Number(env.VITE_DEV_PORT || 5173);

  return {
    plugins: [react()],
    resolve: {
      alias: {
        '@': fileURLToPath(new URL('./src', import.meta.url)),
      },
    },
    server: {
      port: devPort,
      // Listen on all local hostnames, not just localhost/127.0.0.1 -- lets
      // the dev server answer to a custom hosts-file entry (e.g. "faultline")
      // so the address bar can show the project's name instead of localhost.
      host: true,
      allowedHosts: ['faultline', 'faultline.local', 'localhost'],
      // The API is served from a separate process during development. Proxying
      // keeps the browser on one origin, so there is no CORS configuration to
      // keep in step between the two codebases.
      proxy: {
        '/api': {
          target: proxyTarget,
          changeOrigin: true,
        },
      },
    },
    build: {
      outDir: 'dist',
      sourcemap: true,
      chunkSizeWarningLimit: 900,
    },
  };
});
