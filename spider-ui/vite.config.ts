import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '');
  const apiTarget = env.VITE_API_TARGET || process.env.VITE_API_TARGET || 'http://127.0.0.1:8000';
  const devPort = parseInt(env.VITE_DEV_PORT || process.env.VITE_DEV_PORT || '5173', 10);

  return {
    plugins: [react()],
    server: {
      host: '127.0.0.1',
      port: devPort,
      strictPort: true,
      cors: false,
      fs: { strict: true, allow: ['src', 'node_modules', 'index.html'] },
      proxy: {
        '/api': {
          target: apiTarget,
          changeOrigin: false,
          followRedirects: false,
        },
      },
    },
    preview: {
      host: '127.0.0.1',
      port: 4173,
      strictPort: true,
      proxy: {
        '/api': {
          target: apiTarget,
          changeOrigin: false,
          followRedirects: false,
        },
      },
    },
    build: { sourcemap: false },
  };
});
