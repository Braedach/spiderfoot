import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
import path from 'path';
import { sriPlugin } from './src/plugins/vite-plugin-sri';

export default defineConfig({
  plugins: [react(), sriPlugin()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: './src/__tests__/setup.ts',
    include: ['src/**/*.{test,spec}.{ts,tsx}'],
    css: false,
  },
  server: {
    port: 3000,
    proxy: {
      // Anchored to the trailing slash so this only ever matches a real
      // API call (/api/scans, /api/config, ...) — an unanchored '/api'
      // prefix also matches the frontend route /api-keys and sends it to
      // the backend instead of the SPA, a 401 JSON page where the UI
      // should be.
      '^/api/': {
        target: 'https://localhost',
        changeOrigin: true,
        secure: false,
      },
      '^/ws/': {
        target: 'wss://localhost',
        ws: true,
        secure: false,
      },
    },
  },
  build: {
    outDir: '../spiderfoot/static/react',
    emptyOutDir: true,
    sourcemap: false,
  },
});
