import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import path from 'path';

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
    target: 'es2022',
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (id.includes('node_modules')) {
            if (id.includes('/react-dom/') || id.includes('/react/') || id.includes('/scheduler/')) return 'vendor';
            if (id.includes('/react-router')) return 'router';
            if (id.includes('/@tanstack/react-query')) return 'query';
            if (id.includes('/recharts/') || id.includes('/d3-')) return 'charts';
            if (id.includes('/@tanstack/react-table') || id.includes('/@tanstack/react-virtual')) return 'table';
            if (id.includes('/@radix-ui/')) return 'ui';
          }
        },
      },
    },
  },
  server: {
    proxy: {
      '/api': 'http://localhost:8000',
      '/ws': { target: 'ws://localhost:8000', ws: true },
    },
  },
});
