import { fileURLToPath, URL } from 'node:url'

import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// Сборка кладётся в web/static/dist и раздаётся бэкендом по /static/dist/.
// В dev-режиме запросы /api проксируются на FastAPI, поэтому cookie и CSRF
// работают с того же origin.
export default defineConfig({
  plugins: [react()],
  base: '/static/dist/',
  build: {
    outDir: fileURLToPath(new URL('../static/dist', import.meta.url)),
    emptyOutDir: true,
    sourcemap: false,
    target: 'es2020',
  },
  server: {
    host: '127.0.0.1',
    port: 5173,
    strictPort: false,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: false,
      },
    },
  },
  preview: {
    host: '127.0.0.1',
    port: 4173,
  },
})
