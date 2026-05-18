import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    host: '0.0.0.0',
    allowedHosts: [
      'localhost',
      '127.0.0.1',
      '.ngrok-free.app',
      '.ngrok.app',
    ],
    proxy: {
      '/ingest': {
        target: 'http://127.0.0.1:9000',
        changeOrigin: true,
      },
      '/ml': {
        target: 'http://127.0.0.1:9000',
        changeOrigin: true,
      },
      '/agent': {
        target: 'http://127.0.0.1:9000',
        changeOrigin: true,
      },
      '/health': {
        target: 'http://127.0.0.1:9000',
        changeOrigin: true,
      },
    },
  },
})
