import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/safe-view': {
        target: 'http://localhost:5000',
        changeOrigin: true,
      },
      '/api': {
        target: 'https://phishguard-production-59e7.up.railway.app',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api/, ''),
      },
    },
  },
})
