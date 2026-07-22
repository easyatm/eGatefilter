import { defineConfig, loadEnv } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '')
  const apiBase = env.VITE_API_BASE || 'http://127.0.0.1:8081'
  const wsBase = env.VITE_WS_BASE || apiBase.replace(/^http/i, 'ws')

  return {
    plugins: [vue()],
    define: {
      __VUE_OPTIONS_API__: true,
      __VUE_PROD_DEVTOOLS__: false,
      __VUE_PROD_HYDRATION_MISMATCH_DETAILS__: false
    },
    server: {
      proxy: {
        '/api': apiBase,
        '/ws': {
          target: wsBase,
          ws: true
        }
      }
    }
  }
})
