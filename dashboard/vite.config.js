import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'

// En développement, Vite proxifie /api et /ws vers l'API FastAPI. Le navigateur
// ne voit donc qu'une seule origine (localhost:5173), exactement comme en
// production derrière nginx : les cookies de session HttpOnly fonctionnent et
// aucune URL d'API n'est codée en dur dans le code React.
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '')
  const target = env.VITE_DEV_API_TARGET || 'http://127.0.0.1:8000'

  return {
    plugins: [react()],
    server: {
      // host: true écoute sur toutes les interfaces (IPv4 comprise) : un
      // collègue sur une autre machine du réseau peut ouvrir la console en
      // développement, ce que le défaut `localhost` (IPv6 uniquement) empêche.
      host: true,
      port: 5173,
      // Sans cela, Vite bascule silencieusement sur 5174 quand 5173 est occupé
      // par un ancien processus : on croit recharger le nouveau code alors
      // qu'on regarde l'ancien serveur.
      strictPort: true,
      proxy: {
        '/api': {
          target,
          changeOrigin: true,
          rewrite: (path) => path.replace(/^\/api/, ''),
        },
        '/ws': {
          target: target.replace(/^http/, 'ws'),
          ws: true,
          changeOrigin: true,
        },
      },
    },
    build: {
      outDir: 'dist',
      sourcemap: false,
    },
  }
})
