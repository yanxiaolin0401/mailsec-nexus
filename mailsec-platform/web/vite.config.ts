import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
declare const process: { env: Record<string, string | undefined> }
const apiSocket = process.env.PLATFORM_API_SOCKET || decodeURIComponent(new URL('../.local/platform-api.sock', import.meta.url).pathname)

export default defineConfig({
  plugins: [react()],
  server: {
    // Keep Vite's default deny rules when extending them: this root also holds
    // deployment files, which must never enter the JavaScript transform pipeline.
    fs: { deny: ['.env', '.env.*', '*.{crt,pem}', '**/.git/**', 'Dockerfile', '.dockerignore', 'nginx.conf'] },
    proxy: { '/api': { target: { socketPath: apiSocket } as unknown as string } },
  },
})
