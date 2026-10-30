import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { APP_BASE } from './app-path.mjs';
export default defineConfig({ base: `${APP_BASE}/`, plugins: [react()], build: { sourcemap: false }, server: { host: '127.0.0.1' } });
