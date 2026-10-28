import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createApp } from './app.mjs';
import { loadConfig } from './security.mjs';
import { mountProduction } from './static.mjs';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const config = loadConfig();
const runtime = createApp({ config });
const { app } = runtime;
app.get(['/admin', '/admin/{*path}'], (_req, res) => res.status(404).type('text').send('Not Found'));
if (config.production) {
  mountProduction(app, path.join(root, 'dist'));
} else {
  const { createServer } = await import('vite');
  const vite = await createServer({ server: { middlewareMode: true }, appType: 'spa' });
  app.use((_req, res, next) => {
    // Vite HMR uses an inline bootstrap and WebSocket in local development only.
    res.set('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self' ws:; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'"); next();
  });
  app.use(vite.middlewares);
}
app.use(runtime.errorHandler);
const port = Number(process.env.PORT || 3200);
const host = process.env.HOST || '127.0.0.1';
const server = app.listen(port, host, () => console.log(`LIMEN running at ${config.origin}${config.production ? '' : ' (development)'}`));
const stop = () => server.close(() => { runtime.close(); process.exit(0); });
process.on('SIGINT', stop); process.on('SIGTERM', stop);
