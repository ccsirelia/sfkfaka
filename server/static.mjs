import express from 'express';
import path from 'node:path';
import { APP_BASE } from '../app-path.mjs';
export function mountProduction(app, directory) {
  const router = express.Router();
  router.use(express.static(directory, { index: false, maxAge: '1h' }));
  router.get(['/', '/recharge', '/orders', '/subscription', '/help', '/limdh-admin', '/limdh-admin/{*path}'], (_req, res) => {
    res.set('Cache-Control', 'no-cache');
    res.sendFile(path.join(directory, 'index.html'));
  });
  app.use(APP_BASE, router);
}
