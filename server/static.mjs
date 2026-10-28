import express from 'express';
import path from 'node:path';
export function mountProduction(app, directory) {
  app.use(express.static(directory, { index: false, maxAge: '1h' }));
  app.get(['/', '/recharge', '/orders', '/help', '/limdh-admin', '/limdh-admin/{*path}'], (_req, res) => {
    res.set('Cache-Control', 'no-cache');
    res.sendFile(path.join(directory, 'index.html'));
  });
}
