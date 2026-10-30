// Shared by the browser, server and build so every service URL has the same prefix.
export const APP_BASE = '/kmdh';
export const appPath = (path = '/') => `${APP_BASE}${path}`;
export function pagePath(pathname) {
  if (pathname === APP_BASE) return '/';
  return pathname.startsWith(`${APP_BASE}/`) ? pathname.slice(APP_BASE.length) : pathname;
}
