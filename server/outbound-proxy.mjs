import { execFileSync } from 'node:child_process';
import { setGlobalProxyFromEnv } from 'node:http';
import path from 'node:path';

const UPSTREAM_HOST = 'admin-lm.zdhxylc.shop';

// Select the HTTPS proxy configured in Windows Internet Settings, while honoring
// explicit bypass patterns for the fixed upstream host. No credentials are logged.
export function selectWindowsProxy({ enabled, server, bypass = '' }, host = UPSTREAM_HOST) {
  if (Number(enabled) !== 1 || !server) return null;
  const bypassed = bypass.split(';').map(item => item.trim().toLowerCase()).filter(Boolean).some(pattern => {
    if (pattern === '<local>') return !host.includes('.');
    if (pattern.startsWith('<')) return false;
    const normalized = pattern.replace(/^https?:\/\//, '').replace(/:\d+$/, '');
    const expression = normalized.split('*').map(part => part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('.*');
    return new RegExp(`^${expression}$`, 'i').test(host);
  });
  if (bypassed) return null;
  const entries = server.split(';').map(item => item.trim()).filter(Boolean);
  const named = entries.some(item => item.includes('='));
  const target = named ? entries.find(item => /^https=/i.test(item))?.slice(6).trim() : entries[0];
  if (!target) return null;
  try {
    const url = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(target) ? target : `http://${target}`);
    if (!['http:', 'https:'].includes(url.protocol) || url.pathname !== '/' || url.search || url.hash) return null;
    return url.href;
  } catch { return null; }
}

function readWindowsInternetSettings() {
  const executable = path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'reg.exe');
  const key = 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings';
  function read(name) {
    try {
      const output = execFileSync(executable, ['query', key, '/v', name], { encoding: 'utf8', windowsHide: true, timeout: 3000, stdio: ['ignore', 'pipe', 'ignore'] });
      return output.match(new RegExp(`^\\s*${name}\\s+REG_\\w+\\s+(.+?)\\s*$`, 'im'))?.[1] || '';
    } catch { return ''; }
  }
  return { enabled: read('ProxyEnable'), server: read('ProxyServer'), bypass: read('ProxyOverride') };
}

export function configureOutboundProxy() {
  // An explicit HTTPS proxy takes priority over Windows Internet Settings.
  if (!process.env.HTTPS_PROXY && !process.env.https_proxy && process.platform === 'win32' && process.env.USE_WINDOWS_SYSTEM_PROXY !== '0') {
    const proxy = selectWindowsProxy(readWindowsInternetSettings());
    if (proxy) process.env.HTTPS_PROXY = proxy;
  }
  if (process.env.HTTPS_PROXY || process.env.https_proxy || process.env.HTTP_PROXY || process.env.http_proxy) setGlobalProxyFromEnv();
}
