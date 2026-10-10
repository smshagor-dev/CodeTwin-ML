// Loopback-only browser CORS controls. Playwright from NODE_PATH.
const assert = require('node:assert/strict');
const http = require('node:http');
const { chromium } = require('playwright');
const listen = server => new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
(async () => {
  const observations = [];
  const target = http.createServer((req, res) => {
    const mode = req.url.slice(1);
    const origin = req.headers.origin || '';
    observations.push({ method: req.method, cookie: req.headers.cookie, mode });
    const headers = { 'Content-Type': 'application/json', 'Access-Control-Allow-Methods': 'GET', 'Access-Control-Allow-Headers': 'X-Probe' };
    if (req.method === 'OPTIONS' || mode !== 'preflight-only') {
      headers['Access-Control-Allow-Origin'] = mode === 'wildcard' ? '*' : origin;
      headers['Access-Control-Allow-Credentials'] = mode === 'uppercase' ? 'TRUE' : 'true';
    }
    res.writeHead(200, headers); res.end(JSON.stringify({ record: 'loopback-private-control' }));
  });
  const pages = [0, 1].map(() => http.createServer((req, res) => { res.writeHead(200, { 'Content-Type': 'text/html' }); res.end('<!doctype html><title>CORS local lab</title>'); }));
  let browser;
  try {
    await listen(target); for (const server of pages) await listen(server);
    const api = `http://127.0.0.1:${target.address().port}`;
    const origins = pages.map(server => `http://127.0.0.1:${server.address().port}`);
    browser = await chromium.launch({ headless: true, ...(process.env.CHROMIUM_EXECUTABLE ? { executablePath: process.env.CHROMIUM_EXECUTABLE } : {}), args: ['--no-sandbox'] });
    const context = await browser.newContext();
    await context.addCookies([{ name: 'session', value: 'local-lab-session', url: api, sameSite: 'Lax' }]);
    await context.route('**/*', route => [api, ...origins].some(origin => route.request().url().startsWith(`${origin}/`)) ? route.continue() : route.abort());
    const page = await context.newPage();
    for (const origin of origins) {
      await page.goto(origin);
      for (const mode of ['reflect', 'wildcard', 'uppercase', 'preflight-only']) {
        const result = await page.evaluate(async ({ api, mode }) => {
          try { const response = await fetch(`${api}/${mode}`, { credentials: 'include', headers: { 'X-Probe': 'local' } }); return (await response.json()).record; }
          catch { return 'blocked'; }
        }, { api, mode });
        assert.equal(result, mode === 'reflect' ? 'loopback-private-control' : 'blocked', `${origin} ${mode}`);
        console.log(`PASS ${mode}: ${result}`);
      }
    }
    assert(observations.filter(r => r.method === 'OPTIONS').every(r => !r.cookie), 'preflight must be credential-free');
    assert(observations.some(r => r.method === 'GET' && r.cookie?.includes('local-lab-session')), 'credentialed actual GET control');
    console.log(`Verified 8 CORS browser cases with Chromium ${browser.version()}; all traffic stayed on loopback.`);
  } finally {
    if (browser) await browser.close();
    for (const server of [target, ...pages]) if (server.listening) await new Promise(resolve => server.close(resolve));
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
