// Run with Playwright available in NODE_PATH; optionally set CHROMIUM_EXECUTABLE.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const { chromium } = require('playwright');
const fixtures = JSON.parse(fs.readFileSync(path.join(__dirname, '../../crates/web-security-testing/tests/fixtures/xss-contexts.json'), 'utf8'));
(async () => {
  const server = http.createServer((req, res) => {
    const fixture = fixtures.find(case_ => `/${case_.name}` === req.url);
    if (!fixture) { res.writeHead(404); res.end(); return; }
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(fixture.body);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  let browser;
  try {
    browser = await chromium.launch({ headless: true, ...(process.env.CHROMIUM_EXECUTABLE ? { executablePath: process.env.CHROMIUM_EXECUTABLE } : {}), args: ['--no-sandbox'] });
    const page = await browser.newPage();
    const origin = `http://127.0.0.1:${server.address().port}`;
    await page.route('**/*', route => route.request().url().startsWith(`${origin}/`) ? route.continue() : route.abort());
    for (const fixture of fixtures) {
      await page.goto(`${origin}/${fixture.name}`);
      assert.equal(await page.locator('codetwin-xss-lab').count() > 0, fixture.dom, fixture.name);
      if (fixture.context === 'attribute') {
        assert.equal(await page.locator('[title], [onclick]').first().evaluate(el => [...el.attributes].some(attr => attr.value.includes('<codetwin-xss-lab>'))), true, fixture.name);
      }
      console.log(`PASS ${fixture.name}: DOM marker=${fixture.dom}`);
    }
    console.log(`Verified ${fixtures.length} local HTTP fixtures with ${browser.version()}; harmless reflection markers only.`);
  } finally { if (browser) await browser.close(); await new Promise(resolve => server.close(resolve)); }
})().catch(error => { console.error(error); process.exitCode = 1; });
