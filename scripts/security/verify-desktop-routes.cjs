// Production chunk/route smoke with fixture IPC; not native Tauri validation.
const assert = require('node:assert/strict');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { chromium } = require('playwright');
const root = path.resolve(__dirname, '../..');
const origin = 'http://127.0.0.1:4173';
const routes = ['engineering', 'web-security', 'database', 'runtime', 'qa', 'ml', 'repair', 'repair-apply'];
(async () => {
  const server = spawn(process.execPath, [path.join(root, 'node_modules/vite/bin/vite.js'), 'preview', '--host', '127.0.0.1', '--port', '4173', '--strictPort'], { cwd: path.join(root, 'apps/desktop'), stdio: 'pipe' });
  let browser;
  let ready = false;
  let serverError = '';
  server.stderr.on('data', data => { serverError += data; });
  try {
    for (let attempt = 0; attempt < 100; attempt++) {
      assert.equal(server.exitCode, null, `Preview exited: ${serverError}`);
      try { await fetch(origin); ready = true; break; }
      catch { await new Promise(resolve => setTimeout(resolve, 100)); }
    }
    assert(ready, 'Production preview did not start');
    browser = await chromium.launch({ headless: true, ...(process.env.CHROMIUM_EXECUTABLE ? { executablePath: process.env.CHROMIUM_EXECUTABLE } : {}), args: ['--no-sandbox'] });
    const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
    const errors = [];
    const requests = [];
    page.on('pageerror', error => errors.push(error.message));
    page.on('request', request => requests.push(request.url()));
    await page.route('**/*', route => route.request().url().startsWith(`${origin}/`) ? route.continue() : route.abort());
    await page.addInitScript(() => {
      window.__TAURI_INTERNALS__ = { invoke: async command => {
        if (command === 'get_app_preferences') return { display_name: 'Local Developer', theme: 'light', auto_run_security_on_import: false, auto_discover_tests_on_import: false };
        if (command === 'workspace_summary') return { project_count: 0, website_count: 0, active_agents: 0, security_scan_count: 0 };
        return [];
      } };
    });
    await page.goto(`${origin}/#/dashboard`);
    await page.getByRole('heading', { name: 'Welcome to CodeTwin' }).waitFor();
    assert(!requests.some(url => /\/(App|\w+Workspace)-[^/]+\.js/.test(url)), 'Advanced chunks loaded on dashboard');
    console.log('PASS production dashboard excludes advanced chunks');
    await page.goto(`${origin}/#/security`);
    await page.getByRole('tab', { name: 'Expert Web Testing' }).click();
    const newScan = page.getByRole('button', { name: 'New Scan', exact: true });
    await newScan.click();
    const target = page.getByLabel('Target URL', { exact: true });
    const typed = 'https://staging.example.test/native focus';
    await target.pressSequentially(typed);
    assert.equal(await target.inputValue(), typed, 'Controlled modal input lost keystrokes');
    assert(await target.evaluate(element => element === document.activeElement), 'Modal rerender moved input focus');
    await target.press('Escape');
    assert.equal(await page.getByRole('dialog').count(), 0, 'Escape did not close the current modal');
    assert(await newScan.evaluate(element => element === document.activeElement), 'Modal did not restore trigger focus');
    console.log('PASS modal keeps keyboard focus across form edits and restores it on close');
    for (const route of routes) {
      await page.goto(`${origin}/#/${route}`);
      await page.locator('.ws-advanced-shell h1').first().waitFor();
      assert.equal(await page.getByText('Loading workspace…', { exact: true }).count(), 0);
      console.log(`PASS lazy workspace ${route}`);
      await page.getByRole('button', { name: '← Dashboard', exact: true }).click();
      await page.getByRole('heading', { name: 'Welcome to CodeTwin' }).waitFor();
    }
    for (const theme of ['light', 'dark']) {
      for (const width of [1440, 390]) {
        await page.setViewportSize({ width, height: 844 });
        for (const route of ['dashboard', 'projects', 'websites', 'security', 'settings']) {
          await page.goto(`${origin}/#/${route}`);
          await page.locator('.ws-content h1').first().waitFor();
          await page.evaluate(theme => document.documentElement.dataset.theme = theme, theme);
          assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false, `${route} overflows at ${width}px in ${theme}`);
        }
        await page.goto(`${origin}/#/security`);
        await page.getByRole('tab', { name: 'Expert Web Testing' }).click();
        await page.getByRole('button', { name: 'New Scan', exact: true }).click();
        await page.evaluate(theme => document.documentElement.dataset.theme = theme, theme);
        const dialog = page.getByRole('dialog');
        const start = dialog.getByRole('button', { name: 'Start Passive Scan', exact: true });
        const bounds = await start.boundingBox();
        assert(bounds && bounds.y >= 0 && bounds.y + bounds.height <= 844, 'Scan submission must stay visible');
        assert.equal(await dialog.evaluate(element => element.scrollWidth > element.clientWidth), false, 'Modal overflows horizontally');
        const colors = await dialog.locator('select').first().evaluate(element => {
          const style = getComputedStyle(element);
          return [style.color, style.backgroundColor];
        });
        assert.notEqual(colors[0], colors[1], 'Native select text must remain readable');
        await page.keyboard.press('Escape');
      }
    }
    console.log('PASS primary layouts and scrollable scan modal at desktop/mobile in light/dark');
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto(`${origin}/#/web-security`);
    await page.locator('.ws-advanced-shell h1').waitFor();
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
    assert.deepEqual(errors, []);
    console.log('PASS mobile layout and zero page errors; fixture IPC only');
  } finally {
    await browser?.close();
    server.kill();
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
