// Production UI behavior with fixture IPC. Native command validation is separate.
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const { spawn } = require('node:child_process');
const { chromium } = require('playwright');
const root = path.resolve(__dirname, '../..');
const origin = 'http://127.0.0.1:4174';
(async () => {
  const server = spawn(process.execPath, [path.join(root, 'node_modules/vite/bin/vite.js'), 'preview', '--host', '127.0.0.1', '--port', '4174', '--strictPort'], { cwd: path.join(root, 'apps/desktop'), stdio: 'pipe' });
  let browser;
  try {
    for (let n = 0; n < 100; n++) {
      assert.equal(server.exitCode, null);
      try { await fetch(origin); break; } catch { await new Promise(resolve => setTimeout(resolve, 100)); }
    }
    browser = await chromium.launch({ headless: true, ...(process.env.CHROMIUM_EXECUTABLE ? { executablePath: process.env.CHROMIUM_EXECUTABLE } : {}), args: ['--no-sandbox'] });
    const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    await page.addInitScript(() => {
      window.fixture = { empty: sessionStorage.getItem('codetwinFixtureEmpty') === 'true', fail: false, slow: false, scan: 0, discovery: 0, reads: [] };
      const date = '2026-10-11T05:00:00Z';
      const projects = ['a', 'b'].map((id, i) => ({ id, display_name: i ? 'Secondary project' : 'Validation project', root_path: '/local/' + id, path_identity: id, git_remote: null, last_opened_at: date, last_indexed_at: date, file_count: i ? 4 : 12, symbol_count: i ? 7 : 31, language_count: 1, last_index_status: 'completed', last_index_duration_ms: 420 }));
      window.__TAURI_INTERNALS__ = { invoke: async (command, args = {}) => {
        const f = window.fixture;
        if (command === 'get_app_preferences') return { display_name: 'Local Developer', theme: 'light', auto_run_security_on_import: false, auto_discover_tests_on_import: false };
        if (command === 'list_projects') return f.empty ? [] : projects;
        if (command === 'workspace_summary') return { project_count: f.empty ? 0 : 2, website_count: 0, active_agents: 0, security_scan_count: f.scan };
        if (command === 'system_status') return ['backend', 'database', 'indexer'].map(key => ({ key, label: key, state: 'operational', detail: 'Fixture IPC status' }));
        if (command === 'run_security_analysis' || command === 'run_qa_discovery') {
          if (command === 'run_security_analysis') f.scan++; else f.discovery++;
          await new Promise(resolve => setTimeout(resolve, 250));
          return {};
        }
        if (['list_security_findings', 'security_history', 'qa_discovery_history', 'list_project_files'].includes(command)) {
          const id = args.projectId;
          f.reads.push(id + ':' + command);
          if (f.slow && id === 'a') await new Promise(resolve => setTimeout(resolve, 400));
          if (command === 'list_security_findings') {
            if (f.fail) throw new Error('Fixture evidence read failed');
            return [{ id: id + '-finding', project_id: id, title: id === 'a' ? 'Validation finding' : 'Secondary finding', severity: 'high', file_id: id + '-file', source_start_line: 9, status: 'open', last_seen: date }];
          }
          if (command === 'list_project_files') return [{ id: id + '-file', relative_path: 'src/' + id + '.ts', language: 'typescript' }];
          return [{ run_id: id + command, project_id: id, status: 'completed', started_at: date, finished_at: date, duration_ms: 1200, coverage_complete: command === 'security_history' }];
        }
        return [];
      } };
    });
    await page.goto(origin + '/#/dashboard');
    await page.getByRole('button', { name: 'Validation finding', exact: true }).waitFor();
    assert.equal(await page.locator('.ws-overview-metrics dd').nth(0).innerText(), '12');
    assert.equal(await page.locator('.ws-overview-metrics dd').nth(1).innerText(), '31');
    assert(await page.getByText('src/a.ts:9', { exact: true }).count());
    assert(await page.getByText('Coverage incomplete', { exact: true }).count());
    await page.getByRole('button', { name: 'Run Security Scan', exact: true }).click();
    assert(await page.getByRole('button', { name: 'Discover Tests', exact: true }).isDisabled());
    await page.getByRole('button', { name: 'Run Security Scan', exact: true }).waitFor();
    await page.waitForFunction(() => document.querySelector('.ws-overview-finding-link')?.textContent === 'Validation finding');
    assert.equal(await page.evaluate(() => window.fixture.scan), 1);
    await page.getByRole('button', { name: 'Discover Tests', exact: true }).click();
    await page.getByRole('button', { name: 'Discover Tests', exact: true }).waitFor();
    assert.equal(await page.evaluate(() => window.fixture.discovery), 1);
    console.log('PASS persisted metrics, paths, incomplete coverage and explicit scan/discovery actions');
    await page.evaluate(() => { window.fixture.slow = true; });
    await page.getByLabel('Active project', { exact: true }).selectOption('b');
    await page.getByRole('button', { name: 'Secondary finding', exact: true }).waitFor();
    const previousReads = await page.evaluate(() => window.fixture.reads.filter(x => x === 'a:list_security_findings').length);
    await page.getByLabel('Active project', { exact: true }).selectOption('a');
    await page.waitForFunction(previous => window.fixture.reads.filter(x => x === 'a:list_security_findings').length > previous, previousReads);
    await page.getByLabel('Active project', { exact: true }).selectOption('b');
    await page.getByRole('button', { name: 'Secondary finding', exact: true }).waitFor();
    await page.waitForTimeout(500);
    assert.equal(await page.getByRole('button', { name: 'Validation finding', exact: true }).count(), 0);
    console.log('PASS late project response cannot overwrite selected project evidence');
    await page.evaluate(() => { window.fixture.slow = false; window.fixture.fail = true; });
    await page.getByLabel('Active project', { exact: true }).selectOption('a');
    await page.getByText('Evidence unavailable', { exact: true }).waitFor();
    assert(await page.getByText('Findings could not be loaded. Retry the evidence read.', { exact: true }).count());
    await page.evaluate(() => { window.fixture.fail = false; });
    await page.getByRole('button', { name: 'Retry', exact: true }).click();
    await page.getByRole('button', { name: 'Validation finding', exact: true }).waitFor();
    assert.equal(await page.getByText('Evidence unavailable', { exact: true }).count(), 0);
    console.log('PASS failed evidence stays explicit and retry recovers');
    await page.getByRole('button', { name: 'Validation finding', exact: true }).click();
    assert.equal(await page.getByRole('tab', { name: 'Static Source Analysis', exact: true }).getAttribute('aria-selected'), 'true');
    await page.goto(origin + '/#/dashboard');
    await page.getByRole('button', { name: 'Validation finding', exact: true }).waitFor();
    await page.locator('.ws-sidebar-tools summary').click();
    assert.equal(await page.locator('.ws-sidebar-tools a:visible').count(), 8);
    await page.locator('.ws-sidebar-tools summary').click();
    console.log('PASS findings open source analysis and advanced tools stay reachable');
    for (const theme of ['light', 'dark']) {
      for (const width of [1440, 390]) {
        await page.setViewportSize({ width, height: 900 });
        await page.evaluate(theme => document.documentElement.dataset.theme = theme, theme);
        await page.waitForTimeout(200); // Let the existing theme transitions settle.
        assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
        if (process.env.OVERVIEW_SCREENSHOTS) {
          fs.mkdirSync(process.env.OVERVIEW_SCREENSHOTS, { recursive: true });
          await page.screenshot({ path: path.join(process.env.OVERVIEW_SCREENSHOTS, `${theme}-${width}.png`), fullPage: true });
        }
      }
    }
    console.log('PASS populated overview light/dark and desktop/narrow layouts');
    await page.evaluate(() => sessionStorage.setItem('codetwinFixtureEmpty', 'true'));
    await page.reload();
    await page.getByRole('heading', { name: 'Add your first project', exact: true }).waitFor();
    assert(await page.getByRole('button', { name: 'Run Security Scan', exact: true }).isDisabled());
    assert(await page.getByRole('button', { name: 'Discover Tests', exact: true }).isDisabled());
    assert.equal(errors.length, 0, errors.join('\n'));
    console.log('PASS empty workspace disables project operations; no browser errors');
  } finally { await browser?.close(); server.kill('SIGTERM'); }
})().catch(error => { console.error(error); process.exitCode = 1; });
