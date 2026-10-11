// Production UI checks with fixture IPC; native registry/summary tests are separate.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { chromium } = require('playwright');
const root = path.resolve(__dirname, '../..');
const metadata = JSON.parse(fs.readFileSync(path.join(root, 'crates/codetwin-core/src/tool_catalog.json'), 'utf8'));
const origin = 'http://127.0.0.1:4174';
(async () => {
  const server = spawn(process.execPath, [path.join(root, 'node_modules/vite/bin/vite.js'), 'preview', '--host', '127.0.0.1', '--port', '4174', '--strictPort'], { cwd: path.join(root, 'apps/desktop'), stdio: 'pipe' });
  let browser;
  try {
    for (let i = 0; i < 100; i++) {
      assert.equal(server.exitCode, null);
      try { await fetch(origin); break; } catch { await new Promise(resolve => setTimeout(resolve, 100)); }
    }
    browser = await chromium.launch({ headless: true, ...(process.env.CHROMIUM_EXECUTABLE ? { executablePath: process.env.CHROMIUM_EXECUTABLE } : {}), args: ['--no-sandbox'] });
    const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    await page.addInitScript(metadata => {
      window.fixture = { commands: [], fail: false, historyFailed: false, slow: false };
      const date = '2026-10-11T10:00:00Z';
      const projects = ['a', 'b'].map(id => ({ id, display_name: 'Project ' + id, root_path: '/local/' + id, file_count: 1, symbol_count: 1, language_count: 1, last_index_status: 'completed', last_indexed_at: date }));
      window.__TAURI_INTERNALS__ = { invoke: async (command, args = {}) => {
        const f = window.fixture; f.commands.push(command);
        if (command === 'list_projects') return projects;
        if (command === 'get_app_preferences') return { display_name: 'Developer', theme: 'light', auto_run_security_on_import: false, auto_discover_tests_on_import: false };
        if (command === 'workspace_summary') return { project_count: 2, website_count: 0, active_agents: 0, security_scan_count: 0 };
        if (command === 'list_security_tools') {
          const fail = f.fail;
          if (f.slow && args.projectId === 'a') await new Promise(resolve => setTimeout(resolve, 500));
          if (fail) throw new Error('Registry read failed');
          return metadata.map(item => ({ ...item, name: item.id === 'code.sast' && args.projectId === 'b' ? 'Secondary security review' : item.name, definition_version: 1, availability: item.id === 'code.sast' ? 'available' : item.id === 'code.semantics' ? 'requires_setup' : item.id === 'qa.execution' ? 'blocked' : 'planned', reason: item.id === 'qa.execution' ? 'Strict backend unavailable' : 'Fixture prerequisites', operation_kind: item.id === 'code.sast' ? 'passive' : 'unavailable', prerequisites: ['Fixture input'], platforms: ['Fixture desktop'], coverage: 'Fixture coverage', workflow: 'security', setup_workflow: item.id === 'code.semantics' ? 'integrations' : null }));
        }
        if (command === 'recent_security_tool_runs') {
          if (f.historyFailed) throw new Error('Run store unavailable');
          return [{ id: args.projectId + '-scan', source: 'analysis', project_id: args.projectId, kind: args.projectId === 'b' ? 'secondary_analysis' : 'security_analysis', status: 'completed', started_at: date, finished_at: date, duration_ms: 22, tests_passed: null }];
        }
        return [];
      } };
    }, metadata);
    await page.goto(origin + '/#/tools');
    await page.getByRole('article', { name: 'Source security review', exact: true }).waitFor();
    assert.equal(await page.locator('.ws-tool-card').count(), 41);
    await page.getByText('No test verdict', { exact: false }).waitFor();
    const blocked = page.getByRole('article', { name: 'Sandboxed test execution', exact: true });
    assert.equal(await blocked.getByRole('button', { name: 'Unavailable' }).isDisabled(), true);
    const planned = page.getByRole('article', { name: 'Disposable VM analysis', exact: true });
    assert.equal(await planned.getByRole('button', { name: 'Unavailable' }).isDisabled(), true);
    await page.getByLabel('Search tools', { exact: true }).fill('Source security');
    assert.equal(await page.locator('.ws-tool-card').count(), 1);
    await page.getByLabel('Availability', { exact: true }).selectOption('planned');
    await page.getByText('No tools match these filters.', { exact: true }).waitFor();
    await page.getByLabel('Availability', { exact: true }).selectOption('');
    await page.getByLabel('Search tools', { exact: true }).fill('');
    await page.getByLabel('Category', { exact: true }).selectOption('Network');
    assert.equal(await page.locator('.ws-tool-card').count(), 4);
    await page.getByLabel('Category', { exact: true }).selectOption('');
    await page.getByRole('article', { name: 'Language-server enrichment', exact: true }).getByRole('button', { name: 'Set up' }).click();
    await page.getByRole('heading', { name: 'Integrations', exact: true }).waitFor();
    await page.goto(origin + '/#/tools');
    await page.getByRole('article', { name: 'Source security review', exact: true }).getByRole('button', { name: 'Open workflow' }).click();
    assert.equal(await page.getByRole('tab', { name: 'Static Source Analysis' }).getAttribute('aria-selected'), 'true');
    await page.goto(origin + '/#/tools');
    await page.getByRole('article', { name: 'Source security review', exact: true }).waitFor();
    await page.evaluate(() => { window.fixture.historyFailed = true; });
    await page.getByRole('button', { name: 'Refresh availability', exact: true }).click();
    await page.getByRole('alert').filter({ hasText: 'Run store unavailable' }).waitFor();
    assert.equal(await page.locator('.ws-tool-card').count(), 41);
    await page.evaluate(() => { window.fixture.historyFailed = false; window.fixture.fail = true; });
    await page.getByRole('button', { name: 'Refresh availability', exact: true }).click();
    await page.getByRole('alert').filter({ hasText: 'Registry read failed' }).waitFor();
    assert.equal(await page.locator('.ws-tool-card').count(), 0);
    await page.evaluate(() => { window.fixture.fail = false; });
    await page.getByRole('button', { name: 'Refresh availability', exact: true }).click();
    await page.getByRole('article', { name: 'Source security review', exact: true }).waitFor();
    await page.evaluate(() => { window.fixture.slow = true; });
    await page.getByRole('button', { name: 'Refresh availability', exact: true }).click();
    await page.getByLabel('Project', { exact: true }).selectOption('b');
    await page.getByRole('article', { name: 'Secondary security review', exact: true }).waitFor();
    await page.waitForTimeout(600);
    assert.equal(await page.getByRole('article', { name: 'Source security review', exact: true }).count(), 0);
    await page.getByText('secondary analysis', { exact: true }).waitFor();
    for (const theme of ['light', 'dark']) {
      await page.evaluate(value => document.documentElement.dataset.theme = value, theme);
      for (const width of [1440, 390]) {
        await page.setViewportSize({ width, height: 900 });
        assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false, theme + ' overflow at ' + width);
      }
    }
    assert.equal(await page.evaluate(() => window.fixture.commands.some(command => /^(run_|start_|index_project|approve_|apply_)/.test(command))), false);
    assert.deepEqual(errors, []);
    console.log('Tool catalog: inventory/filtering, blocked/planned guards, setup/navigation, separate errors, stale project response, no execution and responsive layout passed.');
  } finally { await browser?.close(); server.kill('SIGTERM'); }
})().catch(error => { console.error(error); process.exitCode = 1; });
