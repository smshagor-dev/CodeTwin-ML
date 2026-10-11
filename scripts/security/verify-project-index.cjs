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
      window.fixture = { empty: sessionStorage.getItem('codetwinFixtureEmpty') === 'true', fail: false, slow: false, scan: 0, discovery: 0, reads: [], indexCalls: [], historyFailed: false };
      const date = '2026-10-11T05:00:00Z';
      const projects = ['a', 'b'].map((id, i) => ({ id, display_name: i ? 'Secondary project' : 'Validation project', root_path: '/local/' + id, path_identity: id, git_remote: null, last_opened_at: date, last_indexed_at: date, file_count: i ? 4 : 12, symbol_count: i ? 7 : 31, language_count: 1, last_index_status: 'completed', last_index_duration_ms: 420 }));
      window.__TAURI_INTERNALS__ = { invoke: async (command, args = {}) => {
        const f = window.fixture;
        if (command === 'discover_project') return { languages: ['typescript'], frameworks: [], package_managers: [], build_systems: [], test_frameworks: [], databases: [], ci_providers: [], project_kinds: [] };
        if (command === 'index_history') {
          if (f.historyFailed) throw new Error('history unavailable');
          if (f.slow && args.projectId === 'a') await new Promise(resolve => setTimeout(resolve, 400));
          return [{ id: args.projectId + '-index', project_id: args.projectId, status: 'completed', started_at: date, finished_at: date, duration_ms: 44, analyzer_version: 'fixture-v1', delta: { files_scanned: 12, files_added: args.projectId === 'a' ? 2 : 9, files_modified: 1, files_unchanged: 8, files_deleted: 1, skipped_files: 0, parse_errors: 0 } }];
        }
        if (command === 'index_project') {
          f.indexCalls.push({ path: args.path, fullRebuild: args.fullRebuild });
          if (f.pauseIndex) await new Promise(resolve => { window.finishIndex = resolve; });
          await new Promise(resolve => setTimeout(resolve, 100));
          return { project_id: args.path.endsWith('b') ? 'b' : 'a', status: 'completed', delta: { files_added: 2, files_modified: 1, files_unchanged: 8, files_deleted: 1, skipped_files: 0, parse_errors: 0 } };
        }
        if (command === 'cancel_project_index') { f.cancelled = true; window.finishIndex?.(); return true; }
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
    await page.goto(origin + '/#/projects');
    await page.getByRole('heading', { name: 'Incremental index evidence', exact: true }).waitFor();
    await page.getByText('Unchanged content', { exact: true }).waitFor();
    assert.equal(await page.locator('dt').filter({ hasText: /^Added$/ }).locator('+ dd').innerText(), '2');
    await page.getByRole('button', { name: 'Re-index', exact: true }).click();
    await page.waitForFunction(() => window.fixture.indexCalls.length === 1);
    await page.getByRole('button', { name: 'Full rebuild', exact: true }).waitFor();
    assert.equal(await page.evaluate(() => window.fixture.indexCalls[0].fullRebuild), false);
    await page.getByRole('button', { name: 'Full rebuild', exact: true }).click();
    await page.waitForFunction(() => window.fixture.indexCalls.length === 2);
    await page.waitForFunction(() => !document.querySelector('.ws-operation-banner'));
    assert.equal(await page.evaluate(() => window.fixture.indexCalls[1].fullRebuild), true);
    await page.evaluate(() => { window.fixture.pauseIndex = true; });
    await page.getByRole('button', { name: 'Re-index', exact: true }).click();
    await page.getByRole('button', { name: 'Secondary project', exact: false }).click();
    await page.getByRole('button', { name: 'Cancel indexing', exact: true }).click();
    await page.waitForFunction(() => window.fixture.cancelled === true);
    await page.waitForTimeout(150);
    assert.equal(await page.locator('dt').filter({ hasText: /^Added$/ }).locator('+ dd').innerText(), '9');
    await page.evaluate(() => { window.fixture.slow = true; });
    await page.getByRole('button', { name: 'Validation project', exact: false }).click();
    await page.getByRole('button', { name: 'Secondary project', exact: false }).click();
    await page.waitForTimeout(550);
    assert.equal(await page.locator('dt').filter({ hasText: /^Added$/ }).locator('+ dd').innerText(), '9');
    await page.evaluate(() => { window.fixture.historyFailed = true; });
    await page.getByRole('button', { name: 'Validation project', exact: false }).click();
    await page.getByRole('alert').filter({ hasText: 'Index history unavailable' }).waitFor();
    await page.evaluate(() => { window.fixture.historyFailed = false; });
    await page.getByRole('button', { name: 'Retry index history', exact: true }).click();
    await page.getByText('Unchanged content', { exact: true }).waitFor();
    await page.getByText('Index run history', { exact: true }).click();
    for (const theme of ['light', 'dark']) {
      await page.evaluate(theme => document.documentElement.dataset.theme = theme, theme);
      for (const width of [1440, 390]) {
        await page.setViewportSize({ width, height: 900 });
        assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
      }
    }
    assert.deepEqual(errors, []);
    console.log('PASS index deltas/history, explicit incremental vs full rebuild, cancellation, stale project discard, retry and responsive layout');
  } finally { await browser?.close(); server.kill('SIGTERM'); }
})().catch(error => { console.error(error); process.exitCode = 1; });
