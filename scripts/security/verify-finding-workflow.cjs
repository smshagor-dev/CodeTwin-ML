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
        if (command === 'list_repair_plans') return [{ id: 'repair-a', project_id: 'a', finding_id: 'a-finding', title: 'Applied repair', rationale: 'Remove unsafe input execution', status: 'applied' }];
        if (command === 'index_project') { f.pipeline = ['index']; return { project_id: 'a', status: 'completed' }; }
        if (command === 'run_security_analysis') { f.pipeline.push('scan'); return { status: 'completed', coverage_complete: !f.incomplete }; }
        if (command === 'verify_repair_plan') { f.pipeline.push('verify'); return { id: 'verification-a', repair_id: 'repair-a', status: 'verified', matched_changes: 1, mismatched_changes: 0, missing_changes: 0 }; }
        if (command === 'read_repair_source') return { file_id: 'a-file', project_id: 'a', relative_path: 'src/a.ts', content_hash: 'pinned-sha256', content: 'eval(input)', byte_size: 11, language: 'typescript' };
        if (command === 'list_repair_candidate_findings') return [{ id: 'a-finding', project_id: 'a', title: 'Validation finding', file_id: 'a-file', status: 'open' }];
        if (command === 'qa_execution_availability') return { execution_enabled: true, reason: 'Fixture strict sandbox' };
        if (command === 'list_qa_execution_plans') return [{ id: 'plan-a', status: 'approved', runner: 'pytest', request: { targets: ['test_a.py'] }, blocking_reasons: [] }];
        if (command === 'list_qa_execution_runs') return [{ id: 'run-a', plan_id: 'plan-a', status: 'completed', project_manifest_sha256: 'manifest', tests_passed: false, parser_completed: true, stdout_excerpt: 'failure: expected 2, received 1', stderr_excerpt: 'error details', stdout_original_bytes: 20, stderr_original_bytes: 500, stderr_truncated: true }];
        if (command === 'run_qa_execution_plan') { await new Promise(resolve => { window.finishRun = resolve; }); return {}; }
        if (command === 'cancel_qa_execution') { f.cancelled = true; window.finishRun(); return true; }
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
    await page.goto(origin + '/#/security?mode=source');
    await page.getByText('Validation finding', { exact: true }).waitFor();
    await page.getByRole('button', { name: 'View source evidence' }).click();
    await page.getByText('SHA-256: pinned-sha256', { exact: true }).waitFor();
    assert((await page.locator('pre').innerText()).includes('1: eval(input)'));
    await page.setViewportSize({ width: 390, height: 900 });
    assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.getByRole('link', { name: 'Create repair proposal' }).click();
    await page.getByText('Finding linked.', { exact: false }).waitFor();
    assert.equal(await page.getByLabel('Repository path').inputValue(), '/local/a');
    assert(await page.locator('input').evaluateAll(inputs => inputs.some(input => input.value === 'Fix: Validation finding')));
    await page.getByRole('button', { name: 'Applied repair', exact: false }).click();
    await page.evaluate(() => { window.fixture.incomplete = true; });
    await page.getByRole('button', { name: 'Re-index, scan & verify', exact: true }).click();
    await page.getByRole('alert').filter({ hasText: 'coverage is incomplete' }).waitFor();
    assert.deepEqual(await page.evaluate(() => window.fixture.pipeline), ['index', 'scan']);
    await page.evaluate(() => { window.fixture.incomplete = false; });
    await page.getByRole('button', { name: 'Re-index, scan & verify', exact: true }).click();
    await page.getByRole('status').filter({ hasText: 'Verification recorded: verified' }).waitFor();
    assert.deepEqual(await page.evaluate(() => window.fixture.pipeline), ['index', 'scan', 'verify']);
    await page.goto(origin + '/#/testing');
    await page.getByText('Tests failed', { exact: true }).waitFor();
    await page.getByText('Run evidence and logs', { exact: true }).click();
    assert(await page.getByText('failure: expected 2, received 1', { exact: true }).count());
    assert(await page.getByText('stderr: 500 bytes', { exact: false }).count());
    await page.getByText('Sandboxed test execution', { exact: true }).first().click();
    await page.getByRole('button', { name: 'Run in sandbox', exact: true }).click();
    await page.getByRole('button', { name: 'Cancel active test run', exact: true }).click();
    await page.waitForFunction(() => window.fixture.cancelled === true);
    await page.getByRole('button', { name: 'Run in sandbox', exact: true }).waitFor();
    for (const width of [1440, 390]) {
      await page.setViewportSize({ width, height: 900 });
      assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
    }
    assert.deepEqual(errors, []);
    console.log('PASS source evidence, finding-linked repair, persisted failure logs, cancellation and responsive layout');
  } finally { await browser?.close(); server.kill('SIGTERM'); }
})().catch(error => { console.error(error); process.exitCode = 1; });
