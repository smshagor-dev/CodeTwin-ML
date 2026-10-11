// Browser interaction with fixture IPC; real analyzer/SQLite tests live in assessment_jobs.rs.
const assert = require('node:assert/strict');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { chromium } = require('playwright');
const root = path.resolve(__dirname, '../..');
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
    const errors = []; page.on('pageerror', error => errors.push(error.message));
    await page.addInitScript(() => {
      const date = '2026-10-11T10:00:00Z';
      window.fixture = JSON.parse(sessionStorage.getItem('assessmentFixture') || 'null') || { calls: [], jobs: { a: [], b: [] }, failed: false, stale: false, failPlan: false, theme: 'light' };
      window.addEventListener('beforeunload', () => sessionStorage.setItem('assessmentFixture', JSON.stringify(window.fixture)));
      const projects = ['a','b'].map(id => ({ id, display_name: 'Project ' + id, root_path: '/local/' + id, file_count: 1, symbol_count: 1, language_count: 1, last_index_status: 'completed', last_indexed_at: date }));
      window.__TAURI_INTERNALS__ = { invoke: async (command, args = {}) => {
        const f = window.fixture; f.calls.push({ command, args });
        if (command === 'list_projects') return projects;
        if (command === 'get_app_preferences') return { display_name: 'Developer', theme: f.theme, auto_run_security_on_import: false, auto_discover_tests_on_import: false };
        if (command === 'workspace_summary') return { project_count: 2, website_count: 0, active_agents: 0, security_scan_count: 0 };
        if (command === 'list_assessment_jobs') {
          const copy = structuredClone(f.jobs[args.projectId]);
          if (f.stale && args.projectId === 'a') await new Promise(resolve => setTimeout(resolve, 600));
          if (f.failed) throw new Error('Assessment store offline');
          return copy;
        }
        if (command === 'create_assessment_plan') {
          if (f.failPlan) throw new Error('Indexed source is stale; reindex');
          const r = args.request;
          const revision = f.jobs[r.project_id].length + 1;
          const job = { id: r.project_id + '-' + revision, project_id: r.project_id, scope_revision: revision, root_path: '/local/' + r.project_id, input_hash: 'a'.repeat(64), file_count: 1, max_files: r.max_files, budget_seconds: r.budget_seconds, definition_version: 1, status: 'planned', cancel_requested: false, message: null, created_at: date, started_at: null, finished_at: null, steps: r.tools.map((tool_id, position) => ({ position, tool_id, status: 'pending', run_id: null, coverage_complete: null })) };
          f.jobs[r.project_id].unshift(job); return structuredClone(job);
        }
        if (command === 'run_assessment_job') {
          const job = Object.values(f.jobs).flat().find(job => job.id === args.id);
          job.status = 'running'; job.started_at = date; job.steps[0].status = 'running';
          await new Promise(resolve => setTimeout(resolve, 3500));
          job.steps[0].status = 'completed'; job.steps[0].run_id = 'real-run-fixture';
          job.status = job.cancel_requested ? 'cancelled' : 'completed'; job.finished_at = date;
          for (const step of job.steps.slice(1)) step.status = job.cancel_requested ? 'cancelled' : 'completed';
          return structuredClone(job);
        }
        if (command === 'cancel_assessment_job') {
          const job = Object.values(f.jobs).flat().find(job => job.id === args.id);
          job.cancel_requested = true;
          if (job.status === 'planned') { job.status = 'cancelled'; job.steps.forEach(step => { step.status = 'cancelled'; }); }
          return null;
        }
        return [];
      } };
    });
    await page.goto(origin + '/#/tools');
    await page.getByText('No saved assessments for this project.', { exact: true }).waitFor();
    assert.equal(await page.evaluate(() => window.fixture.calls.some(call => /^(create_assessment|run_assessment|cancel_assessment)/.test(call.command))), false);
    await page.getByLabel('Maximum indexed files', { exact: true }).fill('0');
    assert.equal(await page.getByRole('button', { name: 'Save assessment plan', exact: true }).isDisabled(), true);
    await page.getByLabel('Maximum indexed files', { exact: true }).fill('100');
    await page.getByRole('button', { name: 'Save assessment plan', exact: true }).click();
    const first = page.getByRole('article', { name: 'Assessment revision 1', exact: true }); await first.waitFor();
    assert.equal(await page.evaluate(() => window.fixture.calls.filter(call => call.command === 'run_assessment_job').length), 0);
    await first.getByRole('button', { name: 'Start assessment', exact: true }).click();
    await first.getByText('Source security: running', { exact: true }).waitFor();
    await first.getByRole('button', { name: 'Cancel assessment', exact: true }).click();
    await first.getByText('Cancellation requested. Waiting for the current analyzer to finish.', { exact: true }).waitFor();
    await first.getByText('cancelled', { exact: true }).waitFor();
    assert.equal(await first.getByRole('progressbar').getAttribute('value'), '1');
    await page.getByRole('button', { name: 'Save assessment plan', exact: true }).click();
    const second = page.getByRole('article', { name: 'Assessment revision 2', exact: true }); await second.waitFor();
    await page.getByRole('button', { name: 'Save assessment plan', exact: true }).click();
    const third = page.getByRole('article', { name: 'Assessment revision 3', exact: true }); await third.waitFor();
    assert.equal(await second.getByRole('button', { name: 'Start assessment', exact: true }).isDisabled(), true);
    await third.getByRole('button', { name: 'Cancel assessment', exact: true }).click();
    await third.getByText('cancelled', { exact: true }).waitFor();
    await page.evaluate(() => { window.fixture.failPlan = true; });
    await page.getByRole('button', { name: 'Save assessment plan', exact: true }).click();
    await page.getByRole('alert').filter({ hasText: 'Indexed source is stale' }).waitFor();
    await page.evaluate(() => { window.fixture.failed = true; });
    await page.getByRole('button', { name: 'Refresh assessments', exact: true }).click();
    await page.getByRole('alert').filter({ hasText: 'Assessment store offline' }).waitFor();
    assert.equal(await second.getByRole('button', { name: 'Start assessment', exact: true }).isDisabled(), true);
    await page.evaluate(() => { window.fixture.failed = false; window.fixture.stale = true; });
    await page.getByRole('button', { name: 'Refresh assessments', exact: true }).click();
    await page.getByLabel('Project', { exact: true }).selectOption('b');
    await page.getByText('No saved assessments for this project.', { exact: true }).waitFor();
    await page.waitForTimeout(750);
    assert.equal(await page.locator('.ws-assessment-job').count(), 0);
    await page.evaluate(() => { window.fixture.failPlan = false; });
    await page.getByRole('button', { name: 'Save assessment plan', exact: true }).click();
    const projectB = page.getByRole('article', { name: 'Assessment revision 1', exact: true }); await projectB.waitFor();
    await projectB.getByRole('button', { name: 'Start assessment', exact: true }).click();
    await projectB.getByText('completed', { exact: true }).waitFor();
    await page.reload(); await page.getByLabel('Project', { exact: true }).selectOption('b'); await projectB.waitFor();
    assert.equal(await page.evaluate(() => window.fixture.calls.filter(call => call.command === 'run_assessment_job').length), 2);
    for (const theme of ['light','dark']) {
      await page.evaluate(theme => { window.fixture.theme = theme; }, theme); await page.reload(); await page.getByLabel('Project', { exact: true }).selectOption('b'); await projectB.waitFor();
      for (const width of [1440,390]) {
        await page.setViewportSize({ width, height: 900 });
        assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1), true, theme + ' ' + width + ' overflow');
      }
    }
    assert.deepEqual(errors, []);
    console.log('Assessment fixture UI passed: explicit plan/start, cancel, revisions, errors, stale scope, reload, light/dark mobile.');
  } finally { if (browser) await browser.close(); server.kill(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
