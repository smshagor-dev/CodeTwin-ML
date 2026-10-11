// Production UI behavior with fixture IPC. Native command validation is separate.
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
    for (let n = 0; n < 100; n++) {
      assert.equal(server.exitCode, null);
      try { await fetch(origin); break; } catch { await new Promise(resolve => setTimeout(resolve, 100)); }
    }
    browser = await chromium.launch({ headless: true, ...(process.env.CHROMIUM_EXECUTABLE ? { executablePath: process.env.CHROMIUM_EXECUTABLE } : {}), args: ['--no-sandbox'] });
    const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    await page.addInitScript(() => {
      window.fixture = {};
      const date = '2026-10-11T05:00:00Z';
      const projects = ['a', 'b'].map((id, i) => ({ id, display_name: i ? 'Secondary project' : 'Validation project', root_path: '/local/' + id, path_identity: id, git_remote: null, last_opened_at: date, last_indexed_at: date, file_count: i ? 4 : 12, symbol_count: i ? 7 : 31, language_count: 1, last_index_status: 'completed', last_index_duration_ms: 420 }));
      window.__TAURI_INTERNALS__ = { invoke: async (command, args = {}) => {
        const f = window.fixture;
        if (command === 'discover_project') return { languages: ['typescript'], frameworks: [], package_managers: [], build_systems: [], test_frameworks: [], databases: [], ci_providers: [], project_kinds: [] };
        if (command === 'index_history') return [];
        if (command === 'git_review_status') {
          const fail = f.gitFail; const slow = f.gitSlow;
          if (slow && args.projectId === 'a') await new Promise(resolve => setTimeout(resolve, 500));
          if (fail) throw new Error('Git unavailable');
          return { branch: args.projectId === 'a' ? 'feature/review' : 'secondary', head: 'a'.repeat(40), changes: f.gitClean ? [] : [{ path: args.projectId + '.ts', original_path: null, staged: 'M', unstaged: 'M' }, { path: 'new.ts', original_path: null, staged: '?', unstaged: '?' }] };
        }
        if (command === 'git_create_reviewed_branch') {
          f.branchCalls = (f.branchCalls || []).concat([args]);
          if (f.branchSlow) await new Promise(resolve => setTimeout(resolve, 500));
          if (f.branchFail) throw new Error('HEAD changed since review');
          return { branch: args.branch, head: args.expectedHead };
        }
        if (command === 'git_review_file') {
          const fail = f.gitFileFail;
          if (f.gitSlow && args.projectId === 'a') await new Promise(resolve => setTimeout(resolve, 500));
          if (fail) throw new Error('File is no longer changed');
          return { path: args.path, staged_diff: args.path === 'new.ts' ? '' : '+staged-' + args.projectId, unstaged_diff: args.path === 'new.ts' ? '' : '+working-' + args.projectId, untracked_content: args.path === 'new.ts' ? '<script>window.gitXss=true</script>' : null, notice: null };
        }
        if (command === 'get_app_preferences') return { display_name: 'Local Developer', theme: 'light', auto_run_security_on_import: false, auto_discover_tests_on_import: false };
        if (command === 'list_projects') return projects;
        if (command === 'workspace_summary') return { project_count: 2, website_count: 0, active_agents: 0, security_scan_count: 0 };
        if (command === 'system_status') return ['backend', 'database', 'indexer'].map(key => ({ key, label: key, state: 'operational', detail: 'Fixture IPC status' }));
        return [];
      } };
    });
    await page.goto(origin + '/#/projects');
    const panel = page.getByRole('region', { name: 'Git change review' });
    await panel.getByRole('button', { name: 'Load Git changes', exact: true }).click();
    await panel.getByText('feature/review', { exact: true }).waitFor();
    assert.equal(await page.evaluate(() => window.fixture.branchCalls), undefined);
    await panel.getByText('Create branch', { exact: true }).click();
    const branchName = panel.getByLabel('New branch name');
    const createBranch = panel.getByRole('button', { name: 'Create at reviewed HEAD', exact: true });
    assert.equal(await createBranch.isDisabled(), true);
    await branchName.fill('feature/local-review');
    await createBranch.click();
    await panel.getByRole('status').filter({ hasText: 'Created feature/local-review' }).waitFor();
    assert.deepEqual(await page.evaluate(() => window.fixture.branchCalls), [{ projectId: 'a', branch: 'feature/local-review', expectedHead: 'a'.repeat(40) }]);
    await panel.getByText('feature/review', { exact: true }).waitFor();
    await page.evaluate(() => { window.fixture.branchFail = true; });
    await branchName.fill('feature/stale');
    await createBranch.click();
    await panel.getByRole('alert').filter({ hasText: 'HEAD changed since review' }).waitFor();
    await page.evaluate(() => { window.fixture.branchFail = false; });
    await branchName.fill('bad name');
    assert.equal(await createBranch.isDisabled(), true);
    await branchName.fill('');
    await panel.getByRole('button', { name: /a.ts/ }).click();
    await panel.getByText('+staged-a', { exact: true }).waitFor();
    await panel.getByText('+working-a', { exact: true }).waitFor();
    await panel.getByRole('button', { name: /new.ts/ }).click();
    await panel.getByText('<script>window.gitXss=true</script>', { exact: true }).waitFor();
    assert.equal(await page.evaluate(() => window.gitXss), undefined);
    await page.evaluate(() => { window.fixture.gitFileFail = true; });
    await panel.getByRole('button', { name: /a.ts/ }).click();
    await panel.getByRole('alert').filter({ hasText: 'File is no longer changed' }).waitFor();
    await page.evaluate(() => { window.fixture.gitFileFail = false; window.fixture.gitFail = true; });
    await panel.getByRole('button', { name: 'Refresh Git changes' }).click();
    await panel.getByRole('alert').filter({ hasText: 'Git unavailable' }).waitFor();
    await page.evaluate(() => { window.fixture.gitFail = false; window.fixture.gitClean = true; });
    await panel.getByRole('button', { name: 'Refresh Git changes' }).click();
    await panel.getByText('Working tree is clean.', { exact: true }).waitFor();
    await page.evaluate(() => { window.fixture.gitClean = false; window.fixture.gitSlow = true; });
    await panel.getByRole('button', { name: 'Refresh Git changes' }).click();
    await page.getByRole('button', { name: /Secondary project.*files/ }).click();
    await panel.getByRole('button', { name: 'Load Git changes' }).click();
    await panel.getByText('secondary', { exact: true }).waitFor();
    await page.waitForTimeout(600);
    assert.equal(await panel.getByText('feature/review', { exact: true }).count(), 0);
    await panel.getByRole('button', { name: /b.ts/ }).click();
    await panel.getByText('+working-b', { exact: true }).waitFor();
    await page.getByRole('button', { name: /Validation project.*files/ }).click();
    await panel.getByRole('button', { name: 'Load Git changes' }).click();
    await panel.getByText('feature/review', { exact: true }).waitFor();
    await panel.getByRole('button', { name: /a.ts/ }).click();
    await page.getByRole('button', { name: /Secondary project.*files/ }).click();
    await panel.getByRole('button', { name: 'Load Git changes' }).click();
    await panel.getByText('secondary', { exact: true }).waitFor();
    await page.waitForTimeout(600);
    assert.equal(await panel.getByText('+working-a', { exact: true }).count(), 0);
    await panel.getByRole('button', { name: /b.ts/ }).click();
    await panel.getByText('+working-b', { exact: true }).waitFor();
    await panel.getByText('Create branch', { exact: true }).click();
    await page.evaluate(() => { window.fixture.branchSlow = true; });
    await panel.getByLabel('New branch name').fill('feature/secondary-review');
    await panel.getByRole('button', { name: 'Create at reviewed HEAD', exact: true }).click();
    await page.getByRole('button', { name: /Validation project.*files/ }).click();
    await panel.getByRole('button', { name: 'Load Git changes' }).click();
    await panel.getByText('feature/review', { exact: true }).waitFor();
    await page.waitForTimeout(600);
    assert.equal(await panel.getByRole('status').filter({ hasText: 'Created feature/secondary-review' }).count(), 0);
    await panel.getByText('Create branch', { exact: true }).click();
    await panel.getByLabel('New branch name').fill('feature/' + 'x'.repeat(112));
    for (const theme of ['light', 'dark']) {
      await page.evaluate(value => document.documentElement.setAttribute('data-theme', value), theme);
      for (const width of [1440, 390]) {
        await page.setViewportSize({ width, height: 900 });
        assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false, theme + ' overflow at ' + width);
      }
    }
    assert.deepEqual(errors, []);
    console.log('Git review/branch UI: explicit branch creation, exact HEAD, stale failure/receipt, separate patches, untracked escaping, errors/retry, stale status/diff, responsive themes passed.');
  } finally {
    await browser?.close();
    server.kill('SIGTERM');
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
