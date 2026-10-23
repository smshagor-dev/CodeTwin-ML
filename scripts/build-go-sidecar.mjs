/** Build the Go companion binary for Tauri's current Rust target triple. */
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const rust = spawnSync('rustc', ['-vV'], { encoding: 'utf8' });
if (rust.error || rust.status !== 0) {
  throw new Error('Rust toolchain is required to discover the Tauri target triple');
}
const host = /^host:\s*(\S+)$/m.exec(rust.stdout)?.[1];
const target = process.env.TAURI_ENV_TARGET_TRIPLE || process.env.CARGO_BUILD_TARGET || host;
if (!target || !/^[A-Za-z0-9_-]+$/.test(target)) {
  throw new Error('Cannot determine a safe target triple');
}
const parts = target.split('-');
const arch = ({ x86_64: 'amd64', i686: '386', aarch64: 'arm64' })[parts[0]];
const os = target.includes('-windows-') ? 'windows' : target.includes('-linux-') ? 'linux' :
  target.includes('-apple-') ? 'darwin' : undefined;
if (!os || !arch) throw new Error(`Unsupported Go/Tauri target: ${target}`);
const extension = os === 'windows' ? '.exe' : '';
const output = join(root, 'apps', 'desktop', 'src-tauri', 'binaries', `codetwin-security-${target}${extension}`);
mkdirSync(dirname(output), { recursive: true });
const result = spawnSync('go', ['build', '-trimpath', '-buildvcs=false', '-o', output, '.'], {
  cwd: join(root, 'services', 'security-engine'),
  env: { ...process.env, GOOS: os, GOARCH: arch, CGO_ENABLED: '0' },
  stdio: 'inherit',
});
if (result.error || result.status !== 0 || !existsSync(output)) {
  throw new Error(`Go companion build failed for ${target}; install Go >=1.23 or use a prebuilt artifact`);
}
console.log(`Built Tauri Go companion: ${output}`);
