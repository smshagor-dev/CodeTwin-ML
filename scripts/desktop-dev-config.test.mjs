import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const read = (relative) => readFileSync(path.join(repoRoot, relative), "utf8");
const json = (relative) => JSON.parse(read(relative));

test("Tauri dev URL matches the Vite IPv4 loopback and fixed port", () => {
  const tauri = json("apps/desktop/src-tauri/tauri.conf.json");
  const vite = read("apps/desktop/vite.config.ts");
  const url = new URL(tauri.build.devUrl);

  assert.equal(url.protocol, "http:");
  assert.equal(url.hostname, "127.0.0.1");
  assert.equal(url.port, "5173");
  assert.match(vite, /host:\s*["']127\.0\.0\.1["']/);
  assert.match(vite, /port:\s*5173\b/);
  assert.match(vite, /strictPort:\s*true\b/);
});

test("Repository root delegates Tauri commands to the desktop workspace", () => {
  const rootScripts = json("package.json").scripts;
  const desktopScripts = json("apps/desktop/package.json").scripts;

  assert.match(rootScripts.tauri, /--workspace @codetwin\/desktop run tauri --$/);
  assert.match(rootScripts["tauri:dev"], /--workspace @codetwin\/desktop run tauri:dev$/);
  assert.match(rootScripts["tauri:build"], /--workspace @codetwin\/desktop run tauri:build$/);
  assert.equal(desktopScripts.tauri, "cargo tauri");
  assert.equal(desktopScripts["tauri:dev"], "cargo tauri dev");
  assert.equal(desktopScripts["tauri:build"], "cargo tauri build");
});
