import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { Dashboard } from "./Dashboard";
import { DesktopRoot } from "./DesktopRoot";

describe("desktop integration surface", () => {
  it("loads the dashboard and unified workspace shell", () => {
    expect(typeof Dashboard).toBe("function");
    expect(typeof DesktopRoot).toBe("function");
  });

  it("keeps failed evidence reads explicit instead of silently converting them to zero", () => {
    const dashboardPath = fileURLToPath(new URL("./Dashboard.tsx", import.meta.url));
    const source = readFileSync(dashboardPath, "utf8");
    expect(source).toContain("Evidence unavailable");
    expect(source).not.toContain("catch { return fallback; }");
    expect(source).toContain("Run deterministic analysis");
    expect(source).toContain("Displayed persisted evidence may be from an earlier successful run.");
    expect(source).not.toContain("Failed analyzers remain explicitly unavailable/incomplete.");
  });
});
