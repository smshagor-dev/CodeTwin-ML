import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { Dashboard } from "./Dashboard";
import { DesktopRoot } from "./DesktopRoot";
import { WorkspaceShell, workspaceRoutePage } from "./workspace/WorkspaceShell";
import { workspaceRoutes } from "./workspace/routes";

describe("desktop integration surface", () => {
  it("loads the dashboard and unified workspace shell", () => {
    expect(typeof Dashboard).toBe("function");
    expect(typeof DesktopRoot).toBe("function");
    expect(typeof WorkspaceShell).toBe("function");
    expect(workspaceRoutes).toHaveLength(12);
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

  it("maps every required route to a production page", () => {
    for (const route of workspaceRoutes) {
      expect(workspaceRoutePage(route)).toBeTruthy();
    }
  });

  it("keeps every required primary route in the production shell", () => {
    const shellPath = fileURLToPath(new URL("./workspace/WorkspaceShell.tsx", import.meta.url));
    const source = readFileSync(shellPath, "utf8");
    for (const label of [
      "Dashboard", "Projects", "Websites", "Agents", "Code Analysis", "Security",
      "Testing", "Deployments", "Integrations", "Settings", "Documentation", "Support",
    ]) {
      expect(source).toContain('label: "' + label + '"');
    }
    expect(source).toContain("Global search");
    expect(source).toContain("Toggle light or dark theme");
  });

  it("keeps destructive project and website actions behind confirmation dialogs", () => {
    const projectSource = readFileSync(fileURLToPath(new URL("./workspace/pages/ProjectsPage.tsx", import.meta.url)), "utf8");
    const websiteSource = readFileSync(fileURLToPath(new URL("./workspace/pages/WebsitesPage.tsx", import.meta.url)), "utf8");
    expect(projectSource).toContain("<ConfirmDialog");
    expect(projectSource).toContain("confirmRemove");
    expect(websiteSource).toContain("<ConfirmDialog");
    expect(websiteSource).toContain("confirmRemove");
  });
