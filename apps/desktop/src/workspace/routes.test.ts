import { describe, expect, it } from "vitest";

import { advancedRoutes, parseRoute, routeHref, workspaceRoutes } from "./routes";

describe("workspace routing", () => {
  it("exposes every required dashboard route", () => {
    expect(workspaceRoutes).toEqual([
      "launch",
      "workspace",
      "dashboard",
      "projects",
      "websites",
      "agents",
      "code-analysis",
      "security",
      "tools",
      "testing",
      "deployments",
      "integrations",
      "settings",
      "documentation",
      "support",
      "workflows",
    ]);
  });

  it("parses supported hash routes and falls back safely", () => {
    expect(parseRoute("#/projects")).toBe("projects");
    expect(parseRoute("#/workflows")).toBe("workflows");
    expect(parseRoute("#/workspace")).toBe("workspace");
    expect(parseRoute("#/workflows?tab=memory")).toBe("workflows");
    expect(parseRoute("#/code-analysis?project=1")).toBe("code-analysis");
    expect(parseRoute("#/database")).toBe("database");
    expect(parseRoute("#/launch")).toBe("launch");
    expect(parseRoute("#/unknown")).toBe("launch");
    expect(parseRoute("")).toBe("launch");
  });

  it("keeps advanced existing workspaces addressable without adding them to the primary sidebar", () => {
    expect(advancedRoutes).toContain("engineering");
    expect(advancedRoutes).toContain("web-security");
    expect(advancedRoutes).toContain("database");
    expect(advancedRoutes).toContain("runtime");
    expect(advancedRoutes).toContain("qa");
    expect(routeHref("repair-apply")).toBe("#/repair-apply");
  });
});
