import { describe, expect, it } from "vitest";

import { advancedRoutes, parseRoute, routeHref, workspaceRoutes } from "./routes";

describe("workspace routing", () => {
  it("exposes every required dashboard route", () => {
    expect(workspaceRoutes).toEqual([
      "dashboard",
      "projects",
      "websites",
      "agents",
      "code-analysis",
      "security",
      "testing",
      "deployments",
      "integrations",
      "settings",
      "documentation",
      "support",
    ]);
  });

  it("parses supported hash routes and falls back safely", () => {
    expect(parseRoute("#/projects")).toBe("projects");
    expect(parseRoute("#/code-analysis?project=1")).toBe("code-analysis");
    expect(parseRoute("#/database")).toBe("database");
    expect(parseRoute("#/unknown")).toBe("dashboard");
    expect(parseRoute("")).toBe("dashboard");
  });

  it("keeps advanced existing workspaces addressable without adding them to the primary sidebar", () => {
    expect(advancedRoutes).toContain("engineering");
    expect(advancedRoutes).toContain("database");
    expect(advancedRoutes).toContain("runtime");
    expect(routeHref("repair-apply")).toBe("#/repair-apply");
  });
});
