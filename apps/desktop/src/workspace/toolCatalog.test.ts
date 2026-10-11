import { describe, expect, it } from "vitest";
import { filterTools, toolAction } from "./toolCatalog";
import type { CatalogTool } from "./types";
const tool: CatalogTool = { id: "code.sast", name: "Source security review", category: "Code", description: "Passive analysis", roadmap: "CS-01", definition_version: 1, availability: "available", reason: "Workflow available", operation_kind: "passive", prerequisites: [], platforms: [], coverage: "Selected deterministic rules", workflow: "security", setup_workflow: null };
describe("tool catalog actions", () => {
  it("blocks planned/blocked items even if they supply a workflow", () => {
    expect(toolAction({ ...tool, availability: "planned", setup_workflow: "projects" })).toBeNull();
    expect(toolAction({ ...tool, availability: "blocked" })).toBeNull();
    expect(toolAction({ ...tool, workflow: "javascript:alert(1)" })).toBeNull();
    expect(toolAction({ ...tool, workflow: "agents" })).toBeNull();
  });
  it("routes missing prerequisites to setup, not their executable workflow", () => {
    expect(toolAction({ ...tool, availability: "requires_setup", setup_workflow: "projects" })).toEqual({ route: "projects", label: "Set up" });
    expect(toolAction({ ...tool, availability: "requires_setup" })).toBeNull();
    expect(toolAction(tool)).toEqual({ route: "security", mode: "source", label: "Open workflow" });
  });
  it("combines search, category, availability and operation without changing inventory", () => {
    const inventory = [tool, { ...tool, id: "network.tls", category: "Network", availability: "planned" as const }];
    expect(filterTools(inventory, "DETERMINISTIC", "Code", "available", "passive")).toEqual([tool]);
    expect(filterTools(inventory, "", "Network", "available", "")).toEqual([]);
    expect(inventory).toHaveLength(2);
  });
});
