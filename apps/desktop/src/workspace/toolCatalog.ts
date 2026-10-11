import type { AppRoute } from "./routes";
import type { CatalogTool, ToolAvailability } from "./types";

export const availabilityLabels: Record<ToolAvailability, string> = {
  available: "Workflow available", requires_setup: "Requires setup", blocked: "Blocked", planned: "Planned",
};
const workflowRoutes = new Set<AppRoute>(["projects", "security", "testing", "integrations", "engineering", "database", "runtime", "repair", "web-security"]);

export function toolAction(tool: CatalogTool): { route: AppRoute; label: string; mode?: string } | null {
  const route = tool.availability === "available" ? tool.workflow : tool.availability === "requires_setup" ? tool.setup_workflow : null;
  if (!route || !workflowRoutes.has(route as AppRoute)) return null;
  const modes: Record<string, string> = { "code.sast": "source", "findings.review": "source", "code.secrets": "supply", "code.history-secrets": "supply", "supply.dependencies": "supply", "supply.sbom": "supply", "web.scoped-scan": "web", "web.identity": "developer", "findings.comparison": "developer", "validation.benchmarks": "benchmark" };
  return { route: route as AppRoute, ...(tool.availability === "available" && route === "security" && modes[tool.id] ? { mode: modes[tool.id] } : {}), label: tool.availability === "requires_setup" ? "Set up" : "Open workflow" };
}

export function filterTools(tools: CatalogTool[], query: string, category: string, availability: string, operation: string) {
  const term = query.trim().toLowerCase();
  return tools.filter(tool => (!category || tool.category === category)
    && (!availability || tool.availability === availability)
    && (!operation || tool.operation_kind === operation)
    && (!term || [tool.id, tool.name, tool.description, tool.coverage].some(value => value.toLowerCase().includes(term))));
}
