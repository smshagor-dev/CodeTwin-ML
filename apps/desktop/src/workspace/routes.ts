export const workspaceRoutes = [
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
] as const;

export const advancedRoutes = [
  "engineering",
  "web-security",
  "database",
  "runtime",
  "qa",
  "ml",
  "repair",
  "repair-apply",
] as const;

export type WorkspaceRoute = (typeof workspaceRoutes)[number];
export type AdvancedRoute = (typeof advancedRoutes)[number];
export type AppRoute = WorkspaceRoute | AdvancedRoute;

const validRoutes = new Set<string>([...workspaceRoutes, ...advancedRoutes]);

export function parseRoute(hash: string): AppRoute {
  const route = hash.replace(/^#\/?/, "").split(/[?&]/, 1)[0]?.trim() ?? "";
  return validRoutes.has(route) ? route as AppRoute : "dashboard";
}

export function routeHref(route: AppRoute): string {
  return "#/" + route;
}

export function navigate(route: AppRoute): void {
  const href = routeHref(route);
  if (window.location.hash === href) {
    window.dispatchEvent(new HashChangeEvent("hashchange"));
    return;
  }
  window.location.hash = href;
}
