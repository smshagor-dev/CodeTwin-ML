import { useEffect, useState } from "react";

import { App } from "./App";
import { DatabaseWorkspace } from "./DatabaseWorkspace";
import { MLWorkspace } from "./MLWorkspace";
import { QaWorkspace } from "./QaWorkspace";
import { RepairApplicationWorkspace } from "./RepairApplicationWorkspace";
import { RepairWorkspace } from "./RepairWorkspace";
import { RuntimeWorkspace } from "./RuntimeWorkspace";
import { WebSecurityWorkspace } from "./WebSecurityWorkspace";
import { WorkspaceProvider } from "./workspace/WorkspaceContext";
import { WorkspaceShell } from "./workspace/WorkspaceShell";
import { navigate, parseRoute, type AdvancedRoute, type AppRoute, type WorkspaceRoute } from "./workspace/routes";
import "./dashboard.css";
import "./ml-workspace.css";
import "./qa-workspace.css";
import "./repair-application-workspace.css";
import "./repair-workspace.css";
import "./runtime-workspace.css";
import "./workspace/workspace.css";

const advanced = new Set<AdvancedRoute>(["engineering", "web-security", "database", "runtime", "qa", "ml", "repair", "repair-apply"]);

function AdvancedWorkspace({ route }: { route: AdvancedRoute }) {
  return (
    <div className="ws-advanced-shell">
      <div className="ws-advanced-bar">
        <button onClick={() => navigate("dashboard")}>← Dashboard</button>
        <span>Advanced CodeTwin workspace · {route.replaceAll("-", " ")}</span>
      </div>
      {route === "engineering" && <App/>}
      {route === "web-security" && <WebSecurityWorkspace/>}
      {route === "database" && <DatabaseWorkspace/>}
      {route === "runtime" && <RuntimeWorkspace/>}
      {route === "qa" && <QaWorkspace/>}
      {route === "ml" && <MLWorkspace/>}
      {route === "repair" && <RepairWorkspace/>}
      {route === "repair-apply" && <RepairApplicationWorkspace/>}
    </div>
  );
}

export function DesktopRoot() {
  const [route, setRoute] = useState<AppRoute>(() => parseRoute(window.location.hash));

  useEffect(() => {
    if (!window.location.hash) window.location.hash = "#/dashboard";
    const update = () => setRoute(parseRoute(window.location.hash));
    window.addEventListener("hashchange", update);
    return () => window.removeEventListener("hashchange", update);
  }, []);

  return (
    <WorkspaceProvider>
      {advanced.has(route as AdvancedRoute)
        ? <AdvancedWorkspace route={route as AdvancedRoute}/>
        : <WorkspaceShell route={route as WorkspaceRoute}/>}
    </WorkspaceProvider>
  );
}
