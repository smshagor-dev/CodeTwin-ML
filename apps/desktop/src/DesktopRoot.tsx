import { useState } from "react";
import { App } from "./App";
import { Dashboard, type DashboardDestination } from "./Dashboard";
import { DatabaseWorkspace } from "./DatabaseWorkspace";
import { QaWorkspace } from "./QaWorkspace";
import { RepairWorkspace } from "./RepairWorkspace";
import { RuntimeWorkspace } from "./RuntimeWorkspace";
import { WebSecurityWorkspace } from "./WebSecurityWorkspace";
import "./dashboard.css";
import "./repair-workspace.css";
import "./runtime-workspace.css";
import "./qa-workspace.css";

type Workspace = "dashboard" | DashboardDestination | "repair";

export function DesktopRoot() {
  const [workspace, setWorkspace] = useState<Workspace>("dashboard");

  return (
    <div className="desktop-root">
      {workspace !== "dashboard" && (
        <nav className="workspace-switcher" aria-label="Desktop workspace switcher">
          <button onClick={() => setWorkspace("dashboard")}>Dashboard</button>
          <button className={workspace === "engineering" ? "active" : ""} onClick={() => setWorkspace("engineering")}>Engineering</button>
          <button className={workspace === "security" ? "active" : ""} onClick={() => setWorkspace("security")}>Security</button>
          <button className={workspace === "database" ? "active" : ""} onClick={() => setWorkspace("database")}>Database</button>
          <button className={workspace === "runtime" ? "active" : ""} onClick={() => setWorkspace("runtime")}>Runtime</button>
          <button className={workspace === "qa" ? "active" : ""} onClick={() => setWorkspace("qa")}>QA</button>
          <button className={workspace === "repair" ? "active" : ""} onClick={() => setWorkspace("repair")}>Repair Lab</button>
        </nav>
      )}
      {workspace === "dashboard" && <Dashboard onNavigate={setWorkspace} />}
      {workspace === "engineering" && <App />}
      {workspace === "security" && <WebSecurityWorkspace />}
      {workspace === "database" && <DatabaseWorkspace />}
      {workspace === "runtime" && <RuntimeWorkspace />}
      {workspace === "qa" && <QaWorkspace />}
      {workspace === "repair" && <RepairWorkspace />}
    </div>
  );
}
