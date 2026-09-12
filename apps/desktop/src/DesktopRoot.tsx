import { useState } from "react";
import { App } from "./App";
import { DatabaseWorkspace } from "./DatabaseWorkspace";
import { QaWorkspace } from "./QaWorkspace";
import { RuntimeWorkspace } from "./RuntimeWorkspace";
import { WebSecurityWorkspace } from "./WebSecurityWorkspace";
import "./runtime-workspace.css";
import "./qa-workspace.css";

type Workspace = "engineering" | "security" | "database" | "runtime" | "qa";

export function DesktopRoot() {
  const [workspace, setWorkspace] = useState<Workspace>("engineering");

  return (
    <div className="desktop-root">
      <nav className="workspace-switcher" aria-label="Desktop workspace switcher">
        <button
          className={workspace === "engineering" ? "active" : ""}
          onClick={() => setWorkspace("engineering")}
        >
          Engineering
        </button>
        <button
          className={workspace === "security" ? "active" : ""}
          onClick={() => setWorkspace("security")}
        >
          Security
        </button>
        <button
          className={workspace === "database" ? "active" : ""}
          onClick={() => setWorkspace("database")}
        >
          Database
        </button>
        <button
          className={workspace === "runtime" ? "active" : ""}
          onClick={() => setWorkspace("runtime")}
        >
          Runtime
        </button>
        <button
          className={workspace === "qa" ? "active" : ""}
          onClick={() => setWorkspace("qa")}
        >
          QA
        </button>
      </nav>
      {workspace === "engineering" && <App />}
      {workspace === "security" && <WebSecurityWorkspace />}
      {workspace === "database" && <DatabaseWorkspace />}
      {workspace === "runtime" && <RuntimeWorkspace />}
      {workspace === "qa" && <QaWorkspace />}
    </div>
  );
}
