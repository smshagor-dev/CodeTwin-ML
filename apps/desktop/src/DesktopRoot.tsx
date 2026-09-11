import { useState } from "react";
import { App } from "./App";
import { DatabaseWorkspace } from "./DatabaseWorkspace";
import { RuntimeWorkspace } from "./RuntimeWorkspace";
import "./runtime-workspace.css";

type Workspace = "engineering" | "database" | "runtime";

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
      </nav>
      {workspace === "engineering" && <App />}
      {workspace === "database" && <DatabaseWorkspace />}
      {workspace === "runtime" && <RuntimeWorkspace />}
    </div>
  );
}
