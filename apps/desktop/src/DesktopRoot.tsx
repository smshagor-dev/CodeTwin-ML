import { useState } from "react";
import { App } from "./App";
import { DatabaseWorkspace } from "./DatabaseWorkspace";

type Workspace = "engineering" | "database";

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
      </nav>
      {workspace === "engineering" ? <App /> : <DatabaseWorkspace />}
    </div>
  );
}
