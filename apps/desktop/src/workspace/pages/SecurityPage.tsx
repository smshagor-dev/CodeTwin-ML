import { useState } from "react";

import { PageHeader } from "../ui";
import { AuthorizedWebSecurityPanel } from "../security/AuthorizedWebSecurityPanel";
import { StaticSecurityPanel } from "../security/StaticSecurityPanel";

export function SecurityPage() {
  const [mode, setMode] = useState<"web" | "source">("web");

  return (
    <div>
      <PageHeader
        eyebrow="APPLICATION SECURITY"
        title="Security"
        description="Combine authorized, bounded web application testing with CodeTwin's existing static source analysis. Active web probes require explicit authorization and remain constrained to the configured scope."
      />
      <div className="ws-security-tabs" role="tablist" aria-label="Security workspace mode">
        <button role="tab" aria-selected={mode === "web"} className={mode === "web" ? "active" : ""} onClick={() => setMode("web")}>
          Authorized Web Testing
        </button>
        <button role="tab" aria-selected={mode === "source"} className={mode === "source" ? "active" : ""} onClick={() => setMode("source")}>
          Static Source Analysis
        </button>
      </div>
      {mode === "web" ? <AuthorizedWebSecurityPanel/> : <StaticSecurityPanel/>}
    </div>
  );
}
