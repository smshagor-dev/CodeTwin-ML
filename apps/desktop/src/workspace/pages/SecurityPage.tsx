import { useState } from "react";

import { PageHeader } from "../ui";
import { AuthorizedWebSecurityPanel } from "../security/AuthorizedWebSecurityPanel";
import { GuidedSecurityOperator } from "../security/GuidedSecurityOperator";
import { StaticSecurityPanel } from "../security/StaticSecurityPanel";

export function SecurityPage() {
  const [mode, setMode] = useState<"developer" | "web" | "source">("developer");

  return (
    <div>
      <PageHeader
        eyebrow="APPLICATION SECURITY"
        title="Security"
        description="Run a guided developer security test, inspect expert web-testing evidence, or review static source findings. Active operations remain authorization-gated and scope-bounded."
      />
      <div className="ws-security-tabs" role="tablist" aria-label="Security workspace mode">
        <button role="tab" aria-selected={mode === "developer"} className={mode === "developer" ? "active" : ""} onClick={() => setMode("developer")}>
          Developer Security Test
        </button>
        <button role="tab" aria-selected={mode === "web"} className={mode === "web" ? "active" : ""} onClick={() => setMode("web")}>
          Expert Web Testing
        </button>
        <button role="tab" aria-selected={mode === "source"} className={mode === "source" ? "active" : ""} onClick={() => setMode("source")}>
          Static Source Analysis
        </button>
      </div>
      {mode === "developer" ? <GuidedSecurityOperator/> : mode === "web" ? <AuthorizedWebSecurityPanel/> : <StaticSecurityPanel/>}
    </div>
  );
}
