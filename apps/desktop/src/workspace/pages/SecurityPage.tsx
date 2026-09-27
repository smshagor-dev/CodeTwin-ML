import { useState } from "react";

import { PageHeader } from "../ui";
import { AuthorizedWebSecurityPanel } from "../security/AuthorizedWebSecurityPanel";
import { GuidedSecurityOperator } from "../security/GuidedSecurityOperator";
import { StaticSecurityPanel } from "../security/StaticSecurityPanel";
import { SupplyChainPanel } from "../security/SupplyChainPanel";

export function SecurityPage() {
  const [mode, setMode] = useState<"developer" | "web" | "source" | "supply">("developer");

  return (
    <div>
      <PageHeader
        eyebrow="APPLICATION SECURITY"
        title="Security"
        description="Run a guided developer security test, inspect expert web-testing evidence, review static source findings, or scan for leaked secrets and vulnerable dependencies. Active operations remain authorization-gated and scope-bounded."
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
        <button role="tab" aria-selected={mode === "supply"} className={mode === "supply" ? "active" : ""} onClick={() => setMode("supply")}>
          Secrets &amp; Dependencies
        </button>
      </div>
      {mode === "developer" ? (
        <GuidedSecurityOperator/>
      ) : mode === "web" ? (
        <AuthorizedWebSecurityPanel/>
      ) : mode === "supply" ? (
        <SupplyChainPanel/>
      ) : (
        <StaticSecurityPanel/>
      )}
    </div>
  );
}
