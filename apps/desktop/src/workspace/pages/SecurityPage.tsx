import { useState } from "react";

import { PageHeader } from "../ui";
import { AuthorizedWebSecurityPanel } from "../security/AuthorizedWebSecurityPanel";
import { DatasetBenchmarkPanel } from "../security/DatasetBenchmarkPanel";
import { GuidedSecurityOperator } from "../security/GuidedSecurityOperator";
import { StaticSecurityPanel } from "../security/StaticSecurityPanel";
import { NetworkAssessmentPanel } from "../security/NetworkAssessmentPanel";
import { SupplyChainPanel } from "../security/SupplyChainPanel";

export function SecurityPage() {
  type Mode = "developer" | "web" | "source" | "supply" | "benchmark" | "network";
  const [mode, setMode] = useState<Mode>(() => {
    const requested = new URLSearchParams(window.location.hash.split("?")[1] ?? "").get("mode");
    return ["developer", "web", "source", "supply", "benchmark", "network"].includes(requested ?? "") ? requested as Mode : "developer";
  });

  return (
    <div>
      <PageHeader
        eyebrow="APPLICATION SECURITY"
        title="Security"
        description="Review application, source and dependency risks. Web testing requires authorization."
      />
      <div className="ws-security-tabs" role="tablist" aria-label="Security workspace mode">
        <button role="tab" aria-selected={mode === "developer"} className={mode === "developer" ? "active" : ""} onClick={() => setMode("developer")}>
          Developer Security Test
        </button>
        <button role="tab" aria-selected={mode === "web"} className={mode === "web" ? "active" : ""} onClick={() => setMode("web")}>
          Expert Web Testing
        </button>
        <button role="tab" aria-selected={mode === "network"} className={mode === "network" ? "active" : ""} onClick={() => setMode("network")}>
          Network Assessment
        </button>
        <button role="tab" aria-selected={mode === "source"} className={mode === "source" ? "active" : ""} onClick={() => setMode("source")}>
          Static Source Analysis
        </button>
        <button role="tab" aria-selected={mode === "supply"} className={mode === "supply" ? "active" : ""} onClick={() => setMode("supply")}>
          Secrets &amp; Dependencies
        </button>
        <button role="tab" aria-selected={mode === "benchmark"} className={mode === "benchmark" ? "active" : ""} onClick={() => setMode("benchmark")}>
          Dataset Benchmarks
        </button>
      </div>
      {mode === "developer" ? (
        <GuidedSecurityOperator/>
      ) : mode === "web" ? (
        <AuthorizedWebSecurityPanel/>
      ) : mode === "network" ? (
        <NetworkAssessmentPanel/>
      ) : mode === "supply" ? (
        <SupplyChainPanel/>
      ) : mode === "benchmark" ? (
        <DatasetBenchmarkPanel/>
      ) : (
        <StaticSecurityPanel/>
      )}
    </div>
  );
}
