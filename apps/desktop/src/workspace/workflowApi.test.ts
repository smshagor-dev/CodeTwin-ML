import { describe, expect, it } from "vitest";

import { dagLevels, evidenceLabel, type WorkflowTask } from "./workflowApi";

function task(id: string, depends_on: string[] = [], extra: Partial<WorkflowTask> = {}): WorkflowTask {
  return {
    id, run_id: "r", plan_revision: 1, key: id, parent_task_id: null, delegation_depth: 0, role: "r", title: id,
    side_effect: "read_only", capabilities: [], scope_digest: "0".repeat(64), state: "queued", reason_code: null,
    attempt_count: 0, max_attempts: 2, output: null, output_sha256: null, summary: null, evidence_class: null,
    depends_on, started_ms: null, finished_ms: null, ...extra,
  };
}

describe("workflow helpers", () => {
  it("groups a diamond DAG into dependency stages", () => {
    const levels = dagLevels([task("d", ["b", "c"]), task("a"), task("b", ["a"]), task("c", ["a"])]);
    expect(levels.map((l) => l.map((t) => t.id).sort())).toEqual([["a"], ["b", "c"], ["d"]]);
  });

  it("does not loop on corrupt cyclic input", () => {
    expect(dagLevels([task("x", ["y"]), task("y", ["x"])]).flat()).toHaveLength(2);
  });

  it("keeps planned, observed, applied and verified distinct", () => {
    expect(evidenceLabel({ state: "awaiting_approval", evidence_class: null })).toBe("awaiting approval");
    expect(evidenceLabel({ state: "completed", evidence_class: "observation" })).toBe("observed");
    expect(evidenceLabel({ state: "completed", evidence_class: "applied_change" })).toBe("applied");
    expect(evidenceLabel({ state: "completed", evidence_class: "validated_result" })).toBe("verified");
    expect(evidenceLabel({ state: "completed", evidence_class: "hypothesis" })).toBe("hypothesis (unverified)");
  });
});
