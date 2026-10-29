import { describe, expect, it } from "vitest";

import { agentConversation, formatMs, formatPercent } from "./platformApi";

const base = { key: "k", evidence_class: "observation", depends_on: [], started_ms: 1, reason_code: null };

describe("platform helpers", () => {
  it("orders the agent conversation by completion and skips silent or superseded tasks", () => {
    const messages = agentConversation([
      { ...base, id: "b", role: "security_reviewer", title: "Findings", summary: "2 findings", finished_ms: 30, depends_on: ["a"] },
      { ...base, id: "a", role: "repository_analyst", title: "Map", summary: "3 files", finished_ms: 10 },
      { ...base, id: "c", role: "qa_planner", title: "Tests", summary: null, finished_ms: 20 },
      { ...base, id: "d", role: "qa_planner", title: "Old", summary: "stale", finished_ms: 5, reason_code: "superseded_by_replan" },
    ]);
    expect(messages.map((m) => m.taskId)).toEqual(["a", "b"]);
    expect(messages[1].inReplyTo).toEqual(["a"]);
  });

  it("formats rates and latencies", () => {
    expect(formatPercent(0.5)).toBe("50%");
    expect(formatPercent(0.004)).toBe("0.40%");
    expect(formatMs(250)).toBe("250 ms");
    expect(formatMs(12_500)).toBe("12.5 s");
  });
});
