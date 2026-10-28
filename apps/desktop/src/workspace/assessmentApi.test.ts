import { describe, expect, it } from "vitest";

import { EMPTY_FILTER, matches, maxSeq, mergeItems, toLogLine, type FindingCard, type StreamEvent } from "./assessmentApi";

function ev(seq: number, extra: Partial<StreamEvent> = {}): StreamEvent {
  return {
    type: "event", key: `e:${seq}`, seq, ts_ms: 1_700_000_000_000 + seq * 1000, run_id: "r", task_id: null, agent: null,
    tool: null, stage: "ORCHESTRATOR", status: "running", target: null, message: `event ${seq}`, duration_ms: null,
    correlation_id: "r", finding_ids: [], ...extra,
  };
}

function card(seq: number, id: string, extra: Partial<FindingCard> = {}): FindingCard {
  return {
    type: "finding", key: `f:t:${id}`, seq, ts_ms: 0, run_id: "r", task_id: "t", agent: "security_reviewer", finding_id: id,
    source: "appsec", title: `Finding ${id}`, severity: "high", verification: "potential", rule_id: "rule", description: "",
    target: "app", location: "app.ts:2", first_seen: "", cwe: "CWE-95", owasp: null, cve: [], cvss: null, confidence: 0.8,
    evidence: [], impact: "", remediation: [], remediation_basis: "", limitations: [], review: null, scan_run_id: "s",
    file_sha256: null, reviewable: true, ...extra,
  };
}

describe("assessment stream merging", () => {
  it("deduplicates replayed and pushed items and keeps seq order", () => {
    const first = mergeItems([], [ev(1), ev(2), card(2, "a")]);
    const replay = mergeItems(first, [ev(2), card(2, "a"), ev(3)]);
    expect(replay.map((i) => i.key)).toEqual(["e:1", "e:2", "f:t:a", "e:3"]);
    expect(maxSeq(replay)).toBe(3);
  });

  it("keeps identity when nothing changes and updates re-delivered findings in place", () => {
    const base = mergeItems([], [ev(1), card(1, "a")]);
    expect(mergeItems(base, [ev(1)])).toBe(base);
    const updated = mergeItems(base, [card(1, "a", { verification: "confirmed" })]);
    expect(updated).toHaveLength(2);
    expect((updated[1] as FindingCard).verification).toBe("confirmed");
  });

  it("sorts out-of-order deliveries after reconnect", () => {
    const items = mergeItems(mergeItems([], [ev(5)]), [ev(3), ev(4)]);
    expect(items.map((i) => i.seq)).toEqual([3, 4, 5]);
  });

  it("caps memory for very long assessments", () => {
    const many = Array.from({ length: 30_000 }, (_, i) => ev(i + 1));
    const merged = mergeItems([], many, 20_000);
    expect(merged).toHaveLength(20_000);
    expect(merged[0].seq).toBe(10_001);
  });
});

describe("assessment stream filtering", () => {
  const items = [
    ev(1, { stage: "AGENT", agent: "security_reviewer" }),
    ev(2, { stage: "ERROR", agent: "deps", message: "osv timeout" }),
    ev(3, { stage: "OK", agent: "qa_planner" }),
    card(4, "crit", { severity: "critical", verification: "potential" }),
    card(4, "conf", { severity: "high", verification: "confirmed" }),
  ];
  const keys = (f: Partial<typeof EMPTY_FILTER>) => items.filter((i) => matches(i, { ...EMPTY_FILTER, ...f })).map((i) => i.key);

  it("keeps severity and verification independent", () => {
    expect(keys({ severity: "critical" })).toEqual(["f:t:crit"]);
    expect(keys({ verification: "confirmed" })).toEqual(["f:t:conf"]);
    expect(keys({ severity: "critical", verification: "confirmed" })).toEqual([]);
  });

  it("filters by kind, agent, passed checks and text", () => {
    expect(keys({ kinds: "errors" })).toEqual(["e:2"]);
    expect(keys({ agent: "qa_planner" })).toEqual(["e:3"]);
    expect(keys({ verification: "passed" })).toEqual(["e:3"]);
    expect(keys({ query: "OSV" })).toEqual(["e:2"]);
  });

  it("renders plain log lines for copy and export", () => {
    expect(toLogLine(card(4, "x", { severity: "critical" }))).toContain("[CRITICAL/Potential]");
    expect(toLogLine(ev(1, { stage: "OK", agent: "qa", duration_ms: 1500 }))).toMatch(/\[OK\] \[qa\] event 1 \(1\.5 s\)$/);
  });
});
