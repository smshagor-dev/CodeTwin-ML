import { describe, expect, it } from "vitest";

import type { GuidedActivityRecord, GuidedSecuritySessionRecord, WebFindingRecord } from "./types";
import { webFindingToCard, webSessionStream, webSessionSummary, webStage } from "./webStream";

const session = { id: "gss-1", target_url: "https://app.example.test", project_id: "p1", scan_id: "scan-1" } as GuidedSecuritySessionRecord;

function activity(seq: number, event_type: string, message: string): GuidedActivityRecord {
  return { id: "a" + seq, session_id: "gss-1", sequence: seq, event_type, phase: "mapping", message, detail_json: "{}", created_at: "2026-10-28T10:00:0" + (seq % 10) + "Z" };
}

function finding(id: string, severity: WebFindingRecord["severity"], confidence: WebFindingRecord["confidence"]): WebFindingRecord {
  return {
    id, scan_id: "scan-1", fingerprint: "fp-" + id, category: "xss", severity, confidence,
    target: "https://app.example.test/x", endpoint_url: "https://app.example.test/x", method: "GET", parameter_name: "q",
    title: "Reflected XSS", description: "desc", reproduction_summary: "repro", impact: "impact", remediation: "encode output",
    references: [], source_file_id: null, source_relative_path: null, source_symbol_id: null, source_symbol_name: null,
    source_confidence: null, status: "open", first_detected: "2026-10-28T10:01:00Z", last_detected: "2026-10-28T10:01:00Z",
  };
}

describe("web session → terminal stream adapter", () => {
  it("maps event_type to a stage tag", () => {
    expect(webStage("scan_failed")).toBe("ERROR");
    expect(webStage("request_denied")).toBe("BLOCKED");
    expect(webStage("finding_detected")).toBe("POTENTIAL");
    expect(webStage("phase_completed")).toBe("OK");
    expect(webStage("mapping_progress")).toBe("INFO");
  });

  it("orders activity events before finding cards", () => {
    const items = webSessionStream(session, [activity(1, "started", "began"), activity(2, "finding_detected", "found")], [finding("f1", "high", "Confirmed")]);
    expect(items.map((i) => i.type)).toEqual(["event", "event", "finding"]);
    expect(items[2].seq).toBeGreaterThan(items[1].seq);
    expect(items[0].run_id).toBe("gss-1");
  });

  it("maps web severity and confidence onto the shared finding model", () => {
    const card = webFindingToCard(session, finding("f2", "informational", "Likely"), 0);
    expect(card.severity).toBe("info");
    expect(card.verification).toBe("validating");
    expect(card.reviewable).toBe(false);
    expect(card.location).toContain("GET");
    expect(card.remediation).toEqual(["encode output"]);
  });

  it("summarizes severity and verification counts", () => {
    const summary = webSessionSummary([
      finding("a", "critical", "Confirmed"),
      finding("b", "high", "Potential"),
      finding("c", "informational", "Likely"),
    ]);
    expect(summary.total).toBe(3);
    expect(summary.critical).toBe(1);
    expect(summary.high).toBe(1);
    expect(summary.info).toBe(1);
    expect(summary.confirmed).toBe(1);
    expect(summary.potential).toBe(1);
    expect(summary.validating).toBe(1);
  });
});
