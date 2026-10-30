import { describe, expect, it } from "vitest";

import { parsePublicKeys, sourceLabel, VERDICT_LABEL, type SourceRecord } from "./reportsApi";

const KEY = "8353cb7747b98d6184761fd5ed619bb7dd39a05e64b7d7359101e7eec1a4971c";

describe("report helpers", () => {
  it("accepts only 64-hex public keys and de-duplicates them case-insensitively", () => {
    const parsed = parsePublicKeys(`${KEY}, ${KEY.toUpperCase()}\nnot-a-key ${KEY.slice(2)}`);
    expect(parsed.keys).toEqual([KEY]);
    expect(parsed.invalid).toEqual(["not-a-key", KEY.slice(2)]);
  });

  it("never labels a non-verified verdict as verified", () => {
    for (const [verdict, label] of Object.entries(VERDICT_LABEL)) {
      if (verdict !== "verified") expect(label.toLowerCase()).not.toContain("verified");
    }
  });

  it("labels sources by title, then by URL", () => {
    const source = {
      id: "src_1", origin: "web", requested_url: "https://a.example/x", final_url: "https://a.example/y",
      canonical_url: null, metadata: { title: null }, content_sha256: "", published_ms: null, retrieved_ms: 0,
      duplicate_of: null, instruction_like_phrases: 0, freshness: null,
    } as unknown as SourceRecord;
    expect(sourceLabel(source)).toBe("https://a.example/y");
    expect(sourceLabel({ ...source, metadata: { ...source.metadata, title: "Advisory" } })).toBe("Advisory");
  });
});
