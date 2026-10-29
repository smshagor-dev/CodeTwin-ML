import { describe, expect, it } from "vitest";

import { describeCause, formatDelta, isLoopbackEndpoint, suppressionState, validateSuppression, type Suppression } from "./intelligenceApi";

const base: Suppression = {
  id: "supp-1", project_id: "p1", scope: "path", matcher: "vendor/", reason: "third-party code",
  created_by: "operator:a", created_ms: 0, expires_ms: 1000, revoked_by: null, revoked_ms: null,
};

describe("security intelligence helpers", () => {
  it("explains why a finding is hidden", () => {
    expect(describeCause("review:false_positive")).toBe("Reviewed as a false positive");
    expect(describeCause("suppression:supp-1")).toBe("Suppressed (supp-1)");
  });

  it("derives suppression state from revocation and expiry", () => {
    expect(suppressionState(base, 500)).toBe("active");
    expect(suppressionState(base, 1000)).toBe("expired");
    expect(suppressionState({ ...base, revoked_by: "operator:a", revoked_ms: 10 }, 500)).toBe("revoked");
  });

  it("mirrors the backend suppression rules", () => {
    const ok = { scope: "path" as const, matcher: "vendor/", reason: "third-party code we do not ship", ttlDays: 30 };
    expect(validateSuppression(ok)).toBeNull();
    expect(validateSuppression({ ...ok, matcher: "  " })).toMatch(/Enter/);
    expect(validateSuppression({ ...ok, matcher: "../etc" })).toMatch(/relative prefix/);
    expect(validateSuppression({ ...ok, reason: "short" })).toMatch(/10–2000/);
    expect(validateSuppression({ ...ok, ttlDays: 0 })).toMatch(/1–365/);
    expect(validateSuppression({ ...ok, ttlDays: 400 })).toMatch(/1–365/);
  });

  it("accepts only loopback embedding endpoints", () => {
    expect(isLoopbackEndpoint("http://127.0.0.1:11434/v1/embeddings")).toBe(true);
    expect(isLoopbackEndpoint("http://localhost:8080/v1/embeddings")).toBe(true);
    expect(isLoopbackEndpoint("https://api.example.com/v1/embeddings")).toBe(false);
    expect(isLoopbackEndpoint("http://127.0.0.1:11434/v1/chat")).toBe(false);
    expect(isLoopbackEndpoint("not a url")).toBe(false);
  });

  it("formats signed run-time deltas", () => {
    expect(formatDelta(null)).toBe("—");
    expect(formatDelta(-300)).toBe("−300 ms");
    expect(formatDelta(1500)).toBe("+1.5 s");
    expect(formatDelta(0)).toBe("±0 ms");
  });
});
