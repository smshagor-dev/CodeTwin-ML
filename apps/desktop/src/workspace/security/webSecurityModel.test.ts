import { describe, expect, it } from "vitest";

import {
  AUTHORIZATION_STATEMENT,
  buildWebScanRequest,
  defaultWebScanConfig,
  parseCustomHeaders,
  splitScopeValues,
  validateWebScanConfig,
} from "./webSecurityModel";

describe("authorized web security configuration", () => {
  it("defaults to bounded passive-only testing", () => {
    const config = defaultWebScanConfig("https://staging.example.test/app");
    expect(config.scope.allowed_hostnames).toEqual(["staging.example.test"]);
    expect(config.scope.max_requests).toBe(200);
    expect(config.scope.concurrency).toBe(2);
    expect(config.scope.active_testing).toBe(false);
    expect(config.scope.allow_non_idempotent_methods).toBe(false);
    expect(config.scope.enable_timing_probes).toBe(false);
    expect(config.scope.authorization_confirmed).toBe(false);
  });

  it("requires the exact authorization gate before execution", () => {
    expect(AUTHORIZATION_STATEMENT).toBe(
      "I own this target or have explicit authorization to perform security testing.",
    );
    const config = defaultWebScanConfig("http://localhost:3000");
    expect(validateWebScanConfig(config)).toMatch(/authorization/i);
    config.scope.authorization_confirmed = true;
    expect(validateWebScanConfig(config)).toBeNull();
  });

  it("rejects malformed and unsafe target schemes", () => {
    const config = defaultWebScanConfig("file:///tmp/app");
    config.scope.authorization_confirmed = true;
    expect(validateWebScanConfig(config)).toMatch(/HTTP/);
    config.scope.target_url = "https://user:pass@example.test";
    config.scope.allowed_hostnames = ["example.test"];
    expect(validateWebScanConfig(config)).toMatch(/credentials/i);
  });

  it("parses and deduplicates scope values", () => {
    expect(splitScopeValues("/api, /admin\n/api")).toEqual(["/api", "/admin"]);
  });

  it("parses explicit custom headers without persisting them in config", () => {
    expect(parseCustomHeaders("X-Test: alpha\nX-Trace: beta")).toEqual([
      ["X-Test", "alpha"],
      ["X-Trace", "beta"],
    ]);
    expect(() => parseCustomHeaders("broken-header")).toThrow(/Name: value/);

    const config = defaultWebScanConfig("http://localhost:3000");
    config.scope.authorization_confirmed = true;
    const request = buildWebScanRequest({
      websiteId: null,
      projectId: null,
      config,
      primaryCookie: "session=secret",
      primaryBearer: "token-secret",
      primaryHeaders: "X-Test: value",
      secondaryEnabled: false,
      secondaryCookie: "",
      secondaryBearer: "",
      secondaryHeaders: "",
    });
    expect(request.primary_auth.cookie_header).toBe("session=secret");
    expect(JSON.stringify(request.config)).not.toContain("token-secret");
    expect(JSON.stringify(request.config)).not.toContain("session=secret");
  });
});
