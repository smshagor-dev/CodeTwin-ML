import { describe, expect, it } from "vitest";

import {
  buildGuidedRequests,
  guidedConfigFor,
  validateGuidedConfig,
} from "./guidedSecurityModel";

describe("guided security developer mode", () => {
  it("uses a bounded deep profile", () => {
    const config = guidedConfigFor("https://staging.example.test", "staging", "deep");
    expect(config.scope.max_requests).toBe(800);
    expect(config.scope.max_crawl_depth).toBe(4);
    expect(config.scope.concurrency).toBe(3);
    expect(config.scope.allow_non_idempotent_methods).toBe(false);
    expect(config.scope.enable_timing_probes).toBe(false);
  });

  it("keeps authorized production conservative", () => {
    const config = guidedConfigFor("https://example.test", "authorized_production", "deep");
    config.scope.authorization_confirmed = true;
    expect(config.scope.max_crawl_depth).toBeLessThanOrEqual(2);
    expect(config.scope.max_requests).toBeLessThanOrEqual(350);
    expect(config.scope.concurrency).toBeLessThanOrEqual(2);
    expect(config.scope.timeout_ms).toBeLessThanOrEqual(5_000);
    expect(config.scope.response_limit_bytes).toBeLessThanOrEqual(512_000);
    expect(config.scope.redirect_limit).toBeLessThanOrEqual(3);
    expect(config.scope.retry_limit).toBe(0);
    expect(config.scope.allow_private_networks).toBe(false);
    expect(config.scope.allow_non_idempotent_methods).toBe(false);
    expect(config.scope.enable_timing_probes).toBe(false);
    expect(config.scope.excluded_paths).toEqual(expect.arrayContaining([
      "/payment",
      "/delete",
      "/email/send",
      "/webhook/production",
      "/admin/destructive",
    ]));

    config.scope.allow_non_idempotent_methods = true;
    expect(validateGuidedConfig(config, "authorized_production")).toMatch(/state-changing/i);
  });

  it("keeps authentication secrets outside persisted config", () => {
    const config = guidedConfigFor("http://localhost:3000", "local", "standard");
    config.scope.authorization_confirmed = true;
    const { prepare, execution } = buildGuidedRequests({
      websiteId: null,
      projectId: "project-1",
      environment: "local",
      testingDepth: "standard",
      authMode: "test_accounts_a_b",
      config,
      primaryCookie: "session=primary-secret",
      primaryBearer: "primary-token",
      primaryHeaders: "X-Test: alpha",
      secondaryCookie: "session=secondary-secret",
      secondaryBearer: "secondary-token",
      secondaryHeaders: "X-Test: beta",
    });

    expect(prepare.primary_auth.cookie_header).toBe("session=primary-secret");
    expect(prepare.secondary_auth?.cookie_header).toBe("session=secondary-secret");
    expect(JSON.stringify(prepare.config)).not.toContain("primary-secret");
    expect(JSON.stringify(prepare.config)).not.toContain("secondary-secret");
    expect(execution.guided_session_id).toBeNull();
  });
});
