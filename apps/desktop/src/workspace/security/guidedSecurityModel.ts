import type {
  GuidedAuthMode,
  GuidedEnvironment,
  GuidedSecurityPrepareRequest,
  GuidedTestingDepth,
  WebScanConfig,
  WebScanStartRequest,
} from "../types";
import {
  buildWebScanRequest,
  defaultWebScanConfig,
  parseCustomHeaders,
  validateWebScanConfig,
} from "./webSecurityModel";

export const GUIDED_AUTHORIZATION_STATEMENT =
  "I own this application or have explicit authorization to security-test it.";

export function guidedConfigFor(
  targetUrl: string,
  environment: GuidedEnvironment,
  depth: GuidedTestingDepth,
): WebScanConfig {
  const config = defaultWebScanConfig(targetUrl);
  config.scope.authorization_confirmed = false;
  config.scope.active_testing = true;
  config.scope.excluded_paths = [
    "/logout",
    "/signout",
    "/payment",
    "/delete",
    "/email/send",
    "/webhook/production",
    "/admin/destructive",
  ];
  config.scope.allow_private_networks = environment === "local" || environment === "development";
  config.scope.allow_non_idempotent_methods = false;
  config.scope.enable_timing_probes = false;

  if (depth === "quick") {
    config.scope.max_crawl_depth = 1;
    config.scope.max_requests = 120;
    config.scope.concurrency = 2;
    config.scope.timeout_ms = 4_000;
  } else if (depth === "standard") {
    config.scope.max_crawl_depth = 2;
    config.scope.max_requests = 350;
    config.scope.concurrency = 2;
    config.scope.timeout_ms = 5_000;
  } else if (depth === "deep") {
    config.scope.max_crawl_depth = 4;
    config.scope.max_requests = 800;
    config.scope.concurrency = 3;
    config.scope.timeout_ms = 7_000;
  }

  if (environment === "authorized_production") {
    config.scope.max_crawl_depth = Math.min(config.scope.max_crawl_depth, 2);
    config.scope.max_requests = Math.min(config.scope.max_requests, 350);
    config.scope.max_requests_per_endpoint = Math.min(config.scope.max_requests_per_endpoint, 20);
    config.scope.min_request_interval_ms = Math.max(config.scope.min_request_interval_ms, 250);
    config.scope.concurrency = Math.min(config.scope.concurrency, 2);
    config.scope.timeout_ms = Math.min(config.scope.timeout_ms, 5_000);
    config.scope.response_limit_bytes = Math.min(config.scope.response_limit_bytes, 512_000);
    config.scope.redirect_limit = Math.min(config.scope.redirect_limit, 3);
    config.scope.retry_limit = 0;
    config.scope.allow_private_networks = false;
    config.scope.allow_non_idempotent_methods = false;
    config.scope.enable_timing_probes = false;
  }
  return config;
}

export function validateGuidedConfig(
  config: WebScanConfig,
  environment: GuidedEnvironment,
): string | null {
  const base = validateWebScanConfig(config);
  if (base) return base;
  if (environment === "authorized_production" && config.scope.allow_non_idempotent_methods) {
    return "Developer Mode does not automatically run state-changing probes against authorized production.";
  }
  if (environment === "authorized_production" && config.scope.enable_timing_probes) {
    return "Developer Mode keeps timing probes disabled for authorized production.";
  }
  if (environment === "authorized_production" && config.scope.max_crawl_depth > 2) {
    return "Authorized production Developer Mode is capped at crawl depth 2.";
  }
  if (environment === "authorized_production" && config.scope.max_requests > 350) {
    return "Authorized production Developer Mode is capped at 350 requests.";
  }
  if (environment === "authorized_production" && config.scope.max_requests_per_endpoint > 20) {
    return "Authorized production Developer Mode is capped at 20 requests per endpoint.";
  }
  if (environment === "authorized_production" && config.scope.min_request_interval_ms < 250) {
    return "Authorized production Developer Mode requires at least 250 ms between requests.";
  }
  if (environment === "authorized_production" && config.scope.concurrency > 2) {
    return "Authorized production Developer Mode is capped at concurrency 2.";
  }
  if (environment === "authorized_production" && config.scope.timeout_ms > 5_000) {
    return "Authorized production Developer Mode is capped at a 5000 ms request timeout.";
  }
  if (environment === "authorized_production" && config.scope.response_limit_bytes > 512_000) {
    return "Authorized production Developer Mode is capped at 512000 response bytes.";
  }
  if (environment === "authorized_production" && config.scope.redirect_limit > 3) {
    return "Authorized production Developer Mode is capped at three redirects.";
  }
  if (environment === "authorized_production" && config.scope.retry_limit > 0) {
    return "Authorized production Developer Mode does not retry requests automatically.";
  }
  if (environment === "authorized_production" && config.scope.allow_private_networks) {
    return "Authorized production Developer Mode cannot enable private-network targeting.";
  }
  return null;
}

export function buildGuidedRequests(args: {
  websiteId: string | null;
  projectId: string | null;
  environment: GuidedEnvironment;
  testingDepth: GuidedTestingDepth;
  authMode: GuidedAuthMode;
  config: WebScanConfig;
  primaryCookie: string;
  primaryBearer: string;
  primaryHeaders: string;
  secondaryCookie: string;
  secondaryBearer: string;
  secondaryHeaders: string;
}): { prepare: GuidedSecurityPrepareRequest; execution: WebScanStartRequest } {
  const secondaryEnabled = args.authMode === "test_accounts_a_b";
  const primaryEnabled = args.authMode !== "none";
  const scan = buildWebScanRequest({
    websiteId: args.websiteId,
    projectId: args.projectId,
    config: args.config,
    primaryCookie: primaryEnabled ? args.primaryCookie : "",
    primaryBearer: primaryEnabled ? args.primaryBearer : "",
    primaryHeaders: primaryEnabled ? args.primaryHeaders : "",
    secondaryEnabled,
    secondaryCookie: secondaryEnabled ? args.secondaryCookie : "",
    secondaryBearer: secondaryEnabled ? args.secondaryBearer : "",
    secondaryHeaders: secondaryEnabled ? args.secondaryHeaders : "",
  });
  return {
    prepare: {
      website_id: scan.website_id,
      project_id: scan.project_id,
      environment: args.environment,
      testing_depth: args.testingDepth,
      auth_mode: args.authMode,
      config: scan.config,
      primary_auth: scan.primary_auth,
      secondary_auth: scan.secondary_auth,
    },
    execution: { ...scan, guided_session_id: null },
  };
}

export function validateGuidedHeaders(value: string): string | null {
  try {
    parseCustomHeaders(value);
    return null;
  } catch (error) {
    return String(error);
  }
}

export function developerFindingExplanation(category: string): {
  what: string;
  fix: string;
  verify: string;
} {
  switch (category) {
    case "sql_injection":
      return {
        what: "Input appears to influence database-query behavior beyond normal application validation.",
        fix: "Keep query structure fixed and bind user values through the project's parameterized query or prepared-statement API.",
        verify: "Retest this finding after the query path is parameterized and confirm the control/test responses no longer diverge.",
      };
    case "xss":
      return {
        what: "User-controlled text was reflected into an HTML context that may not be encoded safely.",
        fix: "Apply context-aware output encoding and avoid unsafe HTML/JavaScript sinks.",
        verify: "Retest the affected parameter and confirm the marker is encoded or remains only inert text.",
      };
    case "access_control":
      return {
        what: "Two supplied test identities produced an authorization result that deserves ownership/role review.",
        fix: "Enforce authorization server-side for every object lookup using the authenticated principal and object policy.",
        verify: "Retest with the same two authorized test accounts and confirm the second identity cannot receive an object it should not access.",
      };
    case "csrf":
      return {
        what: "A state-changing form was discovered without an obvious anti-CSRF field.",
        fix: "Use the framework's CSRF middleware/token validation and an appropriate SameSite cookie policy.",
        verify: "Re-map the form and verify the expected anti-CSRF control is present and enforced.",
      };
    case "open_redirect":
      return {
        what: "A redirect destination appears controllable by request input.",
        fix: "Use relative destinations or map allowed destinations through a fixed server-side allow-list.",
        verify: "Retest with the harmless external marker and confirm the response no longer redirects to it.",
      };
    case "api_input_validation":
      return {
        what: "Malformed API input caused server-error behavior instead of a deterministic client error.",
        fix: "Validate request schemas before business logic and return stable 4xx responses for invalid input.",
        verify: "Retest the same input class and confirm malformed requests are rejected cleanly.",
      };
    default:
      return {
        what: "CodeTwin observed a repeatable security-relevant behavior within the authorized scope.",
        fix: "Review the correlated source candidates and apply the finding-specific remediation before changing code.",
        verify: "Use the targeted retest after the fix and compare the new result with the original evidence.",
      };
  }
}

export function parseStoredJson<T>(value: string, fallback: T): T {
  try {
    return JSON.parse(value) as T;
  } catch {
    return fallback;
  }
}
