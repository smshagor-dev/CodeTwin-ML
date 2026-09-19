import type {
  WebAuthContext,
  WebCheckConfig,
  WebScanConfig,
  WebScanStartRequest,
  WebsiteRecord,
} from "../types";

export const AUTHORIZATION_STATEMENT =
  "I own this target or have explicit authorization to perform security testing.";

export const webCheckLabels: Array<[keyof WebCheckConfig, string]> = [
  ["sql_injection", "SQL injection"],
  ["xss", "Cross-site scripting"],
  ["csrf", "CSRF controls"],
  ["open_redirect", "Open redirect"],
  ["path_traversal", "Path traversal indicators"],
  ["ssrf_indicators", "SSRF indicators"],
  ["template_command_indicators", "Template injection indicators"],
  ["method_misconfiguration", "HTTP method configuration"],
  ["cors", "CORS policy"],
  ["session", "Session and cookie controls"],
  ["access_control", "Access-control comparison"],
  ["api_validation", "API input validation"],
];

export function defaultWebChecks(): WebCheckConfig {
  return {
    sql_injection: true,
    xss: true,
    csrf: true,
    open_redirect: true,
    path_traversal: true,
    ssrf_indicators: true,
    template_command_indicators: true,
    method_misconfiguration: true,
    cors: true,
    session: true,
    access_control: true,
    api_validation: true,
  };
}

export function defaultWebScanConfig(targetUrl: string): WebScanConfig {
  const host = safeHost(targetUrl);
  return {
    scope: {
      target_url: targetUrl.trim(),
      allowed_hostnames: host ? [host] : [],
      allowed_subdomains: [],
      allowed_paths: ["/"],
      excluded_paths: ["/logout", "/signout"],
      max_crawl_depth: 2,
      max_requests: 200,
      concurrency: 2,
      timeout_ms: 5_000,
      response_limit_bytes: 512_000,
      redirect_limit: 3,
      retry_limit: 0,
      active_testing: false,
      allow_non_idempotent_methods: false,
      allow_private_networks: false,
      enable_timing_probes: false,
      authorization_confirmed: false,
    },
    checks: defaultWebChecks(),
  };
}

export function blankWebAuth(): WebAuthContext {
  return {
    cookie_header: null,
    bearer_token: null,
    custom_headers: [],
  };
}

export function splitScopeValues(value: string): string[] {
  return [...new Set(
    value
      .split(/[\n,]/)
      .map((item) => item.trim())
      .filter(Boolean),
  )];
}

export function parseCustomHeaders(value: string): Array<[string, string]> {
  return value
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const separator = line.indexOf(":");
      if (separator <= 0) {
        throw new Error("Custom headers must use one 'Name: value' header per line.");
      }
      const name = line.slice(0, separator).trim();
      const headerValue = line.slice(separator + 1).trim();
      if (!name || !headerValue) {
        throw new Error("Custom headers must include both a name and value.");
      }
      return [name, headerValue] as [string, string];
    });
}

export function websiteTarget(website: WebsiteRecord | undefined): string {
  return website?.url ?? "";
}

export function validateWebScanConfig(config: WebScanConfig): string | null {
  let url: URL;
  try {
    url = new URL(config.scope.target_url);
  } catch {
    return "Enter a valid absolute HTTP or HTTPS target URL.";
  }
  if (!["http:", "https:"].includes(url.protocol) || !url.hostname) {
    return "Only absolute HTTP and HTTPS targets are supported.";
  }
  if (url.username || url.password) {
    return "Do not embed credentials in the target URL.";
  }
  if (!config.scope.authorization_confirmed) {
    return "Explicit authorization confirmation is required before a scan can start.";
  }
  if (!config.scope.allowed_hostnames.length) {
    return "At least one allowed hostname is required.";
  }
  if (config.scope.max_crawl_depth < 0 || config.scope.max_crawl_depth > 8) {
    return "Maximum crawl depth must be between 0 and 8.";
  }
  if (config.scope.max_requests < 1 || config.scope.max_requests > 2_000) {
    return "Maximum requests must be between 1 and 2000.";
  }
  if (config.scope.concurrency < 1 || config.scope.concurrency > 8) {
    return "Concurrency must be between 1 and 8.";
  }
  if (config.scope.timeout_ms < 500 || config.scope.timeout_ms > 30_000) {
    return "Timeout must be between 500 and 30000 ms.";
  }
  if (config.scope.response_limit_bytes < 16_384 || config.scope.response_limit_bytes > 2_097_152) {
    return "Response limit must be between 16384 and 2097152 bytes.";
  }
  if (config.scope.allow_non_idempotent_methods && !config.scope.active_testing) {
    return "Non-idempotent request testing requires active testing to be enabled.";
  }
  if (config.scope.enable_timing_probes && !config.scope.active_testing) {
    return "Timing probes require active testing to be enabled.";
  }
  return null;
}

export function buildWebScanRequest(args: {
  websiteId: string | null;
  projectId: string | null;
  config: WebScanConfig;
  primaryCookie: string;
  primaryBearer: string;
  primaryHeaders: string;
  secondaryEnabled: boolean;
  secondaryCookie: string;
  secondaryBearer: string;
  secondaryHeaders: string;
}): WebScanStartRequest {
  return {
    website_id: args.websiteId,
    project_id: args.projectId,
    config: args.config,
    primary_auth: {
      cookie_header: nullable(args.primaryCookie),
      bearer_token: nullable(args.primaryBearer),
      custom_headers: parseCustomHeaders(args.primaryHeaders),
    },
    secondary_auth: args.secondaryEnabled
      ? {
          cookie_header: nullable(args.secondaryCookie),
          bearer_token: nullable(args.secondaryBearer),
          custom_headers: parseCustomHeaders(args.secondaryHeaders),
        }
      : null,
  };
}

function nullable(value: string): string | null {
  const trimmed = value.trim();
  return trimmed || null;
}

function safeHost(value: string): string {
  try {
    return new URL(value).hostname.toLowerCase();
  } catch {
    return "";
  }
}
