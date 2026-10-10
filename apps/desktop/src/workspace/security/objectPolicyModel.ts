import type {
  ObjectAccessPolicy, ObjectPolicyResult, WebScanConfig, WebScanRecord, WebScanStartRequest,
} from "../types";

export type PolicyFields = {
  identityUrl: string;
  identityPointer: string;
  primaryIdentity: string;
  secondaryIdentity: string;
  objectUrl: string;
  objectPointer: string;
  expectedObject: string;
  shared: boolean;
};

export function policyResult(scan: WebScanRecord | null): ObjectPolicyResult | null {
  try {
    const result = JSON.parse(scan?.config_json ?? "{}").object_policy_result;
    const statuses = ["ViolationConfirmed", "AccessDenied", "SharedAccessObserved", "UnableToVerify"];
    const strings = ["reason", "identity_url", "object_url", "identity_json_pointer", "object_json_pointer"];
    return result && statuses.includes(result.status)
      && strings.every(key => typeof result[key] === "string")
      && typeof result.secondary_access_allowed === "boolean"
      ? result as ObjectPolicyResult : null;
  } catch {
    return null;
  }
}

export function policyReplayConfig(scan: WebScanRecord): WebScanConfig {
  const parsed = JSON.parse(scan.config_json);
  return {
    scope: { ...parsed.scope, authorization_confirmed: false },
    checks: { ...parsed.checks },
  };
}

export function buildObjectPolicy(fields: PolicyFields, request: WebScanStartRequest): ObjectAccessPolicy {
  if (!request.config.scope.active_testing || !request.config.checks.access_control || !request.secondary_auth) {
    throw new Error("Enable active access-control testing and supply both test sessions.");
  }
  const hasCredentials = (auth: WebScanStartRequest["primary_auth"]) => Boolean(
    auth.cookie_header?.trim() || auth.bearer_token?.trim() || auth.custom_headers.length,
  );
  if (!hasCredentials(request.primary_auth) || !hasCredentials(request.secondary_auth)) {
    throw new Error("Supply credentials for both test sessions.");
  }
  const origin = new URL(request.config.scope.target_url).origin;
  for (const value of [fields.identityUrl, fields.objectUrl]) {
    const url = new URL(value);
    if (url.origin !== origin || url.username || url.password || !["http:", "https:"].includes(url.protocol)) {
      throw new Error("Policy URLs must use the target origin without embedded credentials.");
    }
  }
  const principal = (value: string): unknown => {
    if (!value.trim()) throw new Error("Enter both expected principal values.");
    try { return JSON.parse(value); } catch { return value.trim(); }
  };
  const primary = principal(fields.primaryIdentity);
  const secondary = principal(fields.secondaryIdentity);
  if (primary === null || secondary === null || JSON.stringify(primary) === JSON.stringify(secondary)) {
    throw new Error("Expected principals must be distinct and non-null.");
  }
  if (!fields.identityPointer.startsWith("/") || !fields.objectPointer.startsWith("/")) {
    throw new Error("JSON pointers must begin with /.");
  }
  let object: unknown;
  try { object = JSON.parse(fields.expectedObject); }
  catch { throw new Error("Enter valid JSON for the expected protected object."); }
  if (!object || typeof object !== "object" || Array.isArray(object) || !Object.keys(object).length) {
    throw new Error("Expected protected content must be a nonempty JSON object.");
  }
  return {
    identity_url: fields.identityUrl.trim(), identity_json_pointer: fields.identityPointer,
    primary_identity: primary, secondary_identity: secondary,
    object_url: fields.objectUrl.trim(), object_json_pointer: fields.objectPointer,
    expected_object: object as Record<string, unknown>, secondary_access_allowed: fields.shared,
  };
}
