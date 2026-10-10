import { describe, expect, it } from "vitest";
import { buildObjectPolicy, policyReplayConfig, policyResult, type PolicyFields } from "./objectPolicyModel";
import { defaultWebScanConfig } from "./webSecurityModel";
import type { WebScanRecord, WebScanStartRequest } from "../types";
const fields: PolicyFields = { identityUrl: "http://localhost:3000/me", identityPointer: "/principal", primaryIdentity: '"owner"', secondaryIdentity: '"other"', objectUrl: "http://localhost:3000/records/42", objectPointer: "/record", expectedObject: '{"id":42,"content":"private"}', shared: false };
function request(): WebScanStartRequest {
  const config = defaultWebScanConfig("http://localhost:3000");
  config.scope.active_testing = true;
  config.checks.access_control = true;
  return { website_id: null, project_id: null, config, primary_auth: { cookie_header: null, bearer_token: "owner-secret", custom_headers: [] }, secondary_auth: { cookie_header: null, bearer_token: "other-secret", custom_headers: [] } };
}
describe("object policy desktop model", () => {
  it("builds explicit policy separately from persisted scan configuration", () => {
    const req = request();
    expect(buildObjectPolicy(fields, req)).toMatchObject({ primary_identity: "owner", secondary_identity: "other", expected_object: { id: 42, content: "private" } });
    expect(JSON.stringify(req.config)).not.toMatch(/owner-secret|other-secret|"content":"private"/);
  });
  it("requires active checks and two credentialed sessions", () => {
    const req = request(); req.secondary_auth = null;
    expect(() => buildObjectPolicy(fields, req)).toThrow(/both test sessions/);
    const empty = request(); empty.primary_auth.bearer_token = null;
    expect(() => buildObjectPolicy(fields, empty)).toThrow(/credentials/);
    const passive = request(); passive.config.scope.active_testing = false;
    expect(() => buildObjectPolicy(fields, passive)).toThrow(/active/);
  });
  it("rejects cross-origin, embedded-credential and missing protected-content policies", () => {
    for (const identityUrl of ["http://other.test/me", "http://u:p@localhost:3000/me", "file:///me"]) expect(() => buildObjectPolicy({ ...fields, identityUrl }, request())).toThrow();
    for (const expectedObject of ["{}", "[]", "null"]) expect(() => buildObjectPolicy({ ...fields, expectedObject }, request())).toThrow(/nonempty/);
    expect(() => buildObjectPolicy({ ...fields, secondaryIdentity: fields.primaryIdentity }, request())).toThrow(/distinct/);
  });
  it("shows inconclusive outcomes and resets authorization on repeat without replaying secrets", () => {
    const config = request().config; config.scope.authorization_confirmed = true;
    const result = { status: "UnableToVerify", reason: "Session expired", identity_url: fields.identityUrl, object_url: fields.objectUrl, identity_json_pointer: "/principal", object_json_pointer: "/record", secondary_access_allowed: false };
    const scan = { config_json: JSON.stringify({ ...config, object_policy_result: result }) } as WebScanRecord;
    expect(policyResult(scan)?.status).toBe("UnableToVerify");
    expect(policyReplayConfig(scan).scope.authorization_confirmed).toBe(false);
    expect(JSON.stringify(policyReplayConfig(scan))).not.toMatch(/object_policy_result|owner-secret|"content":"private"/);
    expect(policyResult({ config_json: '{"object_policy_result":{"status":"AccessDenied","reason":"ok"}}' } as WebScanRecord)).toBeNull();
    expect(policyResult({ config_json: "invalid" } as WebScanRecord)).toBeNull();
  });
});
