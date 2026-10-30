import { invoke } from "@tauri-apps/api/core";

/** Bibliographic metadata as declared by the source itself (not independently verified). */
export interface SourceMetadata {
  title: string | null;
  authors: string[];
  published: string | null;
  modified: string | null;
  site_name: string | null;
  description: string | null;
  doi: string | null;
  language: string | null;
  declared_canonical: string | null;
}
export interface SourceRecord {
  id: string;
  origin: "web" | "markdown" | "pdf";
  requested_url: string | null;
  final_url: string | null;
  canonical_url: string | null;
  content_sha256: string;
  metadata: SourceMetadata;
  published_ms: number | null;
  retrieved_ms: number;
  duplicate_of: string | null;
  instruction_like_phrases: number;
  freshness: unknown;
}
export interface LinkCheck {
  outcome: "ok" | "changed" | "redirected" | "broken" | "unreachable" | "blocked";
  http_status: number | null;
  final_url: string | null;
  content_sha256: string | null;
  error: string | null;
  checked_ms: number;
}
export type CitationStatus =
  | "verified" | "quote_not_found" | "unrelated_quote" | "contradicted" | "source_unavailable" | "source_changed";
export interface CitationView {
  id: string;
  claim_id: string | null;
  claim: string;
  quote: string | null;
  status: CitationStatus | string;
  term_coverage: number;
  missing_terms: string[];
  verified_ms: number | null;
  source: SourceRecord;
  last_link_check: LinkCheck | null;
}
export interface ClaimConflict { left: CitationView; right: CitationView }
export interface ResearchReport {
  id: string;
  title: string;
  markdown: string;
  sha256: string;
  citations_total: number;
  citations_verified: number;
  created_ms: number;
}
export type CitationExportFormat = "csl_json" | "bibtex" | "markdown";

export interface StoredReport {
  id: string;
  project_id: string;
  run_id: string;
  sequence: number;
  previous_sha256: string | null;
  report_sha256: string;
  created_ms: number;
  report_json: string;
}
export interface ReportBundle {
  format: string;
  report_sha256: string;
  report_json: string;
  signatures: { public_key_hex: string; signature_hex: string; signer_label: string | null }[];
}
export interface SigningRequest { report_id: string; report_sha256: string; payload_hex: string; bundle: ReportBundle }
export type SignatureState = "trusted" | "untrusted" | "revoked" | "invalid";
export type ReportVerdict =
  | "verified" | "unsigned" | "untrusted_signer" | "invalid_signature" | "tampered" | "chain_broken";
export interface ReportVerification {
  report_id: string | null;
  report_sha256: string;
  verdict: ReportVerdict;
  integrity_ok: boolean;
  chain_ok: boolean;
  signatures: { public_key_hex: string; signer_label: string | null; state: SignatureState }[];
  problems: string[];
  disclaimer: string;
}
export interface TrustedSigner {
  public_key_hex: string;
  label: string;
  added_by: string;
  added_ms: number;
  revoked_ms: number | null;
}

const optional = (value: string | null | undefined) => (value && value.trim() ? value.trim() : null);

export const researchApi = {
  fetchSource: (projectId: string, runId: string | null, url: string, searchQuery?: string) =>
    invoke<SourceRecord>("research_fetch_source", { projectId, runId, url, searchQuery: optional(searchQuery) }),
  ingestDocument: (projectId: string, runId: string | null, name: string, bytes: Uint8Array) =>
    invoke<SourceRecord>("research_ingest_document", { projectId, runId, name, bytes: Array.from(bytes) }),
  cite: (projectId: string, runId: string | null, sourceId: string, claim: string, quote?: string) =>
    invoke<CitationView>("research_cite", { projectId, runId, sourceId, claim, quote: optional(quote) }),
  verify: (projectId: string, citationId: string) =>
    invoke<CitationView>("research_verify_citation", { projectId, citationId }),
  list: (projectId: string, runId: string | null) =>
    invoke<CitationView[]>("research_citation_list", { projectId, runId }),
  checkLink: (projectId: string, sourceId: string) =>
    invoke<LinkCheck>("research_check_link", { projectId, sourceId }),
  contradictions: (projectId: string, runId: string | null) =>
    invoke<ClaimConflict[]>("research_contradictions", { projectId, runId }),
  exportCitations: (projectId: string, runId: string | null, format: CitationExportFormat) =>
    invoke<string>("research_export_citations", { projectId, runId, format }),
  report: (projectId: string, runId: string | null, title: string) =>
    invoke<ResearchReport>("research_generate_report", { projectId, runId, title }),
};

export const signedReportApi = {
  create: (runId: string) => invoke<StoredReport>("create_signed_workflow_report", { runId }),
  list: (projectId: string, runId: string | null) =>
    invoke<StoredReport[]>("signed_workflow_reports", { projectId, runId }),
  signingRequest: (projectId: string, reportId: string) =>
    invoke<SigningRequest>("workflow_report_signing_request", { projectId, reportId }),
  attachSignature: (projectId: string, reportId: string, publicKeyHex: string, signatureHex: string, signerLabel?: string) =>
    invoke<ReportVerification>("attach_workflow_report_signature", {
      projectId, reportId, publicKeyHex, signatureHex, signerLabel: optional(signerLabel),
    }),
  verify: (projectId: string, reportId: string) =>
    invoke<ReportVerification>("verify_signed_workflow_report", { projectId, reportId }),
  exportBundle: (projectId: string, reportId: string) =>
    invoke<string>("export_signed_workflow_report", { projectId, reportId }),
  verifyBundle: (bundleJson: string, trustedPublicKeys: string[]) =>
    invoke<ReportVerification>("verify_workflow_report_bundle", { bundleJson, trustedPublicKeys }),
  signers: () => invoke<TrustedSigner[]>("report_signers"),
  trustSigner: (publicKeyHex: string, label: string) =>
    invoke<TrustedSigner>("trust_report_signer", { publicKeyHex, label }),
  revokeSigner: (publicKeyHex: string) => invoke<TrustedSigner>("revoke_report_signer", { publicKeyHex }),
};

export const VERDICT_LABEL: Record<ReportVerdict, string> = {
  verified: "Signature verified (trusted signer)",
  unsigned: "Not signed",
  untrusted_signer: "Signed, but by no trusted signer",
  invalid_signature: "Invalid signature",
  tampered: "Report modified or corrupted",
  chain_broken: "Report chain broken",
};

/** Parse a whitespace/comma separated list of 64-hex public keys; returns invalid tokens separately. */
export function parsePublicKeys(text: string): { keys: string[]; invalid: string[] } {
  const tokens = text.split(/[\s,]+/).map((t) => t.trim()).filter(Boolean);
  const keys: string[] = [];
  const invalid: string[] = [];
  for (const token of tokens) (/^[0-9a-fA-F]{64}$/.test(token) ? keys : invalid).push(token.toLowerCase());
  return { keys: [...new Set(keys)], invalid };
}

export function sourceLabel(source: SourceRecord): string {
  return source.metadata.title ?? source.canonical_url ?? source.final_url ?? source.requested_url ?? source.id;
}

export function downloadText(text: string, filename: string, type = "application/json") {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}
