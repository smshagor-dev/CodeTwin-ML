import { useCallback, useEffect, useState } from "react";

import { Panel, StatusBadge } from "../ui";
import { useWorkspace } from "../WorkspaceContext";
import {
  downloadText, parsePublicKeys, researchApi, signedReportApi, sourceLabel, VERDICT_LABEL,
  type CitationExportFormat, type CitationView, type ReportVerification, type SigningRequest,
  type StoredReport, type TrustedSigner,
} from "../reportsApi";

const time = (ms: number | null | undefined) => (ms ? new Date(ms).toLocaleString() : "—");

function useErrorToast() {
  const { setToast } = useWorkspace();
  return useCallback((error: unknown) => setToast({ tone: "error", message: String(error) }), [setToast]);
}

/**
 * Citations recorded for a run, each with the status of its latest check
 * against the retrieved source snapshot. Nothing here can mark a citation
 * verified: only the backend verifier decides that.
 */
export function RunCitationsPanel({ projectId, runId }: { projectId: string; runId: string }) {
  const onError = useErrorToast();
  const [citations, setCitations] = useState<CitationView[] | null>(null);
  const [url, setUrl] = useState("");
  const [sourceId, setSourceId] = useState("");
  const [claim, setClaim] = useState("");
  const [quote, setQuote] = useState("");
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => researchApi.list(projectId, runId).then(setCitations).catch(onError), [projectId, runId, onError]);
  useEffect(() => { setCitations(null); void load(); }, [load]);

  async function act(fn: () => Promise<unknown>) {
    setBusy(true);
    try { await fn(); await load(); } catch (error) { onError(error); } finally { setBusy(false); }
  }
  async function exportAs(format: CitationExportFormat) {
    try {
      const text = await researchApi.exportCitations(projectId, runId, format);
      const ext = format === "bibtex" ? "bib" : format === "markdown" ? "md" : "json";
      downloadText(text, `codetwin-${runId}-citations.${ext}`, format === "csl_json" ? "application/json" : "text/plain");
    } catch (error) { onError(error); }
  }
  const sources = [...new Map((citations ?? []).map((c) => [c.source.id, c.source])).values()];
  const verified = (citations ?? []).filter((c) => c.status === "verified").length;

  return (
    <Panel title={`Citations (${verified}/${citations?.length ?? 0} verified)`} action={<div className="ws-button-row">
      <button type="button" className="ws-button ws-button-secondary" disabled={!citations?.length} onClick={() => void exportAs("csl_json")}>CSL-JSON</button>
      <button type="button" className="ws-button ws-button-secondary" disabled={!citations?.length} onClick={() => void exportAs("bibtex")}>BibTeX</button>
      <button type="button" className="ws-button ws-button-secondary" disabled={!citations?.length} onClick={() => void exportAs("markdown")}>Markdown</button>
    </div>}>
      <form className="wf-inline-form" onSubmit={(e) => { e.preventDefault(); void act(async () => { const s = await researchApi.fetchSource(projectId, runId, url); setSourceId(s.id); setUrl(""); }); }}>
        <input type="url" required value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://source to retrieve (SSRF-safe, bounded)" aria-label="Source URL"/>
        <button type="submit" className="ws-button ws-button-secondary" disabled={busy || !url}>Retrieve source</button>
      </form>
      <form className="wf-inline-form" onSubmit={(e) => { e.preventDefault(); void act(async () => { await researchApi.cite(projectId, runId, sourceId, claim, quote); setClaim(""); setQuote(""); }); }}>
        <input required value={sourceId} onChange={(e) => setSourceId(e.target.value)} placeholder="Source id" aria-label="Source id" list={`sources-${runId}`}/>
        <datalist id={`sources-${runId}`}>{sources.map((s) => <option key={s.id} value={s.id}>{sourceLabel(s)}</option>)}</datalist>
        <input required maxLength={1000} value={claim} onChange={(e) => setClaim(e.target.value)} placeholder="Claim" aria-label="Claim"/>
        <input value={quote} onChange={(e) => setQuote(e.target.value)} placeholder="Exact supporting quote" aria-label="Supporting quote"/>
        <button type="submit" className="ws-button ws-button-secondary" disabled={busy || !sourceId || !claim}>Cite and verify</button>
      </form>
      {citations === null ? <p className="ws-form-help">Loading citations…</p> : citations.length === 0 ? (
        <p className="ws-form-help">No citations for this run. A claim is only marked verified when its quote is found in the retrieved source text and carries the claim.</p>
      ) : (
        <ul className="wf-citations">{citations.map((c) => {
          const link = c.source.final_url ?? c.source.requested_url;
          const meta = c.source.metadata;
          return (
            <li key={c.id}>
              <div><StatusBadge status={c.status}/> <strong>{c.claim}</strong></div>
              {c.quote && <blockquote>{c.quote}</blockquote>}
              {c.status !== "verified" && c.missing_terms.length > 0 && <small>Missing from source: {c.missing_terms.join(", ")}</small>}
              <small>
                {sourceLabel(c.source)}{meta.authors.length > 0 ? ` · ${meta.authors.join(", ")}` : ""}{meta.site_name ? ` · ${meta.site_name}` : ""}
                {meta.published ? ` · published ${meta.published}` : ""} · retrieved {time(c.source.retrieved_ms)}
                {meta.doi ? ` · DOI ${meta.doi} (declared by source)` : ""}
              </small>
              <small className="wf-hash">{link ?? c.source.origin} · snapshot sha256 {c.source.content_sha256.slice(0, 16)}…{c.source.duplicate_of ? ` · duplicate of ${c.source.duplicate_of}` : ""}</small>
              {c.last_link_check && <small>Link check: <StatusBadge status={c.last_link_check.outcome === "ok" ? "verified" : c.last_link_check.outcome === "changed" ? "source_changed" : "source_unavailable"}/> {c.last_link_check.outcome}{c.last_link_check.http_status ? ` (HTTP ${c.last_link_check.http_status})` : ""} · {time(c.last_link_check.checked_ms)}</small>}
              <div className="ws-button-row">
                <button type="button" className="ws-button ws-button-secondary" disabled={busy} onClick={() => void act(() => researchApi.verify(projectId, c.id))}>Re-verify</button>
                {c.source.origin === "web" && <button type="button" className="ws-button ws-button-secondary" disabled={busy} onClick={() => void act(() => researchApi.checkLink(projectId, c.source.id))}>Check link</button>}
              </div>
            </li>
          );
        })}</ul>
      )}
    </Panel>
  );
}

function VerificationResult({ result }: { result: ReportVerification }) {
  return (
    <div className="wf-signed" role="status">
      <div><StatusBadge status={result.verdict}/> <strong>{VERDICT_LABEL[result.verdict]}</strong></div>
      <small>Integrity {result.integrity_ok ? "intact" : "FAILED"} · chain {result.chain_ok ? "consistent" : "BROKEN"} · sha256 <span className="wf-hash">{result.report_sha256}</span></small>
      {result.signatures.map((s) => (
        <small key={s.public_key_hex}><StatusBadge status={s.state}/> {s.signer_label ?? "unlabelled signer"} · <span className="wf-hash">{s.public_key_hex}</span></small>
      ))}
      {result.problems.map((p) => <small key={p}>⚠ {p}</small>)}
      <small>{result.disclaimer}</small>
    </div>
  );
}

/**
 * Signed workflow reports. The signing key never enters CodeTwin: the operator
 * downloads the bundle, signs it with their own tooling
 * (`scripts/workflow_report_signature.py sign`) and pastes back the public key
 * and signature, which must verify before they are stored.
 */
export function SignedReportPanel({ projectId, runId, settled }: { projectId: string; runId: string; settled: boolean }) {
  const onError = useErrorToast();
  const [reports, setReports] = useState<StoredReport[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [request, setRequest] = useState<SigningRequest | null>(null);
  const [result, setResult] = useState<ReportVerification | null>(null);
  const [publicKey, setPublicKey] = useState("");
  const [signature, setSignature] = useState("");
  const [label, setLabel] = useState("");
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => signedReportApi.list(projectId, runId).then((list) => {
    setReports(list);
    setSelected((current) => current ?? list[0]?.id ?? null);
  }).catch(onError), [projectId, runId, onError]);
  useEffect(() => { setReports([]); setSelected(null); setRequest(null); setResult(null); void load(); }, [load]);
  useEffect(() => {
    setRequest(null);
    setResult(null);
    if (selected) void signedReportApi.verify(projectId, selected).then(setResult).catch(onError);
  }, [projectId, selected, onError]);

  async function act<T>(fn: () => Promise<T>, then?: (value: T) => void) {
    setBusy(true);
    try { const value = await fn(); then?.(value); } catch (error) { onError(error); } finally { setBusy(false); }
  }

  return (
    <Panel title={`Signed reports (${reports.length})`} action={settled ? (
      <button type="button" className="ws-button ws-button-secondary" disabled={busy} onClick={() => void act(() => signedReportApi.create(runId), (r) => { setSelected(r.id); void load(); })}>Create report</button>
    ) : undefined}>
      {!settled && reports.length === 0 && <p className="ws-form-help">A signed report can be created once the run has finished.</p>}
      {reports.length > 0 && (
        <div className="wf-signed">
          <label className="ws-form-help">Report{" "}
            <select value={selected ?? ""} onChange={(e) => setSelected(e.target.value)}>
              {reports.map((r) => <option key={r.id} value={r.id}>#{r.sequence} · {time(r.created_ms)} · {r.report_sha256.slice(0, 12)}</option>)}
            </select>
          </label>
          {result && <VerificationResult result={result}/>}
          {selected && <div className="ws-button-row">
            <button type="button" className="ws-button ws-button-secondary" disabled={busy} onClick={() => void act(() => signedReportApi.signingRequest(projectId, selected), setRequest)}>Prepare signing request</button>
            <button type="button" className="ws-button ws-button-secondary" disabled={busy} onClick={() => void act(() => signedReportApi.exportBundle(projectId, selected), (text) => downloadText(text, `codetwin-report-${selected}.json`))}>Export bundle</button>
            <button type="button" className="ws-button ws-button-secondary" disabled={busy} onClick={() => void act(() => signedReportApi.verify(projectId, selected), setResult)}>Re-verify</button>
          </div>}
          {request && (
            <div className="wf-signed">
              <small>Sign outside CodeTwin, e.g. <code>python scripts/workflow_report_signature.py sign codetwin-report-{request.report_id}.json --key your-key.pem</code>. Raw Ed25519 payload (hex):</small>
              <small className="wf-hash">{request.payload_hex}</small>
              <div className="ws-button-row"><button type="button" className="ws-button ws-button-secondary" onClick={() => downloadText(JSON.stringify(request.bundle, null, 2), `codetwin-report-${request.report_id}.json`)}>Download bundle to sign</button></div>
              <form className="wf-inline-form" onSubmit={(e) => { e.preventDefault(); void act(() => signedReportApi.attachSignature(projectId, request.report_id, publicKey, signature, label), (r) => { setResult(r); setSignature(""); }); }}>
                <input required value={publicKey} onChange={(e) => setPublicKey(e.target.value)} placeholder="Signer public key (64 hex)" aria-label="Signer public key" pattern="[0-9a-fA-F]{64}"/>
                <input required value={signature} onChange={(e) => setSignature(e.target.value)} placeholder="Signature (128 hex)" aria-label="Signature" pattern="[0-9a-fA-F]{128}"/>
                <input value={label} onChange={(e) => setLabel(e.target.value)} placeholder="Signer label" aria-label="Signer label" maxLength={120}/>
                <button type="submit" className="ws-button ws-button-secondary" disabled={busy}>Attach signature</button>
              </form>
            </div>
          )}
        </div>
      )}
      <SignerTrust/>
      <BundleVerifier/>
    </Panel>
  );
}

function SignerTrust() {
  const onError = useErrorToast();
  const [signers, setSigners] = useState<TrustedSigner[] | null>(null);
  const [key, setKey] = useState("");
  const [label, setLabel] = useState("");
  const load = useCallback(() => signedReportApi.signers().then(setSigners).catch(onError), [onError]);
  return (
    <details className="wf-signed">
      <summary onClick={() => { if (signers === null) void load(); }}>Trusted signers</summary>
      <form className="wf-inline-form" onSubmit={(e) => { e.preventDefault(); void signedReportApi.trustSigner(key, label).then(() => { setKey(""); setLabel(""); return load(); }).catch(onError); }}>
        <input required value={key} onChange={(e) => setKey(e.target.value)} placeholder="Public key (64 hex)" aria-label="Trusted public key" pattern="[0-9a-fA-F]{64}"/>
        <input required value={label} onChange={(e) => setLabel(e.target.value)} placeholder="Who holds this key" aria-label="Signer identity" maxLength={120}/>
        <button type="submit" className="ws-button ws-button-secondary">Trust signer</button>
      </form>
      {signers?.length === 0 && <small>No trusted signers. Signed reports verify only as “untrusted signer” until a key is pinned here.</small>}
      <ul className="wf-citations">{(signers ?? []).map((s) => (
        <li key={s.public_key_hex}>
          <div><StatusBadge status={s.revoked_ms ? "revoked" : "trusted"}/> <strong>{s.label}</strong></div>
          <small className="wf-hash">{s.public_key_hex}</small>
          <small>added by {s.added_by} · {time(s.added_ms)}{s.revoked_ms ? ` · revoked ${time(s.revoked_ms)}` : ""}</small>
          {!s.revoked_ms && <div className="ws-button-row"><button type="button" className="ws-button ws-button-secondary" onClick={() => void signedReportApi.revokeSigner(s.public_key_hex).then(load).catch(onError)}>Revoke</button></div>}
        </li>
      ))}</ul>
    </details>
  );
}

function BundleVerifier() {
  const onError = useErrorToast();
  const [bundle, setBundle] = useState("");
  const [keys, setKeys] = useState("");
  const [result, setResult] = useState<ReportVerification | null>(null);
  const parsed = parsePublicKeys(keys);
  return (
    <details className="wf-signed">
      <summary>Verify an exported bundle</summary>
      <small>Checks bytes and signatures against keys you pin here; the local trust store is not used.</small>
      <textarea value={bundle} onChange={(e) => setBundle(e.target.value)} placeholder="Paste bundle JSON" aria-label="Report bundle JSON"/>
      <input value={keys} onChange={(e) => setKeys(e.target.value)} placeholder="Trusted public keys (hex, comma separated)" aria-label="Trusted public keys"/>
      {parsed.invalid.length > 0 && <small>Ignored, not 64-hex keys: {parsed.invalid.join(", ")}</small>}
      <div className="ws-button-row"><button type="button" className="ws-button ws-button-secondary" disabled={!bundle.trim()} onClick={() => void signedReportApi.verifyBundle(bundle, parsed.keys).then(setResult).catch(onError)}>Verify bundle</button></div>
      {result && <VerificationResult result={result}/>}
    </details>
  );
}
