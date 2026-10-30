//! Desktop commands for evidence-backed citations (migration 55) and signed
//! workflow reports (migration 56).
//!
//! Citation status always comes from verification against the retrieved
//! source snapshot; the UI cannot mark anything verified. Report signing
//! keys never enter this process: the WebView receives the exact payload to
//! sign externally and can only attach a signature that already verifies.
use codetwin_core::research_citations::{
    CitationView, ClaimConflict, ExportFormat, LinkCheck, Provenance, ResearchReport,
    ResearchStore, SourceRecord,
};
use codetwin_core::signed_workflow_reports::{
    signing_payload, verify_bundle, ReportBundle, ReportVerification, StoredReport, TrustedSigner,
    WorkflowReportStore,
};
use research_retrieval::citations::RequestBudget;
use research_retrieval::FetchPolicy;
use serde::Serialize;

use crate::workflow_commands::{db, operator};

/// Largest operator-supplied document accepted for ingestion.
const MAX_INGEST_BYTES: usize = 25 * 1024 * 1024;

fn opt(value: Option<String>) -> Option<String> {
    value.map(|v| v.trim().to_owned()).filter(|v| !v.is_empty())
}

// --------------------------------------------------------------- citations

#[tauri::command]
pub async fn research_fetch_source(
    project_id: String,
    run_id: Option<String>,
    url: String,
    search_query: Option<String>,
    app: tauri::AppHandle,
) -> Result<SourceRecord, String> {
    // Network I/O: keep it off the UI thread.
    tauri::async_runtime::spawn_blocking(move || {
        let database = db(&app)?;
        let provenance = Provenance {
            search_query: opt(search_query),
            added_by: operator(),
            ..Provenance::default()
        };
        ResearchStore::new(&database).fetch_source(
            &project_id,
            opt(run_id).as_deref(),
            url.trim(),
            &FetchPolicy::default(),
            &mut RequestBudget::default(),
            provenance,
        )
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
pub fn research_ingest_document(
    project_id: String,
    run_id: Option<String>,
    name: String,
    bytes: Vec<u8>,
    app: tauri::AppHandle,
) -> Result<SourceRecord, String> {
    if bytes.len() > MAX_INGEST_BYTES {
        return Err(format!(
            "document is larger than {} MB",
            MAX_INGEST_BYTES / 1024 / 1024
        ));
    }
    ResearchStore::new(&db(&app)?).ingest(
        &project_id,
        opt(run_id).as_deref(),
        name.trim(),
        &bytes,
        Provenance {
            added_by: operator(),
            ..Provenance::default()
        },
    )
}

#[tauri::command]
pub fn research_cite(
    project_id: String,
    run_id: Option<String>,
    source_id: String,
    claim: String,
    quote: Option<String>,
    app: tauri::AppHandle,
) -> Result<CitationView, String> {
    ResearchStore::new(&db(&app)?).cite(
        &project_id,
        opt(run_id).as_deref(),
        None,
        &source_id,
        &claim,
        opt(quote).as_deref(),
    )
}

#[tauri::command]
pub fn research_verify_citation(
    project_id: String,
    citation_id: String,
    app: tauri::AppHandle,
) -> Result<CitationView, String> {
    ResearchStore::new(&db(&app)?).verify(&project_id, &citation_id)
}

#[tauri::command]
pub fn research_citation_list(
    project_id: String,
    run_id: Option<String>,
    app: tauri::AppHandle,
) -> Result<Vec<CitationView>, String> {
    ResearchStore::new(&db(&app)?).citations(&project_id, opt(run_id).as_deref())
}

#[tauri::command]
pub async fn research_check_link(
    project_id: String,
    source_id: String,
    app: tauri::AppHandle,
) -> Result<LinkCheck, String> {
    tauri::async_runtime::spawn_blocking(move || {
        ResearchStore::new(&db(&app)?).check_link(
            &project_id,
            &source_id,
            &FetchPolicy::default(),
            &mut RequestBudget::default(),
        )
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
pub fn research_contradictions(
    project_id: String,
    run_id: Option<String>,
    app: tauri::AppHandle,
) -> Result<Vec<ClaimConflict>, String> {
    ResearchStore::new(&db(&app)?).contradictions(&project_id, opt(run_id).as_deref())
}

#[tauri::command]
pub fn research_export_citations(
    project_id: String,
    run_id: Option<String>,
    format: String,
    app: tauri::AppHandle,
) -> Result<String, String> {
    let format: ExportFormat = serde_json::from_value(serde_json::Value::String(format))
        .map_err(|_| "unknown export format".to_string())?;
    ResearchStore::new(&db(&app)?).export(&project_id, opt(run_id).as_deref(), format)
}

#[tauri::command]
pub fn research_generate_report(
    project_id: String,
    run_id: Option<String>,
    title: String,
    app: tauri::AppHandle,
) -> Result<ResearchReport, String> {
    ResearchStore::new(&db(&app)?).report(&project_id, opt(run_id).as_deref(), &title)
}

// --------------------------------------------------------- signed reports

#[derive(Serialize)]
pub struct SigningRequest {
    report_id: String,
    report_sha256: String,
    /// Hex of `DOMAIN || sha256`, the exact bytes the external signer signs.
    payload_hex: String,
    /// Exported bundle for `scripts/workflow_report_signature.py sign`.
    bundle: ReportBundle,
}

#[tauri::command]
pub fn create_signed_workflow_report(
    run_id: String,
    app: tauri::AppHandle,
) -> Result<StoredReport, String> {
    WorkflowReportStore::new(&db(&app)?).create_run_report(&run_id)
}

#[tauri::command]
pub fn signed_workflow_reports(
    project_id: String,
    run_id: Option<String>,
    app: tauri::AppHandle,
) -> Result<Vec<StoredReport>, String> {
    WorkflowReportStore::new(&db(&app)?).list(&project_id, opt(run_id).as_deref())
}

#[tauri::command]
pub fn workflow_report_signing_request(
    project_id: String,
    report_id: String,
    app: tauri::AppHandle,
) -> Result<SigningRequest, String> {
    let bundle = WorkflowReportStore::new(&db(&app)?).export(&project_id, &report_id)?;
    let payload = signing_payload(&bundle.report_sha256)?;
    Ok(SigningRequest {
        report_id,
        report_sha256: bundle.report_sha256.clone(),
        payload_hex: payload.iter().map(|b| format!("{b:02x}")).collect(),
        bundle,
    })
}

#[tauri::command]
pub fn attach_workflow_report_signature(
    project_id: String,
    report_id: String,
    public_key_hex: String,
    signature_hex: String,
    signer_label: Option<String>,
    app: tauri::AppHandle,
) -> Result<ReportVerification, String> {
    WorkflowReportStore::new(&db(&app)?).attach_signature(
        &project_id,
        &report_id,
        &public_key_hex,
        &signature_hex,
        opt(signer_label).as_deref(),
        &operator(),
    )
}

#[tauri::command]
pub fn verify_signed_workflow_report(
    project_id: String,
    report_id: String,
    app: tauri::AppHandle,
) -> Result<ReportVerification, String> {
    WorkflowReportStore::new(&db(&app)?).verify(&project_id, &report_id)
}

#[tauri::command]
pub fn export_signed_workflow_report(
    project_id: String,
    report_id: String,
    app: tauri::AppHandle,
) -> Result<String, String> {
    let bundle = WorkflowReportStore::new(&db(&app)?).export(&project_id, &report_id)?;
    serde_json::to_string_pretty(&bundle).map_err(|e| e.to_string())
}

/// Verify a bundle from anywhere (another machine, an archive) against keys
/// the operator pins for this check; the local trust store is not consulted.
#[tauri::command]
pub fn verify_workflow_report_bundle(
    bundle_json: String,
    trusted_public_keys: Vec<String>,
) -> Result<ReportVerification, String> {
    if bundle_json.len() > 8 * 1024 * 1024 {
        return Err("bundle is larger than 8 MB".into());
    }
    let bundle: ReportBundle =
        serde_json::from_str(&bundle_json).map_err(|e| format!("not a report bundle: {e}"))?;
    Ok(verify_bundle(&bundle, &trusted_public_keys))
}

#[tauri::command]
pub fn report_signers(app: tauri::AppHandle) -> Result<Vec<TrustedSigner>, String> {
    WorkflowReportStore::new(&db(&app)?).signers()
}

#[tauri::command]
pub fn trust_report_signer(
    public_key_hex: String,
    label: String,
    app: tauri::AppHandle,
) -> Result<TrustedSigner, String> {
    WorkflowReportStore::new(&db(&app)?).trust_signer(&public_key_hex, &label, &operator())
}

#[tauri::command]
pub fn revoke_report_signer(
    public_key_hex: String,
    app: tauri::AppHandle,
) -> Result<TrustedSigner, String> {
    WorkflowReportStore::new(&db(&app)?).revoke_signer(&public_key_hex)
}
