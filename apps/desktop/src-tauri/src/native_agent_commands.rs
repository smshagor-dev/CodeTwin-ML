use codetwin_core::{
    native_action_log::{ActionReceipt, NativeActionLog},
    native_agent_handoffs::{AgentHandoff, AgentHandoffs, AgentVerification},
    native_agent_memory::{AgentMemory, MemoryEntry},
    native_agents::{AgentRun, HistoricalEvidenceAudit, NativeAgents},
    native_evidence_signatures::{
        assemble_detached_signature, prepare_external_attestation,
        prepare_signer_policy_signing_request, verify_bundle_against_sqlite,
        verify_bundle_with_signed_signer_policy_against_sqlite,
        verify_bundle_with_signer_policy_against_sqlite, PreparedReviewEvidence,
        PreparedSignerPolicySigningRequest, SignedReviewEvidence, SignedTrustedSignerPolicy,
        TrustedSignerPolicy,
    },
    Database,
};
use tauri::Manager;

use crate::{reserve_assessment, AppState};

fn open_db(app: &tauri::AppHandle) -> Result<Database, String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|error| error.to_string())?;
    std::fs::create_dir_all(&dir).map_err(|error| error.to_string())?;
    Database::open(dir.join("codetwin.sqlite3")).map_err(|error| error.to_string())
}

#[tauri::command]
pub fn create_native_agent_review(
    project_id: String,
    objective: String,
    max_files: usize,
    budget_seconds: u64,
    roles: Option<Vec<String>>,
    app: tauri::AppHandle,
) -> Result<AgentRun, String> {
    let db = open_db(&app)?;
    let agents = NativeAgents::new(&db);
    match roles {
        Some(roles) => {
            agents.create_with_roles(&project_id, &objective, max_files, budget_seconds, &roles)
        }
        None => agents.create(&project_id, &objective, max_files, budget_seconds),
    }
}

#[tauri::command]
pub fn native_agent_review(id: String, app: tauri::AppHandle) -> Result<AgentRun, String> {
    let db = open_db(&app)?;
    NativeAgents::new(&db).get(&id)
}

#[tauri::command]
pub fn list_native_agent_reviews(
    project_id: String,
    app: tauri::AppHandle,
) -> Result<Vec<AgentRun>, String> {
    let db = open_db(&app)?;
    NativeAgents::new(&db).list(&project_id)
}

#[tauri::command]
pub fn approve_native_agent_review(id: String, app: tauri::AppHandle) -> Result<AgentRun, String> {
    let db = open_db(&app)?;
    NativeAgents::new(&db).approve(&id)
}

#[tauri::command]
pub fn cancel_native_agent_review(id: String, app: tauri::AppHandle) -> Result<AgentRun, String> {
    let db = open_db(&app)?;
    NativeAgents::new(&db).cancel(&id)
}

#[tauri::command]
pub async fn run_native_agent_review(
    id: String,
    state: tauri::State<'_, AppState>,
) -> Result<AgentRun, String> {
    // Use the same reservations as indexed assessments: no competing index,
    // semantic enrichment, quality or static-security analysis during execution.
    let reservations = reserve_assessment(&state)?;
    let path = state.database_path.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let _reservations = reservations;
        let db = Database::open(path).map_err(|error| error.to_string())?;
        NativeAgents::new(&db).execute(&id)
    })
    .await
    .map_err(|error| error.to_string())?
}

#[tauri::command]
pub fn native_agent_report(id: String, app: tauri::AppHandle) -> Result<String, String> {
    let db = open_db(&app)?;
    NativeAgents::new(&db).report(&id)
}

#[tauri::command]
pub fn list_native_action_receipts(
    id: String,
    app: tauri::AppHandle,
) -> Result<Vec<ActionReceipt>, String> {
    let db = open_db(&app)?;
    let _ = NativeAgents::new(&db).get(&id)?;
    NativeActionLog::new(&db).list(&id)
}

#[tauri::command]
pub fn list_native_agent_memory(
    project_id: String,
    query: String,
    limit: usize,
    app: tauri::AppHandle,
) -> Result<Vec<MemoryEntry>, String> {
    let db = open_db(&app)?;
    AgentMemory::new(&db).search(&project_id, &query, limit)
}

#[tauri::command]
pub fn clear_native_agent_memory(
    project_id: String,
    app: tauri::AppHandle,
) -> Result<usize, String> {
    let db = open_db(&app)?;
    AgentMemory::new(&db).clear(&project_id)
}

#[tauri::command]
pub fn list_native_agent_handoffs(
    id: String,
    app: tauri::AppHandle,
) -> Result<Vec<AgentHandoff>, String> {
    let db = open_db(&app)?;
    AgentHandoffs::new(&db).list(&id)
}

#[tauri::command]
pub fn verify_native_agent_run(
    id: String,
    app: tauri::AppHandle,
) -> Result<AgentVerification, String> {
    let db = open_db(&app)?;
    NativeAgents::new(&db).verify_evidence(&id)
}

#[tauri::command]
pub fn audit_native_evidence_history(
    project_id: String,
    limit: usize,
    before_rowid: Option<String>,
    app: tauri::AppHandle,
) -> Result<HistoricalEvidenceAudit, String> {
    let db = open_db(&app)?;
    NativeAgents::new(&db).audit_completed_history_page(&project_id, limit, before_rowid.as_deref())
}

/// Exports only public fingerprints and the exact bytes an external signer
/// must sign. No private-key generation or access in CodeTwin.
#[tauri::command]
pub fn prepare_native_review_attestation(
    id: String,
    app: tauri::AppHandle,
) -> Result<PreparedReviewEvidence, String> {
    let db = open_db(&app)?;
    prepare_external_attestation(&db, &id)
}

/// Attach a signature from an independent signer and check it immediately
/// against the freshly generated, still-verified SQLite evidence. The
/// trusted key is explicitly supplied by the user, not learned from SQLite.
#[tauri::command]
pub fn assemble_native_review_attestation(
    id: String,
    signature_hex: String,
    trusted_public_key_hex: String,
    app: tauri::AppHandle,
) -> Result<SignedReviewEvidence, String> {
    let db = open_db(&app)?;
    let request = prepare_external_attestation(&db, &id)?;
    let bundle =
        assemble_detached_signature(request.manifest, &trusted_public_key_hex, &signature_hex)?;
    verify_bundle_against_sqlite(&db, &bundle, &trusted_public_key_hex)?;
    Ok(bundle)
}

/// Read-only verification of an imported signed bundle. A separately pinned
/// public key is mandatory even if the JSON includes a claimed signer key.
#[tauri::command]
pub fn verify_native_review_attestation(
    bundle_json: String,
    trusted_public_key_hex: String,
    app: tauri::AppHandle,
) -> Result<String, String> {
    if bundle_json.len() > 512 * 1024 {
        return Err("Signed evidence bundle exceeds 512 KiB".into());
    }
    let bundle: SignedReviewEvidence = serde_json::from_str(&bundle_json)
        .map_err(|_| "Malformed signed evidence bundle".to_string())?;
    let db = open_db(&app)?;
    verify_bundle_against_sqlite(&db, &bundle, &trusted_public_key_hex)?;
    Ok(bundle.manifest.run_id)
}

/// The user supplies a trusted, current policy independently of the signed
/// bundle. No signer keys or policies are loaded from the SQLite database.
/// Strict input bounds keep untrusted imports from consuming excess memory.
#[tauri::command]
pub fn verify_native_review_with_signer_policy(
    bundle_json: String,
    trusted_policy_json: String,
    app: tauri::AppHandle,
) -> Result<(String, u64), String> {
    if bundle_json.len() > 512 * 1024 || trusted_policy_json.len() > 16 * 1024 {
        return Err("Signed evidence or external trust policy exceeds input limits".into());
    }
    let bundle: SignedReviewEvidence = serde_json::from_str(&bundle_json)
        .map_err(|_| "Malformed signed evidence bundle".to_string())?;
    let policy: TrustedSignerPolicy = serde_json::from_str(&trusted_policy_json)
        .map_err(|_| "Malformed external signer trust policy".to_string())?;
    let db = open_db(&app)?;
    verify_bundle_with_signer_policy_against_sqlite(&db, &bundle, &policy)?;
    Ok((bundle.manifest.run_id, policy.revision))
}

/// Export deterministic, domain-separated policy bytes for a separately
/// managed Ed25519 authority. Never accept or store private signing material.
#[tauri::command]
pub fn prepare_native_signer_policy_request(
    policy_json: String,
) -> Result<PreparedSignerPolicySigningRequest, String> {
    if policy_json.len() > 16 * 1024 {
        return Err("External signer trust policy exceeds 16 KiB".into());
    }
    let policy: TrustedSignerPolicy = serde_json::from_str(&policy_json)
        .map_err(|_| "Malformed external signer trust policy".to_string())?;
    prepare_signer_policy_signing_request(policy)
}

/// This stricter path authenticates the policy using a separately pinned
/// authority key and enforces an externally maintained minimum revision.
/// The revision floor is not derived from the imported policy or SQLite.
#[tauri::command]
pub fn verify_native_review_with_signed_signer_policy(
    bundle_json: String,
    signed_policy_json: String,
    trusted_authority_public_key_hex: String,
    minimum_revision: String,
    app: tauri::AppHandle,
) -> Result<(String, u64), String> {
    if bundle_json.len() > 512 * 1024 || signed_policy_json.len() > 16 * 1024 {
        return Err("Signed evidence or signed trust policy exceeds input limits".into());
    }
    let revision_floor = minimum_revision
        .parse::<u64>()
        .map_err(|_| "Minimum policy revision must be a positive u64".to_string())?;
    if revision_floor == 0 {
        return Err("Minimum policy revision must be positive".into());
    }
    let bundle: SignedReviewEvidence = serde_json::from_str(&bundle_json)
        .map_err(|_| "Malformed signed evidence bundle".to_string())?;
    let signed_policy: SignedTrustedSignerPolicy = serde_json::from_str(&signed_policy_json)
        .map_err(|_| "Malformed signed signer trust policy".to_string())?;
    let db = open_db(&app)?;
    verify_bundle_with_signed_signer_policy_against_sqlite(
        &db,
        &bundle,
        &signed_policy,
        &trusted_authority_public_key_hex,
        revision_floor,
    )?;
    Ok((bundle.manifest.run_id, signed_policy.policy.revision))
}

#[tauri::command]
pub fn create_native_task_review(
    project_id: String,
    objective: String,
    max_files: usize,
    budget_seconds: u64,
    proposal: codetwin_core::native_task_plans::TaskProposal,
    app: tauri::AppHandle,
) -> Result<AgentRun, String> {
    codetwin_core::native_task_plans::validate_proposal(&proposal)?;
    let db = open_db(&app)?;
    let selected = proposal
        .tasks
        .iter()
        .map(|task| task.role.clone())
        .collect::<Vec<_>>();
    let run = NativeAgents::new(&db).create_with_roles(
        &project_id,
        &objective,
        max_files,
        budget_seconds,
        &selected,
    )?;
    match codetwin_core::native_agent_delegation::NativeDelegation::new(&db)
        .apply_proposal(&run.id, &proposal)
    {
        Ok(_) => NativeAgents::new(&db).get(&run.id),
        Err(error) => {
            let _ = NativeAgents::new(&db).cancel(&run.id);
            Err(error)
        }
    }
}
