//! Desktop commands for platform operations: model routing per role, local
//! model and search provider settings, LLM analytics, metrics and
//! diagnostics, PDF reports, retention, collaboration/RBAC, and the optional
//! loopback automation API. Secrets (search key) go to the OS credential
//! store; API tokens and invitation codes are returned once and stored only
//! as SHA-256 verifiers.
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, OnceLock};

use codetwin_core::automation_api::{ApiServer, ApiToken, TokenStore};
use codetwin_core::cloud_settings::{CloudSettings, ProviderSettings};
use codetwin_core::collaboration::{
    AccessPolicy, AuditRecord, Collaboration, Comment, Invitation, Membership, PrincipalKind, Role,
};
use codetwin_core::observability::{
    export_diagnostics, llm_analytics, metrics_snapshot, LlmAnalytics, MetricsSnapshot,
};
use codetwin_core::search_settings::{SearchProviderRecord, SearchSettings};
use codetwin_core::workflow_platform::RetentionReport;
use model_gateway::credentials::{CredentialStore, KeyringStore, Secret};
use serde::Serialize;
use tauri::Manager;

use crate::workflow_commands::{
    db, db_path, operator, platform, LOCAL_PROVIDER, SEARCH_KEY_ACCOUNT,
};

fn now_ms() -> i64 {
    codetwin_core::collaboration::now_ms()
}

/// Validate a role → model map supplied by the UI.
pub(crate) fn clean_role_map(
    map: BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, String> {
    let roles: Vec<String> = codetwin_core::workflow_platform::WorkflowPlatform::roles()
        .into_iter()
        .map(|r| r.role)
        .chain(["planner".to_owned()])
        .collect();
    let mut out = BTreeMap::new();
    for (role, model) in map {
        let model = model.trim();
        if model.is_empty() {
            continue;
        }
        if !roles.contains(&role) {
            return Err(format!("unknown role `{role}`"));
        }
        if model.len() > 128 || model.chars().any(char::is_control) {
            return Err(format!("invalid model name for `{role}`"));
        }
        out.insert(role, model.to_owned());
    }
    Ok(out)
}

// ------------------------------------------------------------ local model

#[derive(Serialize)]
pub struct LocalModelStatus {
    settings: Option<ProviderSettings>,
}

#[tauri::command]
pub fn local_model_status(app: tauri::AppHandle) -> Result<LocalModelStatus, String> {
    Ok(LocalModelStatus {
        settings: CloudSettings::new(&db(&app)?).provider(LOCAL_PROVIDER)?,
    })
}

/// Loopback OpenAI-compatible endpoint (e.g. llama.cpp server, Ollama).
#[tauri::command]
pub fn save_local_model_settings(
    base_url: String,
    enabled: bool,
    default_model: Option<String>,
    local_by_role: Option<BTreeMap<String, String>>,
    app: tauri::AppHandle,
) -> Result<ProviderSettings, String> {
    let database = db(&app)?;
    let store = CloudSettings::new(&database);
    let mut s = store.provider(LOCAL_PROVIDER)?.unwrap_or(ProviderSettings {
        provider: LOCAL_PROVIDER.into(),
        kind: "local".into(),
        base_url: String::new(),
        enabled: false,
        role_models: Default::default(),
        updated_ms: 0,
    });
    s.base_url = base_url;
    s.enabled = enabled;
    s.role_models.default_local = default_model
        .map(|m| m.trim().chars().take(128).collect::<String>())
        .filter(|m| !m.is_empty());
    if let Some(map) = local_by_role {
        s.role_models.local_by_role = clean_role_map(map)?;
    }
    store.save_provider(&s)
}

// ---------------------------------------------------------- search provider

#[derive(Serialize)]
pub struct SearchProviderStatus {
    settings: Option<SearchProviderRecord>,
    key_stored: bool,
}

#[tauri::command]
pub fn search_provider_status(app: tauri::AppHandle) -> Result<SearchProviderStatus, String> {
    Ok(SearchProviderStatus {
        settings: SearchSettings::new(&db(&app)?).get()?,
        key_stored: KeyringStore
            .get(SEARCH_KEY_ACCOUNT)
            .map_err(|e| e.to_string())?
            .is_some(),
    })
}

#[tauri::command]
pub fn save_search_provider_settings(
    kind: String,
    base_url: String,
    enabled: bool,
    max_results: Option<usize>,
    app: tauri::AppHandle,
) -> Result<SearchProviderRecord, String> {
    SearchSettings::new(&db(&app)?).save(&kind, &base_url, enabled, max_results.unwrap_or(5))
}

#[tauri::command]
pub fn set_search_provider_key(key: String) -> Result<bool, String> {
    let secret = Secret::new(key).map_err(|e| e.to_string())?;
    KeyringStore
        .set(SEARCH_KEY_ACCOUNT, &secret)
        .map_err(|e| e.to_string())?;
    Ok(true)
}

#[tauri::command]
pub fn clear_search_provider_key() -> Result<bool, String> {
    KeyringStore
        .delete(SEARCH_KEY_ACCOUNT)
        .map_err(|e| e.to_string())
}

// ------------------------------------------------- analytics and metrics

#[tauri::command]
pub fn llm_usage_analytics(
    project_id: Option<String>,
    days: Option<i64>,
    app: tauri::AppHandle,
) -> Result<LlmAnalytics, String> {
    let days = days.unwrap_or(30).clamp(1, 365);
    llm_analytics(
        &db(&app)?,
        project_id.as_deref(),
        now_ms() - days * 24 * 3_600_000,
    )
}

#[tauri::command]
pub fn workflow_metrics(
    project_id: Option<String>,
    app: tauri::AppHandle,
) -> Result<MetricsSnapshot, String> {
    metrics_snapshot(&db(&app)?, project_id.as_deref())
}

/// Write a redacted diagnostics bundle under app data; returns its path.
#[tauri::command]
pub fn export_platform_diagnostics(app: tauri::AppHandle) -> Result<String, String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| e.to_string())?
        .join("diagnostics");
    let path = dir.join(format!("codetwin-diagnostics-{}.json", now_ms()));
    export_diagnostics(&db(&app)?, &path)?;
    Ok(path.display().to_string())
}

#[tauri::command]
pub fn research_citations(
    run_id: String,
    app: tauri::AppHandle,
) -> Result<Vec<serde_json::Value>, String> {
    let db = db(&app)?;
    let mut stmt = db
        .connection()
        .prepare(
            "SELECT c.id, c.claim, c.quote, c.support, s.final_url, s.title, s.content_sha256, s.fetched_ms
             FROM research_citations c JOIN research_sources s ON s.id = c.source_id
             WHERE c.run_id = ?1 ORDER BY c.created_ms LIMIT 500",
        )
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map([run_id], |r| {
            Ok(serde_json::json!({
                "id": r.get::<_, String>(0)?, "claim": r.get::<_, String>(1)?,
                "quote": r.get::<_, Option<String>>(2)?, "support": r.get::<_, String>(3)?,
                "url": r.get::<_, Option<String>>(4)?, "title": r.get::<_, Option<String>>(5)?,
                "sha256": r.get::<_, Option<String>>(6)?, "fetched_ms": r.get::<_, i64>(7)?,
            }))
        })
        .map_err(|e| e.to_string())?;
    rows.collect::<Result<_, _>>().map_err(|e| e.to_string())
}

// ------------------------------------------------------------ PDF reports

fn base64(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            T[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            T[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

#[derive(Serialize)]
pub struct PdfExport {
    path: String,
    base64: String,
    bytes: usize,
}

/// Render the run report as PDF, save it under app data and return it.
#[tauri::command]
pub fn workflow_report_pdf(run_id: String, app: tauri::AppHandle) -> Result<PdfExport, String> {
    let pdf = platform(&app)?.report_pdf(&run_id)?;
    let safe: String = run_id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
        .take(64)
        .collect();
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| e.to_string())?
        .join("reports");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let path = dir.join(format!("{safe}.pdf"));
    std::fs::write(&path, &pdf).map_err(|e| e.to_string())?;
    Ok(PdfExport {
        path: path.display().to_string(),
        bytes: pdf.len(),
        base64: base64(&pdf),
    })
}

#[tauri::command]
pub fn prune_workflow_history(
    older_than_days: u32,
    keep_latest: Option<u32>,
    app: tauri::AppHandle,
) -> Result<RetentionReport, String> {
    platform(&app)?.prune(older_than_days, keep_latest.unwrap_or(20))
}

// ---------------------------------------------------------- collaboration

#[derive(Serialize)]
pub struct AccessOverview {
    policy: AccessPolicy,
    me: String,
    my_role: Option<Role>,
    members: Vec<Membership>,
    invitations: Vec<Invitation>,
}

#[tauri::command]
pub fn project_access(project_id: String, app: tauri::AppHandle) -> Result<AccessOverview, String> {
    let db = db(&app)?;
    let c = Collaboration::new(&db);
    let me = operator();
    Ok(AccessOverview {
        policy: c.policy(&project_id)?,
        my_role: c.role_of(&project_id, &me)?,
        members: c.members(&project_id)?,
        invitations: c.invitations(&project_id)?,
        me,
    })
}

#[tauri::command]
pub fn set_project_access_policy(
    project_id: String,
    enforce_rbac: bool,
    separation_of_duties: bool,
    app: tauri::AppHandle,
) -> Result<AccessPolicy, String> {
    let db = db(&app)?;
    let c = Collaboration::new(&db);
    let me = operator();
    c.ensure_principal(&me, &me, PrincipalKind::Human)?;
    c.set_policy(
        &project_id,
        &AccessPolicy {
            enforce_rbac,
            separation_of_duties,
        },
        &me,
    )
}

#[tauri::command]
pub fn register_principal(
    principal_id: String,
    display_name: String,
    app: tauri::AppHandle,
) -> Result<codetwin_core::collaboration::Principal, String> {
    let id = if principal_id.starts_with("operator:") {
        principal_id
    } else {
        format!("operator:{principal_id}")
    };
    Collaboration::new(&db(&app)?).ensure_principal(&id, &display_name, PrincipalKind::Human)
}

#[tauri::command]
pub fn grant_project_role(
    project_id: String,
    principal_id: String,
    role: String,
    expected_revision: Option<i64>,
    app: tauri::AppHandle,
) -> Result<Membership, String> {
    Collaboration::new(&db(&app)?).grant(
        &project_id,
        &principal_id,
        Role::parse(&role)?,
        &operator(),
        expected_revision,
    )
}

#[tauri::command]
pub fn revoke_project_role(
    project_id: String,
    principal_id: String,
    app: tauri::AppHandle,
) -> Result<bool, String> {
    Collaboration::new(&db(&app)?).revoke(&project_id, &principal_id, &operator())?;
    Ok(true)
}

#[derive(Serialize)]
pub struct CreatedInvitation {
    invitation: Invitation,
    /// Shown once; only its SHA-256 verifier is stored.
    code: String,
}

#[tauri::command]
pub fn create_project_invitation(
    project_id: String,
    role: String,
    ttl_hours: Option<i64>,
    app: tauri::AppHandle,
) -> Result<CreatedInvitation, String> {
    let (invitation, code) = Collaboration::new(&db(&app)?).invite(
        &project_id,
        Role::parse(&role)?,
        &operator(),
        ttl_hours.unwrap_or(72) * 3_600_000,
    )?;
    Ok(CreatedInvitation { invitation, code })
}

#[tauri::command]
pub fn accept_project_invitation(
    code: String,
    principal_id: Option<String>,
    app: tauri::AppHandle,
) -> Result<Membership, String> {
    let db = db(&app)?;
    let c = Collaboration::new(&db);
    let id = principal_id.unwrap_or_else(operator);
    c.ensure_principal(&id, &id, PrincipalKind::Human)?;
    c.accept_invitation(&code, &id)
}

#[tauri::command]
pub fn revoke_project_invitation(
    invitation_id: String,
    app: tauri::AppHandle,
) -> Result<bool, String> {
    Collaboration::new(&db(&app)?).revoke_invitation(&invitation_id, &operator())?;
    Ok(true)
}

#[tauri::command]
pub fn list_comments(
    project_id: String,
    target_kind: String,
    target_id: String,
    app: tauri::AppHandle,
) -> Result<Vec<Comment>, String> {
    Collaboration::new(&db(&app)?).comments(&project_id, &target_kind, &target_id)
}

#[tauri::command]
pub fn add_comment(
    project_id: String,
    target_kind: String,
    target_id: String,
    parent_id: Option<String>,
    body: String,
    app: tauri::AppHandle,
) -> Result<Comment, String> {
    Collaboration::new(&db(&app)?).add_comment(
        &project_id,
        &target_kind,
        &target_id,
        parent_id.as_deref(),
        &operator(),
        &body,
    )
}

#[tauri::command]
pub fn edit_comment(
    comment_id: String,
    body: String,
    expected_revision: i64,
    app: tauri::AppHandle,
) -> Result<Comment, String> {
    Collaboration::new(&db(&app)?).edit_comment(&comment_id, &operator(), &body, expected_revision)
}

#[tauri::command]
pub fn delete_comment(comment_id: String, app: tauri::AppHandle) -> Result<bool, String> {
    Collaboration::new(&db(&app)?).delete_comment(&comment_id, &operator())?;
    Ok(true)
}

#[tauri::command]
pub fn audit_log(
    project_id: Option<String>,
    limit: Option<usize>,
    app: tauri::AppHandle,
) -> Result<Vec<AuditRecord>, String> {
    Collaboration::new(&db(&app)?).audit_log(project_id.as_deref(), limit.unwrap_or(200))
}

// ------------------------------------------------------- automation API

fn api_server() -> &'static Mutex<Option<ApiServer>> {
    static SERVER: OnceLock<Mutex<Option<ApiServer>>> = OnceLock::new();
    SERVER.get_or_init(Default::default)
}

#[derive(Serialize)]
pub struct ApiStatus {
    running: bool,
    address: Option<String>,
}

fn api_status_now() -> Result<ApiStatus, String> {
    let guard = api_server().lock().map_err(|_| "API state poisoned")?;
    Ok(ApiStatus {
        running: guard.is_some(),
        address: guard.as_ref().map(|s| format!("http://{}", s.addr())),
    })
}

#[tauri::command]
pub fn automation_api_status() -> Result<ApiStatus, String> {
    api_status_now()
}

/// Start the loopback-only API (default port 8765). Off until requested.
#[tauri::command]
pub fn start_automation_api(port: Option<u16>, app: tauri::AppHandle) -> Result<ApiStatus, String> {
    {
        let mut guard = api_server().lock().map_err(|_| "API state poisoned")?;
        if guard.is_none() {
            let server = ApiServer::start(
                Arc::new(platform(&app)?),
                db_path(&app)?,
                port.unwrap_or(8765),
            )?;
            *guard = Some(server);
        }
    }
    Collaboration::new(&db(&app)?).audit(
        &operator(),
        "start_automation_api",
        None,
        None,
        "allowed",
        serde_json::json!({}),
    );
    api_status_now()
}

#[tauri::command]
pub fn stop_automation_api(app: tauri::AppHandle) -> Result<ApiStatus, String> {
    if let Some(server) = api_server()
        .lock()
        .map_err(|_| "API state poisoned")?
        .take()
    {
        server.stop();
    }
    Collaboration::new(&db(&app)?).audit(
        &operator(),
        "stop_automation_api",
        None,
        None,
        "allowed",
        serde_json::json!({}),
    );
    api_status_now()
}

#[derive(Serialize)]
pub struct CreatedToken {
    token: ApiToken,
    /// Shown once; only its SHA-256 verifier is stored.
    plaintext: String,
}

#[tauri::command]
pub fn create_api_token(
    project_id: String,
    label: String,
    scopes: Vec<String>,
    ttl_days: Option<u32>,
    app: tauri::AppHandle,
) -> Result<CreatedToken, String> {
    let (token, plaintext) = TokenStore::new(&db(&app)?).create(
        &project_id,
        &label,
        &scopes,
        ttl_days.unwrap_or(30),
        &operator(),
    )?;
    Ok(CreatedToken { token, plaintext })
}

#[tauri::command]
pub fn list_api_tokens(project_id: String, app: tauri::AppHandle) -> Result<Vec<ApiToken>, String> {
    TokenStore::new(&db(&app)?).list(&project_id)
}

#[tauri::command]
pub fn revoke_api_token(token_id: String, app: tauri::AppHandle) -> Result<bool, String> {
    TokenStore::new(&db(&app)?).revoke(&token_id, &operator())?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_rfc4648_vectors() {
        for (input, expected) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64(input.as_bytes()), expected);
        }
    }

    #[test]
    fn role_maps_are_validated() {
        let ok = clean_role_map(
            [
                ("planner".into(), " m ".into()),
                ("qa_planner".into(), "".into()),
            ]
            .into(),
        )
        .unwrap();
        assert_eq!(ok.len(), 1);
        assert_eq!(ok["planner"], "m");
        assert!(clean_role_map([("root".into(), "m".into())].into()).is_err());
    }
}
