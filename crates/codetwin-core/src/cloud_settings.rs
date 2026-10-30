//! Persistence for provider settings, project cloud consent and provider
//! request audit (migration 48). Tokens are never handled here.
use model_gateway::{CallAudit, CloudConsent};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};

use crate::Database;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderSettings {
    pub provider: String,
    pub kind: String,
    pub base_url: String,
    pub enabled: bool,
    pub role_models: model_gateway::router::RoleModels,
    pub updated_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsentRecord {
    pub consent: CloudConsent,
    pub allow_web_research: bool,
    pub revoked_ms: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderRequestRecord {
    pub request_id: String,
    pub project_id: Option<String>,
    pub run_id: Option<String>,
    pub provider: String,
    pub model: String,
    pub outcome: String,
    pub http_status: Option<u16>,
    pub attempts: u32,
    pub latency_ms: u64,
    pub bytes_sent: usize,
    pub credits: u32,
    pub streamed: bool,
    pub created_ms: i64,
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64)
}

pub struct CloudSettings<'a> {
    db: &'a Database,
}

impl<'a> CloudSettings<'a> {
    pub const fn new(db: &'a Database) -> Self {
        Self { db }
    }

    pub fn provider(&self, provider: &str) -> Result<Option<ProviderSettings>, String> {
        self.db
            .connection()
            .query_row(
                "SELECT provider,kind,base_url,enabled,role_models_json,updated_ms FROM provider_settings WHERE provider=?1",
                [provider],
                |r| {
                    let models: String = r.get(4)?;
                    Ok(ProviderSettings {
                        provider: r.get(0)?,
                        kind: r.get(1)?,
                        base_url: r.get(2)?,
                        enabled: r.get::<_, i64>(3)? != 0,
                        role_models: serde_json::from_str(&models).unwrap_or_default(),
                        updated_ms: r.get(5)?,
                    })
                },
            )
            .optional()
            .map_err(|e| e.to_string())
    }

    /// Save non-secret provider settings after validating the base URL.
    pub fn save_provider(&self, settings: &ProviderSettings) -> Result<ProviderSettings, String> {
        let kind = match settings.kind.as_str() {
            "cloud" => model_gateway::ProviderKind::Cloud,
            "local" => model_gateway::ProviderKind::Local,
            _ => return Err("kind must be cloud or local".into()),
        };
        model_gateway::client::validate_base_url(&settings.base_url, kind)
            .map_err(|e| e.to_string())?;
        let models = serde_json::to_string(&settings.role_models).map_err(|e| e.to_string())?;
        if models.len() > 4096 {
            return Err("too many role model mappings".into());
        }
        self.db
            .connection()
            .execute(
                "INSERT INTO provider_settings(provider,kind,base_url,enabled,role_models_json,updated_ms)
                 VALUES (?1,?2,?3,?4,?5,?6)
                 ON CONFLICT(provider) DO UPDATE SET kind=excluded.kind, base_url=excluded.base_url,
                   enabled=excluded.enabled, role_models_json=excluded.role_models_json, updated_ms=excluded.updated_ms",
                params![
                    settings.provider,
                    settings.kind,
                    settings.base_url.trim().trim_end_matches('/'),
                    i64::from(settings.enabled),
                    models,
                    now_ms()
                ],
            )
            .map_err(|e| e.to_string())?;
        self.provider(&settings.provider)?
            .ok_or_else(|| "settings not saved".into())
    }

    pub fn consent(&self, project_id: &str) -> Result<Option<ConsentRecord>, String> {
        self.db
            .connection()
            .query_row(
                "SELECT project_id,allow_cloud,allow_source_excerpts,allow_local_fallback,allow_web_research,
                        max_payload_bytes,granted_by,granted_ms,revoked_ms FROM cloud_consents WHERE project_id=?1",
                [project_id],
                |r| {
                    let revoked: Option<i64> = r.get(8)?;
                    Ok(ConsentRecord {
                        consent: CloudConsent {
                            project_id: r.get(0)?,
                            // A revoked consent is never effective.
                            allow_cloud: r.get::<_, i64>(1)? != 0 && revoked.is_none(),
                            allow_source_excerpts: r.get::<_, i64>(2)? != 0 && revoked.is_none(),
                            allow_local_fallback: r.get::<_, i64>(3)? != 0,
                            max_payload_bytes: r.get::<_, i64>(5)? as usize,
                            granted_by: r.get(6)?,
                            granted_ms: r.get(7)?,
                        },
                        allow_web_research: r.get::<_, i64>(4)? != 0 && revoked.is_none(),
                        revoked_ms: revoked,
                    })
                },
            )
            .optional()
            .map_err(|e| e.to_string())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn grant_consent(
        &self,
        project_id: &str,
        allow_cloud: bool,
        allow_source_excerpts: bool,
        allow_local_fallback: bool,
        allow_web_research: bool,
        max_payload_bytes: usize,
        granted_by: &str,
    ) -> Result<ConsentRecord, String> {
        let who = granted_by.trim();
        if who.is_empty() || who.len() > 120 {
            return Err("operator identity required".into());
        }
        if allow_source_excerpts && !allow_cloud {
            return Err("source excerpts require cloud consent".into());
        }
        self.db
            .connection()
            .execute(
                "INSERT INTO cloud_consents(project_id,allow_cloud,allow_source_excerpts,allow_local_fallback,
                    allow_web_research,max_payload_bytes,granted_by,granted_ms,revoked_ms)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,NULL)
                 ON CONFLICT(project_id) DO UPDATE SET allow_cloud=excluded.allow_cloud,
                   allow_source_excerpts=excluded.allow_source_excerpts, allow_local_fallback=excluded.allow_local_fallback,
                   allow_web_research=excluded.allow_web_research, max_payload_bytes=excluded.max_payload_bytes,
                   granted_by=excluded.granted_by, granted_ms=excluded.granted_ms, revoked_ms=NULL",
                params![
                    project_id,
                    i64::from(allow_cloud),
                    i64::from(allow_source_excerpts),
                    i64::from(allow_local_fallback),
                    i64::from(allow_web_research),
                    max_payload_bytes.clamp(1024, 262_144) as i64,
                    who,
                    now_ms()
                ],
            )
            .map_err(|e| e.to_string())?;
        self.consent(project_id)?
            .ok_or_else(|| "consent not saved".into())
    }

    /// Revocation takes effect immediately for new egress decisions.
    pub fn revoke_consent(&self, project_id: &str) -> Result<bool, String> {
        self.db
            .connection()
            .execute(
                "UPDATE cloud_consents SET revoked_ms=?2 WHERE project_id=?1 AND revoked_ms IS NULL",
                params![project_id, now_ms()],
            )
            .map(|n| n == 1)
            .map_err(|e| e.to_string())
    }

    pub fn record_request(
        &self,
        audit: &CallAudit,
        project_id: Option<&str>,
        run_id: Option<&str>,
        task_id: Option<&str>,
        redactions: usize,
        credits: u32,
        usage: Option<&model_gateway::types::Usage>,
    ) -> Result<(), String> {
        self.db
            .connection()
            .execute(
                "INSERT OR REPLACE INTO provider_requests(request_id,project_id,run_id,task_id,provider,model,operation,
                    outcome,http_status,attempts,latency_ms,bytes_sent,payload_sha256,redactions,credits,
                    prompt_tokens,completion_tokens,streamed,created_ms)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19)",
                params![
                    audit.request_id,
                    project_id,
                    run_id,
                    task_id,
                    audit.provider,
                    audit.model,
                    audit.operation,
                    audit.outcome,
                    audit.http_status,
                    audit.attempts,
                    audit.latency_ms as i64,
                    audit.bytes_sent as i64,
                    audit.payload_sha256,
                    redactions as i64,
                    credits,
                    usage.map(|u| u.prompt_tokens as i64),
                    usage.map(|u| u.completion_tokens as i64),
                    i64::from(audit.streamed),
                    now_ms()
                ],
            )
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    pub fn recent_requests(
        &self,
        project_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<ProviderRequestRecord>, String> {
        let mut stmt = self
            .db
            .connection()
            .prepare(
                "SELECT request_id,project_id,run_id,provider,model,outcome,http_status,attempts,latency_ms,
                        bytes_sent,credits,streamed,created_ms
                 FROM provider_requests WHERE (?1 IS NULL OR project_id=?1) ORDER BY created_ms DESC LIMIT ?2",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(params![project_id, limit.clamp(1, 500) as i64], |r| {
                Ok(ProviderRequestRecord {
                    request_id: r.get(0)?,
                    project_id: r.get(1)?,
                    run_id: r.get(2)?,
                    provider: r.get(3)?,
                    model: r.get(4)?,
                    outcome: r.get(5)?,
                    http_status: r.get(6)?,
                    attempts: r.get(7)?,
                    latency_ms: r.get::<_, i64>(8)? as u64,
                    bytes_sent: r.get::<_, i64>(9)? as usize,
                    credits: r.get(10)?,
                    streamed: r.get::<_, i64>(11)? != 0,
                    created_ms: r.get(12)?,
                })
            })
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<_, _>>().map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consent_grant_revoke_and_settings_validation() {
        let db = Database::open_in_memory().unwrap();
        db.connection()
            .execute(
                "INSERT INTO projects(id,root_path,display_name) VALUES ('p','/p','p')",
                [],
            )
            .unwrap();
        let s = CloudSettings::new(&db);
        assert!(s.consent("p").unwrap().is_none());
        assert!(s
            .grant_consent("p", false, true, false, false, 8192, "op")
            .is_err());
        let c = s
            .grant_consent("p", true, false, true, true, 8192, "operator")
            .unwrap();
        assert!(c.consent.allow_cloud && c.allow_web_research);
        assert!(s.revoke_consent("p").unwrap());
        let c = s.consent("p").unwrap().unwrap();
        assert!(
            !c.consent.allow_cloud && !c.allow_web_research,
            "revocation is immediate"
        );
        let bad = ProviderSettings {
            provider: "openmindai".into(),
            kind: "cloud".into(),
            base_url: "http://evil.example/".into(),
            enabled: true,
            role_models: Default::default(),
            updated_ms: 0,
        };
        assert!(s.save_provider(&bad).is_err());
        let ok = ProviderSettings {
            base_url: model_gateway::OPENMINDAI_DEFAULT_BASE_URL.into(),
            ..bad
        };
        assert!(s.save_provider(&ok).unwrap().enabled);
        let cols: String = db
            .connection()
            .query_row(
                "SELECT group_concat(name) FROM pragma_table_info('provider_settings')",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(
            !cols.contains("token") && !cols.contains("key"),
            "no secret columns"
        );
    }
}
