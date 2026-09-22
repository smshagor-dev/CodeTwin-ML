use std::collections::BTreeMap;

use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;

use crate::Database;

const MAX_LIST: usize = 500;

#[derive(Debug, Error)]
pub enum WebSecurityStoreError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid web security scan configuration: {0}")]
    InvalidConfig(String),
    #[error("web security scan not found: {0}")]
    NotFound(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WebScanCreate {
    pub website_id: Option<String>,
    pub project_id: Option<String>,
    pub target_url: String,
    pub authorization_confirmed: bool,
    pub scope_json: String,
    pub config_json: String,
    pub auth_metadata_json: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WebScanRecord {
    pub id: String,
    pub website_id: Option<String>,
    pub project_id: Option<String>,
    pub target_url: String,
    pub status: String,
    pub phase: String,
    pub authorization_confirmed: bool,
    pub scope_json: String,
    pub config_json: String,
    pub auth_metadata_json: String,
    pub endpoints_discovered: usize,
    pub requests_performed: usize,
    pub findings_count: usize,
    pub last_error: Option<String>,
    pub created_at: String,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub cancelled_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WebEndpointInput {
    pub url: String,
    pub method: String,
    pub depth: usize,
    pub source: String,
    pub parameter_names: Vec<String>,
    pub parameter_locations: BTreeMap<String, String>,
    pub response_header_names: Vec<String>,
    pub cookie_names: Vec<String>,
    pub content_type: Option<String>,
    pub status_code: Option<u16>,
    pub redirect_to: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WebEndpointRecord {
    pub id: String,
    pub scan_id: String,
    pub url: String,
    pub method: String,
    pub depth: usize,
    pub source: String,
    pub parameter_names: Vec<String>,
    pub parameter_locations: BTreeMap<String, String>,
    pub response_header_names: Vec<String>,
    pub cookie_names: Vec<String>,
    pub content_type: Option<String>,
    pub status_code: Option<u16>,
    pub redirect_to: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WebSourceCorrelation {
    pub file_id: String,
    pub relative_path: String,
    pub symbol_id: Option<String>,
    pub symbol_name: Option<String>,
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SourceRouteRecord {
    pub id: String,
    pub project_id: String,
    pub file_id: String,
    pub relative_path: String,
    pub symbol_id: Option<String>,
    pub symbol_name: Option<String>,
    pub framework: String,
    pub router_name: String,
    pub http_method: String,
    pub path_template: String,
    pub handler_name: Option<String>,
    pub parameter_names: Vec<String>,
    pub parameter_locations: BTreeMap<String, String>,
    pub request_content_type: Option<String>,
    pub source_content_hash: String,
    pub start_line: usize,
    pub end_line: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WebSourceEndpointLinkRecord {
    pub id: String,
    pub scan_id: String,
    pub endpoint_id: String,
    pub source_route_id: String,
    pub match_kind: String,
    pub confidence: f64,
    pub parameter_overlap: Vec<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WebFindingInput {
    pub fingerprint: String,
    pub category: String,
    pub severity: String,
    pub confidence: String,
    pub target: String,
    pub endpoint_url: String,
    pub method: String,
    pub parameter_name: Option<String>,
    pub title: String,
    pub description: String,
    pub reproduction_summary: String,
    pub impact: String,
    pub remediation: String,
    pub references: Vec<String>,
    pub source: Option<WebSourceCorrelation>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WebFindingRecord {
    pub id: String,
    pub scan_id: String,
    pub fingerprint: String,
    pub category: String,
    pub severity: String,
    pub confidence: String,
    pub target: String,
    pub endpoint_url: String,
    pub method: String,
    pub parameter_name: Option<String>,
    pub title: String,
    pub description: String,
    pub reproduction_summary: String,
    pub impact: String,
    pub remediation: String,
    pub references: Vec<String>,
    pub source_file_id: Option<String>,
    pub source_relative_path: Option<String>,
    pub source_symbol_id: Option<String>,
    pub source_symbol_name: Option<String>,
    pub source_confidence: Option<f64>,
    pub status: String,
    pub first_detected: String,
    pub last_detected: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WebEvidenceInput {
    pub summary: String,
    pub request_metadata_json: String,
    pub response_metadata_json: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WebEvidenceRecord {
    pub id: String,
    pub finding_id: String,
    pub summary: String,
    pub request_metadata_json: String,
    pub response_metadata_json: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct WebFindingFilter {
    pub severity: Option<String>,
    pub category: Option<String>,
    pub confidence: Option<String>,
    pub endpoint: Option<String>,
    pub status: Option<String>,
}

pub struct AuthorizedWebSecurityStore<'a> {
    database: &'a Database,
}

impl<'a> AuthorizedWebSecurityStore<'a> {
    pub const fn new(database: &'a Database) -> Self {
        Self { database }
    }

    pub fn recover_interrupted_scans(&self) -> Result<usize, WebSecurityStoreError> {
        Ok(self.database.connection().execute(
            "UPDATE web_security_scans
             SET status='failed', phase='failed',
                 last_error='CodeTwin restarted before this scan completed.',
                 finished_at=COALESCE(finished_at, CURRENT_TIMESTAMP)
             WHERE status IN ('queued','running')",
            [],
        )?)
    }

    pub fn create_scan(&self, input: &WebScanCreate) -> Result<WebScanRecord, WebSecurityStoreError> {
        if !input.authorization_confirmed {
            return Err(WebSecurityStoreError::InvalidConfig(
                "explicit authorization confirmation is required".to_string(),
            ));
        }
        let target = Url::parse(input.target_url.trim())
            .map_err(|error| WebSecurityStoreError::InvalidConfig(error.to_string()))?;
        if !matches!(target.scheme(), "http" | "https") || target.host_str().is_none() {
            return Err(WebSecurityStoreError::InvalidConfig(
                "target must be an absolute HTTP(S) URL".to_string(),
            ));
        }
        if !target.username().is_empty() || target.password().is_some() {
            return Err(WebSecurityStoreError::InvalidConfig(
                "credentials must not be embedded in target URLs".to_string(),
            ));
        }
        serde_json::from_str::<serde_json::Value>(&input.scope_json)?;
        serde_json::from_str::<serde_json::Value>(&input.config_json)?;
        serde_json::from_str::<serde_json::Value>(&input.auth_metadata_json)?;

        let id = self.random_id("webscan")?;
        self.database.connection().execute(
            "INSERT INTO web_security_scans(
                id, website_id, project_id, target_url, status, phase,
                authorization_confirmed, scope_json, config_json, auth_metadata_json
             ) VALUES (?1, ?2, ?3, ?4, 'queued', 'queued', 1, ?5, ?6, ?7)",
            params![
                id,
                input.website_id,
                input.project_id,
                target.to_string(),
                input.scope_json,
                input.config_json,
                input.auth_metadata_json,
            ],
        )?;
        self.get_scan(&id)?
            .ok_or_else(|| WebSecurityStoreError::NotFound(id))
    }

    pub fn get_scan(&self, scan_id: &str) -> Result<Option<WebScanRecord>, WebSecurityStoreError> {
        self.database
            .connection()
            .query_row(
                "SELECT id, website_id, project_id, target_url, status, phase,
                        authorization_confirmed, scope_json, config_json, auth_metadata_json,
                        endpoints_discovered, requests_performed, findings_count, last_error,
                        created_at, started_at, finished_at, cancelled_at
                 FROM web_security_scans WHERE id = ?1",
                [scan_id],
                map_scan,
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn list_scans(
        &self,
        website_id: Option<&str>,
        project_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<WebScanRecord>, WebSecurityStoreError> {
        let mut statement = self.database.connection().prepare(
            "SELECT id, website_id, project_id, target_url, status, phase,
                    authorization_confirmed, scope_json, config_json, auth_metadata_json,
                    endpoints_discovered, requests_performed, findings_count, last_error,
                    created_at, started_at, finished_at, cancelled_at
             FROM web_security_scans
             WHERE (?1 IS NULL OR website_id = ?1)
               AND (?2 IS NULL OR project_id = ?2)
             ORDER BY created_at DESC, id DESC LIMIT ?3",
        )?;
        let rows = statement.query_map(
            params![website_id, project_id, bounded(limit) as i64],
            map_scan,
        )?;
        let mut values = Vec::new();
        for row in rows {
            values.push(row?);
        }
        Ok(values)
    }

    pub fn update_progress(
        &self,
        scan_id: &str,
        status: &str,
        phase: &str,
        endpoints: usize,
        requests: usize,
        findings: usize,
    ) -> Result<(), WebSecurityStoreError> {
        validate_status(status, phase)?;
        self.database.connection().execute(
            "UPDATE web_security_scans
             SET status = ?2, phase = ?3,
                 endpoints_discovered = ?4,
                 requests_performed = ?5,
                 findings_count = ?6,
                 started_at = CASE WHEN started_at IS NULL AND ?2 = 'running' THEN CURRENT_TIMESTAMP ELSE started_at END,
                 finished_at = CASE WHEN ?2 IN ('completed','failed','cancelled') THEN CURRENT_TIMESTAMP ELSE finished_at END
             WHERE id = ?1",
            params![scan_id, status, phase, endpoints as i64, requests as i64, findings as i64],
        )?;
        Ok(())
    }

    pub fn fail_scan(&self, scan_id: &str, error: &str) -> Result<(), WebSecurityStoreError> {
        self.database.connection().execute(
            "UPDATE web_security_scans
             SET status='failed', phase='failed', last_error=?2, finished_at=CURRENT_TIMESTAMP
             WHERE id=?1",
            params![scan_id, bounded_text(error, 2_000)],
        )?;
        Ok(())
    }

    pub fn cancel_scan(&self, scan_id: &str) -> Result<(), WebSecurityStoreError> {
        self.database.connection().execute(
            "UPDATE web_security_scans
             SET status='cancelled', phase='cancelled', cancelled_at=CURRENT_TIMESTAMP,
                 finished_at=CURRENT_TIMESTAMP
             WHERE id=?1 AND status IN ('queued','running')",
            [scan_id],
        )?;
        Ok(())
    }

    pub fn record_endpoint(
        &self,
        scan_id: &str,
        endpoint: &WebEndpointInput,
    ) -> Result<WebEndpointRecord, WebSecurityStoreError> {
        let id = stable_id("webendpoint", &[scan_id, &endpoint.method, &endpoint.url]);
        let parameters_json = serde_json::to_string(&endpoint.parameter_names)?;
        let locations_json = serde_json::to_string(&endpoint.parameter_locations)?;
        let response_headers_json = serde_json::to_string(&endpoint.response_header_names)?;
        let cookie_names_json = serde_json::to_string(&endpoint.cookie_names)?;
        self.database.connection().execute(
            "INSERT INTO web_security_endpoints(
                id, scan_id, url, method, depth, source, parameter_names_json,
                parameter_locations_json, response_header_names_json, cookie_names_json,
                content_type, status_code, redirect_to
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
             ON CONFLICT(scan_id, method, url) DO UPDATE SET
                depth = MIN(web_security_endpoints.depth, excluded.depth),
                source = excluded.source,
                parameter_names_json = excluded.parameter_names_json,
                parameter_locations_json = excluded.parameter_locations_json,
                response_header_names_json = excluded.response_header_names_json,
                cookie_names_json = excluded.cookie_names_json,
                content_type = COALESCE(excluded.content_type, web_security_endpoints.content_type),
                status_code = COALESCE(excluded.status_code, web_security_endpoints.status_code),
                redirect_to = COALESCE(excluded.redirect_to, web_security_endpoints.redirect_to)",
            params![
                id,
                scan_id,
                endpoint.url,
                endpoint.method,
                endpoint.depth as i64,
                endpoint.source,
                parameters_json,
                locations_json,
                response_headers_json,
                cookie_names_json,
                endpoint.content_type,
                endpoint.status_code.map(i64::from),
                endpoint.redirect_to,
            ],
        )?;
        self.database
            .connection()
            .query_row(
                "SELECT id, scan_id, url, method, depth, source, parameter_names_json,
                        parameter_locations_json, response_header_names_json, cookie_names_json,
                        content_type, status_code, redirect_to, created_at
                 FROM web_security_endpoints WHERE scan_id=?1 AND method=?2 AND url=?3",
                params![scan_id, endpoint.method, endpoint.url],
                map_endpoint,
            )
            .map_err(Into::into)
    }

    pub fn list_endpoints(
        &self,
        scan_id: &str,
        limit: usize,
    ) -> Result<Vec<WebEndpointRecord>, WebSecurityStoreError> {
        let mut statement = self.database.connection().prepare(
            "SELECT id, scan_id, url, method, depth, source, parameter_names_json,
                    parameter_locations_json, response_header_names_json, cookie_names_json,
                    content_type, status_code, redirect_to, created_at
             FROM web_security_endpoints WHERE scan_id=?1
             ORDER BY depth, url, method LIMIT ?2",
        )?;
        let rows = statement.query_map(params![scan_id, bounded(limit) as i64], map_endpoint)?;
        let mut values = Vec::new();
        for row in rows {
            values.push(row?);
        }
        Ok(values)
    }

    pub fn record_finding(
        &self,
        scan_id: &str,
        finding: &WebFindingInput,
    ) -> Result<WebFindingRecord, WebSecurityStoreError> {
        validate_finding(finding)?;
        let id = stable_id("webfinding", &[scan_id, &finding.fingerprint]);
        let references_json = serde_json::to_string(&finding.references)?;
        let source_file_id = finding.source.as_ref().map(|source| source.file_id.as_str());
        let source_symbol_id = finding
            .source
            .as_ref()
            .and_then(|source| source.symbol_id.as_deref());
        let source_confidence = finding.source.as_ref().map(|source| source.confidence);
        let first_detected: Option<String> = self.database.connection().query_row(
            "SELECT MIN(previous.first_detected)
             FROM web_security_findings previous
             JOIN web_security_scans previous_scan ON previous_scan.id=previous.scan_id
             JOIN web_security_scans current_scan ON current_scan.id=?1
             WHERE previous.fingerprint=?2
               AND previous_scan.target_url=current_scan.target_url
               AND COALESCE(previous_scan.project_id,'')=COALESCE(current_scan.project_id,'')",
            params![scan_id, finding.fingerprint],
            |row| row.get(0),
        )?;
        self.database.connection().execute(
            "INSERT INTO web_security_findings(
                id, scan_id, fingerprint, category, severity, confidence, target,
                endpoint_url, method, parameter_name, title, description,
                reproduction_summary, impact, remediation, references_json,
                source_file_id, source_symbol_id, source_confidence, first_detected
             ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,COALESCE(?20,CURRENT_TIMESTAMP))
             ON CONFLICT(scan_id, fingerprint) DO UPDATE SET
                severity=excluded.severity,
                confidence=excluded.confidence,
                description=excluded.description,
                reproduction_summary=excluded.reproduction_summary,
                impact=excluded.impact,
                remediation=excluded.remediation,
                references_json=excluded.references_json,
                source_file_id=COALESCE(excluded.source_file_id, web_security_findings.source_file_id),
                source_symbol_id=COALESCE(excluded.source_symbol_id, web_security_findings.source_symbol_id),
                source_confidence=COALESCE(excluded.source_confidence, web_security_findings.source_confidence),
                last_detected=CURRENT_TIMESTAMP",
            params![
                id,
                scan_id,
                finding.fingerprint,
                finding.category,
                finding.severity,
                finding.confidence,
                finding.target,
                finding.endpoint_url,
                finding.method,
                finding.parameter_name,
                finding.title,
                finding.description,
                finding.reproduction_summary,
                finding.impact,
                finding.remediation,
                references_json,
                source_file_id,
                source_symbol_id,
                source_confidence,
                first_detected,
            ],
        )?;
        self.get_finding_by_id(&id)?
            .ok_or_else(|| WebSecurityStoreError::NotFound(id))
    }

    pub fn record_evidence(
        &self,
        finding_id: &str,
        evidence: &WebEvidenceInput,
    ) -> Result<WebEvidenceRecord, WebSecurityStoreError> {
        serde_json::from_str::<serde_json::Value>(&evidence.request_metadata_json)?;
        serde_json::from_str::<serde_json::Value>(&evidence.response_metadata_json)?;
        let id = stable_id(
            "webevidence",
            &[
                finding_id,
                &evidence.summary,
                &evidence.request_metadata_json,
                &evidence.response_metadata_json,
            ],
        );
        self.database.connection().execute(
            "INSERT OR IGNORE INTO web_security_evidence(
                id, finding_id, summary, request_metadata_json, response_metadata_json
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                id,
                finding_id,
                bounded_text(&evidence.summary, 2_000),
                evidence.request_metadata_json,
                evidence.response_metadata_json,
            ],
        )?;
        self.database
            .connection()
            .query_row(
                "SELECT id, finding_id, summary, request_metadata_json, response_metadata_json, created_at
                 FROM web_security_evidence WHERE id=?1",
                [id],
                map_evidence,
            )
            .map_err(Into::into)
    }

    pub fn list_findings(
        &self,
        scan_id: &str,
        filter: &WebFindingFilter,
        limit: usize,
    ) -> Result<Vec<WebFindingRecord>, WebSecurityStoreError> {
        let endpoint_pattern = filter
            .endpoint
            .as_ref()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        let mut statement = self.database.connection().prepare(
            "SELECT wf.id, wf.scan_id, wf.fingerprint, wf.category, wf.severity, wf.confidence, wf.target,
                    wf.endpoint_url, wf.method, wf.parameter_name, wf.title, wf.description,
                    wf.reproduction_summary, wf.impact, wf.remediation, wf.references_json,
                    wf.source_file_id, sf.relative_path, wf.source_symbol_id, ss.name,
                    wf.source_confidence, wf.status, wf.first_detected, wf.last_detected
             FROM web_security_findings wf
             LEFT JOIN files sf ON sf.id=wf.source_file_id
             LEFT JOIN symbols ss ON ss.id=wf.source_symbol_id
             WHERE wf.scan_id=?1
               AND (?2 IS NULL OR wf.severity=?2)
               AND (?3 IS NULL OR wf.category=?3)
               AND (?4 IS NULL OR wf.confidence=?4)
               AND (?5 IS NULL OR instr(lower(wf.endpoint_url), lower(?5)) > 0)
               AND (?6 IS NULL OR wf.status=?6)
             ORDER BY
               CASE wf.severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4
                 WHEN 'medium' THEN 3 WHEN 'low' THEN 2 ELSE 1 END DESC,
               wf.last_detected DESC
             LIMIT ?7",
        )?;
        let rows = statement.query_map(
            params![
                scan_id,
                filter.severity,
                filter.category,
                filter.confidence,
                endpoint_pattern,
                filter.status,
                bounded(limit) as i64,
            ],
            map_finding,
        )?;
        let mut values = Vec::new();
        for row in rows {
            values.push(row?);
        }
        Ok(values)
    }

    pub fn finding_evidence(
        &self,
        finding_id: &str,
        limit: usize,
    ) -> Result<Vec<WebEvidenceRecord>, WebSecurityStoreError> {
        let mut statement = self.database.connection().prepare(
            "SELECT id, finding_id, summary, request_metadata_json, response_metadata_json, created_at
             FROM web_security_evidence WHERE finding_id=?1
             ORDER BY created_at, id LIMIT ?2",
        )?;
        let rows = statement.query_map(params![finding_id, bounded(limit) as i64], map_evidence)?;
        let mut values = Vec::new();
        for row in rows {
            values.push(row?);
        }
        Ok(values)
    }

    pub fn update_finding_status(
        &self,
        finding_id: &str,
        status: &str,
    ) -> Result<bool, WebSecurityStoreError> {
        if !matches!(status, "open" | "resolved" | "accepted_risk" | "false_positive") {
            return Err(WebSecurityStoreError::InvalidConfig(
                "invalid finding status".to_string(),
            ));
        }
        Ok(self.database.connection().execute(
            "UPDATE web_security_findings SET status=?2 WHERE id=?1",
            params![finding_id, status],
        )? > 0)
    }

    pub fn list_source_routes(
        &self,
        project_id: &str,
        limit: usize,
    ) -> Result<Vec<SourceRouteRecord>, WebSecurityStoreError> {
        let mut statement = self.database.connection().prepare(
            "SELECT sr.id, sr.project_id, sr.file_id, f.relative_path,
                    sr.symbol_id, s.name, sr.framework, sr.router_name,
                    sr.http_method, sr.path_template, sr.handler_name,
                    sr.parameter_names_json, sr.parameter_locations_json,
                    sr.request_content_type, sr.source_content_hash,
                    sr.start_line, sr.end_line
             FROM source_routes sr
             JOIN files f ON f.id = sr.file_id
             LEFT JOIN symbols s ON s.id = sr.symbol_id AND s.is_active = 1
             WHERE sr.project_id = ?1 AND sr.is_active = 1 AND f.is_active = 1
             ORDER BY sr.path_template, sr.http_method, sr.start_line
             LIMIT ?2",
        )?;
        let rows = statement.query_map(params![project_id, bounded(limit) as i64], |row| {
            let parameter_names_json: String = row.get(11)?;
            let parameter_locations_json: String = row.get(12)?;
            Ok(SourceRouteRecord {
                id: row.get(0)?,
                project_id: row.get(1)?,
                file_id: row.get(2)?,
                relative_path: row.get(3)?,
                symbol_id: row.get(4)?,
                symbol_name: row.get(5)?,
                framework: row.get(6)?,
                router_name: row.get(7)?,
                http_method: row.get(8)?,
                path_template: row.get(9)?,
                handler_name: row.get(10)?,
                parameter_names: serde_json::from_str(&parameter_names_json).unwrap_or_default(),
                parameter_locations: serde_json::from_str(&parameter_locations_json).unwrap_or_default(),
                request_content_type: row.get(13)?,
                source_content_hash: row.get(14)?,
                start_line: row.get::<_, i64>(15)?.max(0) as usize,
                end_line: row.get::<_, i64>(16)?.max(0) as usize,
            })
        })?;
        let mut values = Vec::new();
        for row in rows {
            values.push(row?);
        }
        Ok(values)
    }

    pub fn link_endpoint_to_source_route(
        &self,
        project_id: Option<&str>,
        endpoint: &WebEndpointRecord,
    ) -> Result<Option<WebSourceEndpointLinkRecord>, WebSecurityStoreError> {
        let Some(project_id) = project_id else {
            return Ok(None);
        };
        let url = Url::parse(&endpoint.url)
            .map_err(|error| WebSecurityStoreError::InvalidConfig(error.to_string()))?;
        let routes = self.list_source_routes(project_id, 1_000)?;
        let mut best: Option<(f64, bool, SourceRouteRecord, Vec<String>)> = None;

        for route in routes {
            if route.http_method != endpoint.method {
                continue;
            }
            let Some(exact_path) = route_template_match(&route.path_template, url.path()) else {
                continue;
            };
            let mut overlap: Vec<String> = endpoint
                .parameter_names
                .iter()
                .filter(|name| {
                    route
                        .parameter_names
                        .iter()
                        .any(|candidate| candidate.eq_ignore_ascii_case(name))
                })
                .cloned()
                .collect();
            overlap.sort();
            overlap.dedup();
            let seeded = endpoint.source.starts_with("source_route:");
            let mut confidence: f64 = if seeded {
                0.995
            } else if exact_path {
                0.98
            } else {
                0.93
            };
            if !overlap.is_empty() {
                confidence = (confidence + 0.005).min(0.999);
            }
            if best.as_ref().map_or(true, |(score, _, _, _)| confidence > *score) {
                best = Some((confidence, exact_path, route, overlap));
            }
        }

        let Some((confidence, exact_path, route, overlap)) = best else {
            return Ok(None);
        };
        let match_kind = if endpoint.source.starts_with("source_route:") {
            "seeded"
        } else if exact_path {
            "exact_static"
        } else {
            "template"
        };
        let id = stable_id(
            "web-source-endpoint",
            &[&endpoint.scan_id, &endpoint.id, &route.id],
        );
        let overlap_json = serde_json::to_string(&overlap)?;
        self.database.connection().execute(
            "INSERT INTO web_source_endpoint_links(
               id, scan_id, endpoint_id, source_route_id, match_kind, confidence,
               parameter_overlap_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(scan_id, endpoint_id, source_route_id) DO UPDATE SET
               match_kind = excluded.match_kind,
               confidence = excluded.confidence,
               parameter_overlap_json = excluded.parameter_overlap_json",
            params![
                id,
                endpoint.scan_id,
                endpoint.id,
                route.id,
                match_kind,
                confidence,
                overlap_json,
            ],
        )?;
        let created_at: String = self.database.connection().query_row(
            "SELECT created_at FROM web_source_endpoint_links WHERE id=?1",
            [&id],
            |row| row.get(0),
        )?;
        Ok(Some(WebSourceEndpointLinkRecord {
            id,
            scan_id: endpoint.scan_id.clone(),
            endpoint_id: endpoint.id.clone(),
            source_route_id: route.id,
            match_kind: match_kind.to_string(),
            confidence,
            parameter_overlap: overlap,
            created_at,
        }))
    }

    pub fn list_source_endpoint_links(
        &self,
        scan_id: &str,
        limit: usize,
    ) -> Result<Vec<WebSourceEndpointLinkRecord>, WebSecurityStoreError> {
        let mut statement = self.database.connection().prepare(
            "SELECT id, scan_id, endpoint_id, source_route_id, match_kind,
                    confidence, parameter_overlap_json, created_at
             FROM web_source_endpoint_links
             WHERE scan_id=?1
             ORDER BY confidence DESC, endpoint_id, source_route_id
             LIMIT ?2",
        )?;
        let rows = statement.query_map(params![scan_id, bounded(limit) as i64], |row| {
            let overlap_json: String = row.get(6)?;
            Ok(WebSourceEndpointLinkRecord {
                id: row.get(0)?,
                scan_id: row.get(1)?,
                endpoint_id: row.get(2)?,
                source_route_id: row.get(3)?,
                match_kind: row.get(4)?,
                confidence: row.get(5)?,
                parameter_overlap: serde_json::from_str(&overlap_json).unwrap_or_default(),
                created_at: row.get(7)?,
            })
        })?;
        let mut values = Vec::new();
        for row in rows {
            values.push(row?);
        }
        Ok(values)
    }

    pub fn correlate_source(
        &self,
        project_id: Option<&str>,
        endpoint_url: &str,
        parameter_name: Option<&str>,
    ) -> Result<Option<WebSourceCorrelation>, WebSecurityStoreError> {
        self.correlate_source_for_request(project_id, endpoint_url, None, parameter_name)
    }

    pub fn correlate_source_for_request(
        &self,
        project_id: Option<&str>,
        endpoint_url: &str,
        method: Option<&str>,
        parameter_name: Option<&str>,
    ) -> Result<Option<WebSourceCorrelation>, WebSecurityStoreError> {
        let Some(project_id) = project_id else {
            return Ok(None);
        };
        let url = Url::parse(endpoint_url)
            .map_err(|error| WebSecurityStoreError::InvalidConfig(error.to_string()))?;
        let request_method = method.unwrap_or("").trim().to_ascii_uppercase();
        let parameter = parameter_name.unwrap_or("").trim();

        let routes = self.list_source_routes(project_id, 1_000)?;
        let mut best: Option<(f64, SourceRouteRecord)> = None;
        for route in routes {
            if !request_method.is_empty() && route.http_method != request_method {
                continue;
            }
            let Some(exact_path) = route_template_match(&route.path_template, url.path()) else {
                continue;
            };
            let mut confidence: f64 = if exact_path { 0.96 } else { 0.90 };
            if !request_method.is_empty() {
                confidence += 0.02;
            }
            if !parameter.is_empty()
                && route
                    .parameter_names
                    .iter()
                    .any(|candidate| candidate.eq_ignore_ascii_case(parameter))
            {
                confidence += 0.01;
            }
            confidence = confidence.min(0.99);
            if best.as_ref().map_or(true, |(score, _)| confidence > *score) {
                best = Some((confidence, route));
            }
        }

        if let Some((confidence, route)) = best {
            return Ok(Some(WebSourceCorrelation {
                file_id: route.file_id,
                relative_path: route.relative_path,
                symbol_id: route.symbol_id,
                symbol_name: route.symbol_name.or(route.handler_name),
                confidence,
            }));
        }

        self.correlate_source_heuristic(project_id, &url, parameter)
    }

    fn correlate_source_heuristic(
        &self,
        project_id: &str,
        url: &Url,
        parameter: &str,
    ) -> Result<Option<WebSourceCorrelation>, WebSecurityStoreError> {
        let segment = url
            .path_segments()
            .into_iter()
            .flatten()
            .rev()
            .find(|segment| {
                segment.len() >= 3
                    && segment.chars().any(|character| character.is_ascii_alphabetic())
                    && !matches!(*segment, "api" | "v1" | "v2" | "www")
            })
            .unwrap_or("")
            .to_string();
        if segment.is_empty() && parameter.is_empty() {
            return Ok(None);
        }

        self.database
            .connection()
            .query_row(
                "SELECT f.id, f.relative_path, s.id, s.name,
                        CASE
                          WHEN ?2 <> '' AND lower(s.name)=lower(?2) THEN 0.78
                          WHEN ?3 <> '' AND lower(s.name)=lower(?3) THEN 0.72
                          WHEN sf.id IS NOT NULL THEN 0.68
                          WHEN ?2 <> '' AND instr(lower(f.relative_path), lower(?2)) > 0 THEN 0.58
                          ELSE 0.42
                        END AS confidence
                 FROM files f
                 LEFT JOIN symbols s ON s.file_id=f.id AND s.is_active=1
                 LEFT JOIN findings sf
                   ON sf.project_id=f.project_id
                  AND sf.file_id=f.id
                  AND sf.analyzer_key='appsec'
                  AND sf.status='open'
                 WHERE f.project_id=?1 AND f.is_active=1
                   AND (
                     (?2 <> '' AND (instr(lower(f.relative_path), lower(?2)) > 0
                                    OR lower(s.name)=lower(?2)))
                     OR (?3 <> '' AND lower(s.name)=lower(?3))
                     OR sf.id IS NOT NULL
                   )
                 ORDER BY confidence DESC, f.relative_path, COALESCE(s.start_line, 0)
                 LIMIT 1",
                params![project_id, segment, parameter],
                |row| {
                    Ok(WebSourceCorrelation {
                        file_id: row.get(0)?,
                        relative_path: row.get(1)?,
                        symbol_id: row.get(2)?,
                        symbol_name: row.get(3)?,
                        confidence: row.get(4)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn generate_report(
        &self,
        scan_id: &str,
        format: &str,
    ) -> Result<String, WebSecurityStoreError> {
        let scan = self
            .get_scan(scan_id)?
            .ok_or_else(|| WebSecurityStoreError::NotFound(scan_id.to_string()))?;
        let findings = self.list_findings(scan_id, &WebFindingFilter::default(), MAX_LIST)?;
        let endpoints = self.list_endpoints(scan_id, MAX_LIST)?;
        let generated_at: String = self.database.connection().query_row(
            "SELECT CURRENT_TIMESTAMP",
            [],
            |row| row.get(0),
        )?;
        let mut severity_summary = std::collections::BTreeMap::<String, usize>::new();
        for finding in &findings {
            *severity_summary.entry(finding.severity.clone()).or_default() += 1;
        }
        let mut report_findings = Vec::with_capacity(findings.len());
        for finding in &findings {
            report_findings.push(json!({
                "finding": finding,
                "evidence": self.finding_evidence(&finding.id, 20)?,
            }));
        }

        if format.eq_ignore_ascii_case("json") {
            return Ok(serde_json::to_string_pretty(&json!({
                "title": "CodeTwin Authorized Application Security Report",
                "generated_at": generated_at,
                "scan": scan,
                "methodology": "Bounded authorized crawling, passive response analysis, and non-destructive active probes.",
                "endpoint_inventory": endpoints,
                "severity_summary": severity_summary,
                "findings": report_findings,
                "limitations": [
                    "Automated testing can produce false positives and false negatives.",
                    "Potential and Likely findings require human review.",
                    "Confirmed is reserved for reproducible evidence observed by an implemented bounded probe.",
                    "Source correlation is heuristic unless independently verified."
                ]
            }))?);
        }

        if !format.eq_ignore_ascii_case("markdown") {
            return Err(WebSecurityStoreError::InvalidConfig(
                "report format must be markdown or json".to_string(),
            ));
        }

        let mut report = String::new();
        report.push_str("# CodeTwin Authorized Application Security Report\n\n");
        report.push_str("## Executive Summary\n\n");
        report.push_str(&format!(
            "Generated: {}  \nTarget: {}  \nStatus: **{}**  \nEndpoints discovered: **{}**  \nRequests performed: **{}**  \nFindings: **{}**\n\n",
            generated_at,
            scan.target_url,
            scan.status,
            scan.endpoints_discovered,
            scan.requests_performed,
            findings.len()
        ));
        report.push_str("Severity summary: ");
        for (severity, count) in &severity_summary {
            report.push_str(&format!("**{}:** {}  ", severity, count));
        }
        report.push_str("\n\n");
        report.push_str("## Scope & Authorization\n\n");
        report.push_str(
            "The scan record contains explicit authorization confirmation and the exact bounded scope/configuration used for execution. Authentication metadata records only whether credentials were supplied and custom header names; secret values are not persisted.\n\n",
        );
        report.push_str("Scope configuration JSON:\n\n");
        report.push_str(&scan.scope_json);
        report.push_str("\n\n");
        report.push_str("## Methodology\n\n");
        report.push_str(
            "Bounded target discovery and crawling, passive HTTP/header/cookie analysis, and explicitly enabled non-destructive active probes. CodeTwin does not perform password brute force, database dumping, unrelated record retrieval, persistence, destructive commands, lateral movement, monitoring evasion, or denial-of-service testing.\n\n",
        );
        report.push_str("## Target Inventory\n\n");
        for endpoint in endpoints.iter().take(200) {
            report.push_str(&format!(
                "- {} {} — {}\n",
                endpoint.method,
                endpoint.url,
                endpoint
                    .status_code
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "not requested".to_string())
            ));
        }
        report.push_str("\n## Findings\n\n");
        if findings.is_empty() {
            report.push_str(
                "No findings were observed by the executed checks. This is not a guarantee that the application is vulnerability-free.\n\n",
            );
        }
        for finding in findings {
            report.push_str(&format!(
                "### [{} / {}] {}\n\n- Category: {}\n- Endpoint: {} {}\n- Parameter: {}\n- Status: {}\n- Source correlation: {}\n- Source correlation confidence: {}\n\n{}\n\n**Impact:** {}\n\n**Reproduction:** {}\n\n**Remediation:** {}\n\n",
                finding.severity.to_ascii_uppercase(),
                finding.confidence,
                finding.title,
                finding.category,
                finding.method,
                finding.endpoint_url,
                finding.parameter_name.as_deref().unwrap_or("n/a"),
                finding.status,
                finding
                    .source_relative_path
                    .as_deref()
                    .map(|path| match finding.source_symbol_name.as_deref() {
                        Some(symbol) => format!("{path} → {symbol}"),
                        None => path.to_string(),
                    })
                    .unwrap_or_else(|| "not correlated".to_string()),
                finding
                    .source_confidence
                    .map(|value| format!("{value:.2}"))
                    .unwrap_or_else(|| "not correlated".to_string()),
                finding.description,
                finding.impact,
                finding.reproduction_summary,
                finding.remediation,
            ));
            if !finding.references.is_empty() {
                report.push_str(&format!(
                    "References: {}\n\n",
                    finding.references.join(", ")
                ));
            }
            let evidence = self.finding_evidence(&finding.id, 20)?;
            if !evidence.is_empty() {
                report.push_str("**Observed evidence:**\n\n");
                for item in evidence {
                    report.push_str(&format!(
                        "- {} — request: `{}`; response: `{}`\n",
                        item.summary,
                        bounded_text(&item.request_metadata_json, 800),
                        bounded_text(&item.response_metadata_json, 1_200),
                    ));
                }
                report.push('\n');
            }
        }
        report.push_str("## Testing Limitations\n\n");
        report.push_str(
            "- Automated security testing can produce false positives and false negatives.\n- Potential and Likely findings require human review.\n- Confirmed is reserved for reproducible evidence observed by a bounded implemented probe; it does not imply broader compromise.\n- Source attribution is heuristic unless confidence and source evidence are independently verified.\n",
        );
        Ok(report)
    }

    fn get_finding_by_id(
        &self,
        finding_id: &str,
    ) -> Result<Option<WebFindingRecord>, WebSecurityStoreError> {
        self.database
            .connection()
            .query_row(
                "SELECT wf.id, wf.scan_id, wf.fingerprint, wf.category, wf.severity, wf.confidence, wf.target,
                        wf.endpoint_url, wf.method, wf.parameter_name, wf.title, wf.description,
                        wf.reproduction_summary, wf.impact, wf.remediation, wf.references_json,
                        wf.source_file_id, sf.relative_path, wf.source_symbol_id, ss.name,
                        wf.source_confidence, wf.status, wf.first_detected, wf.last_detected
                 FROM web_security_findings wf
                 LEFT JOIN files sf ON sf.id=wf.source_file_id
                 LEFT JOIN symbols ss ON ss.id=wf.source_symbol_id
                 WHERE wf.id=?1",
                [finding_id],
                map_finding,
            )
            .optional()
            .map_err(Into::into)
    }

    fn random_id(&self, prefix: &str) -> Result<String, WebSecurityStoreError> {
        let random: String = self.database.connection().query_row(
            "SELECT lower(hex(randomblob(16)))",
            [],
            |row| row.get(0),
        )?;
        Ok(format!("{prefix}_{random}"))
    }
}

fn map_scan(row: &rusqlite::Row<'_>) -> rusqlite::Result<WebScanRecord> {
    Ok(WebScanRecord {
        id: row.get(0)?,
        website_id: row.get(1)?,
        project_id: row.get(2)?,
        target_url: row.get(3)?,
        status: row.get(4)?,
        phase: row.get(5)?,
        authorization_confirmed: row.get::<_, i64>(6)? == 1,
        scope_json: row.get(7)?,
        config_json: row.get(8)?,
        auth_metadata_json: row.get(9)?,
        endpoints_discovered: nonnegative(row.get(10)?),
        requests_performed: nonnegative(row.get(11)?),
        findings_count: nonnegative(row.get(12)?),
        last_error: row.get(13)?,
        created_at: row.get(14)?,
        started_at: row.get(15)?,
        finished_at: row.get(16)?,
        cancelled_at: row.get(17)?,
    })
}

fn map_endpoint(row: &rusqlite::Row<'_>) -> rusqlite::Result<WebEndpointRecord> {
    let parameter_names_json: String = row.get(6)?;
    let parameter_locations_json: String = row.get(7)?;
    let response_header_names_json: String = row.get(8)?;
    let cookie_names_json: String = row.get(9)?;
    let parameter_names = serde_json::from_str(&parameter_names_json).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(6, rusqlite::types::Type::Text, Box::new(error))
    })?;
    let parameter_locations = serde_json::from_str(&parameter_locations_json).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(7, rusqlite::types::Type::Text, Box::new(error))
    })?;
    let response_header_names = serde_json::from_str(&response_header_names_json).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(8, rusqlite::types::Type::Text, Box::new(error))
    })?;
    let cookie_names = serde_json::from_str(&cookie_names_json).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(9, rusqlite::types::Type::Text, Box::new(error))
    })?;
    Ok(WebEndpointRecord {
        id: row.get(0)?,
        scan_id: row.get(1)?,
        url: row.get(2)?,
        method: row.get(3)?,
        depth: nonnegative(row.get(4)?),
        source: row.get(5)?,
        parameter_names,
        parameter_locations,
        response_header_names,
        cookie_names,
        content_type: row.get(10)?,
        status_code: row
            .get::<_, Option<i64>>(11)?
            .and_then(|value| u16::try_from(value).ok()),
        redirect_to: row.get(12)?,
        created_at: row.get(13)?,
    })
}

fn map_finding(row: &rusqlite::Row<'_>) -> rusqlite::Result<WebFindingRecord> {
    let references_json: String = row.get(15)?;
    let references = serde_json::from_str(&references_json).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            15,
            rusqlite::types::Type::Text,
            Box::new(error),
        )
    })?;
    Ok(WebFindingRecord {
        id: row.get(0)?,
        scan_id: row.get(1)?,
        fingerprint: row.get(2)?,
        category: row.get(3)?,
        severity: row.get(4)?,
        confidence: row.get(5)?,
        target: row.get(6)?,
        endpoint_url: row.get(7)?,
        method: row.get(8)?,
        parameter_name: row.get(9)?,
        title: row.get(10)?,
        description: row.get(11)?,
        reproduction_summary: row.get(12)?,
        impact: row.get(13)?,
        remediation: row.get(14)?,
        references,
        source_file_id: row.get(16)?,
        source_relative_path: row.get(17)?,
        source_symbol_id: row.get(18)?,
        source_symbol_name: row.get(19)?,
        source_confidence: row.get(20)?,
        status: row.get(21)?,
        first_detected: row.get(22)?,
        last_detected: row.get(23)?,
    })
}

fn map_evidence(row: &rusqlite::Row<'_>) -> rusqlite::Result<WebEvidenceRecord> {
    Ok(WebEvidenceRecord {
        id: row.get(0)?,
        finding_id: row.get(1)?,
        summary: row.get(2)?,
        request_metadata_json: row.get(3)?,
        response_metadata_json: row.get(4)?,
        created_at: row.get(5)?,
    })
}

fn validate_status(status: &str, phase: &str) -> Result<(), WebSecurityStoreError> {
    if !matches!(
        status,
        "queued" | "running" | "completed" | "failed" | "cancelled"
    ) {
        return Err(WebSecurityStoreError::InvalidConfig(
            "invalid scan status".to_string(),
        ));
    }
    if !matches!(
        phase,
        "queued"
            | "discovering"
            | "crawling"
            | "passive_analysis"
            | "active_testing"
            | "correlating"
            | "completed"
            | "failed"
            | "cancelled"
    ) {
        return Err(WebSecurityStoreError::InvalidConfig(
            "invalid scan phase".to_string(),
        ));
    }
    Ok(())
}

fn validate_finding(finding: &WebFindingInput) -> Result<(), WebSecurityStoreError> {
    if !matches!(
        finding.severity.as_str(),
        "critical" | "high" | "medium" | "low" | "informational"
    ) {
        return Err(WebSecurityStoreError::InvalidConfig(
            "invalid finding severity".to_string(),
        ));
    }
    if !matches!(
        finding.confidence.as_str(),
        "Potential" | "Likely" | "Confirmed"
    ) {
        return Err(WebSecurityStoreError::InvalidConfig(
            "invalid finding confidence".to_string(),
        ));
    }
    Ok(())
}

fn stable_id(prefix: &str, parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part.as_bytes());
        hasher.update([0]);
    }
    format!("{prefix}_{:x}", hasher.finalize())
}

fn route_template_match(template: &str, observed: &str) -> Option<bool> {
    let normalize = |value: &str| {
        let trimmed = value.trim();
        if trimmed.len() > 1 {
            trimmed.trim_end_matches('/').to_string()
        } else if trimmed.is_empty() {
            "/".to_string()
        } else {
            trimmed.to_string()
        }
    };
    let template = normalize(template);
    let observed = normalize(observed);
    if template == observed {
        return Some(true);
    }

    let left: Vec<&str> = template.trim_matches('/').split('/').collect();
    let right: Vec<&str> = observed.trim_matches('/').split('/').collect();
    if left.len() != right.len() {
        return None;
    }
    for (expected, actual) in left.iter().zip(right.iter()) {
        let dynamic = (expected.starts_with(':') && expected.len() > 1)
            || (expected.starts_with('{') && expected.ends_with('}') && expected.len() > 2);
        if !dynamic && expected != actual {
            return None;
        }
        if dynamic && actual.is_empty() {
            return None;
        }
    }
    Some(false)
}

fn bounded(value: usize) -> usize {
    value.clamp(1, MAX_LIST)
}

fn nonnegative(value: i64) -> usize {
    usize::try_from(value.max(0)).unwrap_or(usize::MAX)
}

fn bounded_text(value: &str, max: usize) -> String {
    value.chars().take(max).collect()
}


#[cfg(test)]
mod tests {
    use super::{
        AuthorizedWebSecurityStore, WebEndpointInput, WebEvidenceInput, WebFindingFilter,
        WebFindingInput, WebScanCreate,
    };
    use std::fs;

    use tempfile::tempdir;

    use crate::{Database, ProjectIndexService};

    fn create() -> WebScanCreate {
        WebScanCreate {
            website_id: None,
            project_id: None,
            target_url: "http://localhost:8080".to_string(),
            authorization_confirmed: true,
            scope_json: r#"{"target_url":"http://localhost:8080"}"#.to_string(),
            config_json: r#"{"checks":{"sql_injection":true}}"#.to_string(),
            auth_metadata_json:
                r#"{"cookie_supplied":false,"bearer_supplied":false,"custom_header_names":[]}"#
                    .to_string(),
        }
    }

    #[test]
    fn scan_history_endpoints_findings_and_evidence_persist() {
        let database = Database::open_in_memory().expect("database");
        let store = AuthorizedWebSecurityStore::new(&database);
        let scan = store.create_scan(&create()).expect("scan");
        store
            .update_progress(&scan.id, "running", "crawling", 1, 2, 0)
            .expect("progress");
        store
            .record_endpoint(
                &scan.id,
                &WebEndpointInput {
                    url: "http://localhost:8080/search?q=a".to_string(),
                    method: "GET".to_string(),
                    depth: 1,
                    source: "html".to_string(),
                    parameter_names: vec!["q".to_string()],
                    parameter_locations: std::collections::BTreeMap::from([(
                        "q".to_string(),
                        "query".to_string(),
                    )]),
                    response_header_names: vec!["content-type".to_string()],
                    cookie_names: Vec::new(),
                    content_type: Some("text/html".to_string()),
                    status_code: Some(200),
                    redirect_to: None,
                },
            )
            .expect("endpoint");
        let finding = store
            .record_finding(
                &scan.id,
                &WebFindingInput {
                    fingerprint: "fp1".to_string(),
                    category: "sql_injection".to_string(),
                    severity: "high".to_string(),
                    confidence: "Likely".to_string(),
                    target: scan.target_url.clone(),
                    endpoint_url: "http://localhost:8080/search?q=a".to_string(),
                    method: "GET".to_string(),
                    parameter_name: Some("q".to_string()),
                    title: "SQL behavior changed".to_string(),
                    description: "bounded evidence".to_string(),
                    reproduction_summary: "repeat bounded probe".to_string(),
                    impact: "query behavior may be controlled".to_string(),
                    remediation: "parameterize".to_string(),
                    references: vec!["CWE-89".to_string()],
                    source: None,
                },
            )
            .expect("finding");
        store
            .record_evidence(
                &finding.id,
                &WebEvidenceInput {
                    summary: "redacted".to_string(),
                    request_metadata_json: r#"{"Authorization":"<redacted>"}"#.to_string(),
                    response_metadata_json: r#"{"status":500}"#.to_string(),
                },
            )
            .expect("evidence");
        assert_eq!(
            store.list_endpoints(&scan.id, 20).expect("endpoints").len(),
            1
        );
        assert_eq!(
            store
                .list_findings(&scan.id, &WebFindingFilter::default(), 20)
                .expect("findings")
                .len(),
            1
        );
        assert_eq!(
            store
                .finding_evidence(&finding.id, 20)
                .expect("evidence")
                .len(),
            1
        );
        assert_eq!(store.list_scans(None, None, 20).expect("history").len(), 1);
    }

    #[test]
    fn interrupted_scans_are_recovered_as_failed() {
        let database = Database::open_in_memory().expect("database");
        let store = AuthorizedWebSecurityStore::new(&database);
        let scan = store.create_scan(&create()).expect("scan");
        store
            .update_progress(&scan.id, "running", "active_testing", 4, 9, 1)
            .expect("progress");
        assert_eq!(store.recover_interrupted_scans().expect("recover"), 1);
        let recovered = store.get_scan(&scan.id).expect("scan lookup").expect("scan");
        assert_eq!(recovered.status, "failed");
        assert_eq!(recovered.phase, "failed");
        assert!(recovered.last_error.as_deref().is_some_and(|value| value.contains("restarted")));
    }

    #[test]
    fn endpoint_filter_and_first_detection_history_are_persistent() {
        let database = Database::open_in_memory().expect("database");
        let store = AuthorizedWebSecurityStore::new(&database);
        let first_scan = store.create_scan(&create()).expect("first scan");
        let finding_input = WebFindingInput {
            fingerprint: "stable-fingerprint".to_string(),
            category: "xss".to_string(),
            severity: "medium".to_string(),
            confidence: "Likely".to_string(),
            target: first_scan.target_url.clone(),
            endpoint_url: "http://localhost:8080/search?q=a".to_string(),
            method: "GET".to_string(),
            parameter_name: Some("q".to_string()),
            title: "Reflection".to_string(),
            description: "bounded evidence".to_string(),
            reproduction_summary: "repeat marker".to_string(),
            impact: "context dependent".to_string(),
            remediation: "encode output".to_string(),
            references: vec!["CWE-79".to_string()],
            source: None,
        };
        let first = store.record_finding(&first_scan.id, &finding_input).expect("first finding");
        let second_scan = store.create_scan(&create()).expect("second scan");
        let second = store.record_finding(&second_scan.id, &finding_input).expect("second finding");
        assert_eq!(first.first_detected, second.first_detected);

        let filtered = store
            .list_findings(
                &second_scan.id,
                &WebFindingFilter {
                    endpoint: Some("SEARCH?Q".to_string()),
                    ..WebFindingFilter::default()
                },
                20,
            )
            .expect("filtered findings");
        assert_eq!(filtered.len(), 1);
    }

    #[test]
    fn source_correlation_is_heuristic_and_uses_the_existing_index() {
        let project = tempdir().expect("project");
        fs::create_dir_all(project.path().join("src")).expect("src");
        fs::write(
            project.path().join("src/search.ts"),
            "export function search(query: string) { return query; }",
        )
        .expect("source");

        let database = Database::open_in_memory().expect("database");
        let summary = ProjectIndexService::new(&database)
            .index_project(project.path())
            .expect("index project");
        let correlated = AuthorizedWebSecurityStore::new(&database)
            .correlate_source(
                Some(&summary.project_id),
                "http://localhost:8080/api/search?q=a",
                Some("query"),
            )
            .expect("correlate")
            .expect("correlation");
        assert!(correlated.relative_path.ends_with("search.ts"));
        assert!(correlated.confidence < 1.0);
    }

    #[test]
    fn source_routes_persist_fields_and_drive_exact_live_correlation() {
        let project = tempdir().expect("project");
        fs::create_dir_all(project.path().join("src")).expect("src");
        fs::write(
            project.path().join("src/server.ts"),
            r#"
const app = express();
app.post("/api/login/:tenant", (req, res) => {
    const email = req.body.email;
    const password = req.body.password;
    return res.json({ tenant: req.params.tenant, email, password });
});
"#,
        )
        .expect("source");

        let database = Database::open_in_memory().expect("database");
        let summary = ProjectIndexService::new(&database)
            .index_project(project.path())
            .expect("index project");
        let store = AuthorizedWebSecurityStore::new(&database);
        let routes = store
            .list_source_routes(&summary.project_id, 20)
            .expect("source routes");
        let route = routes
            .iter()
            .find(|route| route.path_template == "/api/login/:tenant")
            .expect("login route");
        assert_eq!(route.http_method, "POST");
        assert!(route.parameter_locations.get("tenant").is_some_and(|value| value == "path"));
        assert!(route.parameter_locations.get("email").is_some_and(|value| value == "json"));
        assert!(route.parameter_locations.get("password").is_some_and(|value| value == "json"));

        let correlated = store
            .correlate_source_for_request(
                Some(&summary.project_id),
                "http://localhost:8080/api/login/acme",
                Some("POST"),
                Some("email"),
            )
            .expect("correlate")
            .expect("correlation");
        assert!(correlated.relative_path.ends_with("server.ts"));
        assert!(correlated.confidence >= 0.98);

        let mut scan_input = create();
        scan_input.project_id = Some(summary.project_id.clone());
        let scan = store.create_scan(&scan_input).expect("scan");
        let endpoint = store
            .record_endpoint(
                &scan.id,
                &WebEndpointInput {
                    url: "http://localhost:8080/api/login/acme".to_string(),
                    method: "POST".to_string(),
                    depth: 0,
                    source: "source_route:express:src/server.ts:2".to_string(),
                    parameter_names: vec![
                        "tenant".to_string(),
                        "email".to_string(),
                        "password".to_string(),
                    ],
                    parameter_locations: std::collections::BTreeMap::from([
                        ("tenant".to_string(), "path".to_string()),
                        ("email".to_string(), "json".to_string()),
                        ("password".to_string(), "json".to_string()),
                    ]),
                    response_header_names: Vec::new(),
                    cookie_names: Vec::new(),
                    content_type: Some("application/json".to_string()),
                    status_code: None,
                    redirect_to: None,
                },
            )
            .expect("endpoint");
        let link = store
            .link_endpoint_to_source_route(Some(&summary.project_id), &endpoint)
            .expect("link")
            .expect("source route link");
        assert_eq!(link.source_route_id, route.id);
        assert_eq!(link.match_kind, "seeded");
        assert!(link.parameter_overlap.iter().any(|name| name == "email"));
        assert_eq!(
            store
                .list_source_endpoint_links(&scan.id, 20)
                .expect("source endpoint links")
                .len(),
            1
        );
    }

    #[test]
    fn authorization_is_required_by_persistence_boundary() {
        let database = Database::open_in_memory().expect("database");
        let store = AuthorizedWebSecurityStore::new(&database);
        let mut input = create();
        input.authorization_confirmed = false;
        assert!(store.create_scan(&input).is_err());
    }
}
