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
    pub source_symbol_id: Option<String>,
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
        self.database.connection().execute(
            "INSERT INTO web_security_endpoints(
                id, scan_id, url, method, depth, source, parameter_names_json,
                content_type, status_code, redirect_to
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT(scan_id, method, url) DO UPDATE SET
                depth = MIN(web_security_endpoints.depth, excluded.depth),
                source = excluded.source,
                parameter_names_json = excluded.parameter_names_json,
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
                endpoint.content_type,
                endpoint.status_code.map(i64::from),
                endpoint.redirect_to,
            ],
        )?;
        self.database
            .connection()
            .query_row(
                "SELECT id, scan_id, url, method, depth, source, parameter_names_json,
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
        self.database.connection().execute(
            "INSERT INTO web_security_findings(
                id, scan_id, fingerprint, category, severity, confidence, target,
                endpoint_url, method, parameter_name, title, description,
                reproduction_summary, impact, remediation, references_json,
                source_file_id, source_symbol_id, source_confidence
             ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19)
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
            .map(|value| format!("%{}%", escape_like(value)));
        let mut statement = self.database.connection().prepare(
            "SELECT id, scan_id, fingerprint, category, severity, confidence, target,
                    endpoint_url, method, parameter_name, title, description,
                    reproduction_summary, impact, remediation, references_json,
                    source_file_id, source_symbol_id, source_confidence, status,
                    first_detected, last_detected
             FROM web_security_findings
             WHERE scan_id=?1
               AND (?2 IS NULL OR severity=?2)
               AND (?3 IS NULL OR category=?3)
               AND (?4 IS NULL OR confidence=?4)
               AND (?5 IS NULL OR endpoint_url LIKE ?5 ESCAPE '\')
               AND (?6 IS NULL OR status=?6)
             ORDER BY
               CASE severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4
                 WHEN 'medium' THEN 3 WHEN 'low' THEN 2 ELSE 1 END DESC,
               last_detected DESC
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

    pub fn correlate_source(
        &self,
        project_id: Option<&str>,
        endpoint_url: &str,
    ) -> Result<Option<WebSourceCorrelation>, WebSecurityStoreError> {
        let Some(project_id) = project_id else {
            return Ok(None);
        };
        let url = Url::parse(endpoint_url)
            .map_err(|error| WebSecurityStoreError::InvalidConfig(error.to_string()))?;
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
            .unwrap_or("");
        if segment.is_empty() {
            return Ok(None);
        }
        let pattern = format!("%{}%", escape_like(segment));
        self.database
            .connection()
            .query_row(
                "SELECT f.id, f.relative_path, s.id, s.name,
                        CASE
                          WHEN lower(s.name)=lower(?3) THEN 0.72
                          WHEN lower(f.relative_path) LIKE lower(?2) THEN 0.58
                          ELSE 0.42
                        END AS confidence
                 FROM files f
                 LEFT JOIN symbols s ON s.file_id=f.id AND s.is_active=1
                 WHERE f.project_id=?1 AND f.is_active=1
                   AND (f.relative_path LIKE ?2 ESCAPE '\' OR s.name LIKE ?2 ESCAPE '\')
                 ORDER BY confidence DESC, f.relative_path, s.start_line
                 LIMIT 1",
                params![project_id, pattern, segment],
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

        if format.eq_ignore_ascii_case("json") {
            return Ok(serde_json::to_string_pretty(&json!({
                "title": "CodeTwin Authorized Application Security Report",
                "scan": scan,
                "methodology": "Bounded authorized crawling, passive response analysis, and non-destructive active probes.",
                "endpoint_inventory": endpoints,
                "findings": findings,
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
            "Target: {}  \nStatus: **{}**  \nEndpoints discovered: **{}**  \nRequests performed: **{}**  \nFindings: **{}**\n\n",
            scan.target_url,
            scan.status,
            scan.endpoints_discovered,
            scan.requests_performed,
            findings.len()
        ));
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
                "### [{} / {}] {}\n\n- Category: {}\n- Endpoint: {} {}\n- Parameter: {}\n- Status: {}\n- Source correlation confidence: {}\n\n{}\n\n**Impact:** {}\n\n**Evidence / reproduction:** {}\n\n**Remediation:** {}\n\n",
                finding.severity.to_ascii_uppercase(),
                finding.confidence,
                finding.title,
                finding.category,
                finding.method,
                finding.endpoint_url,
                finding.parameter_name.as_deref().unwrap_or("n/a"),
                finding.status,
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
                "SELECT id, scan_id, fingerprint, category, severity, confidence, target,
                        endpoint_url, method, parameter_name, title, description,
                        reproduction_summary, impact, remediation, references_json,
                        source_file_id, source_symbol_id, source_confidence, status,
                        first_detected, last_detected
                 FROM web_security_findings WHERE id=?1",
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
    let parameter_names = serde_json::from_str(&parameter_names_json).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            6,
            rusqlite::types::Type::Text,
            Box::new(error),
        )
    })?;
    Ok(WebEndpointRecord {
        id: row.get(0)?,
        scan_id: row.get(1)?,
        url: row.get(2)?,
        method: row.get(3)?,
        depth: nonnegative(row.get(4)?),
        source: row.get(5)?,
        parameter_names,
        content_type: row.get(7)?,
        status_code: row
            .get::<_, Option<i64>>(8)?
            .and_then(|value| u16::try_from(value).ok()),
        redirect_to: row.get(9)?,
        created_at: row.get(10)?,
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
        source_symbol_id: row.get(17)?,
        source_confidence: row.get(18)?,
        status: row.get(19)?,
        first_detected: row.get(20)?,
        last_detected: row.get(21)?,
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

fn bounded(value: usize) -> usize {
    value.clamp(1, MAX_LIST)
}

fn nonnegative(value: i64) -> usize {
    usize::try_from(value.max(0)).unwrap_or(usize::MAX)
}

fn bounded_text(value: &str, max: usize) -> String {
    value.chars().take(max).collect()
}

fn escape_like(value: &str) -> String {
    value
        .replace('\', "\\")
        .replace('%', "\%")
        .replace('_', "\_")
}

#[cfg(test)]
mod tests {
    use super::{
        AuthorizedWebSecurityStore, WebEndpointInput, WebEvidenceInput, WebFindingFilter,
        WebFindingInput, WebScanCreate,
    };
    use crate::Database;

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
    fn authorization_is_required_by_persistence_boundary() {
        let database = Database::open_in_memory().expect("database");
        let store = AuthorizedWebSecurityStore::new(&database);
        let mut input = create();
        input.authorization_confirmed = false;
        assert!(store.create_scan(&input).is_err());
    }
}
