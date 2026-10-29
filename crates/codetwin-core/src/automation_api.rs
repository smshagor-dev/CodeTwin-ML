//! Optional local automation REST API.
//!
//! * Off by default; when enabled it binds **127.0.0.1 only**.
//! * Every request except `GET /v1/health` needs `Authorization: Bearer`
//!   with a project-scoped token. Tokens carry explicit scopes, expire, can
//!   be revoked, and are stored only as SHA-256 verifiers.
//! * Requests with an `Origin` header are refused (no browser access, no
//!   CSRF) and the `Host` header must be the loopback address (no DNS
//!   rebinding).
//! * Per-token rate limit, bounded headers/bodies, short socket timeouts,
//!   bounded concurrency; every authenticated request is audited.
//! * There is deliberately **no approval endpoint**: the API can create plans
//!   and read results, but only a human in the desktop can approve
//!   execution, and the store rejects approvals by automated principals.
use std::collections::{BTreeMap, HashMap};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::collaboration::{
    new_id, now_ms, random_secret, sha256_hex, Collaboration, PrincipalKind, Role,
};
use crate::observability::{llm_analytics, metrics_snapshot};
use crate::specialist_workers::InvestigationOptions;
use crate::workflow_platform::WorkflowPlatform;
use crate::Database;

pub const SCOPES: &[&str] = &["runs:read", "runs:write", "reports:read", "analytics:read"];
const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_BODY_BYTES: usize = 64 * 1024;
const MAX_CONNECTIONS: usize = 8;
const RATE_PER_MINUTE: u32 = 120;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiToken {
    pub id: String,
    pub principal_id: String,
    pub label: String,
    pub scopes: Vec<String>,
    pub project_id: String,
    pub created_by: String,
    pub created_ms: i64,
    pub expires_ms: i64,
    pub last_used_ms: Option<i64>,
    pub revoked: bool,
}

impl ApiToken {
    pub fn has(&self, scope: &str) -> bool {
        self.scopes.iter().any(|s| s == scope)
    }
}

pub struct TokenStore<'a> {
    db: &'a Database,
}

impl<'a> TokenStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    fn row(r: &rusqlite::Row<'_>) -> rusqlite::Result<ApiToken> {
        Ok(ApiToken {
            id: r.get(0)?,
            principal_id: r.get(1)?,
            label: r.get(2)?,
            scopes: serde_json::from_str(&r.get::<_, String>(3)?).unwrap_or_default(),
            project_id: r.get(4)?,
            created_by: r.get(5)?,
            created_ms: r.get(6)?,
            expires_ms: r.get(7)?,
            last_used_ms: r.get(8)?,
            revoked: r.get::<_, Option<i64>>(9)?.is_some(),
        })
    }

    const COLUMNS: &'static str = "id,principal_id,label,scopes_json,project_id,created_by,created_ms,expires_ms,last_used_ms,revoked_ms";

    /// Create a project-scoped token. The plaintext is returned once.
    pub fn create(
        &self,
        project_id: &str,
        label: &str,
        scopes: &[String],
        ttl_days: u32,
        actor: &str,
    ) -> Result<(ApiToken, String), String> {
        let collab = Collaboration::new(self.db);
        collab.authorize(
            project_id,
            actor,
            crate::collaboration::Action::ManageTokens,
        )?;
        let label: String = label.trim().chars().take(120).collect();
        if label.is_empty() {
            return Err("token label is required".into());
        }
        let mut scopes: Vec<String> = scopes.to_vec();
        scopes.sort();
        scopes.dedup();
        if scopes.is_empty() || scopes.iter().any(|s| !SCOPES.contains(&s.as_str())) {
            return Err(format!("scopes must be a non-empty subset of {SCOPES:?}"));
        }
        let secret = random_secret()?;
        let plaintext = format!("ctapi_{secret}");
        let id = new_id("tok");
        let principal_id = format!("api:{}", &id[4..]);
        collab.ensure_principal(
            &principal_id,
            &format!("API: {label}"),
            PrincipalKind::Automation,
        )?;
        // Automation principals never hold approver/admin roles.
        let role = if scopes.iter().any(|s| s == "runs:write") {
            Role::Analyst
        } else {
            Role::Viewer
        };
        self.db
            .connection()
            .execute(
                "INSERT INTO project_memberships(project_id,principal_id,role,granted_by,granted_ms)
                 VALUES (?1,?2,?3,?4,?5)",
                params![project_id, principal_id, role.as_str(), actor, now_ms()],
            )
            .map_err(|e| e.to_string())?;
        let now = now_ms();
        let expires = now + i64::from(ttl_days.clamp(1, 365)) * 24 * 3_600_000;
        self.db
            .connection()
            .execute(
                "INSERT INTO api_tokens(id,principal_id,label,token_sha256,scopes_json,project_id,created_by,created_ms,expires_ms)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                params![
                    id,
                    principal_id,
                    label,
                    sha256_hex(plaintext.as_bytes()),
                    serde_json::to_string(&scopes).map_err(|e| e.to_string())?,
                    project_id,
                    actor,
                    now,
                    expires
                ],
            )
            .map_err(|e| e.to_string())?;
        collab.audit(
            actor,
            "create_api_token",
            Some(project_id),
            Some(&id),
            "allowed",
            json!({"scopes": scopes, "expires_ms": expires}),
        );
        Ok((self.get(&id)?, plaintext))
    }

    pub fn get(&self, id: &str) -> Result<ApiToken, String> {
        self.db
            .connection()
            .query_row(
                &format!("SELECT {} FROM api_tokens WHERE id=?1", Self::COLUMNS),
                [id],
                Self::row,
            )
            .map_err(|_| "unknown token".to_owned())
    }

    pub fn list(&self, project_id: &str) -> Result<Vec<ApiToken>, String> {
        let mut stmt = self
            .db
            .connection()
            .prepare(&format!(
                "SELECT {} FROM api_tokens WHERE project_id=?1 ORDER BY created_ms DESC",
                Self::COLUMNS
            ))
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([project_id], Self::row)
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<_, _>>().map_err(|e| e.to_string())
    }

    pub fn revoke(&self, id: &str, actor: &str) -> Result<(), String> {
        let token = self.get(id)?;
        Collaboration::new(self.db).authorize(
            &token.project_id,
            actor,
            crate::collaboration::Action::ManageTokens,
        )?;
        self.db
            .connection()
            .execute(
                "UPDATE api_tokens SET revoked_ms=?2 WHERE id=?1 AND revoked_ms IS NULL",
                params![id, now_ms()],
            )
            .map_err(|e| e.to_string())?;
        self.db
            .connection()
            .execute(
                "UPDATE principals SET disabled=1 WHERE id=?1",
                [&token.principal_id],
            )
            .map_err(|e| e.to_string())?;
        Collaboration::new(self.db).audit(
            actor,
            "revoke_api_token",
            Some(&token.project_id),
            Some(id),
            "allowed",
            json!({}),
        );
        Ok(())
    }

    /// Resolve a presented bearer token (constant-time on the digest via an
    /// indexed lookup of the hash; plaintext is never stored or compared).
    pub fn authenticate(&self, presented: &str) -> Result<ApiToken, String> {
        let presented = presented.trim();
        if !presented.starts_with("ctapi_") || presented.len() != 70 {
            return Err("invalid token".into());
        }
        let token = self
            .db
            .connection()
            .query_row(
                &format!(
                    "SELECT {} FROM api_tokens WHERE token_sha256=?1",
                    Self::COLUMNS
                ),
                [sha256_hex(presented.as_bytes())],
                Self::row,
            )
            .optional()
            .map_err(|e| e.to_string())?
            .ok_or("invalid token")?;
        if token.revoked {
            return Err("token revoked".into());
        }
        if token.expires_ms <= now_ms() {
            return Err("token expired".into());
        }
        let _ = self.db.connection().execute(
            "UPDATE api_tokens SET last_used_ms=?2 WHERE id=?1",
            params![token.id, now_ms()],
        );
        Ok(token)
    }
}

#[derive(Debug, Clone, Default)]
pub struct ApiRequest {
    pub method: String,
    pub path: String,
    pub query: BTreeMap<String, String>,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ApiResponse {
    pub status: u16,
    pub body: Value,
}

fn respond(status: u16, body: Value) -> ApiResponse {
    ApiResponse { status, body }
}

fn error(status: u16, message: &str) -> ApiResponse {
    respond(status, json!({"error": message}))
}

#[derive(Deserialize)]
struct CreateRunBody {
    goal: String,
    #[serde(default)]
    research_urls: Vec<String>,
    #[serde(default)]
    search_queries: Vec<String>,
    #[serde(default)]
    cloud_review: bool,
    #[serde(default)]
    ai_planning: bool,
}

/// Request handling, independent of the socket layer (unit-testable).
pub struct ApiHandler {
    platform: Arc<WorkflowPlatform>,
    db_path: PathBuf,
    port: u16,
    rate: Mutex<HashMap<String, (i64, u32)>>,
}

impl ApiHandler {
    pub fn new(platform: Arc<WorkflowPlatform>, db_path: PathBuf, port: u16) -> Self {
        Self {
            platform,
            db_path,
            port,
            rate: Mutex::new(HashMap::new()),
        }
    }

    fn rate_ok(&self, token_id: &str) -> bool {
        let minute = now_ms() / 60_000;
        let mut map = self.rate.lock().expect("rate mutex");
        let entry = map.entry(token_id.to_owned()).or_insert((minute, 0));
        if entry.0 != minute {
            *entry = (minute, 0);
        }
        entry.1 += 1;
        entry.1 <= RATE_PER_MINUTE
    }

    pub fn handle(&self, req: &ApiRequest) -> ApiResponse {
        let host_ok = req.headers.get("host").is_some_and(|h| {
            h == &format!("127.0.0.1:{}", self.port) || h == &format!("localhost:{}", self.port)
        });
        if !host_ok {
            return error(421, "host header must be the loopback API address");
        }
        if req.headers.contains_key("origin") {
            return error(403, "browser-originated requests are not accepted");
        }
        if req.method == "GET" && req.path == "/v1/health" {
            return respond(200, json!({"ok": true, "api": "codetwin-automation/1"}));
        }
        let db = match Database::open_native_worker(&self.db_path) {
            Ok(db) => db,
            Err(e) => return error(503, &format!("database unavailable: {e}")),
        };
        let collab = Collaboration::new(&db);
        let presented = req
            .headers
            .get("authorization")
            .and_then(|h| h.strip_prefix("Bearer "))
            .unwrap_or_default();
        let token = match TokenStore::new(&db).authenticate(presented) {
            Ok(t) => t,
            Err(e) => {
                collab.audit(
                    "api:unauthenticated",
                    "api_request",
                    None,
                    Some(&req.path),
                    "denied",
                    json!({"reason": e}),
                );
                return error(401, &e);
            }
        };
        if !self.rate_ok(&token.id) {
            return error(429, "rate limit exceeded");
        }
        let response = self.route(req, &token, &db);
        collab.audit(
            &token.principal_id,
            "api_request",
            Some(&token.project_id),
            Some(&format!("{} {}", req.method, req.path)),
            if response.status < 400 {
                "allowed"
            } else if response.status < 500 {
                "denied"
            } else {
                "error"
            },
            json!({"status": response.status, "token": token.id}),
        );
        response
    }

    fn route(&self, req: &ApiRequest, token: &ApiToken, db: &Database) -> ApiResponse {
        let segments: Vec<&str> = req.path.trim_matches('/').split('/').collect();
        let need = |scope: &str| -> Option<ApiResponse> {
            (!token.has(scope)).then(|| error(403, &format!("token lacks scope `{scope}`")))
        };
        let run_in_scope = |run_id: &str| -> Result<(), ApiResponse> {
            match self.platform.detail(run_id) {
                Ok(d) if d.run.project_id == token.project_id => Ok(()),
                // Same answer for "other project" and "missing": no oracle.
                _ => Err(error(404, "run not found")),
            }
        };
        let collab = Collaboration::new(db);
        let view = || {
            collab.authorize(
                &token.project_id,
                &token.principal_id,
                crate::collaboration::Action::View,
            )
        };
        match (req.method.as_str(), segments.as_slice()) {
            ("GET", ["v1", "runs"]) => {
                if let Some(r) = need("runs:read") {
                    return r;
                }
                if let Err(e) = view() {
                    return error(403, &e);
                }
                let limit = req
                    .query
                    .get("limit")
                    .and_then(|l| l.parse().ok())
                    .unwrap_or(50usize)
                    .clamp(1, 100);
                match self.platform.list_runs(Some(&token.project_id), limit) {
                    Ok(runs) => respond(200, json!({"runs": runs})),
                    Err(e) => error(500, &e),
                }
            }
            ("POST", ["v1", "runs"]) => {
                if let Some(r) = need("runs:write") {
                    return r;
                }
                if req.body.len() > MAX_BODY_BYTES {
                    return error(413, "body too large");
                }
                let body: CreateRunBody = match serde_json::from_slice(&req.body) {
                    Ok(b) => b,
                    Err(e) => return error(400, &format!("invalid JSON body: {e}")),
                };
                if body.goal.trim().is_empty() || body.goal.chars().count() > 4000 {
                    return error(400, "goal must be 1–4000 characters");
                }
                let options = InvestigationOptions {
                    research_urls: body.research_urls.into_iter().take(5).collect(),
                    search_queries: body.search_queries.into_iter().take(3).collect(),
                    cloud_review: body.cloud_review,
                    ai_planning: body.ai_planning,
                };
                match self.platform.create_planned_investigation(
                    &token.project_id,
                    body.goal.trim(),
                    &token.principal_id,
                    &options,
                    None,
                ) {
                    Ok((run, approvals, plan)) => respond(
                        201,
                        json!({
                        "run": run, "approvals": approvals, "plan": plan,
                        "note": "execution requires a human approval in the CodeTwin desktop"}),
                    ),
                    Err(e) if e.starts_with("access denied") => error(403, &e),
                    Err(e) => error(422, &e),
                }
            }
            ("GET", ["v1", "runs", id]) => {
                if let Some(r) = need("runs:read") {
                    return r;
                }
                if let Err(r) = run_in_scope(id) {
                    return r;
                }
                match self.platform.detail(id) {
                    Ok(d) => respond(200, json!(d)),
                    Err(e) => error(500, &e),
                }
            }
            ("GET", ["v1", "runs", id, "events"]) => {
                if let Some(r) = need("runs:read") {
                    return r;
                }
                if let Err(r) = run_in_scope(id) {
                    return r;
                }
                let cursor = req
                    .query
                    .get("cursor")
                    .and_then(|c| c.parse().ok())
                    .unwrap_or(0i64);
                match self.platform.events_since(id, cursor, 500) {
                    Ok(events) => respond(200, json!({"events": events})),
                    Err(e) => error(500, &e),
                }
            }
            ("GET", ["v1", "runs", id, "report"]) => {
                if let Some(r) = need("reports:read") {
                    return r;
                }
                if let Err(r) = run_in_scope(id) {
                    return r;
                }
                let format = req.query.get("format").map_or("markdown", String::as_str);
                match self.platform.report(id, format) {
                    Ok(body) => respond(200, json!({"format": format, "body": body})),
                    Err(e) => error(422, &e),
                }
            }
            ("POST", ["v1", "runs", id, "cancel"]) => {
                if let Some(r) = need("runs:write") {
                    return r;
                }
                if let Err(r) = run_in_scope(id) {
                    return r;
                }
                if let Err(e) = collab.authorize(
                    &token.project_id,
                    &token.principal_id,
                    crate::collaboration::Action::ControlRun,
                ) {
                    return error(403, &e);
                }
                match self.platform.cancel(id) {
                    Ok(run) => respond(200, json!({"run": run})),
                    Err(e) => error(422, &e),
                }
            }
            ("GET", ["v1", "analytics"]) => {
                if let Some(r) = need("analytics:read") {
                    return r;
                }
                let days: i64 = req
                    .query
                    .get("days")
                    .and_then(|d| d.parse().ok())
                    .unwrap_or(7)
                    .clamp(1, 365);
                match llm_analytics(
                    db,
                    Some(&token.project_id),
                    now_ms() - days * 24 * 3_600_000,
                ) {
                    Ok(a) => respond(200, json!(a)),
                    Err(e) => error(500, &e),
                }
            }
            ("GET", ["v1", "metrics"]) => {
                if let Some(r) = need("analytics:read") {
                    return r;
                }
                match metrics_snapshot(db, Some(&token.project_id)) {
                    Ok(m) => respond(200, json!(m)),
                    Err(e) => error(500, &e),
                }
            }
            (_, ["v1", "approvals", ..]) => {
                error(403, "approvals are only decided by a human in the desktop")
            }
            _ => error(404, "no such endpoint"),
        }
    }
}

fn parse_request(stream: &mut TcpStream) -> Result<ApiRequest, (u16, &'static str)> {
    let mut buf = Vec::with_capacity(2048);
    let mut chunk = [0u8; 2048];
    let head_end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i;
        }
        if buf.len() > MAX_HEADER_BYTES {
            return Err((431, "headers too large"));
        }
        let n = stream.read(&mut chunk).map_err(|_| (408, "read timeout"))?;
        if n == 0 {
            return Err((400, "incomplete request"));
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = std::str::from_utf8(&buf[..head_end]).map_err(|_| (400, "headers are not UTF-8"))?;
    let mut lines = head.split("\r\n");
    let mut first = lines.next().unwrap_or_default().split(' ');
    let (method, target, version) = (
        first.next().unwrap_or_default().to_owned(),
        first.next().unwrap_or_default().to_owned(),
        first.next().unwrap_or_default(),
    );
    if !version.starts_with("HTTP/1.") || !target.starts_with('/') {
        return Err((400, "malformed request line"));
    }
    let mut headers = BTreeMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_owned());
        }
    }
    let length: usize = headers
        .get("content-length")
        .map(|l| l.parse().map_err(|_| (400, "bad content-length")))
        .transpose()?
        .unwrap_or(0);
    if length > MAX_BODY_BYTES {
        return Err((413, "body too large"));
    }
    let mut body = buf[head_end + 4..].to_vec();
    while body.len() < length {
        let n = stream.read(&mut chunk).map_err(|_| (408, "read timeout"))?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(length);
    let url =
        url::Url::parse(&format!("http://loopback{target}")).map_err(|_| (400, "bad target"))?;
    Ok(ApiRequest {
        method,
        path: url.path().to_owned(),
        query: url
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect(),
        headers,
        body,
    })
}

fn write_response(stream: &mut TcpStream, response: &ApiResponse) {
    let body = response.body.to_string();
    let reason = match response.status {
        200 => "OK",
        201 => "Created",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        413 => "Payload Too Large",
        421 => "Misdirected Request",
        422 => "Unprocessable Entity",
        429 => "Too Many Requests",
        503 => "Service Unavailable",
        _ => "Status",
    };
    let _ = write!(
        stream,
        "HTTP/1.1 {} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nCache-Control: no-store\r\n\
         X-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n{body}",
        response.status,
        body.len()
    );
}

/// A running loopback API server.
pub struct ApiServer {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl ApiServer {
    /// Bind 127.0.0.1:`port` (0 picks a free port) and serve until stopped.
    pub fn start(
        platform: Arc<WorkflowPlatform>,
        db_path: PathBuf,
        port: u16,
    ) -> Result<Self, String> {
        let listener = TcpListener::bind(("127.0.0.1", port))
            .map_err(|e| format!("cannot bind loopback port {port}: {e}"))?;
        listener.set_nonblocking(true).map_err(|e| e.to_string())?;
        let addr = listener.local_addr().map_err(|e| e.to_string())?;
        let handler = Arc::new(ApiHandler::new(platform, db_path, addr.port()));
        let stop = Arc::new(AtomicBool::new(false));
        let active = Arc::new(AtomicUsize::new(0));
        let flag = stop.clone();
        let thread = std::thread::spawn(move || {
            while !flag.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, peer)) => {
                        if !peer.ip().is_loopback() {
                            continue;
                        }
                        let _ = stream.set_nonblocking(false);
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                        let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
                        if active.load(Ordering::SeqCst) >= MAX_CONNECTIONS {
                            write_response(
                                &mut stream,
                                &error(503, "too many concurrent requests"),
                            );
                            continue;
                        }
                        active.fetch_add(1, Ordering::SeqCst);
                        let (handler, active) = (handler.clone(), active.clone());
                        std::thread::spawn(move || {
                            let response = match parse_request(&mut stream) {
                                Ok(req) => handler.handle(&req),
                                Err((status, message)) => error(status, message),
                            };
                            write_response(&mut stream, &response);
                            active.fetch_sub(1, Ordering::SeqCst);
                        });
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(25));
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(100)),
                }
            }
        });
        Ok(Self {
            addr,
            stop,
            thread: Some(thread),
        })
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn stop(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

impl Drop for ApiServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}
