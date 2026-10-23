//! Strictly authorized, single-target TCP service inventory with optional HTTPS trust checks.
//! Deliberately excludes CIDR scanning, packet crafting, credential attacks and shell commands.
use crate::Database;
use reqwest::{blocking::Client, redirect::Policy, Url};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::{
    io,
    net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs},
    time::{Duration, Instant},
};

const MAX_PORTS: usize = 16;
const PER_PORT_TIMEOUT: Duration = Duration::from_millis(750);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkAssessmentRequest {
    pub target: String,
    pub ports: Vec<u16>,
    pub authorization_confirmed: bool,
    pub allow_private_networks: bool,
    pub budget_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkProbe {
    pub port: u16,
    pub address: String,
    pub status: String,
    pub elapsed_ms: u64,
    pub tls_status: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkAssessmentRun {
    pub id: String,
    pub target: String,
    pub ports: Vec<u16>,
    pub addresses: Vec<String>,
    pub allow_private_networks: bool,
    pub status: String,
    pub created_at: String,
    pub message: Option<String>,
    pub probes: Vec<NetworkProbe>,
}

pub struct NetworkAssessment<'a> {
    db: &'a Database,
}

impl<'a> NetworkAssessment<'a> {
    pub const fn new(db: &'a Database) -> Self {
        Self { db }
    }

    pub fn prepare(
        &self,
        request: NetworkAssessmentRequest,
    ) -> Result<NetworkAssessmentRun, String> {
        if !request.authorization_confirmed {
            return Err("Confirm ownership or explicit testing permission first".into());
        }
        let target = validate_target(&request.target)?;
        let ports = validate_ports(&request.ports)?;
        if !(1..=60).contains(&request.budget_seconds) {
            return Err("Assessment time budget must be between 1 and 60 seconds".into());
        }
        // Host resolution happens before persistence; every resulting IP must be in scope.
        let addresses = resolve_target(&target, ports[0], request.allow_private_networks)?;
        let id: String = self
            .db
            .connection()
            .query_row(
                "SELECT 'network_' || lower(hex(randomblob(16)))",
                [],
                |row| row.get(0),
            )
            .map_err(err)?;
        self.db.connection().execute(
            "INSERT INTO network_assessment_runs
             (id,target,ports_json,addresses_json,allow_private_networks,authorization_confirmed,budget_seconds,status)
             VALUES (?1,?2,?3,?4,?5,1,?6,'planned')",
            params![
                id, target, serde_json::to_string(&ports).map_err(err)?,
                serde_json::to_string(&addresses).map_err(err)?,
                i64::from(request.allow_private_networks),
                request.budget_seconds as i64,
            ],
        ).map_err(err)?;
        self.get(&id)
    }

    pub fn approve(&self, id: &str) -> Result<NetworkAssessmentRun, String> {
        let changed = self
            .db
            .connection()
            .execute(
                "UPDATE network_assessment_runs SET status='approved'
             WHERE id=?1 AND status='planned'",
                [id],
            )
            .map_err(err)?;
        if changed != 1 {
            return Err("Assessment is missing or no longer awaiting approval".into());
        }
        self.get(id)
    }

    pub fn cancel(&self, id: &str) -> Result<NetworkAssessmentRun, String> {
        let changed = self.db.connection().execute(
            "UPDATE network_assessment_runs
             SET status='cancelled',finished_at=CURRENT_TIMESTAMP,message='Stopped at an assessment boundary'
             WHERE id=?1 AND status IN ('planned','approved','running')", [id],
        ).map_err(err)?;
        if changed != 1 {
            return Err("No cancellable network assessment found".into());
        }
        self.get(id)
    }

    pub fn get(&self, id: &str) -> Result<NetworkAssessmentRun, String> {
        let mut run = self.db.connection().query_row(
            "SELECT id,target,ports_json,addresses_json,allow_private_networks,status,created_at,message
             FROM network_assessment_runs WHERE id=?1", [id], |row| {
                let ports_json: String = row.get(2)?;
                let addresses_json: String = row.get(3)?;
                Ok((
                    row.get::<_,String>(0)?,row.get::<_,String>(1)?,
                    ports_json, addresses_json,row.get::<_,i64>(4)?,
                    row.get::<_,String>(5)?,row.get::<_,String>(6)?,
                    row.get::<_,Option<String>>(7)?,
                ))
            },
        ).optional().map_err(err)?.map(|(id,target,p,a,private,status,created_at,message)| {
            Ok::<_,String>(NetworkAssessmentRun {
                id,target,
                ports:serde_json::from_str(&p).map_err(err)?,
                addresses:serde_json::from_str(&a).map_err(err)?,
                allow_private_networks:private!=0,
                status,created_at,message,probes:Vec::new(),
            })
        }).ok_or("Network assessment not found")??;
        let mut statement = self
            .db
            .connection()
            .prepare(
                "SELECT port,address,status,elapsed_ms,tls_status FROM network_assessment_probes
             WHERE run_id=?1 ORDER BY port",
            )
            .map_err(err)?;
        run.probes = statement
            .query_map([id], |row| {
                Ok(NetworkProbe {
                    port: row.get(0)?,
                    address: row.get(1)?,
                    status: row.get(2)?,
                    elapsed_ms: row.get(3)?,
                    tls_status: row.get(4)?,
                })
            })
            .map_err(err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(err)?;
        Ok(run)
    }

    pub fn list(&self, limit: usize) -> Result<Vec<NetworkAssessmentRun>, String> {
        let mut statement=self.db.connection().prepare(
            "SELECT id FROM network_assessment_runs ORDER BY created_at DESC,rowid DESC LIMIT ?1"
        ).map_err(err)?;
        let ids = statement
            .query_map([limit.clamp(1, 100) as i64], |row| row.get::<_, String>(0))
            .map_err(err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(err)?;
        ids.iter().map(|id| self.get(id)).collect()
    }

    /// Bounded sequential TCP connect checks. All DNS answers must match the approved snapshot.
    /// Failure/cancellation retains partial observations, never reports a clean assessment.
    pub fn execute(&self, id: &str) -> Result<NetworkAssessmentRun, String> {
        let changed = self
            .db
            .connection()
            .execute(
                "UPDATE network_assessment_runs SET status='running',started_at=CURRENT_TIMESTAMP
             WHERE id=?1 AND status='approved'
               AND NOT EXISTS (
                 SELECT 1 FROM network_assessment_runs
                 WHERE status='running'
               )",
                [id],
            )
            .map_err(err)?;
        if changed != 1 {
            return Err("Approve this exact network assessment before starting".into());
        }
        let result = self.execute_inner(id);
        if let Err(ref reason) = result {
            self.db.connection().execute(
                "UPDATE network_assessment_runs SET status='failed',message=?2,finished_at=CURRENT_TIMESTAMP
                 WHERE id=?1 AND status='running'",
                params![id,reason],
            ).map_err(err)?;
        }
        result?;
        self.db.connection().execute(
            "UPDATE network_assessment_runs SET status='completed',finished_at=CURRENT_TIMESTAMP
             WHERE id=?1 AND status='running'", [id],
        ).map_err(err)?;
        self.get(id)
    }

    /// Any interrupted scan must be explicit after an application restart.
    pub fn recover_interrupted(&self) -> Result<usize, String> {
        self.db
            .connection()
            .execute(
                "UPDATE network_assessment_runs
                 SET status='interrupted',finished_at=CURRENT_TIMESTAMP,
                     message='App closed during review; prepare and approve a new assessment'
                 WHERE status='running'",
                [],
            )
            .map_err(err)
    }

    fn execute_inner(&self, id: &str) -> Result<(), String> {
        let run = self.get(id)?;
        let budget_seconds: i64 = self
            .db
            .connection()
            .query_row(
                "SELECT budget_seconds FROM network_assessment_runs WHERE id=?1",
                [id],
                |row| row.get(0),
            )
            .map_err(err)?;
        let deadline = Instant::now();
        let expected = run.addresses;
        for port in run.ports {
            let status: String = self
                .db
                .connection()
                .query_row(
                    "SELECT status FROM network_assessment_runs WHERE id=?1",
                    [id],
                    |row| row.get(0),
                )
                .map_err(err)?;
            if status != "running" {
                return Err("Assessment was cancelled".into());
            }
            if deadline.elapsed() >= Duration::from_secs(budget_seconds as u64) {
                return Err("Network time budget expired; remaining ports were not checked".into());
            }
            let fresh = resolve_target(&run.target, port, run.allow_private_networks)?;
            if fresh != expected {
                return Err(
                    "DNS answer changed after approval; stop and prepare a new review".into(),
                );
            }
            let address: IpAddr = expected[0].parse().map_err(err)?;
            let socket = SocketAddr::new(address, port);
            let started = Instant::now();
            let remaining =
                Duration::from_secs(budget_seconds as u64).saturating_sub(deadline.elapsed());
            let timeout = PER_PORT_TIMEOUT.min(remaining);
            if timeout.is_zero() {
                return Err("Assessment time budget expired".into());
            }
            let connection = TcpStream::connect_timeout(&socket, timeout);
            let (state, tls_status) = match connection {
                Ok(stream) => {
                    drop(stream);
                    let tls = if matches!(port, 443 | 8443) {
                        Some(
                            if tls_trust_check(
                                &run.target,
                                socket,
                                remaining.min(Duration::from_secs(2)),
                            ) {
                                "verified"
                            } else {
                                "not_verified"
                            }
                            .to_string(),
                        )
                    } else {
                        None
                    };
                    ("open", tls)
                }
                Err(error) => (classify_error(&error), None),
            };
            self.db.connection().execute(
                "INSERT INTO network_assessment_probes(run_id,port,address,status,elapsed_ms,tls_status)
                 VALUES(?1,?2,?3,?4,?5,?6)",
                params![id,port,address.to_string(),state,started.elapsed().as_millis() as i64,tls_status],
            ).map_err(err)?;
        }
        Ok(())
    }
}

/// HTTPS peer trust only; this deliberately does not audit cipher strength.
fn tls_trust_check(target: &str, address: SocketAddr, timeout: Duration) -> bool {
    let port = address.port();
    let authority = if target.contains(':') {
        format!("[{target}]")
    } else {
        target.to_owned()
    };
    let url = match Url::parse(&format!("https://{authority}:{port}/")) {
        Ok(url) => url,
        Err(_) => return false,
    };
    let client = match Client::builder()
        .timeout(timeout)
        .redirect(Policy::none())
        .no_proxy()
        .resolve(target, address)
        .build()
    {
        Ok(client) => client,
        Err(_) => return false,
    };
    client.head(url).send().is_ok()
}

fn validate_ports(ports: &[u16]) -> Result<Vec<u16>, String> {
    if ports.is_empty() || ports.len() > MAX_PORTS || ports.contains(&0) {
        return Err("Select 1-16 explicit TCP ports, each between 1 and 65535".into());
    }
    let mut result = ports.to_vec();
    result.sort_unstable();
    result.dedup();
    if result.len() != ports.len() {
        return Err("Duplicate TCP ports are not allowed".into());
    }
    Ok(result)
}
fn validate_target(raw: &str) -> Result<String, String> {
    let target = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if target.is_empty()
        || target.len() > 253
        || target.contains('/')
        || target.contains('\\')
        || target.contains('@')
        || target.contains('%')
        || target.contains(' ')
        || target.contains('?')
        || target.contains('#')
        || target.contains('*')
    {
        return Err("Supply one exact hostname or IP, not a URL, wildcard, range or CIDR".into());
    }
    if target.parse::<IpAddr>().is_ok() {
        return Ok(target);
    }
    if target != "localhost" && !target.contains('.') {
        return Err("Use a fully qualified hostname to avoid DNS search-suffix scope expansion".into());
    }
    if target.contains(':')
        || target.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-')
        })
    {
        return Err("Invalid exact DNS hostname".into());
    }
    Ok(target)
}
fn resolve_target(host: &str, port: u16, allow_private: bool) -> Result<Vec<String>, String> {
    let addresses: Vec<SocketAddr> = (host, port)
        .to_socket_addrs()
        .map_err(|_| "Unable to resolve authorized target".to_string())?
        .collect();
    if addresses.is_empty() {
        return Err("Target has no DNS addresses".into());
    }
    let mut results: Vec<String> = addresses
        .iter()
        .map(|socket| socket.ip().to_string())
        .collect();
    results.sort();
    results.dedup();
    if results.len() > 16 {
        return Err("Too many DNS addresses for bounded assessment".into());
    }
    for address in &results {
        let ip: IpAddr = address.parse().map_err(err)?;
        if !allowed_address(ip, allow_private) {
            return Err(format!(
                "DNS resolved to a blocked or unapproved address: {address}"
            ));
        }
    }
    Ok(results)
}
fn allowed_address(ip: IpAddr, allow_private: bool) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, _, _] = v4.octets();
            let dangerous = v4.is_unspecified()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_documentation()
                || a >= 240
                || a == 0
                || (a == 100 && (64..=127).contains(&b))
                || (a == 198 && (b == 18 || b == 19));
            if dangerous {
                return false;
            }
            let local = v4.is_loopback() || v4.is_private() || v4.is_link_local();
            !local || allow_private
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() {
                return allow_private;
            }
            if let Some(v4) = v6.to_ipv4() {
                return allowed_address(IpAddr::V4(v4), allow_private);
            }
            if v6.is_unspecified() || v6.is_multicast() {
                return false;
            }
            let local = v6.is_loopback() || v6.is_unique_local() || v6.is_unicast_link_local();
            !local || allow_private
        }
    }
}
fn classify_error(e: &io::Error) -> &'static str {
    match e.kind() {
        io::ErrorKind::ConnectionRefused => "closed",
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => "timeout",
        _ => "unreachable",
    }
}
fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    #[test]
    fn rejects_out_of_scope_and_unsafe_targets() {
        assert!(validate_target("127.0.0.1/24").is_err());
        assert!(validate_target("https://example.org").is_err());
        assert!(validate_target("unqualified-host").is_err());
        assert!(validate_target("my-host.example.org").is_ok());
        assert!(validate_target("evil.example.org?x").is_err());
        assert!(!allowed_address("127.0.0.1".parse().unwrap(), false));
        assert!(allowed_address("127.0.0.1".parse().unwrap(), true));
        assert!(allowed_address("::1".parse().unwrap(), true));
        assert!(!allowed_address("::1".parse().unwrap(), false));
        assert!(!allowed_address("224.0.0.1".parse().unwrap(), true));
        assert!(!allowed_address("192.0.2.10".parse().unwrap(), true));
        assert!(validate_ports(&[22, 443, 22]).is_err());
        assert!(validate_ports(&[0]).is_err());
        assert!(validate_ports(&(1..=17).collect::<Vec<_>>()).is_err());
    }

    #[test]
    fn approved_loopback_scan_persists_evidence_without_out_of_scope_requests() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let db = Database::open_in_memory().unwrap();
        let service = NetworkAssessment::new(&db);
        let request = NetworkAssessmentRequest {
            target: "127.0.0.1".into(),
            ports: vec![port],
            authorization_confirmed: true,
            allow_private_networks: true,
            budget_seconds: 10,
        };
        let prepared = service.prepare(request.clone()).unwrap();
        assert_eq!(prepared.status, "planned");
        assert!(service.execute(&prepared.id).is_err());
        let approved = service.approve(&prepared.id).unwrap();
        assert_eq!(approved.status, "approved");
        let result = service.execute(&prepared.id).unwrap();
        assert_eq!(result.status, "completed");
        assert_eq!(result.probes.len(), 1);
        assert_eq!(result.probes[0].status, "open");
        assert_eq!(service.list(10).unwrap().len(), 1);
        assert!(service.execute(&prepared.id).is_err());
        assert!(service
            .prepare(NetworkAssessmentRequest {
                authorization_confirmed: false,
                ..request.clone()
            })
            .is_err());
        assert!(service
            .prepare(NetworkAssessmentRequest {
                allow_private_networks: false,
                ..request
            })
            .is_err());
    }
    #[test]
    fn active_and_interrupted_runs_never_continue_without_fresh_approval() {
        let db = Database::open_in_memory().unwrap();
        let service = NetworkAssessment::new(&db);
        let request = NetworkAssessmentRequest {
            target: "127.0.0.1".into(),
            ports: vec![12345],
            authorization_confirmed: true,
            allow_private_networks: true,
            budget_seconds: 5,
        };
        let first = service.prepare(request.clone()).unwrap();
        service.approve(&first.id).unwrap();
        db.connection().execute(
            "UPDATE network_assessment_runs SET status='running' WHERE id=?1",
            [&first.id],
        ).unwrap();
        let second = service.prepare(request).unwrap();
        service.approve(&second.id).unwrap();
        assert!(service.execute(&second.id).is_err());
        assert_eq!(service.recover_interrupted().unwrap(), 1);
        assert_eq!(service.get(&first.id).unwrap().status, "interrupted");
        assert!(service.execute(&first.id).is_err());
        assert_eq!(service.get(&second.id).unwrap().status, "approved");
    }

    #[test]
    fn cancelled_plan_cannot_dispatch() {
        let db = Database::open_in_memory().unwrap();
        let service = NetworkAssessment::new(&db);
        let run = service
            .prepare(NetworkAssessmentRequest {
                target: "127.0.0.1".into(),
                ports: vec![12345],
                authorization_confirmed: true,
                allow_private_networks: true,
                budget_seconds: 5,
            })
            .unwrap();
        service.cancel(&run.id).unwrap();
        assert!(service.approve(&run.id).is_err());
        assert!(service.execute(&run.id).is_err());
    }
}
