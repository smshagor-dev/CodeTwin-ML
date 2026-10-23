//! Audited, durable evidence for strictly scoped private-network inspections.
use crate::{
    network_inspection::{NetworkInspection, NetworkScope},
    Database,
};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInspectionRecord {
    pub id: i64,
    pub target_ip: String,
    pub scope_sha256: String,
    pub status: String,
    pub ports_requested: usize,
    pub ports_tested: usize,
    pub result_sha256: Option<String>,
    pub failure_code: Option<String>,
    pub started_at: String,
    pub finished_at: Option<String>,
    pub inspection: Option<NetworkInspection>,
}

pub struct NetworkInspectionStore<'a> {
    db: &'a Database,
}

impl<'a> NetworkInspectionStore<'a> {
    pub const fn new(db: &'a Database) -> Self {
        Self { db }
    }

    pub fn recover_interrupted(&self) -> Result<usize, String> {
        self.db
            .connection()
            .execute(
                "UPDATE network_inspection_runs SET status='interrupted', \
             failure_code='application_restarted', finished_at=CURRENT_TIMESTAMP \
             WHERE status='running'",
                [],
            )
            .map_err(err)
    }

    pub fn begin(&self, scope: &NetworkScope) -> Result<i64, String> {
        let ports = scope.validate()?;
        let serialized = serde_json::to_vec(scope).map_err(err)?;
        let scope_sha = format!("{:x}", Sha256::digest(&serialized));
        self.db
            .connection()
            .execute(
                "INSERT INTO network_inspection_runs(target_ip,scope_sha256,ports_requested) \
             VALUES (?1,?2,?3)",
                params![scope.target.to_string(), scope_sha, ports.len()],
            )
            .map_err(err)?;
        Ok(self.db.connection().last_insert_rowid())
    }

    pub fn finish(
        &self,
        id: i64,
        scope: &NetworkScope,
        outcome: &Result<NetworkInspection, String>,
    ) -> Result<(), String> {
        let scope_sha = format!("{:x}", Sha256::digest(serde_json::to_vec(scope).map_err(err)?));
        let (stored_scope, stored_target): (String, String) = self.db.connection()
            .query_row(
                "SELECT scope_sha256,target_ip FROM network_inspection_runs WHERE id=?1 AND status='running'",
                [id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(err)?;
        if stored_scope != scope_sha || stored_target != scope.target.to_string() {
            return Err("Approved network scope changed before recording evidence".into());
        }
        let changed = match outcome {
            Ok(inspection) => {
                let ports = scope.validate()?;
                if inspection.target != scope.target
                    || inspection.tested_ports != ports.len()
                    || inspection.observations.len() != ports.len()
                    || inspection
                        .observations
                        .iter()
                        .map(|item| item.port)
                        .collect::<Vec<_>>()
                        != ports
                    || inspection.observations.iter().any(|item| {
                        !matches!(item.state.as_str(), "open" | "closed" | "unreachable")
                    })
                {
                    return Err("Inspection results did not match the authorized scope".into());
                }
                let serialized = serde_json::to_string(inspection).map_err(err)?;
                let sha = format!("{:x}", Sha256::digest(serialized.as_bytes()));
                self.db
                    .connection()
                    .execute(
                        "UPDATE network_inspection_runs SET status='completed', \
                     result_json=?2,result_sha256=?3,ports_tested=?4, \
                     finished_at=CURRENT_TIMESTAMP WHERE id=?1 AND status='running'",
                        params![id, serialized, sha, inspection.tested_ports],
                    )
                    .map_err(err)?
            }
            Err(_) => self
                .db
                .connection()
                .execute(
                    "UPDATE network_inspection_runs SET status='failed', \
                 failure_code='inspection_failed',finished_at=CURRENT_TIMESTAMP \
                 WHERE id=?1 AND status='running'",
                    [id],
                )
                .map_err(err)?,
        };
        if changed != 1 {
            return Err("Inspection record missing or already finalized".into());
        }
        Ok(())
    }

    pub fn list(&self, max_results: usize) -> Result<Vec<NetworkInspectionRecord>, String> {
        let mut stmt = self
            .db
            .connection()
            .prepare(
                "SELECT id,target_ip,scope_sha256,status,ports_requested,ports_tested, \
             result_json,result_sha256,failure_code,started_at,finished_at \
             FROM network_inspection_runs ORDER BY id DESC LIMIT ?1",
            )
            .map_err(err)?;
        let records = stmt
            .query_map([max_results.clamp(1, 50)], |row| {
                let raw: Option<String> = row.get(6)?;
                let expected_hash: Option<String> = row.get(7)?;
                let decoded = match (&raw, &expected_hash) {
                    (Some(body), Some(hash)) => {
                        let actual = format!("{:x}", Sha256::digest(body.as_bytes()));
                        if actual != *hash {
                            return Err(rusqlite::Error::InvalidQuery);
                        }
                        let result = serde_json::from_str::<NetworkInspection>(body)
                            .map_err(|_| rusqlite::Error::InvalidQuery)?;
                        Some(result)
                    }
                    (None, None) => None,
                    _ => return Err(rusqlite::Error::InvalidQuery),
                };
                let record = NetworkInspectionRecord {
                    id: row.get(0)?,
                    target_ip: row.get(1)?,
                    scope_sha256: row.get(2)?,
                    status: row.get(3)?,
                    ports_requested: row.get(4)?,
                    ports_tested: row.get(5)?,
                    result_sha256: expected_hash,
                    failure_code: row.get(8)?,
                    started_at: row.get(9)?,
                    finished_at: row.get(10)?,
                    inspection: decoded,
                };
                if let Some(result) = &record.inspection {
                    if result.target.to_string() != record.target_ip
                        || result.tested_ports != record.ports_tested
                        || record.status != "completed"
                    {
                        return Err(rusqlite::Error::InvalidQuery);
                    }
                }
                Ok(record)
            })
            .map_err(err)?;
        records.collect::<Result<Vec<_>, _>>().map_err(err)
    }

}

fn err(error: impl std::fmt::Display) -> String {
    error.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network_inspection::inspect_tcp;
    use std::net::{IpAddr, Ipv4Addr, TcpListener};

    #[test]
    fn records_real_loopback_scan_and_detects_modified_evidence() {
        let db = Database::open_in_memory().unwrap();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let address = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let scope = NetworkScope {
            authorized: true,
            target: address,
            allowed_addresses: vec![address],
            ports: vec![port],
            timeout_ms: 500,
        };
        let store = NetworkInspectionStore::new(&db);
        let id = store.begin(&scope).unwrap();
        assert_eq!(store.list(10).unwrap()[0].status, "running");
        store.finish(id, &scope, &inspect_tcp(&scope)).unwrap();
        let result = store.list(10).unwrap();
        assert_eq!(result[0].status, "completed");
        assert_eq!(
            result[0].inspection.as_ref().unwrap().observations[0].state,
            "open"
        );
        assert!(store.finish(id, &scope, &inspect_tcp(&scope)).is_err());
        db.connection()
            .execute(
                "UPDATE network_inspection_runs SET result_json='{}' WHERE id=?1",
                [id],
            )
            .unwrap();
        assert!(store.list(10).is_err());
    }

    #[test]
    fn audit_records_failures_and_interrupted_workers() {
        let db = Database::open_in_memory().unwrap();
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let scope = NetworkScope {
            authorized: true,
            target: ip,
            allowed_addresses: vec![ip],
            ports: vec![8043],
            timeout_ms: 500,
        };
        let store = NetworkInspectionStore::new(&db);
        let id = store.begin(&scope).unwrap();
        let failed: Result<NetworkInspection, String> = Err("unavailable".into());
        store.finish(id, &scope, &failed).unwrap();
        assert_eq!(
            store.list(10).unwrap()[0].failure_code.as_deref(),
            Some("inspection_failed")
        );
        store.begin(&scope).unwrap();
        assert_eq!(store.recover_interrupted().unwrap(), 1);
        let rows = store.list(10).unwrap();
        assert_eq!(rows[0].status, "interrupted");
    }
}
