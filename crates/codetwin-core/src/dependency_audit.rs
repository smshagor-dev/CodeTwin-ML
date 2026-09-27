//! Dependency vulnerability auditing: lockfile inventory matched against OSV advisories.
//!
//! Advisory data comes from an explicit source. The online source sends only package
//! ecosystem, name and version to the OSV API; the offline source reads a local directory
//! of OSV JSON records (for example an extracted `all.zip` export) and never uses the
//! network.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use dependency_audit::{
    affects, manifest_kind, parse_manifest, summarize, Advisory, Dependency, Ecosystem, MatchBasis,
    OsvClient,
};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use thiserror::Error;
use walkdir::{DirEntry, WalkDir};

use crate::{deterministic_id, normalize_relative_path, AnalysisStatus, Database};

const ANALYZER_KEY: &str = "dependency_audit";
const MAX_MANIFESTS: usize = 2_000;
const MAX_MANIFEST_BYTES: u64 = 64 * 1024 * 1024;
const MAX_DEPTH: usize = 16;
const MAX_OFFLINE_RECORDS: usize = 500_000;
const MAX_OFFLINE_RECORD_BYTES: u64 = 4 * 1024 * 1024;
const MAX_QUERY: usize = 5_000;

#[derive(Debug, Error)]
pub enum DependencyAuditError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("project not found: {0}")]
    ProjectNotFound(String),
    #[error("project root is not a directory: {0}")]
    InvalidProjectRoot(String),
    #[error("offline OSV directory is not readable: {0}")]
    InvalidAdvisoryDirectory(String),
    #[error("advisory lookup failed: {0}")]
    AdvisorySource(String),
}

/// Where advisory data comes from. Callers choose explicitly; there is no silent default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AdvisorySource {
    /// Query the OSV API (sends package ecosystem, name and version only).
    OsvApi { base_url: String },
    /// Match against local OSV JSON records; no network access.
    OfflineDirectory { path: PathBuf },
}

impl AdvisorySource {
    fn label(&self) -> String {
        match self {
            Self::OsvApi { base_url } => format!("osv_api:{base_url}"),
            Self::OfflineDirectory { .. } => "offline_osv_directory".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencyAuditSummary {
    pub project_id: String,
    pub run_id: String,
    pub status: AnalysisStatus,
    pub coverage_complete: bool,
    pub advisory_source: String,
    pub manifests: usize,
    pub manifest_errors: Vec<String>,
    pub packages: usize,
    pub unpinned_requirements: usize,
    pub vulnerable_packages: usize,
    pub observations: usize,
    pub findings_opened: usize,
    pub findings_refreshed: usize,
    pub findings_resolved: usize,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DependencyFindingRecord {
    pub id: String,
    pub advisory_id: String,
    pub display_id: String,
    pub aliases: Vec<String>,
    pub severity: String,
    pub cvss_score: Option<f64>,
    pub confidence: f64,
    pub title: String,
    pub description: String,
    pub ecosystem: String,
    pub package: String,
    pub version: String,
    pub manifest_path: String,
    pub line: Option<usize>,
    pub fixed_versions: Vec<String>,
    pub references: Vec<String>,
    pub is_dev: bool,
    pub match_basis: String,
    pub status: String,
    pub first_seen: String,
    pub last_seen: String,
    pub resolved_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencyRecord {
    pub ecosystem: String,
    pub name: String,
    pub version: String,
    pub manifest_path: String,
    pub is_dev: bool,
    pub open_advisories: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencyAuditRunRecord {
    pub run_id: String,
    pub status: String,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub duration_ms: Option<u64>,
    pub coverage_complete: bool,
    pub advisory_source: String,
    pub packages: usize,
    pub vulnerable_packages: usize,
    pub findings_opened: usize,
    pub findings_resolved: usize,
}

struct InventoryEntry {
    manifest_path: String,
    dependency: Dependency,
}

struct Inventory {
    entries: Vec<InventoryEntry>,
    manifests: usize,
    errors: Vec<String>,
    unpinned: usize,
    complete: bool,
}

struct Observation {
    fingerprint: String,
    entry_index: usize,
    advisory: Advisory,
    basis: MatchBasis,
}

pub struct DependencyAuditService<'a> {
    database: &'a Database,
}

impl<'a> DependencyAuditService<'a> {
    pub const fn new(database: &'a Database) -> Self {
        Self { database }
    }

    pub fn audit_project(
        &self,
        project_id: &str,
        source: &AdvisorySource,
    ) -> Result<DependencyAuditSummary, DependencyAuditError> {
        let connection = self.database.connection();
        let root = fs::canonicalize(project_root(connection, project_id)?)?;
        if !root.is_dir() {
            return Err(DependencyAuditError::InvalidProjectRoot(
                root.display().to_string(),
            ));
        }
        if let AdvisorySource::OfflineDirectory { path } = source {
            if !path.is_dir() {
                return Err(DependencyAuditError::InvalidAdvisoryDirectory(
                    path.display().to_string(),
                ));
            }
        }
        let started = Instant::now();
        let run_id = new_run_id(project_id);
        let configuration_json = json!({
            "analyzer_version": dependency_audit::ANALYZER_VERSION,
            "advisory_source": source.label(),
            "network_used": matches!(source, AdvisorySource::OsvApi { .. }),
            "data_sent": if matches!(source, AdvisorySource::OsvApi { .. }) {
                "package ecosystem, name and version only"
            } else {
                "none"
            },
            "repository_commands_executed": false,
        })
        .to_string();
        connection.execute(
            "INSERT INTO analysis_runs(id, project_id, status, analyzer_version, started_at, configuration_json, run_kind) \
             VALUES (?1, ?2, 'running', ?3, CURRENT_TIMESTAMP, ?4, 'dependency_audit')",
            params![run_id, project_id, dependency_audit::ANALYZER_VERSION, configuration_json],
        )?;

        let result = collect_inventory(&root).and_then(|inventory| {
            let (observations, advisory_complete) =
                match_advisories(connection, &inventory, source)?;
            persist(
                connection,
                project_id,
                &run_id,
                source,
                inventory,
                observations,
                advisory_complete,
                elapsed_ms(started),
            )
        });
        result.inspect_err(|_| {
            let _ = finish_run(
                connection,
                &run_id,
                AnalysisStatus::Failed,
                elapsed_ms(started),
            );
        })
    }

    pub fn list_findings(
        &self,
        project_id: &str,
        status: Option<&str>,
        limit: usize,
    ) -> Result<Vec<DependencyFindingRecord>, DependencyAuditError> {
        let mut statement = self.database.connection().prepare(
            "SELECT f.id, f.severity, COALESCE(f.confidence, 0), f.title, f.description, \
                    COALESCE(e.uri, ''), e.line_start, COALESCE(e.metadata_json, '{}'), f.status, \
                    f.first_seen, f.last_seen, f.resolved_at \
             FROM findings f LEFT JOIN finding_evidence e ON e.finding_id = f.id \
             WHERE f.project_id = ?1 AND f.analyzer_key = ?2 AND (?3 IS NULL OR f.status = ?3) \
             ORDER BY f.status = 'open' DESC, \
                      CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, \
                      f.last_seen DESC \
             LIMIT ?4",
        )?;
        let rows = statement.query_map(
            params![project_id, ANALYZER_KEY, status, bounded(limit)],
            |row| {
                let metadata: Value =
                    serde_json::from_str(&row.get::<_, String>(7)?).unwrap_or_default();
                let strings = |key: &str| -> Vec<String> {
                    metadata[key]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(Value::as_str)
                        .map(ToString::to_string)
                        .collect()
                };
                let text = |key: &str| metadata[key].as_str().unwrap_or_default().to_string();
                Ok(DependencyFindingRecord {
                    id: row.get(0)?,
                    advisory_id: text("advisory_id"),
                    display_id: text("display_id"),
                    aliases: strings("aliases"),
                    severity: row.get(1)?,
                    cvss_score: metadata["cvss_score"].as_f64(),
                    confidence: row.get(2)?,
                    title: row.get(3)?,
                    description: row.get(4)?,
                    ecosystem: text("ecosystem"),
                    package: text("package"),
                    version: text("version"),
                    manifest_path: row.get(5)?,
                    line: row.get::<_, Option<i64>>(6)?.map(to_usize),
                    fixed_versions: strings("fixed_versions"),
                    references: strings("references"),
                    is_dev: metadata["is_dev"].as_bool().unwrap_or(false),
                    match_basis: text("match_basis"),
                    status: row.get(8)?,
                    first_seen: row.get(9)?,
                    last_seen: row.get(10)?,
                    resolved_at: row.get(11)?,
                })
            },
        )?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn list_inventory(
        &self,
        project_id: &str,
        limit: usize,
    ) -> Result<Vec<DependencyRecord>, DependencyAuditError> {
        let mut statement = self.database.connection().prepare(
            "SELECT d.ecosystem, d.name, d.version, d.manifest_path, d.is_dev, \
                    (SELECT COUNT(*) FROM findings f JOIN finding_evidence e ON e.finding_id = f.id \
                     WHERE f.project_id = d.project_id AND f.analyzer_key = ?2 AND f.status = 'open' \
                       AND e.uri = d.manifest_path \
                       AND json_extract(e.metadata_json, '$.package') = d.name \
                       AND json_extract(e.metadata_json, '$.version') = d.version) AS open_advisories \
             FROM dependency_inventory d \
             WHERE d.project_id = ?1 AND d.is_active = 1 \
             ORDER BY open_advisories DESC, d.ecosystem, d.name, d.version LIMIT ?3",
        )?;
        let rows =
            statement.query_map(params![project_id, ANALYZER_KEY, bounded(limit)], |row| {
                Ok(DependencyRecord {
                    ecosystem: row.get(0)?,
                    name: row.get(1)?,
                    version: row.get(2)?,
                    manifest_path: row.get(3)?,
                    is_dev: row.get::<_, i64>(4)? == 1,
                    open_advisories: to_usize(row.get(5)?),
                })
            })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn history(
        &self,
        project_id: &str,
        limit: usize,
    ) -> Result<Vec<DependencyAuditRunRecord>, DependencyAuditError> {
        let mut statement = self.database.connection().prepare(
            "SELECT r.id, r.status, r.started_at, r.finished_at, r.duration_ms, \
                    COALESCE(m.coverage_complete, 0), COALESCE(m.advisory_source, ''), \
                    COALESCE(m.packages, 0), COALESCE(m.vulnerable_packages, 0), \
                    COALESCE(m.findings_opened, 0), COALESCE(m.findings_resolved, 0) \
             FROM analysis_runs r LEFT JOIN dependency_audit_run_metrics m ON m.run_id = r.id \
             WHERE r.project_id = ?1 AND r.run_kind = 'dependency_audit' \
             ORDER BY r.started_at DESC, r.rowid DESC LIMIT ?2",
        )?;
        let rows = statement.query_map(params![project_id, bounded(limit.min(100))], |row| {
            Ok(DependencyAuditRunRecord {
                run_id: row.get(0)?,
                status: row.get(1)?,
                started_at: row.get(2)?,
                finished_at: row.get(3)?,
                duration_ms: row
                    .get::<_, Option<i64>>(4)?
                    .map(|value| value.max(0) as u64),
                coverage_complete: row.get::<_, i64>(5)? == 1,
                advisory_source: row.get(6)?,
                packages: to_usize(row.get(7)?),
                vulnerable_packages: to_usize(row.get(8)?),
                findings_opened: to_usize(row.get(9)?),
                findings_resolved: to_usize(row.get(10)?),
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }
}

fn collect_inventory(root: &Path) -> Result<Inventory, DependencyAuditError> {
    let mut inventory = Inventory {
        entries: Vec::new(),
        manifests: 0,
        errors: Vec::new(),
        unpinned: 0,
        complete: true,
    };
    let walker = WalkDir::new(root)
        .follow_links(false)
        .max_depth(MAX_DEPTH)
        .into_iter()
        .filter_entry(|entry| !should_skip(entry));
    for entry in walker {
        let Ok(entry) = entry else {
            inventory.complete = false;
            continue;
        };
        if !entry.file_type().is_file() {
            continue;
        }
        let Some(kind) = entry.file_name().to_str().and_then(manifest_kind) else {
            continue;
        };
        let Some(relative_path) = entry
            .path()
            .strip_prefix(root)
            .ok()
            .and_then(|path| path.to_str())
            .and_then(|path| normalize_relative_path(path, false))
        else {
            continue;
        };
        inventory.manifests += 1;
        if inventory.manifests > MAX_MANIFESTS {
            inventory.complete = false;
            break;
        }
        let text = match entry.metadata() {
            Ok(metadata) if metadata.len() <= MAX_MANIFEST_BYTES => {
                fs::read_to_string(entry.path())
            }
            Ok(_) => Err(std::io::Error::other("manifest exceeds the size limit")),
            Err(error) => Err(error.into()),
        };
        let parsed = text
            .map_err(|error| error.to_string())
            .and_then(|text| parse_manifest(kind, &text));
        match parsed {
            Ok(parsed) => {
                inventory.unpinned += parsed.unpinned;
                inventory
                    .entries
                    .extend(
                        parsed
                            .dependencies
                            .into_iter()
                            .map(|dependency| InventoryEntry {
                                manifest_path: relative_path.clone(),
                                dependency,
                            }),
                    );
            }
            Err(error) => {
                // A manifest we could not read means absence of findings is unproven.
                inventory.complete = false;
                inventory.errors.push(format!("{relative_path}: {error}"));
            }
        }
    }
    Ok(inventory)
}

type PackageKey = (Ecosystem, String, String);

fn package_key(dependency: &Dependency) -> PackageKey {
    (
        dependency.ecosystem,
        dependency.ecosystem.normalize_name(&dependency.name),
        dependency.version.clone(),
    )
}

/// Returns advisories per package key and whether the advisory lookup was complete.
fn match_advisories(
    connection: &Connection,
    inventory: &Inventory,
    source: &AdvisorySource,
) -> Result<(Vec<Observation>, bool), DependencyAuditError> {
    let mut unique: BTreeMap<PackageKey, &Dependency> = BTreeMap::new();
    for entry in &inventory.entries {
        unique
            .entry(package_key(&entry.dependency))
            .or_insert(&entry.dependency);
    }
    let mut matched: BTreeMap<PackageKey, Vec<(Value, MatchBasis)>> = BTreeMap::new();
    let mut complete = true;

    match source {
        AdvisorySource::OsvApi { base_url } => {
            let client = OsvClient::new(base_url)
                .map_err(|error| DependencyAuditError::AdvisorySource(error.to_string()))?;
            let keys: Vec<PackageKey> = unique.keys().cloned().collect();
            let dependencies: Vec<Dependency> = unique.values().map(|&dep| dep.clone()).collect();
            let ids = client
                .query_batch(&dependencies)
                .map_err(|error| DependencyAuditError::AdvisorySource(error.to_string()))?;
            let mut records: BTreeMap<String, Value> = BTreeMap::new();
            for id in ids.iter().flatten() {
                if records.contains_key(id) {
                    continue;
                }
                match client.vulnerability(id) {
                    Ok(record) => {
                        cache_record(connection, id, &record)?;
                        records.insert(id.clone(), record);
                    }
                    Err(_) => match cached_record(connection, id)? {
                        Some(record) => {
                            records.insert(id.clone(), record);
                        }
                        None => complete = false,
                    },
                }
            }
            for (key, ids) in keys.into_iter().zip(ids) {
                let found = ids
                    .iter()
                    .filter_map(|id| records.get(id))
                    .map(|record| (record.clone(), MatchBasis::OsvApi))
                    .collect::<Vec<_>>();
                if !found.is_empty() {
                    matched.insert(key, found);
                }
            }
        }
        AdvisorySource::OfflineDirectory { path } => {
            let wanted: BTreeSet<(Ecosystem, String)> = unique
                .keys()
                .map(|(ecosystem, name, _)| (*ecosystem, name.clone()))
                .collect();
            let (records, offline_complete) = load_offline_records(path, &wanted);
            complete &= offline_complete;
            for (key, dependency) in &unique {
                let found: Vec<(Value, MatchBasis)> = records
                    .get(&(key.0, key.1.clone()))
                    .into_iter()
                    .flatten()
                    .filter_map(|record| {
                        affects(record, dependency).map(|basis| (record.clone(), basis))
                    })
                    .collect();
                if !found.is_empty() {
                    matched.insert(key.clone(), found);
                }
            }
        }
    }

    let mut observations = Vec::new();
    for (entry_index, entry) in inventory.entries.iter().enumerate() {
        let Some(records) = matched.get(&package_key(&entry.dependency)) else {
            continue;
        };
        for (record, basis) in records {
            let Some(advisory) = summarize(record, &entry.dependency) else {
                continue;
            };
            let fingerprint = deterministic_id(
                "dependency-finding",
                &[
                    entry.dependency.ecosystem.osv_name(),
                    &entry
                        .dependency
                        .ecosystem
                        .normalize_name(&entry.dependency.name),
                    &entry.dependency.version,
                    &entry.manifest_path,
                    &advisory.id,
                ],
            );
            observations.push(Observation {
                fingerprint,
                entry_index,
                advisory,
                basis: *basis,
            });
        }
    }
    Ok((observations, complete))
}

/// Loads OSV records whose affected packages appear in the inventory.
fn load_offline_records(
    path: &Path,
    wanted: &BTreeSet<(Ecosystem, String)>,
) -> (BTreeMap<(Ecosystem, String), Vec<Value>>, bool) {
    let mut records: BTreeMap<(Ecosystem, String), Vec<Value>> = BTreeMap::new();
    let mut complete = true;
    let mut seen = 0usize;
    for entry in WalkDir::new(path).follow_links(false).max_depth(4) {
        let Ok(entry) = entry else {
            complete = false;
            continue;
        };
        if !entry.file_type().is_file()
            || entry.path().extension().and_then(|value| value.to_str()) != Some("json")
        {
            continue;
        }
        seen += 1;
        if seen > MAX_OFFLINE_RECORDS {
            complete = false;
            break;
        }
        let record: Option<Value> = entry
            .metadata()
            .ok()
            .filter(|metadata| metadata.len() <= MAX_OFFLINE_RECORD_BYTES)
            .and_then(|_| fs::read(entry.path()).ok())
            .and_then(|bytes| serde_json::from_slice(&bytes).ok());
        let Some(record) = record else {
            complete = false;
            continue;
        };
        let mut keys = BTreeSet::new();
        for affected in record
            .get("affected")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let ecosystem = affected
                .pointer("/package/ecosystem")
                .and_then(Value::as_str)
                .and_then(Ecosystem::from_osv_name);
            let name = affected.pointer("/package/name").and_then(Value::as_str);
            if let (Some(ecosystem), Some(name)) = (ecosystem, name) {
                let key = (ecosystem, ecosystem.normalize_name(name));
                if wanted.contains(&key) {
                    keys.insert(key);
                }
            }
        }
        for key in keys {
            records.entry(key).or_default().push(record.clone());
        }
    }
    (records, complete)
}

fn cache_record(connection: &Connection, id: &str, record: &Value) -> Result<(), rusqlite::Error> {
    connection.execute(
        "INSERT INTO osv_advisories(id, modified, record_json, fetched_at) VALUES (?1, ?2, ?3, CURRENT_TIMESTAMP) \
         ON CONFLICT(id) DO UPDATE SET modified = excluded.modified, record_json = excluded.record_json, \
         fetched_at = CURRENT_TIMESTAMP",
        params![id, record.get("modified").and_then(Value::as_str), record.to_string()],
    )?;
    Ok(())
}

fn cached_record(connection: &Connection, id: &str) -> Result<Option<Value>, rusqlite::Error> {
    Ok(connection
        .query_row(
            "SELECT record_json FROM osv_advisories WHERE id = ?1",
            [id],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .and_then(|json| serde_json::from_str(&json).ok()))
}

#[allow(clippy::too_many_arguments)]
fn persist(
    connection: &Connection,
    project_id: &str,
    run_id: &str,
    source: &AdvisorySource,
    inventory: Inventory,
    observations: Vec<Observation>,
    advisory_complete: bool,
    duration_ms: u64,
) -> Result<DependencyAuditSummary, DependencyAuditError> {
    let coverage_complete = inventory.complete && advisory_complete;
    let existing = existing_findings(connection, project_id)?;
    let observed: BTreeSet<&str> = observations
        .iter()
        .map(|item| item.fingerprint.as_str())
        .collect();
    let findings_opened = observations
        .iter()
        .filter(|item| !existing.contains_key(item.fingerprint.as_str()))
        .count();
    let findings_refreshed = observations.len() - findings_opened;
    let findings_resolved = if coverage_complete {
        existing
            .iter()
            .filter(|(fingerprint, (_, status))| {
                status == "open" && !observed.contains(fingerprint.as_str())
            })
            .count()
    } else {
        0
    };
    let vulnerable_packages = observations
        .iter()
        .map(|item| package_key(&inventory.entries[item.entry_index].dependency))
        .collect::<BTreeSet<_>>()
        .len();

    let transaction = connection.unchecked_transaction()?;
    let mut active_ids = BTreeSet::new();
    for entry in &inventory.entries {
        let dependency = &entry.dependency;
        let id = deterministic_id(
            "dependency",
            &[
                project_id,
                dependency.ecosystem.osv_name(),
                &dependency.name,
                &dependency.version,
                &entry.manifest_path,
            ],
        );
        transaction.execute(
            "INSERT INTO dependency_inventory(id, project_id, ecosystem, name, version, manifest_path, is_dev, last_run_id, is_active) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1) \
             ON CONFLICT(project_id, ecosystem, name, version, manifest_path) DO UPDATE SET \
               is_dev = excluded.is_dev, last_run_id = excluded.last_run_id, last_seen_at = CURRENT_TIMESTAMP, is_active = 1",
            params![
                id,
                project_id,
                dependency.ecosystem.osv_name(),
                dependency.name,
                dependency.version,
                entry.manifest_path,
                i64::from(dependency.is_dev),
                run_id,
            ],
        )?;
        active_ids.insert(id);
    }
    if inventory.complete {
        let stale: Vec<String> = {
            let mut statement = transaction.prepare(
                "SELECT id FROM dependency_inventory WHERE project_id = ?1 AND is_active = 1",
            )?;
            let ids = statement
                .query_map([project_id], |row| row.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?;
            ids.into_iter()
                .filter(|id| !active_ids.contains(id))
                .collect()
        };
        for id in stale {
            transaction.execute(
                "UPDATE dependency_inventory SET is_active = 0, last_run_id = ?2 WHERE id = ?1",
                params![id, run_id],
            )?;
        }
    }
    if coverage_complete {
        transaction.execute(
            "UPDATE findings SET status = 'resolved', resolved_at = CURRENT_TIMESTAMP, last_run_id = ?2 \
             WHERE project_id = ?1 AND analyzer_key = ?3 AND status = 'open'",
            params![project_id, run_id, ANALYZER_KEY],
        )?;
    }
    for item in &observations {
        let entry = &inventory.entries[item.entry_index];
        let dependency = &entry.dependency;
        let advisory = &item.advisory;
        let finding_id = existing.get(item.fingerprint.as_str()).map_or_else(
            || deterministic_id("finding", &[project_id, ANALYZER_KEY, &item.fingerprint]),
            |(id, _)| id.clone(),
        );
        let display_id = advisory.display_id().to_string();
        let title = format!(
            "{}@{} is affected by {display_id}",
            dependency.name, dependency.version
        );
        let fix = if advisory.fixed_versions.is_empty() {
            "No fixed version is published yet; consider an alternative package or a mitigation."
                .to_string()
        } else {
            format!(
                "Upgrade to a fixed version: {}.",
                advisory.fixed_versions.join(", ")
            )
        };
        let description = format!(
            "{} ({} package{}, declared in {}). {fix}",
            advisory.summary,
            dependency.ecosystem.osv_name(),
            if dependency.is_dev {
                ", development only"
            } else {
                ""
            },
            entry.manifest_path,
        );
        transaction.execute(
            "INSERT INTO findings( \
               id, project_id, run_id, category, sub_category, severity, confidence, title, description, \
               file_id, symbol_id, source_start_line, source_end_line, cwe, owasp, status, fingerprint, \
               rule_version, first_seen, last_seen, analyzer_key, last_run_id, resolved_at \
             ) VALUES (?1, ?2, ?3, 'dependency', 'dependency.vulnerable_package', ?4, ?5, ?6, ?7, \
                       (SELECT id FROM files WHERE project_id = ?2 AND relative_path = ?8), NULL, ?9, ?9, ?10, \
                       'A06:2021 Vulnerable and Outdated Components', 'open', ?11, ?12, \
                       CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, ?13, ?3, NULL) \
             ON CONFLICT(project_id, fingerprint) DO UPDATE SET \
               run_id = excluded.run_id, severity = excluded.severity, confidence = excluded.confidence, \
               title = excluded.title, description = excluded.description, cwe = excluded.cwe, \
               source_start_line = excluded.source_start_line, source_end_line = excluded.source_end_line, \
               status = 'open', rule_version = excluded.rule_version, last_seen = CURRENT_TIMESTAMP, \
               last_run_id = excluded.last_run_id, resolved_at = NULL",
            params![
                finding_id,
                project_id,
                run_id,
                advisory.severity,
                item.basis.confidence(),
                title,
                description,
                entry.manifest_path,
                dependency.line.map(|line| i64::try_from(line).unwrap_or(i64::MAX)),
                advisory.cwe,
                item.fingerprint,
                dependency_audit::ANALYZER_VERSION,
                ANALYZER_KEY,
            ],
        )?;
        transaction.execute(
            "DELETE FROM finding_evidence WHERE finding_id = ?1",
            [&finding_id],
        )?;
        transaction.execute(
            "INSERT INTO finding_evidence(id, finding_id, evidence_type, uri, line_start, line_end, summary, metadata_json) \
             VALUES (?1, ?2, 'dependency_advisory', ?3, ?4, ?4, ?5, ?6)",
            params![
                deterministic_id("dependency-evidence", &[&finding_id]),
                finding_id,
                entry.manifest_path,
                dependency.line.map(|line| i64::try_from(line).unwrap_or(i64::MAX)),
                format!("{}@{} matched {} ({})", dependency.name, dependency.version, advisory.id, item.basis.as_str()),
                json!({
                    "ecosystem": dependency.ecosystem.osv_name(),
                    "package": dependency.name,
                    "version": dependency.version,
                    "is_dev": dependency.is_dev,
                    "advisory_id": advisory.id,
                    "display_id": display_id,
                    "aliases": advisory.aliases,
                    "cvss_score": advisory.cvss_score,
                    "fixed_versions": advisory.fixed_versions,
                    "references": advisory.references,
                    "advisory_modified": advisory.modified,
                    "match_basis": item.basis.as_str(),
                    "advisory_source": source.label(),
                })
                .to_string(),
            ],
        )?;
    }
    transaction.execute(
        "INSERT INTO dependency_audit_run_metrics( \
           run_id, coverage_complete, advisory_source, manifests, packages, unpinned_requirements, \
           vulnerable_packages, observations, findings_opened, findings_refreshed, findings_resolved \
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            run_id,
            i64::from(coverage_complete),
            source.label(),
            to_i64(inventory.manifests),
            to_i64(inventory.entries.len()),
            to_i64(inventory.unpinned),
            to_i64(vulnerable_packages),
            to_i64(observations.len()),
            to_i64(findings_opened),
            to_i64(findings_refreshed),
            to_i64(findings_resolved),
        ],
    )?;
    finish_run(&transaction, run_id, AnalysisStatus::Completed, duration_ms)?;
    transaction.commit()?;

    Ok(DependencyAuditSummary {
        project_id: project_id.to_string(),
        run_id: run_id.to_string(),
        status: AnalysisStatus::Completed,
        coverage_complete,
        advisory_source: source.label(),
        manifests: inventory.manifests,
        manifest_errors: inventory.errors,
        packages: inventory.entries.len(),
        unpinned_requirements: inventory.unpinned,
        vulnerable_packages,
        observations: observations.len(),
        findings_opened,
        findings_refreshed,
        findings_resolved,
        duration_ms,
    })
}

fn existing_findings(
    connection: &Connection,
    project_id: &str,
) -> Result<BTreeMap<String, (String, String)>, rusqlite::Error> {
    let mut statement = connection.prepare(
        "SELECT fingerprint, id, status FROM findings WHERE project_id = ?1 AND analyzer_key = ?2",
    )?;
    let rows = statement.query_map(params![project_id, ANALYZER_KEY], |row| {
        Ok((row.get(0)?, (row.get(1)?, row.get(2)?)))
    })?;
    rows.collect()
}

fn should_skip(entry: &DirEntry) -> bool {
    entry.depth() > 0
        && entry.file_type().is_dir()
        && matches!(
            entry.file_name().to_str(),
            Some(
                ".git"
                    | "node_modules"
                    | "target"
                    | ".venv"
                    | "venv"
                    | "dist"
                    | "build"
                    | ".next"
                    | ".cache"
                    | "vendor"
                    | "__pycache__"
            )
        )
}

fn project_root(
    connection: &Connection,
    project_id: &str,
) -> Result<PathBuf, DependencyAuditError> {
    connection
        .query_row(
            "SELECT root_path FROM projects WHERE id = ?1",
            [project_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .map(PathBuf::from)
        .ok_or_else(|| DependencyAuditError::ProjectNotFound(project_id.to_string()))
}

fn finish_run(
    connection: &Connection,
    run_id: &str,
    status: AnalysisStatus,
    duration_ms: u64,
) -> Result<(), rusqlite::Error> {
    connection.execute(
        "UPDATE analysis_runs SET status = ?2, finished_at = CURRENT_TIMESTAMP, duration_ms = ?3 WHERE id = ?1",
        params![run_id, status.as_db(), i64::try_from(duration_ms).unwrap_or(i64::MAX)],
    )?;
    Ok(())
}

fn new_run_id(project_id: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    deterministic_id("dependency-audit-run", &[project_id, &nanos.to_string()])
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn bounded(limit: usize) -> i64 {
    i64::try_from(limit.clamp(1, MAX_QUERY)).unwrap_or(1)
}

fn to_usize(value: i64) -> usize {
    usize::try_from(value).unwrap_or(0)
}

fn to_i64(value: usize) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}
