use std::{
    collections::{BTreeMap, BTreeSet},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;

use crate::{deterministic_id, AnalysisStatus, Database};

const ANALYZER_KEY: &str = "code_quality";
const ANALYZER_VERSION: &str = "code-quality-v1";
const QUERY_VERSION: &str = "persisted-index-quality-v1";
const RULE_VERSION: &str = "1";
const RULE_OVERSIZED_DEFINITION: &str = "quality.oversized_definition";
const RULE_DEEP_DECLARATION: &str = "quality.deep_declaration_nesting";
const RULE_HIGH_FAN_OUT: &str = "quality.high_local_fan_out";
const RULE_DEPENDENCY_CYCLE: &str = "quality.local_dependency_cycle";
const LARGE_DEFINITION_LINES: usize = 120;
const VERY_LARGE_DEFINITION_LINES: usize = 300;
const DEEP_DECLARATION_DEPTH: usize = 5;
const VERY_DEEP_DECLARATION_DEPTH: usize = 8;
const HIGH_FAN_OUT: usize = 20;
const VERY_HIGH_FAN_OUT: usize = 40;
const MAX_SYMBOLS: usize = 200_000;
const MAX_IMPORT_EDGES: usize = 50_000;
const MAX_CYCLE_EVIDENCE: usize = 100;
const MAX_FINDINGS_QUERY: usize = 500;
const MAX_EVIDENCE_QUERY: usize = 500;
const MAX_HISTORY_QUERY: usize = 100;

#[derive(Debug, Error)]
pub enum QualityAnalysisError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("project not found: {0}")]
    ProjectNotFound(String),
    #[error("quality symbol graph exceeds the bounded limit of {limit} active symbols")]
    SymbolGraphTooLarge { limit: usize },
    #[error("quality import graph exceeds the bounded limit of {limit} resolved local edges")]
    ImportGraphTooLarge { limit: usize },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QualityRunSummary {
    pub project_id: String,
    pub run_id: String,
    pub status: AnalysisStatus,
    pub rules_evaluated: usize,
    pub observations: usize,
    pub findings_opened: usize,
    pub findings_refreshed: usize,
    pub findings_resolved: usize,
    pub oversized_definitions: usize,
    pub deep_declarations: usize,
    pub high_fan_out_files: usize,
    pub dependency_cycles: usize,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QualityRunRecord {
    pub run_id: String,
    pub project_id: String,
    pub status: AnalysisStatus,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub duration_ms: Option<u64>,
    pub rules_evaluated: usize,
    pub observations: usize,
    pub findings_opened: usize,
    pub findings_refreshed: usize,
    pub findings_resolved: usize,
    pub oversized_definitions: usize,
    pub deep_declarations: usize,
    pub high_fan_out_files: usize,
    pub dependency_cycles: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QualityFindingRecord {
    pub id: String,
    pub project_id: String,
    pub run_id: String,
    pub rule_id: String,
    pub severity: String,
    pub confidence: Option<f64>,
    pub title: String,
    pub description: String,
    pub file_id: Option<String>,
    pub symbol_id: Option<String>,
    pub source_start_line: Option<usize>,
    pub source_end_line: Option<usize>,
    pub status: String,
    pub fingerprint: String,
    pub rule_version: Option<String>,
    pub first_seen: String,
    pub last_seen: String,
    pub resolved_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingEvidenceRecord {
    pub id: String,
    pub finding_id: String,
    pub evidence_type: String,
    pub uri: Option<String>,
    pub line_start: Option<usize>,
    pub line_end: Option<usize>,
    pub summary: String,
    pub metadata_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QualityRuleRecord {
    pub id: String,
    pub title: String,
    pub description: String,
    pub threshold: String,
}

pub struct CodeQualityService<'a> {
    database: &'a Database,
}

impl<'a> CodeQualityService<'a> {
    pub const fn new(database: &'a Database) -> Self {
        Self { database }
    }

    pub fn analyze_project(
        &self,
        project_id: &str,
    ) -> Result<QualityRunSummary, QualityAnalysisError> {
        ensure_project(self.database.connection(), project_id)?;
        let started = Instant::now();
        let run_id = new_run_id(project_id);
        let configuration_json = quality_configuration_json();
        let config_fingerprint = deterministic_id(
            "quality-config",
            &[ANALYZER_VERSION, QUERY_VERSION, &configuration_json],
        );

        self.database.connection().execute(
            "INSERT INTO analysis_runs( \
               id, project_id, status, analyzer_version, started_at, configuration_json, run_kind, query_version, config_fingerprint \
             ) VALUES (?1, ?2, 'running', ?3, CURRENT_TIMESTAMP, ?4, 'code_quality', ?5, ?6)",
            params![
                run_id,
                project_id,
                ANALYZER_VERSION,
                configuration_json,
                QUERY_VERSION,
                config_fingerprint,
            ],
        )?;

        let collected = match collect_observations(self.database.connection(), project_id) {
            Ok(collected) => collected,
            Err(error) => {
                let _ = finish_run(
                    self.database.connection(),
                    &run_id,
                    AnalysisStatus::Failed,
                    elapsed_ms(started),
                );
                return Err(error);
            }
        };

        let duration_ms = elapsed_ms(started);
        match persist_observations(
            self.database.connection(),
            project_id,
            &run_id,
            collected,
            duration_ms,
        ) {
            Ok(summary) => Ok(summary),
            Err(error) => {
                let _ = finish_run(
                    self.database.connection(),
                    &run_id,
                    AnalysisStatus::Failed,
                    duration_ms,
                );
                Err(error)
            }
        }
    }

    pub fn list_findings(
        &self,
        project_id: &str,
        status: Option<&str>,
        limit: usize,
    ) -> Result<Vec<QualityFindingRecord>, QualityAnalysisError> {
        let limit = bounded(limit, MAX_FINDINGS_QUERY);
        let mut statement = self.database.connection().prepare(
            "SELECT id, project_id, run_id, COALESCE(sub_category, ''), severity, confidence, title, description, \
                    file_id, symbol_id, source_start_line, source_end_line, status, fingerprint, rule_version, \
                    first_seen, last_seen, resolved_at \
             FROM findings \
             WHERE project_id = ?1 AND analyzer_key = ?2 AND (?3 IS NULL OR status = ?3) \
             ORDER BY CASE severity \
                        WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 \
                        WHEN 'low' THEN 2 ELSE 1 END DESC, \
                      status, last_seen DESC, id \
             LIMIT ?4",
        )?;
        let rows =
            statement.query_map(params![project_id, ANALYZER_KEY, status, limit], |row| {
                Ok(QualityFindingRecord {
                    id: row.get(0)?,
                    project_id: row.get(1)?,
                    run_id: row.get(2)?,
                    rule_id: row.get(3)?,
                    severity: row.get(4)?,
                    confidence: row.get(5)?,
                    title: row.get(6)?,
                    description: row.get(7)?,
                    file_id: row.get(8)?,
                    symbol_id: row.get(9)?,
                    source_start_line: optional_usize(row.get(10)?),
                    source_end_line: optional_usize(row.get(11)?),
                    status: row.get(12)?,
                    fingerprint: row.get(13)?,
                    rule_version: row.get(14)?,
                    first_seen: row.get(15)?,
                    last_seen: row.get(16)?,
                    resolved_at: row.get(17)?,
                })
            })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn finding_evidence(
        &self,
        finding_id: &str,
        limit: usize,
    ) -> Result<Vec<FindingEvidenceRecord>, QualityAnalysisError> {
        let mut statement = self.database.connection().prepare(
            "SELECT id, finding_id, evidence_type, uri, line_start, line_end, summary, metadata_json \
             FROM finding_evidence \
             WHERE finding_id = ?1 \
             ORDER BY COALESCE(uri, ''), COALESCE(line_start, 0), id \
             LIMIT ?2",
        )?;
        let rows = statement.query_map(
            params![finding_id, bounded(limit, MAX_EVIDENCE_QUERY)],
            |row| {
                Ok(FindingEvidenceRecord {
                    id: row.get(0)?,
                    finding_id: row.get(1)?,
                    evidence_type: row.get(2)?,
                    uri: row.get(3)?,
                    line_start: optional_usize(row.get(4)?),
                    line_end: optional_usize(row.get(5)?),
                    summary: row.get(6)?,
                    metadata_json: row.get(7)?,
                })
            },
        )?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn history(
        &self,
        project_id: &str,
        limit: usize,
    ) -> Result<Vec<QualityRunRecord>, QualityAnalysisError> {
        let mut statement = self.database.connection().prepare(
            "SELECT a.id, a.project_id, a.status, a.started_at, a.finished_at, a.duration_ms, \
                    COALESCE(q.rules_evaluated, 0), COALESCE(q.observations, 0), \
                    COALESCE(q.findings_opened, 0), COALESCE(q.findings_refreshed, 0), \
                    COALESCE(q.findings_resolved, 0), COALESCE(q.oversized_definitions, 0), \
                    COALESCE(q.deep_declarations, 0), COALESCE(q.high_fan_out_files, 0), \
                    COALESCE(q.dependency_cycles, 0) \
             FROM analysis_runs a \
             LEFT JOIN quality_run_metrics q ON q.run_id = a.id \
             WHERE a.project_id = ?1 AND a.run_kind = 'code_quality' \
             ORDER BY a.started_at DESC, a.id DESC LIMIT ?2",
        )?;
        let rows = statement.query_map(
            params![project_id, bounded(limit, MAX_HISTORY_QUERY)],
            |row| {
                let status_text: String = row.get(2)?;
                let status = AnalysisStatus::from_db(&status_text).ok_or_else(|| {
                    conversion_error(2, format!("invalid analysis status {status_text}"))
                })?;
                Ok(QualityRunRecord {
                    run_id: row.get(0)?,
                    project_id: row.get(1)?,
                    status,
                    started_at: row.get(3)?,
                    finished_at: row.get(4)?,
                    duration_ms: row.get::<_, Option<i64>>(5)?.map(to_u64),
                    rules_evaluated: to_usize(row.get(6)?),
                    observations: to_usize(row.get(7)?),
                    findings_opened: to_usize(row.get(8)?),
                    findings_refreshed: to_usize(row.get(9)?),
                    findings_resolved: to_usize(row.get(10)?),
                    oversized_definitions: to_usize(row.get(11)?),
                    deep_declarations: to_usize(row.get(12)?),
                    high_fan_out_files: to_usize(row.get(13)?),
                    dependency_cycles: to_usize(row.get(14)?),
                })
            },
        )?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn rules(&self) -> Vec<QualityRuleRecord> {
        quality_rules()
    }
}

#[derive(Debug, Clone)]
struct ActiveSymbol {
    id: String,
    file_id: String,
    kind: String,
    name: String,
    qualified_name: Option<String>,
    parent_symbol_id: Option<String>,
    start_line: usize,
    end_line: usize,
    relative_path: String,
}

#[derive(Debug, Clone)]
struct ImportEdge {
    id: String,
    source_file_id: String,
    target_file_id: String,
    source_path: String,
    target_path: String,
    raw_specifier: String,
    start_line: usize,
    end_line: usize,
}

#[derive(Debug, Clone)]
struct QualityEvidence {
    key: String,
    evidence_type: String,
    uri: Option<String>,
    line_start: Option<usize>,
    line_end: Option<usize>,
    summary: String,
    metadata_json: String,
}

#[derive(Debug, Clone)]
struct QualityObservation {
    fingerprint: String,
    rule_id: &'static str,
    severity: &'static str,
    title: String,
    description: String,
    file_id: Option<String>,
    symbol_id: Option<String>,
    source_start_line: Option<usize>,
    source_end_line: Option<usize>,
    evidence: Vec<QualityEvidence>,
}

#[derive(Debug, Default)]
struct RuleCounts {
    oversized_definitions: usize,
    deep_declarations: usize,
    high_fan_out_files: usize,
    dependency_cycles: usize,
}

#[derive(Debug)]
struct CollectedQuality {
    observations: Vec<QualityObservation>,
    counts: RuleCounts,
}

#[derive(Debug)]
struct ExistingFinding {
    id: String,
    status: String,
}

fn collect_observations(
    connection: &Connection,
    project_id: &str,
) -> Result<CollectedQuality, QualityAnalysisError> {
    let symbols = load_symbols(connection, project_id)?;
    let imports = load_resolved_imports(connection, project_id)?;
    let mut observations = Vec::new();
    let mut counts = RuleCounts::default();

    collect_oversized_definitions(project_id, &symbols, &mut observations, &mut counts);
    collect_deep_declarations(project_id, &symbols, &mut observations, &mut counts);
    collect_high_fan_out(project_id, &imports, &mut observations, &mut counts);
    collect_dependency_cycles(project_id, &imports, &mut observations, &mut counts);

    observations.sort_by(|left, right| left.fingerprint.cmp(&right.fingerprint));
    Ok(CollectedQuality {
        observations,
        counts,
    })
}

fn load_symbols(
    connection: &Connection,
    project_id: &str,
) -> Result<Vec<ActiveSymbol>, QualityAnalysisError> {
    let mut statement = connection.prepare(
        "SELECT s.id, s.file_id, s.kind, s.name, s.qualified_name, s.parent_symbol_id, \
                s.start_line, s.end_line, f.relative_path \
         FROM symbols s \
         JOIN files f ON f.id = s.file_id \
         WHERE s.project_id = ?1 AND s.is_active = 1 AND f.is_active = 1 \
         ORDER BY f.relative_path, s.start_line, s.start_column, s.id \
         LIMIT ?2",
    )?;
    let rows = statement.query_map(
        params![project_id, to_i64(MAX_SYMBOLS.saturating_add(1))],
        |row| {
            Ok(ActiveSymbol {
                id: row.get(0)?,
                file_id: row.get(1)?,
                kind: row.get(2)?,
                name: row.get(3)?,
                qualified_name: row.get(4)?,
                parent_symbol_id: row.get(5)?,
                start_line: to_usize(row.get(6)?),
                end_line: to_usize(row.get(7)?),
                relative_path: row.get(8)?,
            })
        },
    )?;
    let symbols = rows.collect::<Result<Vec<_>, _>>()?;
    if symbols.len() > MAX_SYMBOLS {
        return Err(QualityAnalysisError::SymbolGraphTooLarge { limit: MAX_SYMBOLS });
    }
    Ok(symbols)
}

fn load_resolved_imports(
    connection: &Connection,
    project_id: &str,
) -> Result<Vec<ImportEdge>, QualityAnalysisError> {
    let mut statement = connection.prepare(
        "SELECT i.id, i.source_file_id, i.resolved_target_file_id, \
                source.relative_path, target.relative_path, i.raw_specifier, \
                i.start_line, i.end_line \
         FROM import_references i \
         JOIN files source ON source.id = i.source_file_id \
         JOIN files target ON target.id = i.resolved_target_file_id \
         WHERE i.project_id = ?1 AND i.resolution_state = 'resolved_local' \
           AND i.resolved_target_file_id IS NOT NULL \
           AND source.is_active = 1 AND target.is_active = 1 \
         ORDER BY source.relative_path, target.relative_path, i.start_line, i.id \
         LIMIT ?2",
    )?;
    let rows = statement.query_map(
        params![project_id, to_i64(MAX_IMPORT_EDGES.saturating_add(1))],
        |row| {
            Ok(ImportEdge {
                id: row.get(0)?,
                source_file_id: row.get(1)?,
                target_file_id: row.get(2)?,
                source_path: row.get(3)?,
                target_path: row.get(4)?,
                raw_specifier: row.get(5)?,
                start_line: to_usize(row.get(6)?),
                end_line: to_usize(row.get(7)?),
            })
        },
    )?;
    let imports = rows.collect::<Result<Vec<_>, _>>()?;
    if imports.len() > MAX_IMPORT_EDGES {
        return Err(QualityAnalysisError::ImportGraphTooLarge {
            limit: MAX_IMPORT_EDGES,
        });
    }
    Ok(imports)
}

fn collect_oversized_definitions(
    project_id: &str,
    symbols: &[ActiveSymbol],
    output: &mut Vec<QualityObservation>,
    counts: &mut RuleCounts,
) {
    for symbol in symbols {
        let lines = symbol
            .end_line
            .saturating_sub(symbol.start_line)
            .saturating_add(1);
        if lines < LARGE_DEFINITION_LINES {
            continue;
        }
        counts.oversized_definitions += 1;
        let display = symbol
            .qualified_name
            .as_deref()
            .unwrap_or(symbol.name.as_str());
        let severity = if lines >= VERY_LARGE_DEFINITION_LINES {
            "high"
        } else {
            "medium"
        };
        let fingerprint = deterministic_id(
            "quality-finding",
            &[project_id, RULE_OVERSIZED_DEFINITION, &symbol.id],
        );
        output.push(QualityObservation {
            fingerprint,
            rule_id: RULE_OVERSIZED_DEFINITION,
            severity,
            title: format!("Large definition: {display}"),
            description: format!(
                "The persisted {kind} definition spans {lines} lines; the deterministic quality threshold is {threshold} lines.",
                kind = symbol.kind,
                threshold = LARGE_DEFINITION_LINES,
            ),
            file_id: Some(symbol.file_id.clone()),
            symbol_id: Some(symbol.id.clone()),
            source_start_line: Some(symbol.start_line),
            source_end_line: Some(symbol.end_line),
            evidence: vec![QualityEvidence {
                key: symbol.id.clone(),
                evidence_type: "source".to_string(),
                uri: Some(symbol.relative_path.clone()),
                line_start: Some(symbol.start_line),
                line_end: Some(symbol.end_line),
                summary: format!(
                    "Persisted definition range is {}–{} ({} lines).",
                    symbol.start_line, symbol.end_line, lines
                ),
                metadata_json: json!({
                    "rule": RULE_OVERSIZED_DEFINITION,
                    "symbol_kind": symbol.kind,
                    "measured_lines": lines,
                    "threshold_lines": LARGE_DEFINITION_LINES,
                })
                .to_string(),
            }],
        });
    }
}

fn collect_deep_declarations(
    project_id: &str,
    symbols: &[ActiveSymbol],
    output: &mut Vec<QualityObservation>,
    counts: &mut RuleCounts,
) {
    let parent_by_id: BTreeMap<&str, Option<&str>> = symbols
        .iter()
        .map(|symbol| (symbol.id.as_str(), symbol.parent_symbol_id.as_deref()))
        .collect();

    for symbol in symbols {
        let depth = declaration_depth(symbol.id.as_str(), &parent_by_id);
        if depth < DEEP_DECLARATION_DEPTH {
            continue;
        }
        counts.deep_declarations += 1;
        let display = symbol
            .qualified_name
            .as_deref()
            .unwrap_or(symbol.name.as_str());
        let severity = if depth >= VERY_DEEP_DECLARATION_DEPTH {
            "medium"
        } else {
            "low"
        };
        let fingerprint = deterministic_id(
            "quality-finding",
            &[project_id, RULE_DEEP_DECLARATION, &symbol.id],
        );
        output.push(QualityObservation {
            fingerprint,
            rule_id: RULE_DEEP_DECLARATION,
            severity,
            title: format!("Deeply nested declaration: {display}"),
            description: format!(
                "The persisted declaration-parent chain has depth {depth}; the deterministic quality threshold is {threshold}.",
                threshold = DEEP_DECLARATION_DEPTH,
            ),
            file_id: Some(symbol.file_id.clone()),
            symbol_id: Some(symbol.id.clone()),
            source_start_line: Some(symbol.start_line),
            source_end_line: Some(symbol.end_line),
            evidence: vec![QualityEvidence {
                key: symbol.id.clone(),
                evidence_type: "source".to_string(),
                uri: Some(symbol.relative_path.clone()),
                line_start: Some(symbol.start_line),
                line_end: Some(symbol.end_line),
                summary: format!("Persisted declaration nesting depth is {depth}."),
                metadata_json: json!({
                    "rule": RULE_DEEP_DECLARATION,
                    "measured_depth": depth,
                    "threshold_depth": DEEP_DECLARATION_DEPTH,
                    "parent_symbol_id": symbol.parent_symbol_id,
                })
                .to_string(),
            }],
        });
    }
}

fn declaration_depth(symbol_id: &str, parent_by_id: &BTreeMap<&str, Option<&str>>) -> usize {
    let mut current = symbol_id;
    let mut seen = BTreeSet::new();
    let mut depth = 0usize;
    while seen.insert(current) {
        let Some(parent) = parent_by_id.get(current).and_then(|parent| *parent) else {
            break;
        };
        depth = depth.saturating_add(1);
        current = parent;
    }
    depth
}

fn collect_high_fan_out(
    project_id: &str,
    imports: &[ImportEdge],
    output: &mut Vec<QualityObservation>,
    counts: &mut RuleCounts,
) {
    let mut by_source = BTreeMap::<String, BTreeMap<String, &ImportEdge>>::new();
    for edge in imports {
        by_source
            .entry(edge.source_file_id.clone())
            .or_default()
            .entry(edge.target_file_id.clone())
            .or_insert(edge);
    }

    for (source_file_id, targets) in by_source {
        if targets.len() < HIGH_FAN_OUT {
            continue;
        }
        let Some(first) = targets.values().next() else {
            continue;
        };
        counts.high_fan_out_files += 1;
        let severity = if targets.len() >= VERY_HIGH_FAN_OUT {
            "medium"
        } else {
            "low"
        };
        let fingerprint = deterministic_id(
            "quality-finding",
            &[project_id, RULE_HIGH_FAN_OUT, &source_file_id],
        );
        let evidence = targets
            .values()
            .map(|edge| QualityEvidence {
                key: edge.id.clone(),
                evidence_type: "dependency".to_string(),
                uri: Some(edge.source_path.clone()),
                line_start: Some(edge.start_line),
                line_end: Some(edge.end_line),
                summary: format!(
                    "Resolved local import {} targets {}.",
                    edge.raw_specifier, edge.target_path
                ),
                metadata_json: json!({
                    "rule": RULE_HIGH_FAN_OUT,
                    "import_id": edge.id,
                    "target_file_id": edge.target_file_id,
                    "target_path": edge.target_path,
                })
                .to_string(),
            })
            .collect();
        output.push(QualityObservation {
            fingerprint,
            rule_id: RULE_HIGH_FAN_OUT,
            severity,
            title: format!("High local dependency fan-out: {}", first.source_path),
            description: format!(
                "This file has {} distinct resolved local dependency targets; the deterministic quality threshold is {}.",
                targets.len(),
                HIGH_FAN_OUT,
            ),
            file_id: Some(source_file_id),
            symbol_id: None,
            source_start_line: None,
            source_end_line: None,
            evidence,
        });
    }
}

fn collect_dependency_cycles(
    project_id: &str,
    imports: &[ImportEdge],
    output: &mut Vec<QualityObservation>,
    counts: &mut RuleCounts,
) {
    let mut nodes = BTreeSet::new();
    for edge in imports {
        nodes.insert(edge.source_file_id.clone());
        nodes.insert(edge.target_file_id.clone());
    }
    let components = strongly_connected_components(&nodes, imports);
    for component in components {
        let member_set: BTreeSet<&str> = component.iter().map(String::as_str).collect();
        let internal_edges: Vec<&ImportEdge> = imports
            .iter()
            .filter(|edge| {
                member_set.contains(edge.source_file_id.as_str())
                    && member_set.contains(edge.target_file_id.as_str())
            })
            .collect();
        let self_loop = component.len() == 1
            && internal_edges
                .iter()
                .any(|edge| edge.source_file_id == edge.target_file_id);
        if component.len() < 2 && !self_loop {
            continue;
        }

        counts.dependency_cycles += 1;
        let mut paths = BTreeSet::new();
        for edge in &internal_edges {
            paths.insert(edge.source_path.clone());
            paths.insert(edge.target_path.clone());
        }
        let joined_members = component.join("|");
        let fingerprint = deterministic_id(
            "quality-finding",
            &[project_id, RULE_DEPENDENCY_CYCLE, &joined_members],
        );
        let severity = if component.len() >= 6 {
            "high"
        } else {
            "medium"
        };
        let preview = paths.iter().take(6).cloned().collect::<Vec<_>>().join(", ");
        let evidence = internal_edges
            .iter()
            .take(MAX_CYCLE_EVIDENCE)
            .map(|edge| QualityEvidence {
                key: edge.id.clone(),
                evidence_type: "dependency".to_string(),
                uri: Some(edge.source_path.clone()),
                line_start: Some(edge.start_line),
                line_end: Some(edge.end_line),
                summary: format!(
                    "Resolved local import {} -> {} via {}.",
                    edge.source_path, edge.target_path, edge.raw_specifier
                ),
                metadata_json: json!({
                    "rule": RULE_DEPENDENCY_CYCLE,
                    "import_id": edge.id,
                    "source_file_id": edge.source_file_id,
                    "target_file_id": edge.target_file_id,
                })
                .to_string(),
            })
            .collect();
        output.push(QualityObservation {
            fingerprint,
            rule_id: RULE_DEPENDENCY_CYCLE,
            severity,
            title: format!(
                "Resolved local dependency cycle ({} file{})",
                component.len(),
                if component.len() == 1 { "" } else { "s" }
            ),
            description: format!(
                "The resolved-local import graph contains a strongly connected component with {} file{}: {}{}",
                component.len(),
                if component.len() == 1 { "" } else { "s" },
                preview,
                if paths.len() > 6 { ", …" } else { "" },
            ),
            file_id: None,
            symbol_id: None,
            source_start_line: None,
            source_end_line: None,
            evidence,
        });
    }
}

fn strongly_connected_components(
    nodes: &BTreeSet<String>,
    edges: &[ImportEdge],
) -> Vec<Vec<String>> {
    let mut forward = BTreeMap::<String, Vec<String>>::new();
    let mut reverse = BTreeMap::<String, Vec<String>>::new();
    for node in nodes {
        forward.entry(node.clone()).or_default();
        reverse.entry(node.clone()).or_default();
    }
    for edge in edges {
        forward
            .entry(edge.source_file_id.clone())
            .or_default()
            .push(edge.target_file_id.clone());
        reverse
            .entry(edge.target_file_id.clone())
            .or_default()
            .push(edge.source_file_id.clone());
    }
    for neighbors in forward.values_mut().chain(reverse.values_mut()) {
        neighbors.sort();
        neighbors.dedup();
    }

    let mut visited = BTreeSet::new();
    let mut finish_order = Vec::new();
    for node in nodes {
        if visited.contains(node) {
            continue;
        }
        dfs_finish(node, &forward, &mut visited, &mut finish_order);
    }

    visited.clear();
    let mut components = Vec::new();
    for node in finish_order.into_iter().rev() {
        if visited.contains(&node) {
            continue;
        }
        let mut component = Vec::new();
        let mut stack = vec![node.clone()];
        visited.insert(node);
        while let Some(current) = stack.pop() {
            component.push(current.clone());
            if let Some(neighbors) = reverse.get(&current) {
                for neighbor in neighbors.iter().rev() {
                    if visited.insert(neighbor.clone()) {
                        stack.push(neighbor.clone());
                    }
                }
            }
        }
        component.sort();
        components.push(component);
    }
    components.sort_by(|left, right| left.first().cmp(&right.first()));
    components
}

fn dfs_finish(
    start: &str,
    graph: &BTreeMap<String, Vec<String>>,
    visited: &mut BTreeSet<String>,
    finish_order: &mut Vec<String>,
) {
    let mut stack = vec![(start.to_string(), false)];
    while let Some((node, expanded)) = stack.pop() {
        if expanded {
            finish_order.push(node);
            continue;
        }
        if !visited.insert(node.clone()) {
            continue;
        }
        stack.push((node.clone(), true));
        if let Some(neighbors) = graph.get(&node) {
            for neighbor in neighbors.iter().rev() {
                if !visited.contains(neighbor) {
                    stack.push((neighbor.clone(), false));
                }
            }
        }
    }
}

fn persist_observations(
    connection: &Connection,
    project_id: &str,
    run_id: &str,
    collected: CollectedQuality,
    duration_ms: u64,
) -> Result<QualityRunSummary, QualityAnalysisError> {
    let existing = load_existing_findings(connection, project_id)?;
    let observed_fingerprints: BTreeSet<&str> = collected
        .observations
        .iter()
        .map(|observation| observation.fingerprint.as_str())
        .collect();
    let findings_opened = collected
        .observations
        .iter()
        .filter(|observation| !existing.contains_key(observation.fingerprint.as_str()))
        .count();
    let findings_refreshed = collected.observations.len().saturating_sub(findings_opened);
    let findings_resolved = existing
        .iter()
        .filter(|(fingerprint, finding)| {
            finding.status == "open" && !observed_fingerprints.contains(fingerprint.as_str())
        })
        .count();

    let transaction = connection.unchecked_transaction()?;
    transaction.execute(
        "UPDATE findings SET status = 'resolved', resolved_at = CURRENT_TIMESTAMP, last_run_id = ?2 \
         WHERE project_id = ?1 AND analyzer_key = ?3 AND status = 'open'",
        params![project_id, run_id, ANALYZER_KEY],
    )?;

    for observation in &collected.observations {
        let finding_id = existing.get(observation.fingerprint.as_str()).map_or_else(
            || {
                deterministic_id(
                    "finding",
                    &[project_id, ANALYZER_KEY, &observation.fingerprint],
                )
            },
            |finding| finding.id.clone(),
        );
        transaction.execute(
            "INSERT INTO findings( \
               id, project_id, run_id, category, sub_category, severity, confidence, title, description, \
               file_id, symbol_id, source_start_line, source_end_line, status, fingerprint, rule_version, \
               model_version, first_seen, last_seen, analyzer_key, last_run_id, resolved_at \
             ) VALUES ( \
               ?1, ?2, ?3, 'quality', ?4, ?5, 1.0, ?6, ?7, ?8, ?9, ?10, ?11, 'open', ?12, ?13, \
               NULL, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, ?14, ?3, NULL \
             ) \
             ON CONFLICT(project_id, fingerprint) DO UPDATE SET \
               run_id = excluded.run_id, category = excluded.category, sub_category = excluded.sub_category, \
               severity = excluded.severity, confidence = excluded.confidence, title = excluded.title, \
               description = excluded.description, file_id = excluded.file_id, symbol_id = excluded.symbol_id, \
               source_start_line = excluded.source_start_line, source_end_line = excluded.source_end_line, \
               status = 'open', rule_version = excluded.rule_version, model_version = NULL, \
               last_seen = CURRENT_TIMESTAMP, analyzer_key = excluded.analyzer_key, \
               last_run_id = excluded.last_run_id, resolved_at = NULL",
            params![
                finding_id,
                project_id,
                run_id,
                observation.rule_id,
                observation.severity,
                observation.title,
                observation.description,
                observation.file_id,
                observation.symbol_id,
                optional_i64(observation.source_start_line),
                optional_i64(observation.source_end_line),
                observation.fingerprint,
                RULE_VERSION,
                ANALYZER_KEY,
            ],
        )?;
        transaction.execute(
            "DELETE FROM finding_evidence WHERE finding_id = ?1",
            [&finding_id],
        )?;
        for evidence in &observation.evidence {
            let evidence_id = deterministic_id(
                "finding-evidence",
                &[&finding_id, observation.rule_id, &evidence.key],
            );
            transaction.execute(
                "INSERT INTO finding_evidence( \
                   id, finding_id, evidence_type, uri, line_start, line_end, summary, metadata_json \
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    evidence_id,
                    finding_id,
                    evidence.evidence_type,
                    evidence.uri,
                    optional_i64(evidence.line_start),
                    optional_i64(evidence.line_end),
                    evidence.summary,
                    evidence.metadata_json,
                ],
            )?;
        }
    }

    let rules_evaluated = quality_rules().len();
    transaction.execute(
        "INSERT INTO quality_run_metrics( \
           run_id, rules_evaluated, observations, findings_opened, findings_refreshed, findings_resolved, \
           oversized_definitions, deep_declarations, high_fan_out_files, dependency_cycles \
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            run_id,
            to_i64(rules_evaluated),
            to_i64(collected.observations.len()),
            to_i64(findings_opened),
            to_i64(findings_refreshed),
            to_i64(findings_resolved),
            to_i64(collected.counts.oversized_definitions),
            to_i64(collected.counts.deep_declarations),
            to_i64(collected.counts.high_fan_out_files),
            to_i64(collected.counts.dependency_cycles),
        ],
    )?;
    finish_run(&transaction, run_id, AnalysisStatus::Completed, duration_ms)?;
    transaction.commit()?;

    Ok(QualityRunSummary {
        project_id: project_id.to_string(),
        run_id: run_id.to_string(),
        status: AnalysisStatus::Completed,
        rules_evaluated,
        observations: collected.observations.len(),
        findings_opened,
        findings_refreshed,
        findings_resolved,
        oversized_definitions: collected.counts.oversized_definitions,
        deep_declarations: collected.counts.deep_declarations,
        high_fan_out_files: collected.counts.high_fan_out_files,
        dependency_cycles: collected.counts.dependency_cycles,
        duration_ms,
    })
}

fn load_existing_findings(
    connection: &Connection,
    project_id: &str,
) -> Result<BTreeMap<String, ExistingFinding>, rusqlite::Error> {
    let mut statement = connection.prepare(
        "SELECT fingerprint, id, status FROM findings \
         WHERE project_id = ?1 AND analyzer_key = ?2 \
         ORDER BY fingerprint",
    )?;
    let rows = statement.query_map(params![project_id, ANALYZER_KEY], |row| {
        Ok((
            row.get::<_, String>(0)?,
            ExistingFinding {
                id: row.get(1)?,
                status: row.get(2)?,
            },
        ))
    })?;
    rows.collect()
}

fn ensure_project(connection: &Connection, project_id: &str) -> Result<(), QualityAnalysisError> {
    let exists: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM projects WHERE id = ?1)",
        [project_id],
        |row| row.get(0),
    )?;
    if exists {
        Ok(())
    } else {
        Err(QualityAnalysisError::ProjectNotFound(
            project_id.to_string(),
        ))
    }
}

fn finish_run(
    connection: &Connection,
    run_id: &str,
    status: AnalysisStatus,
    duration_ms: u64,
) -> Result<(), rusqlite::Error> {
    connection.execute(
        "UPDATE analysis_runs \
         SET status = ?2, finished_at = CURRENT_TIMESTAMP, duration_ms = ?3 \
         WHERE id = ?1",
        params![
            run_id,
            status.as_str(),
            i64::try_from(duration_ms).unwrap_or(i64::MAX),
        ],
    )?;
    Ok(())
}

fn quality_rules() -> Vec<QualityRuleRecord> {
    vec![
        QualityRuleRecord {
            id: RULE_OVERSIZED_DEFINITION.to_string(),
            title: "Oversized definition".to_string(),
            description:
                "Flags persisted definition symbols whose source range is unusually large."
                    .to_string(),
            threshold: format!(">= {LARGE_DEFINITION_LINES} lines"),
        },
        QualityRuleRecord {
            id: RULE_DEEP_DECLARATION.to_string(),
            title: "Deep declaration nesting".to_string(),
            description:
                "Flags persisted definitions with a long structural declaration-parent chain."
                    .to_string(),
            threshold: format!(">= {DEEP_DECLARATION_DEPTH} parent levels"),
        },
        QualityRuleRecord {
            id: RULE_HIGH_FAN_OUT.to_string(),
            title: "High local dependency fan-out".to_string(),
            description: "Flags files with many distinct resolved-local import targets."
                .to_string(),
            threshold: format!(">= {HIGH_FAN_OUT} local targets"),
        },
        QualityRuleRecord {
            id: RULE_DEPENDENCY_CYCLE.to_string(),
            title: "Resolved local dependency cycle".to_string(),
            description:
                "Flags strongly connected components in the resolved-local file import graph."
                    .to_string(),
            threshold: "cycle size >= 2 files, or a self-import".to_string(),
        },
    ]
}

fn quality_configuration_json() -> String {
    json!({
        "large_definition_lines": LARGE_DEFINITION_LINES,
        "very_large_definition_lines": VERY_LARGE_DEFINITION_LINES,
        "deep_declaration_depth": DEEP_DECLARATION_DEPTH,
        "very_deep_declaration_depth": VERY_DEEP_DECLARATION_DEPTH,
        "high_fan_out": HIGH_FAN_OUT,
        "very_high_fan_out": VERY_HIGH_FAN_OUT,
        "max_symbols": MAX_SYMBOLS,
        "max_import_edges": MAX_IMPORT_EDGES,
        "rule_version": RULE_VERSION,
    })
    .to_string()
}

fn new_run_id(project_id: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .to_string();
    deterministic_id("quality-run", &[project_id, &nanos])
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn bounded(value: usize, maximum: usize) -> i64 {
    i64::try_from(value.clamp(1, maximum)).unwrap_or(i64::MAX)
}

fn to_i64(value: usize) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn to_usize(value: i64) -> usize {
    usize::try_from(value).unwrap_or(0)
}

fn to_u64(value: i64) -> u64 {
    u64::try_from(value).unwrap_or(0)
}

fn optional_i64(value: Option<usize>) -> Option<i64> {
    value.map(|value| i64::try_from(value).unwrap_or(i64::MAX))
}

fn optional_usize(value: Option<i64>) -> Option<usize> {
    value.map(to_usize)
}

fn conversion_error(column: usize, message: String) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(column, rusqlite::types::Type::Text, message.into())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{
        declaration_depth, strongly_connected_components, ActiveSymbol, ImportEdge,
        DEEP_DECLARATION_DEPTH,
    };

    #[test]
    fn declaration_depth_stops_at_root_and_cycles() {
        let symbols = [
            ActiveSymbol {
                id: "a".into(),
                file_id: "file".into(),
                kind: "class".into(),
                name: "a".into(),
                qualified_name: None,
                parent_symbol_id: None,
                start_line: 1,
                end_line: 10,
                relative_path: "a.ts".into(),
            },
            ActiveSymbol {
                id: "b".into(),
                file_id: "file".into(),
                kind: "method".into(),
                name: "b".into(),
                qualified_name: None,
                parent_symbol_id: Some("a".into()),
                start_line: 2,
                end_line: 9,
                relative_path: "a.ts".into(),
            },
        ];
        let parent_by_id = symbols
            .iter()
            .map(|symbol| (symbol.id.as_str(), symbol.parent_symbol_id.as_deref()))
            .collect();
        assert_eq!(declaration_depth("a", &parent_by_id), 0);
        assert_eq!(declaration_depth("b", &parent_by_id), 1);
        const _: () = assert!(DEEP_DECLARATION_DEPTH > 1);
    }

    #[test]
    fn finds_strongly_connected_components_deterministically() {
        let edges = vec![
            edge("1", "a", "b"),
            edge("2", "b", "a"),
            edge("3", "b", "c"),
            edge("4", "c", "d"),
            edge("5", "d", "c"),
        ];
        let nodes = ["a", "b", "c", "d", "e"]
            .into_iter()
            .map(str::to_string)
            .collect::<BTreeSet<_>>();
        let components = strongly_connected_components(&nodes, &edges);
        assert!(components.contains(&vec!["a".to_string(), "b".to_string()]));
        assert!(components.contains(&vec!["c".to_string(), "d".to_string()]));
        assert!(components.contains(&vec!["e".to_string()]));
    }

    fn edge(id: &str, source: &str, target: &str) -> ImportEdge {
        ImportEdge {
            id: id.into(),
            source_file_id: source.into(),
            target_file_id: target.into(),
            source_path: format!("{source}.ts"),
            target_path: format!("{target}.ts"),
            raw_specifier: format!("./{target}"),
            start_line: 1,
            end_line: 1,
        }
    }
}
