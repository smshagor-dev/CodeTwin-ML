use lsp_enrichment::{LanguageServerConfig, LanguageServerKind};
use serde::{Deserialize, Serialize};

use crate::AnalysisStatus;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SemanticEnrichmentRequest {
    #[serde(default)]
    pub server_kinds: Vec<LanguageServerKind>,
    #[serde(default)]
    pub trusted_project: bool,
    #[serde(default = "default_max_files")]
    pub max_files: usize,
    #[serde(default = "default_max_symbols")]
    pub max_symbols: usize,
    #[serde(default = "default_max_references")]
    pub max_references_per_symbol: usize,
    #[serde(default = "default_max_definition_lookups")]
    pub max_definition_lookups: usize,
    #[serde(default = "default_timeout_ms")]
    pub request_timeout_ms: u64,
}

const fn default_max_files() -> usize {
    100
}

const fn default_max_symbols() -> usize {
    500
}

const fn default_max_references() -> usize {
    25
}

const fn default_max_definition_lookups() -> usize {
    1500
}

const fn default_timeout_ms() -> u64 {
    5000
}

impl Default for SemanticEnrichmentRequest {
    fn default() -> Self {
        Self {
            server_kinds: Vec::new(),
            trusted_project: false,
            max_files: default_max_files(),
            max_symbols: default_max_symbols(),
            max_references_per_symbol: default_max_references(),
            max_definition_lookups: default_max_definition_lookups(),
            request_timeout_ms: default_timeout_ms(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticServerStatus {
    Completed,
    Failed,
    NotConfigured,
    Disabled,
    NoFiles,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticServerRun {
    pub kind: LanguageServerKind,
    pub status: SemanticServerStatus,
    pub files_processed: usize,
    pub symbols_processed: usize,
    pub symbols_matched: usize,
    pub reference_locations: usize,
    pub definitions_resolved: usize,
    pub relations_persisted: usize,
    pub graph_edges_materialized: usize,
    pub error: Option<String>,
    pub server_name: Option<String>,
    pub server_version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticRunSummary {
    pub project_id: String,
    pub run_id: String,
    pub status: AnalysisStatus,
    pub files_processed: usize,
    pub symbols_processed: usize,
    pub symbols_matched: usize,
    pub reference_locations: usize,
    pub definitions_resolved: usize,
    pub relations_persisted: usize,
    pub graph_edges_materialized: usize,
    pub errors: usize,
    pub duration_ms: u64,
    pub servers: Vec<SemanticServerRun>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticRelationDirection {
    Incoming,
    Outgoing,
    Subject,
    All,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticRelationRecord {
    pub id: String,
    pub project_id: String,
    pub run_id: String,
    pub subject_symbol_id: String,
    pub occurrence_file_id: String,
    pub container_symbol_id: Option<String>,
    pub target_file_id: String,
    pub target_symbol_id: Option<String>,
    pub relationship: String,
    pub occurrence_start_line: usize,
    pub occurrence_start_column: usize,
    pub occurrence_end_line: usize,
    pub occurrence_end_column: usize,
    pub target_start_line: usize,
    pub target_start_column: usize,
    pub target_end_line: usize,
    pub target_end_column: usize,
    pub provider_kind: LanguageServerKind,
    pub server_name: Option<String>,
    pub server_version: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticSymbolState {
    Resolved,
    NoReferences,
    Unmatched,
    Unsupported,
    Error,
    Stale,
}

impl SemanticSymbolState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Resolved => "resolved",
            Self::NoReferences => "no_references",
            Self::Unmatched => "unmatched",
            Self::Unsupported => "unsupported",
            Self::Error => "error",
            Self::Stale => "stale",
        }
    }

    pub fn from_db(value: &str) -> Option<Self> {
        match value {
            "resolved" => Some(Self::Resolved),
            "no_references" => Some(Self::NoReferences),
            "unmatched" => Some(Self::Unmatched),
            "unsupported" => Some(Self::Unsupported),
            "error" => Some(Self::Error),
            "stale" => Some(Self::Stale),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticSymbolStateRecord {
    pub symbol_id: String,
    pub project_id: String,
    pub run_id: String,
    pub provider_kind: LanguageServerKind,
    pub state: SemanticSymbolState,
    pub reference_locations: usize,
    pub definitions_resolved: usize,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticRunRecord {
    pub run_id: String,
    pub project_id: String,
    pub status: AnalysisStatus,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub duration_ms: Option<u64>,
    pub files_processed: usize,
    pub symbols_processed: usize,
    pub symbols_matched: usize,
    pub reference_locations: usize,
    pub definitions_resolved: usize,
    pub relations_persisted: usize,
    pub graph_edges_materialized: usize,
    pub errors: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LanguageServerConfigRecord {
    pub config: LanguageServerConfig,
    pub configured: bool,
}
