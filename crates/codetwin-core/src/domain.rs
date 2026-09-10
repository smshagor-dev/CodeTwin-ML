use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisStatus {
    Queued,
    Running,
    Completed,
    Failed,
    Cancelled,
    Interrupted,
}

impl AnalysisStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Interrupted => "interrupted",
        }
    }

    pub fn from_db(value: &str) -> Option<Self> {
        match value {
            "queued" => Some(Self::Queued),
            "running" => Some(Self::Running),
            "completed" => Some(Self::Completed),
            "failed" => Some(Self::Failed),
            "cancelled" => Some(Self::Cancelled),
            "interrupted" => Some(Self::Interrupted),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportResolutionState {
    Observed,
    ResolvedLocal,
    External,
    Unresolved,
    Unsupported,
}

impl ImportResolutionState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::ResolvedLocal => "resolved_local",
            Self::External => "external",
            Self::Unresolved => "unresolved",
            Self::Unsupported => "unsupported",
        }
    }

    pub fn from_db(value: &str) -> Option<Self> {
        match value {
            "observed" => Some(Self::Observed),
            "resolved_local" => Some(Self::ResolvedLocal),
            "external" => Some(Self::External),
            "unresolved" => Some(Self::Unresolved),
            "unsupported" => Some(Self::Unsupported),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    Source,
    Test,
    Runtime,
    Trace,
    Screenshot,
    Dependency,
    Database,
    SecurityTool,
    Model,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalysisRun {
    pub id: String,
    pub project_id: String,
    pub status: AnalysisStatus,
    pub analyzer_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectRecord {
    pub id: String,
    pub display_name: String,
    pub root_path: String,
    pub path_identity: String,
    pub git_remote: Option<String>,
    pub last_opened_at: Option<String>,
    pub last_indexed_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceFileRecord {
    pub id: String,
    pub project_id: String,
    pub relative_path: String,
    pub relative_path_identity: String,
    pub language: Option<String>,
    pub content_hash: String,
    pub byte_size: u64,
    pub ast_root_kind: Option<String>,
    pub parse_state: Option<String>,
    pub is_active: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymbolRecord {
    pub id: String,
    pub project_id: String,
    pub file_id: String,
    pub kind: String,
    pub name: String,
    pub qualified_name: Option<String>,
    pub parent_symbol_id: Option<String>,
    pub fingerprint: String,
    pub start_line: usize,
    pub start_column: usize,
    pub end_line: usize,
    pub end_column: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportReferenceRecord {
    pub id: String,
    pub project_id: String,
    pub source_file_id: String,
    pub raw_specifier: String,
    pub kind: String,
    pub start_line: usize,
    pub start_column: usize,
    pub end_line: usize,
    pub end_column: usize,
    pub resolution_state: ImportResolutionState,
    pub resolved_target_file_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct IndexDelta {
    pub files_scanned: usize,
    pub files_added: usize,
    pub files_modified: usize,
    pub files_unchanged: usize,
    pub files_deleted: usize,
    pub symbols_added: usize,
    pub symbols_updated: usize,
    pub symbols_removed: usize,
    pub parse_errors: usize,
    pub skipped_files: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexSummary {
    pub project_id: String,
    pub run_id: String,
    pub status: AnalysisStatus,
    pub delta: IndexDelta,
    pub graph_node_count: usize,
    pub graph_edge_count: usize,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct GraphSummary {
    pub node_count: usize,
    pub edge_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphNodeRecord {
    pub id: String,
    pub project_id: String,
    pub node_type: String,
    pub external_key: String,
    pub label: String,
    pub metadata_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphEdgeRecord {
    pub id: String,
    pub project_id: String,
    pub source_node_id: String,
    pub target_node_id: String,
    pub relationship: String,
    pub metadata_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphNeighborhood {
    pub center: GraphNodeRecord,
    pub nodes: Vec<GraphNodeRecord>,
    pub edges: Vec<GraphEdgeRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexRunRecord {
    pub id: String,
    pub project_id: String,
    pub status: AnalysisStatus,
    pub analyzer_version: String,
    pub query_version: Option<String>,
    pub config_fingerprint: Option<String>,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub duration_ms: Option<u64>,
    pub delta: IndexDelta,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SymbolSearchMode {
    Exact,
    Prefix,
    Substring,
}

impl SymbolSearchMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Prefix => "prefix",
            Self::Substring => "substring",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymbolSearchQuery {
    pub query: String,
    pub mode: SymbolSearchMode,
    pub kind: Option<String>,
    pub language: Option<String>,
    pub file: Option<String>,
    pub qualified_only: bool,
    pub limit: usize,
}
