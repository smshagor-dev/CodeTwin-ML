pub mod db;
pub mod domain;
pub mod identity;
pub mod index_service;

pub use db::{Database, DatabaseError};
pub use domain::{
    AnalysisRun, AnalysisStatus, EvidenceKind, FindingSeverity, GraphSummary, ImportReferenceRecord,
    ImportResolutionState, IndexDelta, IndexSummary, ProjectRecord, SourceFileRecord, SymbolRecord,
};
pub use identity::{
    deterministic_id, file_id, graph_edge_id, graph_node_id, is_windows_path_identity,
    normalize_path_identity, normalize_path_text, normalize_relative_path, project_id,
    symbol_fingerprint,
};
pub use index_service::{IndexServiceError, ProjectIndexService};
