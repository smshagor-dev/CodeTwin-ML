pub mod db;
pub mod domain;
pub mod identity;
pub mod impact_analysis;
pub mod import_resolver;
pub mod persistent_index;
pub mod query_service;

pub use db::{Database, DatabaseError};
pub use domain::{
    AnalysisRun, AnalysisStatus, EvidenceKind, FindingSeverity, GraphEdgeRecord, GraphNeighborhood,
    GraphNodeRecord, GraphSummary, ImportReferenceRecord, ImportResolutionState, IndexDelta,
    IndexRunRecord, IndexSummary, ProjectRecord, SourceFileRecord, SymbolRecord, SymbolSearchMode,
    SymbolSearchQuery,
};
pub use identity::{
    deterministic_id, file_id, graph_edge_id, graph_node_id, is_windows_path_identity,
    normalize_path_identity, normalize_path_text, normalize_relative_path, project_id,
    symbol_fingerprint,
};
pub use impact_analysis::{
    ImpactAnalysisError, ImpactAnalysisService, ImpactReport, ImpactedFileRecord,
};
pub use import_resolver::{resolve_import, ResolvedImport};
pub use persistent_index::{IndexServiceError, ProjectIndexService};
pub use query_service::{ProjectQueryService, QueryServiceError};
