pub mod database_analysis;
pub mod db;
pub mod domain;
pub mod identity;
pub mod impact_analysis;
pub mod import_resolver;
pub mod ml_inference;
pub mod persistent_index;
pub mod qa_discovery;
pub mod qa_execution;
pub mod quality_analysis;
pub mod query_service;
pub mod repair_application;
pub mod repair_workflow;
pub mod repair_workspace;
pub mod runtime_analysis;
pub mod security_analysis;
pub mod semantic_config;
pub mod semantic_domain;
pub mod semantic_query;
pub mod semantic_resolution;
pub mod semantic_service;
pub mod symbol_reference;
pub mod workspace;
pub mod web_security;

pub use database_analysis::{
    DatabaseAnalysisError, DatabaseAnalysisService, DatabaseArtifactRecord, DatabaseFindingRecord,
    DatabaseRuleRecord, DatabaseRunRecord, DatabaseRunSummary,
};
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
pub use lsp_enrichment::{LanguageServerConfig, LanguageServerKind};
pub use ml_inference::{
    MlFindingLinkRecord, MlInferenceError, MlInferenceObservation, MlInferenceRecord,
    MlInferenceStore, MlScore,
};
pub use persistent_index::{IndexServiceError, ProjectIndexService};
pub use qa_discovery::{
    QaArtifactRecord, QaDiscoveryError, QaDiscoveryRunRecord, QaDiscoveryRunSummary,
    QaDiscoveryService, QaFrameworkSummary,
};
pub use qa_execution::{
    QaExecutionAvailability, QaExecutionError, QaExecutionPlanRecord, QaExecutionProjectManifest,
    QaExecutionService,
};
pub use quality_analysis::{
    CodeQualityService, FindingEvidenceRecord, QualityAnalysisError, QualityFindingRecord,
    QualityRuleRecord, QualityRunRecord, QualityRunSummary,
};
pub use query_service::{ProjectQueryService, QueryServiceError};
pub use repair_application::{
    RepairApplicationError, RepairApplicationItemRecord, RepairApplicationRunRecord,
    RepairApplicationService,
};
pub use repair_workflow::{
    RepairChangeRecord, RepairPlanRecord, RepairVerificationItemRecord,
    RepairVerificationRunRecord, RepairWorkflowError, VerifiedRepairService,
};
pub use repair_workspace::{
    RepairFindingRecord, RepairSourceSnapshot, RepairWorkspaceError, RepairWorkspaceQueryService,
};
pub use runtime_analysis::{
    RuntimeAnalysisError, RuntimeArtifactRecord, RuntimeFindingRecord, RuntimeReliabilityService,
    RuntimeRuleRecord, RuntimeRunRecord, RuntimeRunSummary,
};
pub use security_analysis::{
    CodeSecurityService, SecurityAnalysisError, SecurityFindingRecord, SecurityRuleRecord,
    SecurityRunRecord, SecurityRunSummary,
};
pub use semantic_config::{LanguageServerConfigService, SemanticConfigError};
pub use semantic_domain::{
    LanguageServerConfigRecord, SemanticEnrichmentRequest, SemanticImportResolutionRecord,
    SemanticRelationDirection, SemanticRelationRecord, SemanticRunRecord, SemanticRunSummary,
    SemanticServerRun, SemanticServerStatus, SemanticSymbolState, SemanticSymbolStateRecord,
};
pub use semantic_query::{SemanticQueryError, SemanticQueryService};
pub use semantic_resolution::{
    SemanticReferenceRecord, SemanticResolutionError, SemanticResolutionSummary,
    SemanticSymbolResolver,
};
pub use semantic_service::{SemanticEnrichmentService, SemanticServiceError};
pub use symbol_reference::{
    ReferenceRefreshSummary, SymbolReferenceError, SymbolReferenceObservationRecord,
    SymbolReferenceService,
};

pub use workspace::{
    normalize_website_url, AppPreferences, ProjectOverview, WebsiteInput, WebsiteRecord,
    WorkspaceActivity, WorkspaceError, WorkspaceSearchResult, WorkspaceService, WorkspaceSummary,
};

pub use web_security::{
    AuthorizedWebSecurityStore, WebEndpointInput, WebEndpointRecord, WebEvidenceInput,
    WebEvidenceRecord, WebFindingFilter, WebFindingInput, WebFindingRecord, WebScanCreate,
    WebScanRecord, WebSecurityStoreError, WebSourceCorrelation,
};
