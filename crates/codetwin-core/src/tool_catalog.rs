//! A read-only workflow registry. Catalog entries never grant execution capabilities.
use crate::{Database, LanguageServerConfigService, QaExecutionService, WorkspaceService};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ToolWorkflow {
    Projects,
    Security,
    Testing,
    Integrations,
    Engineering,
    Database,
    Runtime,
    Repair,
    WebSecurity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolAvailability {
    Available,
    RequiresSetup,
    Blocked,
    Planned,
}

#[derive(Debug, Deserialize)]
struct Metadata {
    id: String,
    name: String,
    category: String,
    description: String,
    roadmap: String,
}

#[derive(Debug, Serialize)]
pub struct CatalogTool {
    pub id: String,
    pub name: String,
    pub category: String,
    pub description: String,
    pub roadmap: String,
    pub definition_version: u32,
    pub availability: ToolAvailability,
    pub reason: String,
    pub operation_kind: String,
    pub prerequisites: Vec<String>,
    pub platforms: Vec<String>,
    pub coverage: String,
    pub workflow: Option<ToolWorkflow>,
    pub setup_workflow: Option<ToolWorkflow>,
}

struct RegisteredWorkflow {
    workflow: ToolWorkflow,
    project: bool,
    operation: &'static str,
    prerequisites: &'static [&'static str],
    coverage: &'static str,
}

// Registration is explicit and compiled. Metadata cannot invent a handler or shell command.
fn registered(id: &str) -> Option<RegisteredWorkflow> {
    use ToolWorkflow::*;
    let (workflow, project, operation, prerequisites, coverage): (_, _, _, &[&str], _) = match id {
        "code.index" => (Projects, false, "passive", &["A readable local project folder"], "Supported source grammars; incremental indexing does not execute project code."),
        "code.sast" => (Security, true, "passive", &["Fresh source index"], "Selected deterministic rules and supported taint flows; not proof of exploitability."),
        "code.semantics" => (Engineering, true, "external_execution", &["Enabled trusted language-server configuration", "Explicit enrichment action"], "Supported language servers only; external execution remains explicit."),
        "code.secrets" => (Security, true, "passive", &["Readable project files"], "Bounded text scans with redacted findings; binary/oversized files may be skipped."),
        "code.history-secrets" => (Security, true, "passive_git", &["Git installed", "A local Git repository"], "Reachable refs within configured scan bounds; no dangling-object or submodule coverage."),
        "supply.dependencies" => (Security, true, "passive_or_consented_network", &["Supported exact-version dependency manifests", "Offline advisories or consented online lookup"], "Known advisories for supported resolved versions; unknown versions are not guessed."),
        "supply.sbom" => (Security, true, "export", &["Dependency inventory", "Explicit export destination"], "CycloneDX component/vulnerability export; no complete dependency graph claim."),
        "web.scoped-scan" | "web.identity" => (Security, false, "scoped_network", &["Authorized target and bounded scope", "Approved operations", "Test identities for access checks"], "Supported scoped checks; role/tenant coverage depends on supplied identities and fixtures."),
        "infra.containers" => (Runtime, true, "passive", &["Supported Dockerfile/Compose artifacts"], "Passive configuration checks only; does not scan images or start containers."),
        "infra.database" => (Database, true, "passive", &["Supported SQL/Prisma artifacts"], "Passive artifact review; does not connect to a database."),
        "qa.discovery" => (Testing, true, "passive", &["Readable supported test/config artifacts"], "Discovery proves presence, not successful test execution."),
        "qa.execution" => (Testing, true, "isolated_execution", &["Strict OS backend", "Trusted hash-pinned runner", "Approved project/runtime manifests and plan"], "Windows strict backend only; launch can still be blocked by plan or isolation checks."),
        "validation.benchmarks" => (Security, false, "offline_benchmark", &["Installed integrity-checked datasets", "Selected supported benchmark"], "Dataset-specific results with provenance; does not establish global accuracy."),
        "findings.review" => (Security, true, "local_record_write", &["Persisted finding and matching evidence identity", "Reviewer reason"], "Human feedback remains separate from scanner resolution and benchmark accuracy."),
        "findings.comparison" => (Security, false, "evidence_review", &["Two persisted guided scan runs"], "Guided web scan comparison only; not a general cross-engine comparison."),
        "repair.verified" => (Repair, true, "reviewed_write", &["Reviewed candidate diff", "Matching source hashes", "Explicit approval and verification"], "Hash-guarded repairs, rollback and selected verification; not automatic universal repair."),
        "git.publication" => (Projects, true, "explicit_publication", &["Git repository root and reviewed HEAD", "GitHub Contents/Pull requests write token", "Remote parent exists; non-default destination branch"], "One unsigned SHA-1 UTF-8 commit, hash-verified REST upload and separate same-repository draft PR; no force or full-history push."),
        "git.review" => (Projects, true, "passive_git", &["Git installed", "Project is a Git repository root"], "Bounded read-only status/diff; opening this workflow does not probe Git or mutate the index."),
        _ => return None,
    };
    Some(RegisteredWorkflow {
        workflow,
        project,
        operation,
        prerequisites,
        coverage,
    })
}

#[derive(Debug, Serialize)]
pub struct CatalogRunSummary {
    pub id: String,
    pub source: String,
    pub project_id: Option<String>,
    pub kind: String,
    pub status: String,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub duration_ms: Option<i64>,
    pub tests_passed: Option<bool>,
}

pub struct ToolCatalogService<'a> {
    database: &'a Database,
}
impl<'a> ToolCatalogService<'a> {
    pub const fn new(database: &'a Database) -> Self {
        Self { database }
    }

    pub fn recent_runs(
        &self,
        project_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<CatalogRunSummary>, String> {
        // Reuse existing provenance stores; no new scheduler or lifecycle is implied.
        if let Some(id) = project_id {
            WorkspaceService::new(self.database)
                .get_project(id)
                .map_err(|error| error.to_string())?
                .ok_or_else(|| "Selected project no longer exists".to_string())?;
        }
        let mut statement = self.database.connection().prepare(
            "SELECT id,source,project_id,kind,status,started_at,finished_at,duration_ms,tests_passed FROM (
               SELECT id,'analysis' AS source,project_id,run_kind AS kind,status,started_at,finished_at,duration_ms,NULL AS tests_passed,COALESCE(started_at,'') AS sort_time,rowid AS sequence FROM analysis_runs WHERE (?1 IS NULL OR project_id=?1)
               UNION ALL
               SELECT id,'web',project_id,'authorized_web_scan',status,started_at,finished_at,NULL,NULL,COALESCE(started_at,created_at),rowid FROM web_security_scans WHERE (?1 IS NULL OR project_id=?1)
               UNION ALL
               SELECT id,'qa',project_id,'qa_execution',status,started_at,finished_at,duration_ms,CASE WHEN status='completed' AND parser_completed=1 THEN tests_passed ELSE NULL END,COALESCE(started_at,created_at),rowid FROM qa_execution_runs WHERE (?1 IS NULL OR project_id=?1)
             ) ORDER BY julianday(sort_time) DESC,source,sequence DESC LIMIT ?2"
        ).map_err(|error| error.to_string())?;
        let result = statement
            .query_map(
                rusqlite::params![project_id, limit.clamp(1, 100) as i64],
                |row| {
                    Ok(CatalogRunSummary {
                        id: row.get(0)?,
                        source: row.get(1)?,
                        project_id: row.get(2)?,
                        kind: row.get(3)?,
                        status: row.get(4)?,
                        started_at: row.get(5)?,
                        finished_at: row.get(6)?,
                        duration_ms: row.get(7)?,
                        tests_passed: row.get(8)?,
                    })
                },
            )
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string());
        result
    }

    pub fn list(&self, project_id: Option<&str>) -> Result<Vec<CatalogTool>, String> {
        let has_project = match project_id {
            None => false,
            Some(id) => WorkspaceService::new(self.database)
                .get_project(id)
                .map_err(|error| error.to_string())?
                .ok_or_else(|| {
                    "Selected project no longer exists; refresh the workspace".to_string()
                })
                .map(|_| true)?,
        };
        let language_server = LanguageServerConfigService::new(self.database)
            .list()
            .map_err(|error| error.to_string())?
            .iter()
            .any(|config| config.enabled && !config.executable_path.trim().is_empty());
        let qa = QaExecutionService::new(self.database).availability();
        build_catalog(
            has_project,
            language_server,
            qa.execution_enabled,
            &qa.reason,
        )
    }
}

fn build_catalog(
    has_project: bool,
    language_server: bool,
    qa_enabled: bool,
    qa_reason: &str,
) -> Result<Vec<CatalogTool>, String> {
    let metadata: Vec<Metadata> = serde_json::from_str(include_str!("tool_catalog.json"))
        .map_err(|error| error.to_string())?;
    metadata.into_iter().map(|item| {
        let registration = registered(&item.id);
        let mut row = CatalogTool {
            id: item.id, name: item.name, category: item.category, description: item.description, roadmap: item.roadmap,
            definition_version: 1, availability: ToolAvailability::Planned,
            reason: "This catalog capability has no registered desktop workflow yet.".into(),
            operation_kind: "unavailable".into(), prerequisites: Vec::new(), platforms: Vec::new(),
            coverage: "Planned capability; no execution or complete coverage is claimed.".into(), workflow: None, setup_workflow: None,
        };
        if let Some(registration) = registration {
            row.operation_kind = registration.operation.into();
            row.prerequisites = registration.prerequisites.iter().map(|value| (*value).into()).collect();
            row.platforms = if row.id == "qa.execution" { vec!["Windows".into()] } else { vec!["Desktop platforms with required dependencies".into()] };
            row.coverage = registration.coverage.into();
            if row.id == "qa.execution" && !qa_enabled {
                row.availability = ToolAvailability::Blocked; row.reason = qa_reason.into();
            } else if registration.project && !has_project {
                row.availability = ToolAvailability::RequiresSetup;
                row.reason = "Select or import a project before opening this workflow.".into(); row.setup_workflow = Some(ToolWorkflow::Projects);
            } else if row.id == "code.semantics" && !language_server {
                row.availability = ToolAvailability::RequiresSetup;
                row.reason = "Enable a trusted language-server configuration first.".into(); row.setup_workflow = Some(ToolWorkflow::Integrations);
            } else {
                row.availability = ToolAvailability::Available;
                row.reason = "Workflow is available. Targets, prerequisites and approvals are checked inside it before execution.".into();
                row.workflow = Some(registration.workflow);
            }
        }
        Ok(row)
    }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn planned_metadata_never_provides_execution_or_workflow() {
        let rows = build_catalog(true, true, true, "enabled").unwrap();
        assert_eq!(rows.len(), 41);
        let ids: std::collections::BTreeSet<_> = rows.iter().map(|row| &row.id).collect();
        assert_eq!(ids.len(), rows.len());
        for row in rows
            .iter()
            .filter(|row| row.availability == ToolAvailability::Planned)
        {
            assert!(row.workflow.is_none() && row.setup_workflow.is_none());
        }
        for id in ["binary.dynamic-lab", "ai.assistance", "reports.unified"] {
            assert_eq!(
                rows.iter().find(|row| row.id == id).unwrap().availability,
                ToolAvailability::Planned
            );
        }
    }
    #[test]
    fn publication_opens_projects_but_requires_setup_without_a_project() {
        let rows = build_catalog(false, true, true, "enabled").unwrap();
        let row = rows.iter().find(|row| row.id == "git.publication").unwrap();
        assert_eq!(row.availability, ToolAvailability::RequiresSetup);
        assert!(row.workflow.is_none());
        let rows = build_catalog(true, true, true, "enabled").unwrap();
        let row = rows.iter().find(|row| row.id == "git.publication").unwrap();
        assert_eq!(row.availability, ToolAvailability::Available);
        assert_eq!(row.workflow, Some(ToolWorkflow::Projects));
        assert_eq!(row.operation_kind, "explicit_publication");
    }
    #[test]
    fn project_and_lsp_requirements_are_independent() {
        let rows = build_catalog(false, false, true, "enabled").unwrap();
        assert_eq!(
            rows.iter()
                .find(|row| row.id == "code.sast")
                .unwrap()
                .availability,
            ToolAvailability::RequiresSetup
        );
        assert_eq!(
            rows.iter()
                .find(|row| row.id == "web.scoped-scan")
                .unwrap()
                .availability,
            ToolAvailability::Available
        );
        let rows = build_catalog(true, false, true, "enabled").unwrap();
        let lsp = rows.iter().find(|row| row.id == "code.semantics").unwrap();
        assert_eq!(lsp.setup_workflow, Some(ToolWorkflow::Integrations));
        assert!(lsp.workflow.is_none());
    }
    #[test]
    fn qa_missing_backend_blocks_even_with_project_and_configuration() {
        let rows = build_catalog(true, true, false, "Strict backend missing").unwrap();
        let qa = rows.iter().find(|row| row.id == "qa.execution").unwrap();
        assert_eq!(qa.availability, ToolAvailability::Blocked);
        assert!(qa.workflow.is_none());
        assert_eq!(qa.reason, "Strict backend missing");
    }
    #[test]
    fn missing_project_and_corrupt_config_are_not_silently_available() {
        let db = Database::open_in_memory().unwrap();
        let service = ToolCatalogService::new(&db);
        assert!(service.list(Some("missing")).is_err());
        assert!(service.list(None).is_ok());
        db.connection().execute("INSERT INTO settings(scope,key,value_json) VALUES ('application','lsp.server.typescript','bad json')", []).unwrap();
        assert!(service.list(None).is_err());
    }
    #[test]
    fn summaries_are_bounded_scoped_and_do_not_invent_test_verdicts() {
        let db = Database::open_in_memory().unwrap();
        db.connection().execute_batch("INSERT INTO projects(id,root_path,display_name) VALUES ('a','/a','A'),('b','/b','B');
          INSERT INTO analysis_runs(id,project_id,status,analyzer_version,run_kind,started_at) VALUES ('old','a','completed','v1','security_analysis','2026-10-11 10:00:00'),('other','b','failed','v1','source_index','2026-10-11 12:00:00');
          INSERT INTO web_security_scans(id,project_id,target_url,status,phase,authorization_confirmed,scope_json,config_json,auth_metadata_json,started_at) VALUES ('web','a','http://127.0.0.1','cancelled','cancelled',1,'{}','{}','{}','2026-10-11 11:00:00');").unwrap();
        db.connection().execute_batch("INSERT INTO qa_execution_plans(id,project_id,runner_kind,status,request_json,toolchain_json,policy_json,capabilities_json,command_json,provenance_json,approved_project_manifest_sha256,approved_project_manifest_json,approved_external_read_surface_sha256,approved_external_read_surface_json) VALUES ('plan','a','pytest','approved','{}','{}','{}','{}','{}','{}',printf('%064d',0),'{}',printf('%064d',0),'{}');
          INSERT INTO qa_execution_runs(id,plan_id,project_id,status,started_at,parser_completed,tests_passed,project_manifest_sha256,external_read_surface_sha256) VALUES ('incomplete-qa','plan','a','completed','2026-10-11T11:30:00Z',0,1,printf('%064d',0),printf('%064d',0)),('passed-qa','plan','a','completed','2026-10-11 11:35:00',1,1,printf('%064d',0),printf('%064d',0));").unwrap();
        let service = ToolCatalogService::new(&db);
        let runs = service.recent_runs(Some("a"), 1000).unwrap();
        assert_eq!(runs.len(), 4);
        assert_eq!(runs[0].source, "qa");
        assert_eq!(runs[0].tests_passed, Some(true));
        assert_eq!(runs[1].tests_passed, None);
        assert_eq!(runs[2].source, "web");
        assert_eq!(runs[2].status, "cancelled");
        assert!(runs[1..].iter().all(|run| run.tests_passed.is_none()));
        assert_eq!(service.recent_runs(None, 1).unwrap()[0].id, "other");
        assert!(service.recent_runs(Some("missing"), 20).is_err());
    }
}
