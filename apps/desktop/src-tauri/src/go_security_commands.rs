use std::{
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use codetwin_core::{
    native_agent_delegation::NativeDelegation,
    native_agent_memory::AgentMemory,
    native_agents::{AgentRun, AgentStep, NativeAgents},
    native_task_plans::{parse_proposal, validate_proposal, TaskProposal},
    Database, WorkspaceService,
};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use tauri::Manager;

use crate::{reserve_assessment, AppState};

const MAX_RESPONSE_BYTES: usize = 6000;
const PLANNER_TIMEOUT: Duration = Duration::from_secs(10);
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Serialize)]
pub struct GoSecurityReadiness {
    configured: bool,
    detail: String,
}

fn binary_path() -> Result<PathBuf, String> {
    if let Some(value) = std::env::var_os("CODETWIN_GO_SECURITY_BIN") {
        let path = PathBuf::from(value);
        if !path.is_absolute() || !path.is_file() {
            return Err("Go engine override must be an existing absolute executable path".into());
        }
        return Ok(path);
    }
    let current =
        std::env::current_exe().map_err(|_| "Cannot locate the CodeTwin desktop executable")?;
    let name = if cfg!(windows) {
        "codetwin-security.exe"
    } else {
        "codetwin-security"
    };
    let path = current
        .parent()
        .ok_or("Cannot resolve CodeTwin desktop binary directory")?
        .join(name);
    if path.is_file() {
        return Ok(path);
    }
    // Tauri dev builds compile the companion into the Tauri source tree,
    // while release bundles install it alongside the desktop executable.
    #[cfg(debug_assertions)]
    {
        let target = env!("TAURI_ENV_TARGET_TRIPLE");
        let suffix = if cfg!(windows) { ".exe" } else { "" };
        let candidate = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("binaries")
            .join(format!("codetwin-security-{target}{suffix}"));
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err("Go security companion was not found; build it with npm run build:go-sidecar".into())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GoHealth {
    engine: String,
    protocol_version: u8,
    storage: String,
    functions: Vec<String>,
}

/// A bounded handshake prevents accidentally dispatching to an unrelated program.
fn probe_binary(binary: &Path) -> Result<(), String> {
    let mut child = Command::new(binary)
        .arg("--health")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "Cannot launch Go security engine for health check")?;
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let output = child
                    .wait_with_output()
                    .map_err(|_| "Cannot read Go security engine health result")?;
                if !status.success() || output.stdout.len() > 512 {
                    return Err("Go security engine handshake failed".into());
                }
                let health: GoHealth = serde_json::from_slice(&output.stdout)
                    .map_err(|_| "Go security engine handshake was not valid JSON")?;
                if health.engine != "codetwin-security"
                    || health.protocol_version != 1
                    || health.storage != "rust-sqlite"
                    || !health.functions.iter().any(|feature| feature == "plan")
                    || !health.functions.iter().any(|feature| feature == "dispatch")
                    || !health.functions.iter().any(|feature| feature == "refine")
                {
                    return Err("Incompatible Go security engine protocol".into());
                }
                return Ok(());
            }
            Ok(None) if start.elapsed() < PROBE_TIMEOUT => {
                thread::sleep(Duration::from_millis(20));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("Go security engine handshake timed out".into());
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("Go security engine handshake process failed".into());
            }
        }
    }
}

#[tauri::command]
pub fn go_security_engine_readiness() -> GoSecurityReadiness {
    match binary_path().and_then(|path| probe_binary(&path)) {
        Ok(()) => GoSecurityReadiness {
            configured: true,
            detail: "Bundled Go planner verified; approved reviews use SQLite".into(),
        },
        Err(reason) => GoSecurityReadiness {
            configured: false,
            detail: reason,
        },
    }
}

#[derive(Serialize)]
struct MemoryHint {
    role: String,
    status: String,
}

#[derive(Serialize)]
struct PlannerRequest<'a> {
    protocol_version: u8,
    objective: &'a str,
    history: &'a [MemoryHint],
}

fn local_plan(
    binary: &Path,
    objective: &str,
    history: &[MemoryHint],
) -> Result<TaskProposal, String> {
    probe_binary(binary)?;
    let request = serde_json::to_vec(&PlannerRequest {
        protocol_version: 1,
        objective,
        history,
    })
    .map_err(|_| "Cannot encode Go security plan request")?;
    let mut child = Command::new(binary)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "Cannot start configured Go security engine")?;
    let write_result = child
        .stdin
        .take()
        .ok_or_else(|| "Go security engine stdin was unavailable".to_string())
        .and_then(|mut stdin| {
            stdin
                .write_all(&request)
                .map_err(|_| "Go security engine rejected its input".to_string())
        });
    if let Err(reason) = write_result {
        let _ = child.kill();
        let _ = child.wait();
        return Err(reason);
    }
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let output = child
                    .wait_with_output()
                    .map_err(|_| "Cannot read Go security engine response")?;
                if !status.success() {
                    return Err("Go security engine rejected the plan request".into());
                }
                if output.stdout.len() > MAX_RESPONSE_BYTES {
                    return Err("Go security engine response exceeded the limit".into());
                }
                let response = String::from_utf8(output.stdout)
                    .map_err(|_| "Go security engine response is not UTF-8")?;
                let (proposal, _) = parse_proposal(response.trim())?;
                return Ok(proposal);
            }
            Ok(None) if start.elapsed() < PLANNER_TIMEOUT => {
                thread::sleep(Duration::from_millis(25));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("Go security planner timed out".into());
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("Go security planner process failed".into());
            }
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GoRefineOperation {
    pub op: String,
    pub role: String,
    pub objective: Option<String>,
    pub after_role: Option<String>,
}

/// Adapted Go task-delta algorithm runs as a no-network, no-SQLite process.
/// Rust checks the *input and output* against the approved passive role DAG.
fn local_refine(
    binary: &Path,
    current: &TaskProposal,
    operations: &[GoRefineOperation],
) -> Result<TaskProposal, String> {
    validate_proposal(current)?;
    if operations.is_empty() || operations.len() > 8 {
        return Err("Provide 1-8 bounded task refinements".into());
    }
    for operation in operations {
        if !matches!(operation.op.as_str(), "add" | "modify" | "remove")
            || !matches!(
                operation.role.as_str(),
                "secrets" | "qa" | "database" | "runtime"
            )
            || operation.after_role.is_some()
            || (operation.op != "remove"
                && operation
                    .objective
                    .as_ref()
                    .is_none_or(|value| value.trim().is_empty() || value.len() > 300))
        {
            return Err("Unsupported or unsafe specialist refinement".into());
        }
    }
    probe_binary(binary)?;
    let body = serde_json::to_vec(&serde_json::json!({
        "protocol_version": 1,
        "current": current,
        "operations": operations
    }))
    .map_err(|_| "Cannot encode Go refinement request")?;
    if body.len() > 8192 {
        return Err("Go refinement request exceeds the size budget".into());
    }
    let mut child = Command::new(binary)
        .arg("--refine")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "Cannot start Go subtask refinement")?;
    let write_result = child
        .stdin
        .take()
        .ok_or_else(|| "Go subtask refinement stdin unavailable".to_string())
        .and_then(|mut stdin| {
            stdin
                .write_all(&body)
                .map_err(|_| "Go subtask refinement input failed".to_string())
        });
    if let Err(error) = write_result {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error);
    }
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let output = child
                    .wait_with_output()
                    .map_err(|_| "Cannot read Go refinement output")?;
                if !status.success() || output.stdout.len() > MAX_RESPONSE_BYTES {
                    return Err("Go rejected the refinement request".into());
                }
                let response = String::from_utf8(output.stdout)
                    .map_err(|_| "Go refinement response was not UTF-8")?;
                let (proposal, _) = parse_proposal(response.trim())?;
                return Ok(proposal);
            }
            Ok(None) if start.elapsed() < PLANNER_TIMEOUT => {
                thread::sleep(Duration::from_millis(25));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("Go subtask refinement timed out".into());
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("Go subtask refinement process failed".into());
            }
        }
    }
}

#[tauri::command]
pub async fn refine_go_security_task_plan(
    project_id: String,
    current: TaskProposal,
    operations: Vec<GoRefineOperation>,
    app: tauri::AppHandle,
) -> Result<TaskProposal, String> {
    validate_proposal(&current)?;
    let binary = binary_path()?;
    let folder = app
        .path()
        .app_data_dir()
        .map_err(|error| error.to_string())?;
    tauri::async_runtime::spawn_blocking(move || {
        let db =
            Database::open(folder.join("codetwin.sqlite3")).map_err(|error| error.to_string())?;
        let project = WorkspaceService::new(&db)
            .get_project(&project_id)
            .map_err(|error| error.to_string())?
            .ok_or("Select an indexed project")?;
        if project.last_indexed_at.is_none() || project.file_count == 0 {
            return Err("Index a nonempty project before refining its task plan".into());
        }
        local_refine(&binary, &current, &operations)
    })
    .await
    .map_err(|error| error.to_string())?
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GoDispatchAdvice {
    pub ready: Vec<String>,
    pub waiting: Vec<String>,
    pub running: Vec<String>,
    pub terminal: bool,
    pub reason: String,
}

/// Sidecar-proposed schedule is advisory; Rust independently checks the ready set.
fn local_dispatch(binary: &Path, request: &serde_json::Value) -> Result<GoDispatchAdvice, String> {
    probe_binary(binary)?;
    let body = serde_json::to_vec(request).map_err(|_| "Cannot encode approved task graph")?;
    if body.len() > 8192 {
        return Err("Approved task graph exceeds protocol limit".into());
    }
    let mut child = Command::new(binary)
        .arg("--dispatch")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "Cannot start local Go scheduler")?;
    let write_result = child
        .stdin
        .take()
        .ok_or_else(|| "Go scheduler stdin is unavailable".to_string())
        .and_then(|mut stdin| {
            stdin
                .write_all(&body)
                .map_err(|_| "Go scheduler input failed".to_string())
        });
    if let Err(error) = write_result {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error);
    }
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let output = child
                    .wait_with_output()
                    .map_err(|_| "Cannot read local Go scheduler output")?;
                if !status.success() || output.stdout.len() > 4096 {
                    return Err("Local Go scheduler rejected the persisted graph".into());
                }
                return serde_json::from_slice(&output.stdout)
                    .map_err(|_| "Invalid Go scheduling response".into());
            }
            Ok(None) if start.elapsed() < PLANNER_TIMEOUT => {
                thread::sleep(Duration::from_millis(25));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("Local Go scheduler timed out".into());
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("Local Go scheduler process failed".into());
            }
        }
    }
}

/// The Go suggestion is untrusted until it matches the Rust/SQLite dependency graph.
fn verified_dispatch(db: &Database, id: &str, binary: &Path) -> Result<GoDispatchAdvice, String> {
    let run = NativeAgents::new(db).get(id)?;
    let graph = NativeDelegation::new(db).graph(id)?;
    if graph.run_id != run.id || graph.tasks.len() != run.steps.len() {
        return Err("Persisted review graph mismatch".into());
    }
    let positions = graph
        .tasks
        .iter()
        .map(|task| (task.position, task.tool.as_str()))
        .collect::<std::collections::BTreeMap<_, _>>();
    let tasks = graph
        .tasks
        .iter()
        .map(|task| {
            let depends_on = task
                .requires
                .iter()
                .map(|position| {
                    positions
                        .get(position)
                        .copied()
                        .ok_or("Missing predecessor")
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(serde_json::json!({
                "role": task.tool,
                "status": task.status,
                "depends_on": depends_on
            }))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let request = serde_json::json!({
        "protocol_version": 1,
        "run_status": run.status,
        "max_parallel": 2,
        "tasks": tasks
    });
    let advice = local_dispatch(binary, &request)?;
    let running = graph
        .tasks
        .iter()
        .filter(|task| task.status == "running")
        .count();
    let has_failure = graph
        .tasks
        .iter()
        .any(|task| task.status == "failed" || task.status == "cancelled");
    let can_dispatch =
        matches!(run.status.as_str(), "approved" | "running") && !has_failure && running <= 2;
    let expected = if can_dispatch {
        graph
            .tasks
            .iter()
            .filter(|task| task.status == "pending")
            .filter(|task| {
                task.requires.iter().all(|required| {
                    graph.tasks.iter().any(|predecessor| {
                        predecessor.position == *required && predecessor.status == "completed"
                    })
                })
            })
            .take(2usize.saturating_sub(running))
            .map(|task| task.tool.clone())
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    if advice.ready != expected {
        return Err("Go scheduling recommendation did not match Rust authorization graph".into());
    }
    Ok(advice)
}

#[tauri::command]
pub async fn go_security_dispatch_preview(
    id: String,
    app: tauri::AppHandle,
) -> Result<GoDispatchAdvice, String> {
    let binary = binary_path()?;
    let folder = app
        .path()
        .app_data_dir()
        .map_err(|error| error.to_string())?;
    tauri::async_runtime::spawn_blocking(move || {
        let db =
            Database::open(folder.join("codetwin.sqlite3")).map_err(|error| error.to_string())?;
        verified_dispatch(&db, &id, &binary)
    })
    .await
    .map_err(|error| error.to_string())?
}

#[derive(Debug, Serialize)]
pub struct GoDispatchAuditRecord {
    id: i64,
    position: usize,
    role: String,
    verdict: String,
    ready: Vec<String>,
    reason: String,
    created_at: String,
}

fn record_dispatch(
    db: &Database,
    run: &AgentRun,
    step: &AgentStep,
    ready: &[String],
    allowed: bool,
    reason: &str,
) -> Result<(), String> {
    let ready_json =
        serde_json::to_string(ready).map_err(|_| "Cannot encode Go scheduling audit")?;
    db.connection()
        .execute(
            "INSERT INTO go_dispatch_audit(run_id,position,role,verdict,ready_json,reason)
         VALUES (?1,?2,?3,?4,?5,?6)",
            params![
                run.id,
                step.position,
                step.tool,
                if allowed { "allowed" } else { "denied" },
                ready_json,
                reason,
            ],
        )
        .map_err(|error| error.to_string())?;
    Ok(())
}

fn verify_and_record_go_step(
    db: &Database,
    run: &AgentRun,
    step: &AgentStep,
    binary: &Path,
) -> Result<(), String> {
    match verified_dispatch(db, &run.id, binary) {
        Ok(advice) => {
            let allowed = advice.ready.iter().any(|role| role == &step.tool);
            record_dispatch(
                db,
                run,
                step,
                &advice.ready,
                allowed,
                if allowed {
                    "approved role is dependency-ready"
                } else {
                    "role was not dependency-ready"
                },
            )?;
            if allowed {
                Ok(())
            } else {
                Err("Go scheduler refused the next unverified specialist".into())
            }
        }
        Err(error) => {
            record_dispatch(db, run, step, &[], false, "Go dispatch verification failed")?;
            Err(error)
        }
    }
}

#[tauri::command]
pub fn list_go_dispatch_audit(
    id: String,
    app: tauri::AppHandle,
) -> Result<Vec<GoDispatchAuditRecord>, String> {
    let folder = app
        .path()
        .app_data_dir()
        .map_err(|error| error.to_string())?;
    let db = Database::open(folder.join("codetwin.sqlite3")).map_err(|error| error.to_string())?;
    let _ = NativeAgents::new(&db).get(&id)?;
    let mut statement = db
        .connection()
        .prepare(
            "SELECT id,position,role,verdict,ready_json,reason,created_at
         FROM go_dispatch_audit WHERE run_id=?1 ORDER BY id DESC LIMIT 100",
        )
        .map_err(|error| error.to_string())?;
    let saved = statement
        .query_map([id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, usize>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
            ))
        })
        .map_err(|error| error.to_string())?;
    saved
        .map(|row| {
            let (id, position, role, verdict, ready_json, reason, created_at) =
                row.map_err(|error| error.to_string())?;
            let ready = serde_json::from_str(&ready_json)
                .map_err(|_| "Invalid persisted Go audit payload")?;
            Ok(GoDispatchAuditRecord {
                id,
                position,
                role,
                verdict,
                ready,
                reason,
                created_at,
            })
        })
        .collect()
}

/// Run the existing approved Rust specialists with a Go dispatch-policy check
/// before *each* step. No unapproved sidecar command is ever executed.
#[tauri::command]
pub async fn run_native_go_review(
    id: String,
    state: tauri::State<'_, AppState>,
) -> Result<AgentRun, String> {
    let reservations = reserve_assessment(&state)?;
    let binary = binary_path()?;
    let path = state.database_path.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let _reservations = reservations;
        let db = Database::open(path).map_err(|error| error.to_string())?;
        let check = |db: &Database, run: &AgentRun, step: &AgentStep| {
            verify_and_record_go_step(db, run, step, &binary)
        };
        NativeAgents::new(&db).execute_with_dispatch(&id, &check)
    })
    .await
    .map_err(|error| error.to_string())?
}

#[tauri::command]
pub async fn suggest_go_security_task_plan(
    project_id: String,
    objective: String,
    app: tauri::AppHandle,
) -> Result<TaskProposal, String> {
    if objective.trim().is_empty() || objective.len() > 2000 {
        return Err("Review objective must be 1–2000 bytes".into());
    }
    let binary = binary_path()?;
    let root = app
        .path()
        .app_data_dir()
        .map_err(|error| error.to_string())?;
    tauri::async_runtime::spawn_blocking(move || {
        let db =
            Database::open(root.join("codetwin.sqlite3")).map_err(|error| error.to_string())?;
        let project = WorkspaceService::new(&db)
            .get_project(&project_id)
            .map_err(|error| error.to_string())?
            .ok_or("Select an indexed project")?;
        if project.last_indexed_at.is_none() || project.file_count == 0 {
            return Err("Index a nonempty project before requesting a Go task plan".into());
        }
        let history = AgentMemory::new(&db)
            .search(&project_id, "", 12)?
            .into_iter()
            .map(|entry| MemoryHint {
                role: entry.tool,
                status: entry.status,
            })
            .collect::<Vec<_>>();
        local_plan(&binary, &objective, &history)
    })
    .await
    .map_err(|error| error.to_string())?
}

#[cfg(test)]
mod tests {
    use super::{local_plan, MemoryHint};
    use std::path::PathBuf;

    #[test]
    fn bundled_go_process_executes_approved_rust_review_with_sqlite() {
        if std::env::var("CODETWIN_TEST_GO_SIDECAR").ok().as_deref() != Some("1") {
            return;
        }
        let target = env!("TAURI_ENV_TARGET_TRIPLE");
        let suffix = if cfg!(windows) { ".exe" } else { "" };
        let binary = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("binaries")
            .join(format!("codetwin-security-{target}{suffix}"));
        let sandbox = tempfile::tempdir().expect("isolated SQLite fixture");
        let db = super::Database::open(sandbox.path().join("review.sqlite3"))
            .expect("open SQLite WAL database");
        let source = sandbox.path().join("project");
        std::fs::create_dir_all(&source).expect("create indexed project");
        std::fs::write(source.join("source.ts"), "export const valid = true;")
            .expect("write benign test source");
        let project_id = codetwin_core::ProjectIndexService::new(&db)
            .index_project(&source)
            .expect("index approved source")
            .project_id;
        let reviews = super::NativeAgents::new(&db);
        let run = reviews
            .create_with_roles(
                &project_id,
                "Review source for quality and security",
                10,
                300,
                &["scout".to_string(), "source".to_string()],
            )
            .expect("prepare source review");
        reviews.approve(&run.id).expect("explicitly approve review");
        let check = |db: &super::Database, run: &super::AgentRun, step: &super::AgentStep| {
            super::verify_and_record_go_step(db, run, step, &binary)
        };
        let result = reviews
            .execute_with_dispatch(&run.id, &check)
            .expect("complete Rust review with real Go dispatch checks");
        assert_eq!(result.status, "completed", "{:?}", result.message);
        assert!(result.steps.iter().all(|step| step.status == "completed"));
        let evidence = codetwin_core::native_agent_handoffs::AgentHandoffs::new(&db)
            .verify(&run.id)
            .expect("verify persisted SQLite evidence handoff");
        assert!(evidence.verified, "{:?}", evidence.issues);
        let allowed: i64 = db
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM go_dispatch_audit WHERE run_id=?1 AND verdict='allowed'",
                [&run.id],
                |row| row.get(0),
            )
            .expect("count persisted scheduling decisions");
        assert_eq!(allowed, 2);
        let receipts = codetwin_core::native_action_log::NativeActionLog::new(&db)
            .list(&run.id)
            .expect("read Go-gated specialist action receipts");
        assert_eq!(receipts.len(), 2);
        assert!(receipts.iter().all(|receipt| receipt.status == "completed"));
    }

    #[test]
    fn bundled_go_refinement_preserves_rust_role_validation() {
        if std::env::var("CODETWIN_TEST_GO_SIDECAR").ok().as_deref() != Some("1") {
            return;
        }
        let target = env!("TAURI_ENV_TARGET_TRIPLE");
        let suffix = if cfg!(windows) { ".exe" } else { "" };
        let binary = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("binaries")
            .join(format!("codetwin-security-{target}{suffix}"));
        let plan = codetwin_core::native_task_plans::TaskProposal {
            tasks: vec![
                codetwin_core::native_task_plans::PlannedSpecialist {
                    role: "scout".into(),
                    objective: "Inventory indexed source".into(),
                    depends_on: vec![],
                },
                codetwin_core::native_task_plans::PlannedSpecialist {
                    role: "source".into(),
                    objective: "Review source evidence".into(),
                    depends_on: vec!["scout".into()],
                },
                codetwin_core::native_task_plans::PlannedSpecialist {
                    role: "qa".into(),
                    objective: "Audit test coverage".into(),
                    depends_on: vec!["source".into()],
                },
            ],
            rationale: "Unapproved passive task review".into(),
        };
        let edited = super::local_refine(
            &binary,
            &plan,
            &[super::GoRefineOperation {
                op: "modify".into(),
                role: "qa".into(),
                objective: Some("Review regression tests and missing coverage".into()),
                after_role: None,
            }],
        )
        .expect("real upstream-derived Go patch must return a valid Rust DAG");
        assert_eq!(
            edited.tasks[2].objective,
            "Review regression tests and missing coverage"
        );
        assert_eq!(edited.tasks[2].depends_on, ["source"]);
        assert!(super::local_refine(
            &binary,
            &plan,
            &[super::GoRefineOperation {
                op: "remove".into(),
                role: "scout".into(),
                objective: None,
                after_role: None,
            }]
        )
        .is_err());
    }

    #[test]
    fn bundled_go_process_roundtrips_review_memory() {
        if std::env::var("CODETWIN_TEST_GO_SIDECAR").ok().as_deref() != Some("1") {
            return;
        }
        let target = env!("TAURI_ENV_TARGET_TRIPLE");
        let suffix = if cfg!(windows) { ".exe" } else { "" };
        let binary = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("binaries")
            .join(format!("codetwin-security-{target}{suffix}"));
        assert!(
            binary.is_file(),
            "build the target-specific Go companion before testing"
        );
        let context = [MemoryHint {
            role: "secrets".to_owned(),
            status: "failed".to_owned(),
        }];
        let proposed = local_plan(&binary, "Review test coverage", &context)
            .expect("real Go process must complete the bounded protocol");
        let roles = proposed
            .tasks
            .iter()
            .map(|task| task.role.as_str())
            .collect::<Vec<_>>();
        assert_eq!(roles, ["scout", "source", "secrets", "qa"]);
        let input = serde_json::json!({
            "protocol_version": 1,
            "run_status": "approved",
            "max_parallel": 2,
            "tasks": [
                {"role":"scout","status":"pending","depends_on":[]},
                {"role":"source","status":"pending","depends_on":["scout"]},
                {"role":"qa","status":"pending","depends_on":["source"]}
            ]
        });
        let preview = super::local_dispatch(&binary, &input)
            .expect("real Go process must validate approved specialist dependency graph");
        assert_eq!(preview.ready, ["scout"]);
        assert!(!preview.terminal);
    }
}
