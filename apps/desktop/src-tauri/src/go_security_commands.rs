use std::{
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use codetwin_core::{
    native_agent_memory::AgentMemory,
    native_task_plans::{parse_proposal, TaskProposal},
    Database, WorkspaceService,
};
use serde::{Deserialize, Serialize};
use tauri::Manager;

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
    if !path.is_file() {
        return Err(
            "Bundled Go security engine missing; rebuild the Tauri application with Go installed"
                .into(),
        );
    }
    Ok(path)
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

fn local_plan(binary: &Path, objective: &str, history: &[MemoryHint]) -> Result<TaskProposal, String> {
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
