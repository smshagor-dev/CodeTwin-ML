use std::{
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use codetwin_core::{
    native_task_plans::{parse_proposal, TaskProposal},
    Database, WorkspaceService,
};
use serde::Serialize;
use tauri::Manager;

const MAX_RESPONSE_BYTES: usize = 6000;
const PLANNER_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Serialize)]
pub struct GoSecurityReadiness {
    configured: bool,
    detail: String,
}

fn binary_path() -> Result<PathBuf, String> {
    let value = std::env::var_os("CODETWIN_GO_SECURITY_BIN")
        .ok_or("Set CODETWIN_GO_SECURITY_BIN to the compiled local Go security engine")?;
    let path = PathBuf::from(value);
    if !path.is_absolute() || !path.is_file() {
        return Err("Go security engine must be an existing absolute executable path".into());
    }
    Ok(path)
}

#[tauri::command]
pub fn go_security_engine_readiness() -> GoSecurityReadiness {
    match binary_path() {
        Ok(_) => GoSecurityReadiness {
            configured: true,
            detail: "Local Go security planner is configured; no network or PostgreSQL required"
                .into(),
        },
        Err(reason) => GoSecurityReadiness {
            configured: false,
            detail: reason,
        },
    }
}

#[derive(Serialize)]
struct PlannerRequest<'a> {
    protocol_version: u8,
    objective: &'a str,
}

fn local_plan(binary: &Path, objective: &str) -> Result<TaskProposal, String> {
    let request = serde_json::to_vec(&PlannerRequest {
        protocol_version: 1,
        objective,
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
        .ok_or("Go security engine stdin was unavailable")
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
        let db = Database::open(root.join("codetwin.sqlite3"))
            .map_err(|error| error.to_string())?;
        let project = WorkspaceService::new(&db)
            .get_project(&project_id)
            .map_err(|error| error.to_string())?
            .ok_or("Select an indexed project")?;
        if project.last_indexed_at.is_none() || project.file_count == 0 {
            return Err("Index a nonempty project before requesting a Go task plan".into());
        }
        local_plan(&binary, &objective)
    })
    .await
    .map_err(|error| error.to_string())?
}
