use std::time::Duration;

use codetwin_core::{
    AppPreferences, Database, ProjectOverview, WebsiteInput, WebsiteRecord, WorkspaceActivity,
    WorkspaceSearchResult, WorkspaceService, WorkspaceSummary,
};
use reqwest::{blocking::Client, redirect::Policy};
use serde::Serialize;

use super::{with_database, AppState};

#[derive(Debug)]
struct WebsiteProbe {
    status: &'static str,
    http_status: Option<u16>,
    error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SystemStatusEntry {
    pub key: &'static str,
    pub label: &'static str,
    pub state: &'static str,
    pub detail: &'static str,
}

#[tauri::command]
pub fn list_projects(
    search: Option<String>,
    limit: usize,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<ProjectOverview>, String> {
    with_database(&state, |database| {
        WorkspaceService::new(database)
            .list_projects(search.as_deref(), limit)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
pub fn remove_project(
    project_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<bool, String> {
    with_database(&state, |database| {
        WorkspaceService::new(database)
            .remove_project(&project_id)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
pub fn list_websites(
    search: Option<String>,
    limit: usize,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<WebsiteRecord>, String> {
    with_database(&state, |database| {
        WorkspaceService::new(database)
            .list_websites(search.as_deref(), limit)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
pub fn add_website(
    input: WebsiteInput,
    state: tauri::State<'_, AppState>,
) -> Result<WebsiteRecord, String> {
    with_database(&state, |database| {
        WorkspaceService::new(database)
            .add_website(&input)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
pub fn remove_website(
    website_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<bool, String> {
    with_database(&state, |database| {
        WorkspaceService::new(database)
            .remove_website(&website_id)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
pub async fn check_website(
    website_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<WebsiteRecord, String> {
    let website = with_database(&state, |database| {
        WorkspaceService::new(database)
            .get_website(&website_id)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| format!("website not found: {website_id}"))
    })?;
    let normalized_url = website.normalized_url.clone();
    let database_path = state.database_path.clone();
    let probe = tauri::async_runtime::spawn_blocking(move || probe_website(&normalized_url))
        .await
        .map_err(|error| error.to_string())?;
    let database = Database::open(database_path).map_err(|error| error.to_string())?;
    WorkspaceService::new(&database)
        .update_website_check(
            &website_id,
            probe.status,
            probe.http_status,
            probe.error.as_deref(),
        )
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub fn workspace_summary(
    state: tauri::State<'_, AppState>,
) -> Result<WorkspaceSummary, String> {
    with_database(&state, |database| {
        WorkspaceService::new(database)
            .summary()
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
pub fn recent_activity(
    limit: usize,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<WorkspaceActivity>, String> {
    with_database(&state, |database| {
        WorkspaceService::new(database)
            .recent_activity(limit)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
pub fn search_workspace(
    query: String,
    limit: usize,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<WorkspaceSearchResult>, String> {
    with_database(&state, |database| {
        WorkspaceService::new(database)
            .search(&query, limit)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
pub fn get_app_preferences(
    state: tauri::State<'_, AppState>,
) -> Result<AppPreferences, String> {
    with_database(&state, |database| {
        WorkspaceService::new(database)
            .preferences()
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
pub fn save_app_preferences(
    preferences: AppPreferences,
    state: tauri::State<'_, AppState>,
) -> Result<AppPreferences, String> {
    with_database(&state, |database| {
        WorkspaceService::new(database)
            .save_preferences(&preferences)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
pub fn system_status(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<SystemStatusEntry>, String> {
    with_database(&state, |database| {
        database
            .connection()
            .query_row("SELECT 1", [], |_| Ok(()))
            .map_err(|error| error.to_string())
    })?;
    Ok(vec![
        SystemStatusEntry {
            key: "backend",
            label: "Backend",
            state: "operational",
            detail: "Tauri command bridge is available.",
        },
        SystemStatusEntry {
            key: "database",
            label: "Database",
            state: "operational",
            detail: "Application SQLite storage is available.",
        },
        SystemStatusEntry {
            key: "indexer",
            label: "Source Indexer",
            state: "operational",
            detail: "Persistent Tree-sitter indexing is available.",
        },
        SystemStatusEntry {
            key: "security",
            label: "Security Scanner",
            state: "operational",
            detail: "Static source security analysis is available.",
        },
        SystemStatusEntry {
            key: "testing",
            label: "Testing",
            state: "limited",
            detail: "Passive QA discovery is available; test execution remains disabled by sandbox policy.",
        },
        SystemStatusEntry {
            key: "agents",
            label: "Agents",
            state: "unavailable",
            detail: "No autonomous agent runtime is implemented.",
        },
        SystemStatusEntry {
            key: "deployment",
            label: "Deployment",
            state: "unavailable",
            detail: "Deployment execution is not implemented.",
        },
    ])
}

fn probe_website(url: &str) -> WebsiteProbe {
    let client = match Client::builder()
        .timeout(Duration::from_secs(8))
        .redirect(Policy::limited(5))
        .user_agent("CodeTwin/0.1 website-availability-check")
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            return WebsiteProbe {
                status: "offline",
                http_status: None,
                error: Some(format!("HTTP client setup failed: {error}")),
            }
        }
    };

    match client.head(url).send() {
        Ok(response) => {
            let code = response.status().as_u16();
            WebsiteProbe {
                status: if response.status().is_success() || response.status().is_redirection() {
                    "online"
                } else {
                    "degraded"
                },
                http_status: Some(code),
                error: if response.status().is_success() || response.status().is_redirection() {
                    None
                } else {
                    Some(format!("HTTP {code}"))
                },
            }
        }
        Err(error) => WebsiteProbe {
            status: "offline",
            http_status: None,
            error: Some(error.to_string()),
        },
    }
}
