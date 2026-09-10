use std::collections::BTreeMap;

use project_discovery::ProjectProfile;
use source_indexer::IndexResult;

#[tauri::command]
fn discover_project(path: String) -> Result<ProjectProfile, String> {
    project_discovery::discover_project(path).map_err(|error| error.to_string())
}

#[tauri::command]
fn index_project(path: String) -> Result<IndexResult, String> {
    source_indexer::index_project(path, &BTreeMap::new()).map_err(|error| error.to_string())
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![discover_project, index_project])
        .run(tauri::generate_context!())
        .expect("error while running CodeTwin ML");
}
