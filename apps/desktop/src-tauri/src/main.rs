use project_discovery::ProjectProfile;

#[tauri::command]
fn discover_project(path: String) -> Result<ProjectProfile, String> {
    project_discovery::discover_project(path).map_err(|error| error.to_string())
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![discover_project])
        .run(tauri::generate_context!())
        .expect("error while running CodeTwin ML");
}
