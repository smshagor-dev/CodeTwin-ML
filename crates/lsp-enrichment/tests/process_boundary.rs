use std::{fs, time::Duration};

use lsp_enrichment::{LanguageServerConfig, LanguageServerKind, LspError, StdioLanguageServer};
use tempfile::tempdir;

fn config(path: String) -> LanguageServerConfig {
    LanguageServerConfig {
        kind: LanguageServerKind::TypeScript,
        executable_path: path,
        arguments: Vec::new(),
        initialization_options: None,
        enabled: true,
    }
}

#[test]
fn requires_explicit_project_trust_before_validating_or_spawning() {
    let project = tempdir().expect("project");
    let error = StdioLanguageServer::start(
        &config("relative-server".into()),
        project.path(),
        false,
        Duration::from_millis(100),
    )
    .expect_err("untrusted project must be rejected");
    assert!(matches!(error, LspError::TrustRequired));
}

#[test]
fn rejects_relative_executable_paths() {
    let project = tempdir().expect("project");
    let error = StdioLanguageServer::start(
        &config("relative-server".into()),
        project.path(),
        true,
        Duration::from_millis(100),
    )
    .expect_err("relative executable must be rejected");
    assert!(matches!(error, LspError::RelativeExecutable(_)));
}

#[test]
fn rejects_executables_stored_inside_the_analyzed_project() {
    let project = tempdir().expect("project");
    let server = project.path().join("tools").join("language-server");
    fs::create_dir_all(server.parent().expect("parent")).expect("tools dir");
    fs::write(&server, b"not executed").expect("server file");

    let error = StdioLanguageServer::start(
        &config(server.to_string_lossy().into_owned()),
        project.path(),
        true,
        Duration::from_millis(100),
    )
    .expect_err("project-local executable must be rejected");
    assert!(matches!(error, LspError::ExecutableInsideProject(_)));
}
