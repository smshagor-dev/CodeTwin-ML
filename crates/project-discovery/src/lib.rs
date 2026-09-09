use std::{collections::BTreeSet, fs, path::Path};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use walkdir::WalkDir;

#[derive(Debug, Error)]
pub enum DiscoveryError {
    #[error("project root does not exist: {0}")]
    MissingRoot(String),
    #[error("project root is not a directory: {0}")]
    NotDirectory(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ProjectProfile {
    pub languages: Vec<String>,
    pub frameworks: Vec<String>,
    pub package_managers: Vec<String>,
    pub build_systems: Vec<String>,
    pub test_frameworks: Vec<String>,
    pub databases: Vec<String>,
    pub ci_providers: Vec<String>,
    pub project_kinds: Vec<String>,
}

pub fn discover_project(root: impl AsRef<Path>) -> Result<ProjectProfile, DiscoveryError> {
    let root = root.as_ref();
    if !root.exists() {
        return Err(DiscoveryError::MissingRoot(root.display().to_string()));
    }
    if !root.is_dir() {
        return Err(DiscoveryError::NotDirectory(root.display().to_string()));
    }

    let mut languages = BTreeSet::new();
    let mut frameworks = BTreeSet::new();
    let mut package_managers = BTreeSet::new();
    let mut build_systems = BTreeSet::new();
    let mut test_frameworks = BTreeSet::new();
    let mut databases = BTreeSet::new();
    let mut ci_providers = BTreeSet::new();
    let mut project_kinds = BTreeSet::new();

    for entry in WalkDir::new(root)
        .max_depth(5)
        .follow_links(false)
        .into_iter()
        .filter_map(Result::ok)
    {
        let path = entry.path();
        if should_skip(path) {
            continue;
        }
        if path.is_file() {
            detect_language(path, &mut languages);
            detect_marker(
                root,
                path,
                &mut frameworks,
                &mut package_managers,
                &mut build_systems,
                &mut test_frameworks,
                &mut databases,
                &mut ci_providers,
                &mut project_kinds,
            );
        }
    }

    Ok(ProjectProfile {
        languages: languages.into_iter().collect(),
        frameworks: frameworks.into_iter().collect(),
        package_managers: package_managers.into_iter().collect(),
        build_systems: build_systems.into_iter().collect(),
        test_frameworks: test_frameworks.into_iter().collect(),
        databases: databases.into_iter().collect(),
        ci_providers: ci_providers.into_iter().collect(),
        project_kinds: project_kinds.into_iter().collect(),
    })
}

fn should_skip(path: &Path) -> bool {
    path.components().any(|part| {
        matches!(
            part.as_os_str().to_str(),
            Some(".git" | "node_modules" | "target" | ".venv" | "dist" | "build")
        )
    })
}

fn detect_language(path: &Path, languages: &mut BTreeSet<String>) {
    let Some(ext) = path.extension().and_then(|v| v.to_str()) else {
        return;
    };
    let language = match ext.to_ascii_lowercase().as_str() {
        "ts" | "tsx" => "TypeScript",
        "js" | "jsx" | "mjs" | "cjs" => "JavaScript",
        "py" => "Python",
        "rs" => "Rust",
        "go" => "Go",
        "c" | "h" => "C",
        "cc" | "cpp" | "cxx" | "hpp" | "hh" => "C++",
        "php" => "PHP",
        _ => return,
    };
    languages.insert(language.to_string());
}

#[allow(clippy::too_many_arguments)]
fn detect_marker(
    root: &Path,
    path: &Path,
    frameworks: &mut BTreeSet<String>,
    package_managers: &mut BTreeSet<String>,
    build_systems: &mut BTreeSet<String>,
    test_frameworks: &mut BTreeSet<String>,
    databases: &mut BTreeSet<String>,
    ci_providers: &mut BTreeSet<String>,
    project_kinds: &mut BTreeSet<String>,
) {
    let file_name = path
        .file_name()
        .and_then(|v| v.to_str())
        .unwrap_or_default();
    let relative = path
        .strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/");

    match file_name {
        "package.json" => {
            package_managers.insert("npm-compatible".into());
            project_kinds.insert("JavaScript/TypeScript application".into());
            if let Ok(text) = fs::read_to_string(path) {
                for (needle, label) in [
                    ("\"react\"", "React"),
                    ("\"next\"", "Next.js"),
                    ("\"vite\"", "Vite"),
                ] {
                    if text.contains(needle) {
                        frameworks.insert(label.into());
                    }
                }
                for (needle, label) in [
                    ("\"vitest\"", "Vitest"),
                    ("\"jest\"", "Jest"),
                    ("\"playwright\"", "Playwright"),
                    ("\"cypress\"", "Cypress"),
                ] {
                    if text.contains(needle) {
                        test_frameworks.insert(label.into());
                    }
                }
                for (needle, label) in [
                    ("\"prisma\"", "Prisma"),
                    ("\"drizzle", "Drizzle"),
                    ("\"sequelize\"", "Sequelize"),
                    ("\"typeorm\"", "TypeORM"),
                ] {
                    if text.contains(needle) {
                        databases.insert(label.into());
                    }
                }
            }
        }
        "pnpm-lock.yaml" | "pnpm-workspace.yaml" => {
            package_managers.insert("pnpm".into());
        }
        "yarn.lock" => {
            package_managers.insert("Yarn".into());
        }
        "Cargo.toml" => {
            build_systems.insert("Cargo".into());
            project_kinds.insert("Rust".into());
        }
        "pyproject.toml" | "requirements.txt" => {
            project_kinds.insert("Python".into());
        }
        "go.mod" => {
            build_systems.insert("Go modules".into());
            project_kinds.insert("Go".into());
        }
        "composer.json" => {
            package_managers.insert("Composer".into());
            project_kinds.insert("PHP".into());
        }
        "CMakeLists.txt" => {
            build_systems.insert("CMake".into());
        }
        "Makefile" => {
            build_systems.insert("Make".into());
        }
        "Dockerfile" | "docker-compose.yml" | "docker-compose.yaml" => {
            project_kinds.insert("Containerized".into());
        }
        "schema.prisma" => {
            databases.insert("Prisma".into());
        }
        _ => {}
    }

    if relative.starts_with(".github/workflows/")
        && (relative.ends_with(".yml") || relative.ends_with(".yaml"))
    {
        ci_providers.insert("GitHub Actions".into());
    }
}

#[cfg(test)]
mod tests {
    use super::discover_project;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn discovers_stack_from_real_files() {
        let dir = tempdir().expect("tempdir");
        fs::write(dir.path().join("package.json"), r#"{"dependencies":{"react":"1","@prisma/client":"1"},"devDependencies":{"vitest":"1","vite":"1"}}"#).expect("package");
        fs::write(dir.path().join("pnpm-lock.yaml"), "lockfileVersion: 9").expect("lock");
        fs::write(dir.path().join("main.ts"), "export const x = 1").expect("ts");
        fs::create_dir_all(dir.path().join(".github/workflows")).expect("workflows");
        fs::write(dir.path().join(".github/workflows/ci.yml"), "name: CI").expect("ci");

        let profile = discover_project(dir.path()).expect("discover");
        assert!(profile.languages.contains(&"TypeScript".into()));
        assert!(profile.frameworks.contains(&"React".into()));
        assert!(profile.frameworks.contains(&"Vite".into()));
        assert!(profile.package_managers.contains(&"pnpm".into()));
        assert!(profile.test_frameworks.contains(&"Vitest".into()));
        assert!(profile.databases.contains(&"Prisma".into()));
        assert!(profile.ci_providers.contains(&"GitHub Actions".into()));
    }
}
