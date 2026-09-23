use std::collections::BTreeMap;

use crate::{normalize_relative_path, ImportResolutionState};

const JAVASCRIPT_SOURCE_EXTENSIONS: [&str; 6] = ["ts", "tsx", "js", "jsx", "mjs", "cjs"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedImport {
    pub state: ImportResolutionState,
    pub target_file_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhpPsr4Root {
    pub namespace_prefix: String,
    pub directory: String,
}

pub fn resolve_import(
    source_relative_path: &str,
    source_language: &str,
    raw_specifier: &str,
    files_by_identity: &BTreeMap<String, String>,
    case_insensitive: bool,
) -> ResolvedImport {
    resolve_import_with_php_psr4(
        source_relative_path,
        source_language,
        raw_specifier,
        files_by_identity,
        case_insensitive,
        &[],
    )
}

pub fn resolve_import_with_php_psr4(
    source_relative_path: &str,
    source_language: &str,
    raw_specifier: &str,
    files_by_identity: &BTreeMap<String, String>,
    case_insensitive: bool,
    php_psr4_roots: &[PhpPsr4Root],
) -> ResolvedImport {
    let specifier = raw_specifier.trim();

    let candidates = match source_language {
        "TypeScript" | "TypeScript TSX" | "JavaScript" => {
            if !(specifier.starts_with("./") || specifier.starts_with("../")) {
                return ResolvedImport {
                    state: ImportResolutionState::External,
                    target_file_id: None,
                };
            }
            let Some(base) = relative_import_base(source_relative_path, specifier) else {
                return ResolvedImport {
                    state: ImportResolutionState::Unresolved,
                    target_file_id: None,
                };
            };
            javascript_resolution_candidates(&base)
        }
        "Python" => {
            if !specifier.starts_with('.') {
                return ResolvedImport {
                    state: ImportResolutionState::External,
                    target_file_id: None,
                };
            }
            let Some(base) = python_relative_import_base(source_relative_path, specifier) else {
                return ResolvedImport {
                    state: ImportResolutionState::Unresolved,
                    target_file_id: None,
                };
            };
            python_resolution_candidates(&base)
        }
        "PHP" => {
            let candidates = php_resolution_candidates(specifier, php_psr4_roots);
            if candidates.is_empty() {
                return ResolvedImport {
                    state: ImportResolutionState::External,
                    target_file_id: None,
                };
            }
            candidates
        }
        _ => {
            return ResolvedImport {
                state: ImportResolutionState::Unsupported,
                target_file_id: None,
            };
        }
    };

    for candidate in candidates {
        let Some(identity) = normalize_relative_path(&candidate, case_insensitive) else {
            continue;
        };
        if let Some(target_file_id) = files_by_identity.get(&identity) {
            return ResolvedImport {
                state: ImportResolutionState::ResolvedLocal,
                target_file_id: Some(target_file_id.clone()),
            };
        }
    }

    ResolvedImport {
        state: ImportResolutionState::Unresolved,
        target_file_id: None,
    }
}

fn relative_import_base(source_relative_path: &str, specifier: &str) -> Option<String> {
    let normalized_source = normalize_relative_path(source_relative_path, false)?;
    let parent = normalized_source
        .rsplit_once('/')
        .map_or("", |(parent, _)| parent);
    let combined = if parent.is_empty() {
        specifier.to_string()
    } else {
        format!("{parent}/{specifier}")
    };
    normalize_relative_path(&combined, false)
}

fn javascript_resolution_candidates(base: &str) -> Vec<String> {
    let final_segment = base.rsplit('/').next().unwrap_or(base);
    let has_extension = final_segment
        .rsplit_once('.')
        .is_some_and(|(_, extension)| JAVASCRIPT_SOURCE_EXTENSIONS.contains(&extension));
    if has_extension {
        return vec![base.to_string()];
    }

    let mut candidates = Vec::with_capacity(JAVASCRIPT_SOURCE_EXTENSIONS.len() * 2);
    for extension in JAVASCRIPT_SOURCE_EXTENSIONS {
        candidates.push(format!("{base}.{extension}"));
    }
    for extension in JAVASCRIPT_SOURCE_EXTENSIONS {
        candidates.push(format!("{base}/index.{extension}"));
    }
    candidates
}

fn php_resolution_candidates(
    specifier: &str,
    php_psr4_roots: &[PhpPsr4Root],
) -> Vec<String> {
    let raw = specifier
        .split_once(" as ")
        .map(|(qualified, _)| qualified)
        .unwrap_or(specifier)
        .trim()
        .trim_start_matches('\\');
    if raw.is_empty() || raw.contains('{') || raw.contains('}') || raw.contains(',') {
        return Vec::new();
    }

    let mut candidates = Vec::new();
    for root in php_psr4_roots {
        let prefix = root
            .namespace_prefix
            .trim()
            .trim_start_matches('\\')
            .trim_end_matches('\\');
        if prefix.is_empty() {
            continue;
        }
        let Some(rest) = raw
            .strip_prefix(prefix)
            .and_then(|tail| tail.strip_prefix('\\'))
        else {
            continue;
        };
        let directory = root.directory.replace('\\', "/");
        let directory = directory.trim().trim_matches('/');
        if directory.is_empty() {
            continue;
        }
        let relative = rest.replace('\\', "/");
        if relative.is_empty() {
            continue;
        }
        candidates.push(format!("{directory}/{relative}.php"));
    }

    let namespace_path = raw.replace('\\', "/");
    if namespace_path.is_empty() {
        return Vec::new();
    }
    candidates.push(format!("{namespace_path}.php"));
    if let Some(rest) = namespace_path.strip_prefix("App/") {
        candidates.push(format!("app/{rest}.php"));
    }
    if let Some(rest) = namespace_path.strip_prefix("Tests/") {
        candidates.push(format!("tests/{rest}.php"));
    }
    candidates.dedup();
    candidates
}

fn python_relative_import_base(
    source_relative_path: &str,
    specifier: &str,
) -> Option<String> {
    let normalized_source = normalize_relative_path(source_relative_path, false)?;
    let parent = normalized_source
        .rsplit_once('/')
        .map_or("", |(parent, _)| parent);
    let mut components: Vec<&str> = parent
        .split('/')
        .filter(|component| !component.is_empty())
        .collect();

    let dot_count = specifier.chars().take_while(|character| *character == '.').count();
    if dot_count == 0 {
        return None;
    }
    let parents_to_pop = dot_count.saturating_sub(1);
    if parents_to_pop > components.len() {
        return None;
    }
    for _ in 0..parents_to_pop {
        components.pop();
    }

    let module = &specifier[dot_count..];
    let mut path = components.join("/");
    if !module.is_empty() {
        let module_path = module.replace('.', "/");
        if path.is_empty() {
            path = module_path;
        } else {
            path.push('/');
            path.push_str(&module_path);
        }
    }
    normalize_relative_path(&path, false)
}

fn python_resolution_candidates(base: &str) -> Vec<String> {
    vec![format!("{base}.py"), format!("{base}/__init__.py")]
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::ImportResolutionState;

    use super::{resolve_import, resolve_import_with_php_psr4, PhpPsr4Root};

    fn files(paths: &[&str]) -> BTreeMap<String, String> {
        paths
            .iter()
            .map(|path| ((*path).to_string(), format!("id:{path}")))
            .collect()
    }

    #[test]
    fn resolves_relative_extensions_and_index_files() {
        let available = files(&[
            "src/util.ts",
            "src/view.tsx",
            "src/js.js",
            "src/widget.jsx",
            "src/pkg/index.ts",
            "shared/index.tsx",
        ]);
        for (source, specifier, expected) in [
            ("src/main.ts", "./util", "src/util.ts"),
            ("src/main.ts", "./view.tsx", "src/view.tsx"),
            ("src/main.ts", "./js", "src/js.js"),
            ("src/main.ts", "./widget.jsx", "src/widget.jsx"),
            ("src/main.ts", "./pkg", "src/pkg/index.ts"),
            ("src/nested/main.ts", "../../shared", "shared/index.tsx"),
        ] {
            let resolved = resolve_import(source, "TypeScript", specifier, &available, false);
            assert_eq!(resolved.state, ImportResolutionState::ResolvedLocal, "{specifier}");
            assert_eq!(resolved.target_file_id.as_deref(), Some(&format!("id:{expected}")));
        }
    }

    #[test]
    fn resolves_python_relative_modules_and_packages() {
        let available = BTreeMap::from([
            ("app/users.py".to_string(), "users-file".to_string()),
            ("app/shared/routes/__init__.py".to_string(), "routes-package".to_string()),
        ]);

        let direct = resolve_import(
            "app/main.py",
            "Python",
            ".users",
            &available,
            false,
        );
        assert_eq!(direct.state, ImportResolutionState::ResolvedLocal);
        assert_eq!(direct.target_file_id.as_deref(), Some("users-file"));

        let package = resolve_import(
            "app/admin/main.py",
            "Python",
            "..shared.routes",
            &available,
            false,
        );
        assert_eq!(package.state, ImportResolutionState::ResolvedLocal);
        assert_eq!(package.target_file_id.as_deref(), Some("routes-package"));
    }

    #[test]
    fn resolves_laravel_app_namespace_and_aliases() {
        let available = BTreeMap::from([
            (
                "app/Http/Controllers/UserController.php".to_string(),
                "user-controller".to_string(),
            ),
            (
                "tests/Feature/UserTest.php".to_string(),
                "user-test".to_string(),
            ),
        ]);

        let controller = resolve_import(
            "routes/api.php",
            "PHP",
            r"App\Http\Controllers\UserController",
            &available,
            false,
        );
        assert_eq!(controller.state, ImportResolutionState::ResolvedLocal);
        assert_eq!(controller.target_file_id.as_deref(), Some("user-controller"));

        let aliased = resolve_import(
            "routes/api.php",
            "PHP",
            r"App\Http\Controllers\UserController as Users",
            &available,
            false,
        );
        assert_eq!(aliased.state, ImportResolutionState::ResolvedLocal);
        assert_eq!(aliased.target_file_id.as_deref(), Some("user-controller"));

        let test = resolve_import(
            "routes/api.php",
            "PHP",
            r"Tests\Feature\UserTest",
            &available,
            false,
        );
        assert_eq!(test.state, ImportResolutionState::ResolvedLocal);
        assert_eq!(test.target_file_id.as_deref(), Some("user-test"));
    }
    #[test]
    fn resolves_custom_composer_psr4_roots_without_breaking_default_php_fallbacks() {
        let available = BTreeMap::from([
            (
                "src/Domain/Users/Http/UserController.php".to_string(),
                "domain-user-controller".to_string(),
            ),
            (
                "packages/acme/src/Service.php".to_string(),
                "acme-service".to_string(),
            ),
        ]);
        let roots = vec![
            PhpPsr4Root {
                namespace_prefix: r"Domain\".to_string(),
                directory: "src/Domain/".to_string(),
            },
            PhpPsr4Root {
                namespace_prefix: r"Acme\Package\".to_string(),
                directory: "packages/acme/src".to_string(),
            },
        ];

        let domain = resolve_import_with_php_psr4(
            "routes/api.php",
            "PHP",
            r"Domain\Users\Http\UserController",
            &available,
            false,
            &roots,
        );
        assert_eq!(domain.state, ImportResolutionState::ResolvedLocal);
        assert_eq!(
            domain.target_file_id.as_deref(),
            Some("domain-user-controller")
        );

        let package = resolve_import_with_php_psr4(
            "routes/api.php",
            "PHP",
            r"Acme\Package\Service",
            &available,
            false,
            &roots,
        );
        assert_eq!(package.state, ImportResolutionState::ResolvedLocal);
        assert_eq!(package.target_file_id.as_deref(), Some("acme-service"));
    }

    #[test]
    fn distinguishes_external_unresolved_and_unsupported() {
        let available = BTreeMap::new();
        assert_eq!(
            resolve_import("src/main.ts", "TypeScript", "react", &available, false).state,
            ImportResolutionState::External
        );
        assert_eq!(
            resolve_import("src/main.ts", "TypeScript", "./missing", &available, false).state,
            ImportResolutionState::Unresolved
        );
        assert_eq!(
            resolve_import("src/main.py", "Python", "requests", &available, false).state,
            ImportResolutionState::External
        );
    }
}
