use std::collections::BTreeMap;

use crate::{normalize_relative_path, ImportResolutionState};

const SOURCE_EXTENSIONS: [&str; 6] = ["ts", "tsx", "js", "jsx", "mjs", "cjs"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedImport {
    pub state: ImportResolutionState,
    pub target_file_id: Option<String>,
}

pub fn resolve_import(
    source_relative_path: &str,
    source_language: &str,
    raw_specifier: &str,
    files_by_identity: &BTreeMap<String, String>,
    case_insensitive: bool,
) -> ResolvedImport {
    if !matches!(source_language, "TypeScript" | "TypeScript TSX" | "JavaScript") {
        return ResolvedImport {
            state: ImportResolutionState::Unsupported,
            target_file_id: None,
        };
    }

    let specifier = raw_specifier.trim();
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

    for candidate in resolution_candidates(&base) {
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

fn resolution_candidates(base: &str) -> Vec<String> {
    let final_segment = base.rsplit('/').next().unwrap_or(base);
    let has_extension = final_segment
        .rsplit_once('.')
        .is_some_and(|(_, extension)| SOURCE_EXTENSIONS.contains(&extension));
    if has_extension {
        return vec![base.to_string()];
    }

    let mut candidates = Vec::with_capacity(SOURCE_EXTENSIONS.len() * 2);
    for extension in SOURCE_EXTENSIONS {
        candidates.push(format!("{base}.{extension}"));
    }
    for extension in SOURCE_EXTENSIONS {
        candidates.push(format!("{base}/index.{extension}"));
    }
    candidates
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::ImportResolutionState;

    use super::resolve_import;

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
            resolve_import("src/main.py", "Python", ".local", &available, false).state,
            ImportResolutionState::Unsupported
        );
    }
}
