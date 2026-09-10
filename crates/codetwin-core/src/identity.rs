use std::{fmt::Write as _, path::Path};

use sha2::{Digest, Sha256};

pub fn normalize_path_identity(path: &Path) -> String {
    normalize_path_text(&path.to_string_lossy())
}

pub fn normalize_path_text(input: &str) -> String {
    let mut value = input.replace('\\', "/");
    if let Some(rest) = value.strip_prefix("//?/UNC/") {
        value = format!("//{rest}");
    } else if let Some(rest) = value.strip_prefix("//?/") {
        value = rest.to_string();
    }

    let unc = value.starts_with("//");
    let mut parts = Vec::new();
    for part in value.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." {
            if parts.last().is_some_and(|previous| *previous != "..") {
                parts.pop();
            } else if !unc {
                parts.push(part);
            }
            continue;
        }
        parts.push(part);
    }

    let absolute = value.starts_with('/') && !unc;
    let mut normalized = if unc {
        format!("//{}", parts.join("/"))
    } else if absolute {
        format!("/{}", parts.join("/"))
    } else {
        parts.join("/")
    };

    let windows_like = normalized.starts_with("//")
        || normalized.as_bytes().get(1).is_some_and(|byte| *byte == b':');
    if windows_like {
        normalized = normalized.to_lowercase();
    }
    if normalized.len() > 1 && !is_drive_root(&normalized) {
        normalized = normalized.trim_end_matches('/').to_string();
    }
    normalized
}

pub fn normalize_relative_path(input: &str, case_insensitive: bool) -> Option<String> {
    let value = input.replace('\\', "/");
    if value.starts_with('/') || value.as_bytes().get(1).is_some_and(|byte| *byte == b':') {
        return None;
    }

    let mut parts = Vec::new();
    for part in value.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            _ => parts.push(part),
        }
    }
    let normalized = parts.join("/");
    if normalized.is_empty() {
        return None;
    }
    Some(if case_insensitive {
        normalized.to_lowercase()
    } else {
        normalized
    })
}

pub fn deterministic_id(namespace: &str, parts: &[&str]) -> String {
    let mut digest = Sha256::new();
    digest.update(namespace.as_bytes());
    for part in parts {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part.as_bytes());
    }
    format!("{namespace}:{}", hex_digest(digest.finalize()))
}

pub fn project_id(path_identity: &str) -> String {
    deterministic_id("project", &[path_identity])
}

pub fn file_id(project_id: &str, relative_path_identity: &str) -> String {
    deterministic_id("file", &[project_id, relative_path_identity])
}

pub fn symbol_fingerprint(
    project_id: &str,
    file_id: &str,
    kind: &str,
    qualified_or_name: &str,
    parent_scope: Option<&str>,
) -> String {
    deterministic_id(
        "symbol",
        &[
            project_id,
            file_id,
            kind,
            parent_scope.unwrap_or(""),
            qualified_or_name,
        ],
    )
}

pub fn graph_node_id(project_id: &str, node_type: &str, external_key: &str) -> String {
    deterministic_id("node", &[project_id, node_type, external_key])
}

pub fn graph_edge_id(
    project_id: &str,
    source_node_id: &str,
    target_node_id: &str,
    relationship: &str,
) -> String {
    deterministic_id(
        "edge",
        &[project_id, source_node_id, target_node_id, relationship],
    )
}

fn is_drive_root(value: &str) -> bool {
    value.len() == 3
        && value.as_bytes().get(1).is_some_and(|byte| *byte == b':')
        && value.ends_with('/')
}

fn hex_digest(bytes: impl AsRef<[u8]>) -> String {
    let bytes = bytes.as_ref();
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::{normalize_path_text, normalize_relative_path, symbol_fingerprint};

    #[test]
    fn normalizes_windows_paths_for_identity() {
        assert_eq!(
            normalize_path_text(r"\\?\C:\Work Space\CodeTwin\src\..\SRC\"),
            "c:/work space/codetwin/src"
        );
        assert_eq!(
            normalize_path_text(r"C:\WORK SPACE\CodeTwin"),
            normalize_path_text(r"c:/work space/codetwin/")
        );
    }

    #[test]
    fn normalizes_unicode_and_mixed_relative_paths() {
        assert_eq!(
            normalize_relative_path(r"src\মডিউল/./main.ts", false).as_deref(),
            Some("src/মডিউল/main.ts")
        );
        assert!(normalize_relative_path("../outside.ts", false).is_none());
    }

    #[test]
    fn symbol_fingerprint_does_not_depend_on_line_numbers() {
        let first = symbol_fingerprint("p", "f", "function", "Service.run", Some("Service"));
        let moved = symbol_fingerprint("p", "f", "function", "Service.run", Some("Service"));
        assert_eq!(first, moved);
    }
}
