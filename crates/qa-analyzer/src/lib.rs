use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const ANALYZER_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const DETECTOR_VERSION: &str = "qa-test-discovery-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QaArtifactKind {
    TestFile,
    ConfigFile,
}

impl QaArtifactKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TestFile => "test_file",
            Self::ConfigFile => "config_file",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct QaDetection {
    pub artifact_kind: QaArtifactKind,
    pub framework: String,
    pub evidence_kind: String,
}

pub fn is_candidate_path(relative_path: &str) -> bool {
    let normalized = relative_path.replace('\\', "/").to_ascii_lowercase();
    let file_name = normalized.rsplit('/').next().unwrap_or(normalized.as_str());

    if matches!(
        file_name,
        "package.json"
            | "pytest.ini"
            | "pyproject.toml"
            | "phpunit.xml"
            | "phpunit.xml.dist"
    ) || file_name.starts_with("jest.config.")
        || file_name.starts_with("vitest.config.")
        || file_name.starts_with("playwright.config.")
        || file_name.starts_with("cypress.config.")
    {
        return true;
    }

    if matches!(file_name.rsplit_once('.').map(|(_, ext)| ext), Some("js" | "jsx" | "ts" | "tsx"))
        && (file_name.contains(".test.")
            || file_name.contains(".spec.")
            || normalized.contains("/__tests__/")
            || normalized.starts_with("__tests__/")
            || normalized.contains("/cypress/e2e/")
            || normalized.starts_with("cypress/e2e/"))
    {
        return true;
    }

    if file_name.ends_with(".py")
        && (file_name.starts_with("test_")
            || file_name.ends_with("_test.py")
            || normalized.contains("/tests/")
            || normalized.starts_with("tests/"))
    {
        return true;
    }

    if file_name.ends_with(".rs") {
        return true;
    }

    if file_name.ends_with("_test.go") {
        return true;
    }

    file_name.ends_with("test.php")
        || (file_name.ends_with(".php")
            && (normalized.contains("/tests/") || normalized.starts_with("tests/")))
}

pub fn detect_artifacts(relative_path: &str, source: &str) -> Vec<QaDetection> {
    let normalized = relative_path.replace('\\', "/").to_ascii_lowercase();
    let file_name = normalized.rsplit('/').next().unwrap_or(normalized.as_str());
    let source_lower = source.to_ascii_lowercase();
    let mut detections = BTreeSet::new();

    detect_config(file_name, source, &source_lower, &mut detections);
    detect_test_file(&normalized, file_name, &source_lower, &mut detections);

    detections.into_iter().collect()
}

fn detect_config(
    file_name: &str,
    source: &str,
    source_lower: &str,
    detections: &mut BTreeSet<QaDetection>,
) {
    if file_name == "package.json" {
        detect_package_manifest(source, detections);
    }

    for (prefix, framework) in [
        ("jest.config.", "jest"),
        ("vitest.config.", "vitest"),
        ("playwright.config.", "playwright"),
        ("cypress.config.", "cypress"),
    ] {
        if file_name.starts_with(prefix) {
            detections.insert(config_detection(framework, "config_filename"));
        }
    }

    if file_name == "pytest.ini"
        || (file_name == "pyproject.toml" && source_lower.contains("[tool.pytest"))
    {
        detections.insert(config_detection("pytest", "config_filename"));
    }

    if matches!(file_name, "phpunit.xml" | "phpunit.xml.dist") {
        detections.insert(config_detection("phpunit", "config_filename"));
    }
}

fn detect_package_manifest(source: &str, detections: &mut BTreeSet<QaDetection>) {
    let Ok(value) = serde_json::from_str::<Value>(source) else {
        return;
    };

    for section in ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"] {
        let Some(map) = value.get(section).and_then(Value::as_object) else {
            continue;
        };
        for (package, framework) in [
            ("jest", "jest"),
            ("@jest/globals", "jest"),
            ("vitest", "vitest"),
            ("@playwright/test", "playwright"),
            ("cypress", "cypress"),
        ] {
            if map.contains_key(package) {
                detections.insert(config_detection(framework, "manifest_dependency"));
            }
        }
    }

    if let Some(scripts) = value.get("scripts").and_then(Value::as_object) {
        for command in scripts.values().filter_map(Value::as_str) {
            let command = command.to_ascii_lowercase();
            for (needle, framework) in [
                ("vitest", "vitest"),
                ("playwright test", "playwright"),
                ("cypress", "cypress"),
                ("jest", "jest"),
            ] {
                if command.contains(needle) {
                    detections.insert(config_detection(framework, "manifest_script"));
                }
            }
        }
    }
}

fn detect_test_file(
    normalized: &str,
    file_name: &str,
    source_lower: &str,
    detections: &mut BTreeSet<QaDetection>,
) {
    let js_like = matches!(
        file_name.rsplit_once('.').map(|(_, ext)| ext),
        Some("js" | "jsx" | "ts" | "tsx")
    );
    if js_like
        && (file_name.contains(".test.")
            || file_name.contains(".spec.")
            || normalized.contains("/__tests__/")
            || normalized.starts_with("__tests__/")
            || normalized.contains("/cypress/e2e/")
            || normalized.starts_with("cypress/e2e/"))
    {
        let framework = if source_lower.contains("@playwright/test") {
            "playwright"
        } else if normalized.contains("cypress/") || source_lower.contains("cy.") {
            "cypress"
        } else if source_lower.contains("from \"vitest\"")
            || source_lower.contains("from 'vitest'")
            || source_lower.contains("vitest")
        {
            "vitest"
        } else if source_lower.contains("@jest/globals") || source_lower.contains("jest.") {
            "jest"
        } else {
            "javascript_test_unknown"
        };
        detections.insert(test_detection(framework, "path_and_source"));
    }

    if file_name.ends_with(".py")
        && (file_name.starts_with("test_")
            || file_name.ends_with("_test.py")
            || normalized.contains("/tests/")
            || normalized.starts_with("tests/"))
    {
        let framework = if source_lower.contains("pytest") {
            "pytest"
        } else if source_lower.contains("unittest") {
            "unittest"
        } else {
            "python_test_unknown"
        };
        detections.insert(test_detection(framework, "path_and_source"));
    }

    if file_name.ends_with(".rs")
        && ((normalized.contains("/tests/") || normalized.starts_with("tests/"))
            || source_lower.contains("#[test]")
            || source_lower.contains("#[tokio::test]")
            || source_lower.contains("#[cfg(test)]"))
    {
        detections.insert(test_detection("rust_test", "path_or_attribute"));
    }

    if file_name.ends_with("_test.go") {
        detections.insert(test_detection("go_test", "filename_convention"));
    }

    if file_name.ends_with("test.php")
        || (file_name.ends_with(".php")
            && (normalized.contains("/tests/") || normalized.starts_with("tests/")))
    {
        let framework = if source_lower.contains("phpunit") || source_lower.contains("testcase") {
            "phpunit"
        } else {
            "php_test_unknown"
        };
        detections.insert(test_detection(framework, "path_and_source"));
    }
}

fn config_detection(framework: &str, evidence_kind: &str) -> QaDetection {
    QaDetection {
        artifact_kind: QaArtifactKind::ConfigFile,
        framework: framework.to_string(),
        evidence_kind: evidence_kind.to_string(),
    }
}

fn test_detection(framework: &str, evidence_kind: &str) -> QaDetection {
    QaDetection {
        artifact_kind: QaArtifactKind::TestFile,
        framework: framework.to_string(),
        evidence_kind: evidence_kind.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::{detect_artifacts, is_candidate_path, QaArtifactKind};

    #[test]
    fn detects_vitest_test_and_manifest_evidence() {
        let test = detect_artifacts(
            "src/math.test.ts",
            "import { describe, it } from 'vitest'; describe('x', () => it('y', () => {}));",
        );
        assert!(test.iter().any(|item| {
            item.artifact_kind == QaArtifactKind::TestFile && item.framework == "vitest"
        }));

        let manifest = detect_artifacts(
            "package.json",
            r#"{"devDependencies":{"vitest":"^2.0.0","@playwright/test":"^1.0.0"},"scripts":{"e2e":"playwright test"}}"#,
        );
        assert!(manifest.iter().any(|item| item.framework == "vitest"));
        assert!(manifest.iter().any(|item| item.framework == "playwright"));
    }

    #[test]
    fn detects_python_rust_go_and_php_tests() {
        assert!(detect_artifacts("tests/test_api.py", "import pytest").iter().any(|item| item.framework == "pytest"));
        assert!(detect_artifacts("src/lib.rs", "#[cfg(test)] mod tests { #[test] fn ok() {} }").iter().any(|item| item.framework == "rust_test"));
        assert!(detect_artifacts("pkg/store_test.go", "package pkg").iter().any(|item| item.framework == "go_test"));
        assert!(detect_artifacts("tests/UserTest.php", "use PHPUnit\\Framework\\TestCase;").iter().any(|item| item.framework == "phpunit"));
    }

    #[test]
    fn candidate_filter_rejects_normal_source_files() {
        assert!(is_candidate_path("src/lib.rs"));
        assert!(is_candidate_path("tests/api.spec.ts"));
        assert!(!is_candidate_path("src/api.ts"));
        assert!(!is_candidate_path("README.md"));
    }
}
