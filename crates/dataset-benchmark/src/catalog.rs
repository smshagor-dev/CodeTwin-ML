use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::BenchmarkError;

/// The catalog shipped with this build. Revisions, sizes and SHA-256 pins come from here, so a
/// benchmark only reads files that match what the installer was told to download.
pub const EMBEDDED_CATALOG: &str = include_str!("../../../datasets/catalog.json");

#[derive(Debug, Clone, Deserialize)]
pub struct Catalog {
    pub schema_version: u32,
    pub datasets: Vec<DatasetSpec>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DatasetSpec {
    pub id: String,
    pub name: String,
    pub repository: String,
    pub revision: String,
    pub license: String,
    pub license_url: String,
    pub files: Vec<FileSpec>,
    #[serde(default)]
    pub benchmark: Option<BenchmarkProfile>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FileSpec {
    pub path: String,
    pub size_bytes: Option<u64>,
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BenchmarkTask {
    /// Labeled vulnerable / not vulnerable code samples.
    VulnerabilityDetection,
    /// Before/after pairs where the "after" side is a fix.
    RepairPairs,
    /// Free text (patches, code) scanned only for secret-scanner noise.
    SecretProbe,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ColumnHints {
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub cwe: Option<String>,
    #[serde(default)]
    pub language: Option<String>,
    #[serde(default)]
    pub before: Option<String>,
    #[serde(default)]
    pub after: Option<String>,
    #[serde(default)]
    pub text: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BenchmarkProfile {
    pub task: BenchmarkTask,
    #[serde(default)]
    pub default_language: Option<String>,
    #[serde(default)]
    pub columns: ColumnHints,
}

impl Catalog {
    pub fn embedded() -> Result<Self, BenchmarkError> {
        Self::parse(EMBEDDED_CATALOG)
    }

    pub fn parse(text: &str) -> Result<Self, BenchmarkError> {
        let catalog: Catalog = serde_json::from_str(text)
            .map_err(|error| BenchmarkError::Catalog(error.to_string()))?;
        if catalog.schema_version != 1 {
            return Err(BenchmarkError::Catalog(
                "unsupported dataset catalog schema".to_string(),
            ));
        }
        for dataset in &catalog.datasets {
            if !is_safe_segment(&dataset.id) || !is_safe_segment(&dataset.revision) {
                return Err(BenchmarkError::Catalog(format!(
                    "unsafe dataset id or revision: {}",
                    dataset.id
                )));
            }
            for file in &dataset.files {
                safe_relative_path(&file.path)?;
            }
        }
        Ok(catalog)
    }

    pub fn dataset(&self, id: &str) -> Option<&DatasetSpec> {
        self.datasets.iter().find(|dataset| dataset.id == id)
    }
}

impl DatasetSpec {
    /// Installed layout shared by the Windows installer and the developer prefetch cache:
    /// `<root>/<dataset id>/<revision>/<file path>`.
    pub fn revision_root(&self, datasets_root: &Path) -> PathBuf {
        datasets_root.join(&self.id).join(&self.revision)
    }

    /// Files whose split matches `split`. `test` matches `data/test-….parquet` and
    /// `small/test-….parquet`; `small/test` matches only the latter.
    pub fn split_files(&self, split: &str) -> Vec<&FileSpec> {
        self.files
            .iter()
            .filter(|file| split_matches(&file.path, split))
            .collect()
    }

    pub fn splits(&self) -> Vec<String> {
        let mut splits: Vec<String> = self
            .files
            .iter()
            .map(|file| split_name(&file.path))
            .collect();
        splits.sort();
        splits.dedup();
        splits
    }
}

/// `data/test-00000-of-00001.parquet` -> `test`; `small/test-00000-of-00001.parquet` -> `small/test`.
pub fn split_name(path: &str) -> String {
    let mut parts: Vec<&str> = path.split('/').collect();
    let file = parts.pop().unwrap_or_default();
    let stem = file.split(['-', '.']).next().unwrap_or(file);
    match parts.last() {
        Some(parent) if *parent != "data" && !parent.is_empty() => format!("{parent}/{stem}"),
        _ => stem.to_string(),
    }
}

fn split_matches(path: &str, split: &str) -> bool {
    let name = split_name(path);
    name == split || name.rsplit('/').next() == Some(split)
}

fn is_safe_segment(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._-".contains(character))
}

pub fn safe_relative_path(value: &str) -> Result<PathBuf, BenchmarkError> {
    let path = Path::new(value);
    let valid = !value.is_empty()
        && !value.contains('\\')
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)));
    if !valid {
        return Err(BenchmarkError::Catalog(format!(
            "unsafe dataset path: {value}"
        )));
    }
    Ok(value.split('/').collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_catalog_has_benchmark_profiles() {
        let catalog = Catalog::embedded().unwrap();
        let profiled: Vec<&str> = catalog
            .datasets
            .iter()
            .filter(|dataset| dataset.benchmark.is_some())
            .map(|dataset| dataset.id.as_str())
            .collect();
        assert!(profiled.contains(&"code_x_glue_defect_detection"));
        assert!(profiled.contains(&"code_security_vulnerability"));
        for dataset in &catalog.datasets {
            for file in &dataset.files {
                assert!(file.sha256.as_deref().is_some_and(|hash| hash.len() == 64));
            }
        }
    }

    #[test]
    fn split_names_follow_hugging_face_layout() {
        assert_eq!(split_name("data/test-00000-of-00001.parquet"), "test");
        assert_eq!(
            split_name("small/validation-00000-of-00001.parquet"),
            "small/validation"
        );
        assert!(split_matches("small/test-00000-of-00001.parquet", "test"));
        assert!(split_matches(
            "small/test-00000-of-00001.parquet",
            "small/test"
        ));
        assert!(!split_matches(
            "medium/test-00000-of-00001.parquet",
            "small/test"
        ));
        assert!(!split_matches("data/train-00000-of-00001.parquet", "test"));
    }

    #[test]
    fn rejects_traversal() {
        assert!(safe_relative_path("../x.parquet").is_err());
        assert!(safe_relative_path("/abs.parquet").is_err());
        assert!(safe_relative_path("a\\b.parquet").is_err());
        assert!(safe_relative_path("data/test.parquet").is_ok());
    }
}
