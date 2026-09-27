//! Row access to Hugging Face parquet shards plus the column, label, CWE and language
//! normalization needed to score analyzers against them.

use std::{collections::BTreeSet, fs::File, path::Path, sync::Arc};

use parquet::{
    file::reader::{FileReader, SerializedFileReader},
    record::Field,
    schema::types::Type,
};
use serde::{Deserialize, Serialize};

use crate::{
    catalog::{BenchmarkProfile, BenchmarkTask},
    BenchmarkError,
};

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Text(String),
    List(Vec<Value>),
}

impl Value {
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Value::Text(text) => Some(text),
            _ => None,
        }
    }
}

fn convert(field: &Field) -> Value {
    match field {
        Field::Null => Value::Null,
        Field::Bool(value) => Value::Bool(*value),
        Field::Byte(value) => Value::Int(i64::from(*value)),
        Field::Short(value) => Value::Int(i64::from(*value)),
        Field::Int(value) => Value::Int(i64::from(*value)),
        Field::Long(value) => Value::Int(*value),
        Field::UByte(value) => Value::Int(i64::from(*value)),
        Field::UShort(value) => Value::Int(i64::from(*value)),
        Field::UInt(value) => Value::Int(i64::from(*value)),
        Field::ULong(value) => Value::Int(i64::try_from(*value).unwrap_or(i64::MAX)),
        Field::Float(value) => Value::Float(f64::from(*value)),
        Field::Double(value) => Value::Float(*value),
        Field::Str(value) => Value::Text(value.clone()),
        Field::Bytes(value) => match std::str::from_utf8(value.data()) {
            Ok(text) => Value::Text(text.to_string()),
            Err(_) => Value::Null,
        },
        Field::ListInternal(list) => Value::List(list.elements().iter().map(convert).collect()),
        _ => Value::Null,
    }
}

pub struct Table {
    reader: SerializedFileReader<File>,
}

impl Table {
    pub fn open(path: &Path) -> Result<Self, BenchmarkError> {
        let file = File::open(path).map_err(|error| BenchmarkError::Io(path.into(), error))?;
        let reader = SerializedFileReader::new(file)
            .map_err(|error| BenchmarkError::Parquet(format!("{}: {error}", path.display())))?;
        Ok(Self { reader })
    }

    pub fn columns(&self) -> Vec<String> {
        self.reader
            .metadata()
            .file_metadata()
            .schema()
            .get_fields()
            .iter()
            .map(|field| field.name().to_string())
            .collect()
    }

    pub fn num_rows(&self) -> u64 {
        u64::try_from(self.reader.metadata().file_metadata().num_rows()).unwrap_or(0)
    }

    /// Visits rows `0, stride, 2*stride, …` (at most `limit`), passing the requested columns
    /// in order. Missing columns come back as `Value::Null`.
    pub fn for_each_row(
        &self,
        wanted: &[String],
        stride: u64,
        limit: usize,
        mut visit: impl FnMut(u64, Vec<Value>),
    ) -> Result<(), BenchmarkError> {
        let root = self.reader.metadata().file_metadata().schema();
        let fields: Vec<Arc<Type>> = root
            .get_fields()
            .iter()
            .filter(|field| wanted.iter().any(|name| name == field.name()))
            .cloned()
            .collect();
        let projection = Type::group_type_builder(root.name())
            .with_fields(fields)
            .build()
            .map_err(|error| BenchmarkError::Parquet(error.to_string()))?;
        let rows = self
            .reader
            .get_row_iter(Some(projection))
            .map_err(|error| BenchmarkError::Parquet(error.to_string()))?;
        let stride = stride.max(1);
        let mut visited = 0usize;
        for (index, row) in (0u64..).zip(rows) {
            if visited >= limit {
                break;
            }
            let row = row.map_err(|error| BenchmarkError::Parquet(error.to_string()))?;
            if index % stride != 0 {
                continue;
            }
            let values = wanted
                .iter()
                .map(|name| {
                    row.get_column_iter()
                        .find(|(column, _)| *column == name)
                        .map(|(_, field)| convert(field))
                        .unwrap_or(Value::Null)
                })
                .collect();
            visit(index, values);
            visited += 1;
        }
        Ok(())
    }
}

const CODE_COLUMNS: &[&str] = &[
    "func",
    "code",
    "source_code",
    "source",
    "snippet",
    "function",
    "content",
    "code_snippet",
    "vulnerable_code",
    "text",
];
const LABEL_COLUMNS: &[&str] = &[
    "target",
    "label",
    "is_vulnerable",
    "vulnerable",
    "vul",
    "is_vuln",
    "labels",
    "vulnerability",
];
const CWE_COLUMNS: &[&str] = &["cwe", "cwe_id", "cwe_ids", "cwes", "cwe_type", "CWE ID"];
const LANGUAGE_COLUMNS: &[&str] = &["language", "lang", "programming_language"];

/// Which parquet columns feed a task. Recorded in the report so a reader can check it.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ColumnMapping {
    pub code: Option<String>,
    pub label: Option<String>,
    pub cwe: Option<String>,
    pub language: Option<String>,
    pub before: Option<String>,
    pub after: Option<String>,
    pub text: Vec<String>,
}

impl ColumnMapping {
    pub fn wanted(&self) -> Vec<String> {
        let mut wanted: Vec<String> = [
            &self.code,
            &self.label,
            &self.cwe,
            &self.language,
            &self.before,
            &self.after,
        ]
        .into_iter()
        .flatten()
        .cloned()
        .collect();
        wanted.extend(self.text.iter().cloned());
        let mut seen = BTreeSet::new();
        wanted.retain(|name| seen.insert(name.clone()));
        wanted
    }
}

fn pick(columns: &[String], hint: Option<&String>, candidates: &[&str]) -> Option<String> {
    if let Some(hint) = hint {
        if columns.contains(hint) {
            return Some(hint.clone());
        }
    }
    candidates.iter().find_map(|candidate| {
        columns
            .iter()
            .find(|column| column.eq_ignore_ascii_case(candidate))
            .cloned()
    })
}

/// Resolves a profile's column hints against the columns a shard actually has. Hints win;
/// otherwise common Hugging Face names are tried. Fails with the available columns listed.
pub fn resolve_columns(
    profile: &BenchmarkProfile,
    columns: &[String],
) -> Result<ColumnMapping, String> {
    let hints = &profile.columns;
    let missing = |what: &str| {
        format!(
            "could not find a {what} column; available columns: {}",
            columns.join(", ")
        )
    };
    match profile.task {
        BenchmarkTask::VulnerabilityDetection => {
            let code =
                pick(columns, hints.code.as_ref(), CODE_COLUMNS).ok_or_else(|| missing("code"))?;
            let label = pick(columns, hints.label.as_ref(), LABEL_COLUMNS)
                .ok_or_else(|| missing("label"))?;
            let language = pick(columns, hints.language.as_ref(), LANGUAGE_COLUMNS);
            if language.is_none() && profile.default_language.is_none() {
                return Err(missing("language"));
            }
            Ok(ColumnMapping {
                code: Some(code),
                label: Some(label),
                cwe: pick(columns, hints.cwe.as_ref(), CWE_COLUMNS),
                language,
                ..ColumnMapping::default()
            })
        }
        BenchmarkTask::RepairPairs => {
            let before = pick(
                columns,
                hints.before.as_ref(),
                &["buggy", "before", "source"],
            )
            .ok_or_else(|| missing("before"))?;
            let after = pick(columns, hints.after.as_ref(), &["fixed", "after", "target"])
                .ok_or_else(|| missing("after"))?;
            Ok(ColumnMapping {
                before: Some(before),
                after: Some(after),
                language: pick(columns, hints.language.as_ref(), LANGUAGE_COLUMNS),
                ..ColumnMapping::default()
            })
        }
        BenchmarkTask::SecretProbe => {
            let text: Vec<String> = hints
                .text
                .iter()
                .filter(|name| columns.contains(name))
                .cloned()
                .collect();
            if text.is_empty() {
                return Err(missing("text"));
            }
            Ok(ColumnMapping {
                text,
                ..ColumnMapping::default()
            })
        }
    }
}

/// `true` = vulnerable. Unrecognized values return `None` and the sample is skipped.
pub fn parse_label(value: &Value) -> Option<bool> {
    match value {
        Value::Bool(value) => Some(*value),
        Value::Int(value) => Some(*value != 0),
        Value::Float(value) => Some(*value != 0.0),
        Value::Text(text) => {
            let normalized = text.trim().to_ascii_lowercase().replace(['-', '_'], " ");
            match normalized.as_str() {
                "1" | "true" | "yes" | "vulnerable" | "vuln" | "insecure" | "bad" | "unsafe" => {
                    Some(true)
                }
                "0" | "false" | "no" | "safe" | "secure" | "benign" | "clean" | "good"
                | "not vulnerable" | "non vulnerable" | "fixed" => Some(false),
                _ => None,
            }
        }
        Value::List(items) if items.len() == 1 => parse_label(&items[0]),
        _ => None,
    }
}

/// Normalizes `CWE-79`, `79`, `cwe_79`, `CWE-79, CWE-89` and lists to `CWE-<n>` identifiers.
pub fn parse_cwes(value: &Value) -> BTreeSet<String> {
    let mut cwes = BTreeSet::new();
    match value {
        Value::Int(number) if *number > 0 => {
            cwes.insert(format!("CWE-{number}"));
        }
        Value::Text(text) => {
            for token in text.split(|character: char| !character.is_ascii_alphanumeric()) {
                let digits = token
                    .strip_prefix("CWE")
                    .or_else(|| token.strip_prefix("cwe"))
                    .unwrap_or(token);
                if !digits.is_empty()
                    && digits.len() <= 5
                    && digits.chars().all(|c| c.is_ascii_digit())
                {
                    if let Ok(number) = digits.parse::<u32>() {
                        if number > 0 {
                            cwes.insert(format!("CWE-{number}"));
                        }
                    }
                }
            }
        }
        Value::List(items) => {
            for item in items {
                cwes.extend(parse_cwes(item));
            }
        }
        _ => {}
    }
    cwes
}

/// Maps dataset language labels to the names the security analyzer accepts.
pub fn normalize_language(raw: &str) -> String {
    let lowered = raw.trim().to_ascii_lowercase();
    match lowered.as_str() {
        "c" => "C",
        "c++" | "cpp" | "cxx" | "cc" => "C++",
        "python" | "py" | "python3" => "Python",
        "javascript" | "js" | "node" | "nodejs" => "JavaScript",
        "typescript" | "ts" => "TypeScript",
        "tsx" => "TypeScript TSX",
        "go" | "golang" => "Go",
        "rust" | "rs" => "Rust",
        "php" => "PHP",
        "java" => "Java",
        "c#" | "csharp" | "cs" => "C#",
        "ruby" | "rb" => "Ruby",
        "kotlin" | "kt" => "Kotlin",
        "swift" => "Swift",
        _ => return raw.trim().to_string(),
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::ColumnHints;

    #[test]
    fn labels_from_common_encodings() {
        assert_eq!(parse_label(&Value::Bool(true)), Some(true));
        assert_eq!(parse_label(&Value::Int(0)), Some(false));
        assert_eq!(parse_label(&Value::Text("Vulnerable".into())), Some(true));
        assert_eq!(
            parse_label(&Value::Text("not_vulnerable".into())),
            Some(false)
        );
        assert_eq!(parse_label(&Value::Text("maybe".into())), None);
        assert_eq!(parse_label(&Value::Null), None);
    }

    #[test]
    fn cwe_normalization() {
        let cwes = parse_cwes(&Value::Text("CWE-79, cwe_89; 22".into()));
        assert_eq!(
            cwes.into_iter().collect::<Vec<_>>(),
            vec!["CWE-22", "CWE-79", "CWE-89"]
        );
        assert!(parse_cwes(&Value::Text("NVD-CWE-Other".into())).is_empty());
        assert_eq!(parse_cwes(&Value::Int(78)).len(), 1);
    }

    #[test]
    fn languages_map_to_analyzer_names() {
        assert_eq!(normalize_language("cpp"), "C++");
        assert_eq!(normalize_language("Python"), "Python");
        assert_eq!(normalize_language("golang"), "Go");
        assert_eq!(normalize_language("Elixir"), "Elixir");
    }

    #[test]
    fn column_resolution_prefers_hints_and_reports_missing() {
        let columns: Vec<String> = ["id", "func", "target", "project"]
            .map(String::from)
            .to_vec();
        let profile = BenchmarkProfile {
            task: BenchmarkTask::VulnerabilityDetection,
            default_language: Some("C".into()),
            columns: ColumnHints::default(),
        };
        let mapping = resolve_columns(&profile, &columns).unwrap();
        assert_eq!(mapping.code.as_deref(), Some("func"));
        assert_eq!(mapping.label.as_deref(), Some("target"));

        let without_label: Vec<String> = ["id", "func"].map(String::from).to_vec();
        let error = resolve_columns(&profile, &without_label).unwrap_err();
        assert!(error.contains("label") && error.contains("func"));

        let no_language = BenchmarkProfile {
            default_language: None,
            ..profile
        };
        assert!(resolve_columns(&no_language, &columns).is_err());
    }
}
