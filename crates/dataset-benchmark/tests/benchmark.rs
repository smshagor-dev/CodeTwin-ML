use std::{fs::File, path::Path, sync::Arc};

use dataset_benchmark::{run_benchmark, write_report, BenchmarkOptions, Catalog, DatasetStatus};
use parquet::{
    basic::Compression,
    data_type::{BoolType, ByteArray, ByteArrayType},
    file::{properties::WriterProperties, writer::SerializedFileWriter},
    schema::parser::parse_message_type,
};
use sha2::{Digest, Sha256};

enum Column<'a> {
    Text(&'a str, Vec<&'a str>),
    Bool(&'a str, Vec<bool>),
}

fn write_parquet(path: &Path, columns: &[Column<'_>]) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let fields: Vec<String> = columns
        .iter()
        .map(|column| match column {
            Column::Text(name, _) => format!("REQUIRED BYTE_ARRAY {name} (UTF8);"),
            Column::Bool(name, _) => format!("REQUIRED BOOLEAN {name};"),
        })
        .collect();
    let schema = Arc::new(
        parse_message_type(&format!("message schema {{ {} }}", fields.join(" "))).unwrap(),
    );
    let properties = Arc::new(
        WriterProperties::builder()
            .set_compression(Compression::SNAPPY)
            .build(),
    );
    let mut writer =
        SerializedFileWriter::new(File::create(path).unwrap(), schema, properties).unwrap();
    let mut group = writer.next_row_group().unwrap();
    for column in columns {
        let mut target = group.next_column().unwrap().unwrap();
        match column {
            Column::Text(_, values) => {
                let values: Vec<ByteArray> =
                    values.iter().map(|value| ByteArray::from(*value)).collect();
                target
                    .typed::<ByteArrayType>()
                    .write_batch(&values, None, None)
                    .unwrap();
            }
            Column::Bool(_, values) => {
                target
                    .typed::<BoolType>()
                    .write_batch(values, None, None)
                    .unwrap();
            }
        }
        target.close().unwrap();
    }
    group.close().unwrap();
    writer.close().unwrap();
}

fn sha256(path: &Path) -> String {
    Sha256::digest(std::fs::read(path).unwrap())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn catalog_for(entries: &[(&str, &Path, &str, serde_json::Value)]) -> Catalog {
    let datasets: Vec<serde_json::Value> = entries
        .iter()
        .map(|(id, file, relative, benchmark)| {
            let (size, hash) = if file.is_file() {
                (std::fs::metadata(file).unwrap().len(), sha256(file))
            } else {
                (1, "0".repeat(64))
            };
            serde_json::json!({
                "id": id,
                "name": format!("Fixture <{id}>"),
                "repository": format!("fixture/{id}"),
                "revision": "rev1",
                "license": "apache-2.0",
                "license_url": "https://www.apache.org/licenses/LICENSE-2.0",
                "files": [{"path": relative, "size_bytes": size, "sha256": hash}],
                "benchmark": benchmark,
            })
        })
        .collect();
    Catalog::parse(&serde_json::json!({"schema_version": 1, "datasets": datasets}).to_string())
        .unwrap()
}

#[test]
fn scores_a_labeled_multilanguage_dataset() {
    let root = tempfile::tempdir().unwrap();
    let file = root
        .path()
        .join("vuln/rev1/data/test-00000-of-00001.parquet");
    write_parquet(
        &file,
        &[
            Column::Text(
                "code",
                vec![
                    "void f(char *d, char *s) { strcpy(d, s); }\n",
                    "import hashlib\nhashlib.sha1(data).digest()\n",
                    "def add(a, b):\n    return a + b\n",
                    "eval(source);\n",
                    "class A { void run() {} }\n",
                    "int g(int x) { return x + 1; }\n",
                    "print('unlabeled')\n",
                ],
            ),
            Column::Text(
                "label",
                vec!["1", "vulnerable", "safe", "0", "1", "1", "maybe"],
            ),
            Column::Text(
                "cwe",
                vec!["CWE-120", "CWE-327", "", "", "CWE-79", "CWE-190", ""],
            ),
            Column::Text(
                "language",
                vec!["c", "python", "python", "javascript", "java", "c", "python"],
            ),
        ],
    );
    let catalog = catalog_for(&[(
        "vuln",
        &file,
        "data/test-00000-of-00001.parquet",
        serde_json::json!({"task": "vulnerability_detection"}),
    )]);
    let report = run_benchmark(&catalog, &BenchmarkOptions::new(root.path()));
    let dataset = &report.datasets[0];
    assert_eq!(
        dataset.status,
        DatasetStatus::Evaluated,
        "{:?}",
        dataset.message
    );
    assert!(dataset.files[0].verified);
    assert_eq!(dataset.total_rows, 7);
    let columns = dataset.columns.as_ref().unwrap();
    assert_eq!(columns.code.as_deref(), Some("code"));
    assert_eq!(columns.cwe.as_deref(), Some("cwe"));

    let metrics = dataset.vulnerability.as_ref().unwrap();
    assert_eq!(metrics.rows_read, 7);
    assert_eq!(metrics.skipped_unlabeled, 1);
    assert_eq!(metrics.skipped_unsupported_language.get("Java"), Some(&1));
    assert_eq!(metrics.evaluated, 5);
    // strcpy and sha1 are caught; the integer function is a miss; eval on a sample labeled
    // safe is a false positive; the plain Python function is a true negative.
    assert_eq!(metrics.confusion.true_positive, 2);
    assert_eq!(metrics.confusion.false_negative, 1);
    assert_eq!(metrics.confusion.false_positive, 1);
    assert_eq!(metrics.confusion.true_negative, 1);
    assert_eq!(metrics.by_cwe["CWE-120"].matched_cwe, 1);
    assert_eq!(metrics.by_cwe["CWE-190"].flagged, 0);
    assert!(metrics.by_rule.contains_key("security.unsafe_c_string_api"));
    assert_eq!(
        metrics.by_rule["security.dynamic_code_execution"].fired_on_safe,
        1
    );
    assert_eq!(metrics.by_language.len(), 3);

    let out = root.path().join("report");
    let files = write_report(&report, &out).unwrap();
    let html = std::fs::read_to_string(&files.html).unwrap();
    assert!(html.contains("Fixture &lt;vuln&gt;"));
    assert!(!html.contains("Fixture <vuln>"));
    assert!(html.contains("security.unsafe_c_string_api"));
    let markdown = std::fs::read_to_string(&files.markdown).unwrap();
    assert!(markdown.contains("| Labeled vulnerable | 2 | 1 |"));
    let json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&files.json).unwrap()).unwrap();
    assert_eq!(
        json["datasets"][0]["vulnerability"]["confusion"]["true_positive"],
        2
    );
    assert_eq!(json["schema_version"], 1);
}

#[test]
fn sampling_is_capped_and_strided() {
    let root = tempfile::tempdir().unwrap();
    let file = root
        .path()
        .join("big/rev1/data/test-00000-of-00001.parquet");
    let code: Vec<&str> = (0..100).map(|_| "int f(void) { return 0; }\n").collect();
    let labels: Vec<bool> = (0..100).map(|index| index % 2 == 0).collect();
    write_parquet(
        &file,
        &[Column::Text("func", code), Column::Bool("target", labels)],
    );
    let catalog = catalog_for(&[(
        "big",
        &file,
        "data/test-00000-of-00001.parquet",
        serde_json::json!({"task": "vulnerability_detection", "default_language": "C"}),
    )]);
    let mut options = BenchmarkOptions::new(root.path());
    options.max_samples = 10;
    let report = run_benchmark(&catalog, &options);
    let dataset = &report.datasets[0];
    assert_eq!(dataset.stride, 10);
    let metrics = dataset.vulnerability.as_ref().unwrap();
    assert_eq!(metrics.evaluated, 10);
    // Every 10th row starting at 0 has an even index, so all sampled rows are labeled vulnerable.
    assert_eq!(metrics.confusion.false_negative, 10);
    assert_eq!(metrics.scores.recall, Some(0.0));
}

#[test]
fn refuses_tampered_missing_and_unmappable_datasets() {
    let root = tempfile::tempdir().unwrap();
    let good = root
        .path()
        .join("tampered/rev1/data/test-00000-of-00001.parquet");
    write_parquet(
        &good,
        &[
            Column::Text("func", vec!["x"]),
            Column::Bool("target", vec![true]),
        ],
    );
    let odd = root
        .path()
        .join("odd/rev1/data/test-00000-of-00001.parquet");
    write_parquet(
        &odd,
        &[
            Column::Text("body", vec!["x"]),
            Column::Text("verdict_text", vec!["y"]),
        ],
    );
    let catalog = catalog_for(&[
        (
            "tampered",
            &good,
            "data/test-00000-of-00001.parquet",
            serde_json::json!({"task": "vulnerability_detection", "default_language": "C"}),
        ),
        (
            "missing",
            &root.path().join("nope.parquet"),
            "data/test-00000-of-00001.parquet",
            serde_json::json!({"task": "vulnerability_detection", "default_language": "C"}),
        ),
        (
            "odd",
            &odd,
            "data/test-00000-of-00001.parquet",
            serde_json::json!({"task": "vulnerability_detection", "default_language": "C"}),
        ),
    ]);
    // Tamper after the catalog pinned the original bytes.
    let mut bytes = std::fs::read(&good).unwrap();
    let middle = bytes.len() / 2;
    bytes[middle] ^= 0xff;
    std::fs::write(&good, bytes).unwrap();

    let report = run_benchmark(&catalog, &BenchmarkOptions::new(root.path()));
    let status = |id: &str| report.datasets.iter().find(|d| d.id == id).unwrap();
    assert_eq!(status("tampered").status, DatasetStatus::IntegrityFailed);
    assert!(status("tampered").vulnerability.is_none());
    assert_eq!(status("missing").status, DatasetStatus::NotInstalled);
    let odd = status("odd");
    assert_eq!(odd.status, DatasetStatus::SchemaUnrecognized);
    assert!(odd
        .message
        .as_deref()
        .unwrap()
        .contains("body, verdict_text"));
    assert_eq!(report.evaluated(), 0);

    let mut options = BenchmarkOptions::new(root.path());
    options.split = "validation".into();
    let report = run_benchmark(&catalog, &options);
    assert!(report.datasets[0]
        .message
        .as_deref()
        .unwrap()
        .contains("available: test"));
}

#[test]
fn repair_pairs_and_secret_probe() {
    let root = tempfile::tempdir().unwrap();
    let pairs = root
        .path()
        .join("pairs/rev1/small/test-00000-of-00001.parquet");
    write_parquet(
        &pairs,
        &[
            Column::Text(
                "buggy",
                vec![
                    "void f(char *d, char *s) { strcpy(d, s); }\n",
                    "int a(void) { return 1; }\n",
                ],
            ),
            Column::Text(
                "fixed",
                vec![
                    "void f(char *d, char *s, size_t n) { strncpy(d, s, n); }\n",
                    "int a(void) { char b[4]; strcpy(b, \"x\"); return 1; }\n",
                ],
            ),
        ],
    );
    let patches = root
        .path()
        .join("patches/rev1/data/test-00000-of-00001.parquet");
    let aws_key = ["AKIA", "Q3EGRZ7XKTM5WP2N"].concat();
    let patch_with_key = format!("+aws_access_key_id = {aws_key}\n");
    write_parquet(
        &patches,
        &[
            Column::Text("patch", vec![patch_with_key.as_str(), "+x = 1\n"]),
            Column::Text("test_patch", vec!["+assert True\n", ""]),
        ],
    );
    let catalog = catalog_for(&[
        (
            "pairs",
            &pairs,
            "small/test-00000-of-00001.parquet",
            serde_json::json!({"task": "repair_pairs", "default_language": "C"}),
        ),
        (
            "patches",
            &patches,
            "data/test-00000-of-00001.parquet",
            serde_json::json!({"task": "secret_probe", "columns": {"text": ["patch", "test_patch"]}}),
        ),
    ]);
    let report = run_benchmark(&catalog, &BenchmarkOptions::new(root.path()));

    let pair_metrics = report.datasets[0].repair_pairs.as_ref().unwrap();
    assert_eq!(pair_metrics.pairs_evaluated, 2);
    assert_eq!(pair_metrics.pairs_flagged_before, 1);
    assert_eq!(pair_metrics.pairs_with_new_findings, 1);
    assert_eq!(
        pair_metrics
            .rules_introduced_by_fix
            .get("security.unsafe_c_string_api"),
        Some(&1)
    );

    let probe = report.datasets[1].secret_probe.as_ref().unwrap();
    assert_eq!(probe.texts_scanned, 3);
    assert_eq!(probe.texts_with_hits, 1);
    assert!(probe.hits_by_rule.contains_key("secret.aws_access_key_id"));
    let json = serde_json::to_string(&report).unwrap();
    assert!(
        !json.contains(&aws_key),
        "raw secret must not appear in the report"
    );
}

#[test]
fn unsupported_language_pairs_are_explained() {
    let root = tempfile::tempdir().unwrap();
    let pairs = root
        .path()
        .join("java/rev1/small/test-00000-of-00001.parquet");
    write_parquet(
        &pairs,
        &[
            Column::Text("buggy", vec!["public void a() {}"]),
            Column::Text("fixed", vec!["public void b() {}"]),
        ],
    );
    let catalog = catalog_for(&[(
        "java",
        &pairs,
        "small/test-00000-of-00001.parquet",
        serde_json::json!({"task": "repair_pairs", "default_language": "Java"}),
    )]);
    let report = run_benchmark(&catalog, &BenchmarkOptions::new(root.path()));
    let dataset = &report.datasets[0];
    assert_eq!(dataset.status, DatasetStatus::Evaluated);
    assert!(dataset
        .message
        .as_deref()
        .unwrap()
        .contains("does not support Java"));
}
