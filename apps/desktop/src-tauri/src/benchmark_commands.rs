use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use dataset_benchmark::{
    rfc3339, run_benchmark, write_report, BenchmarkOptions, BenchmarkReport, BenchmarkTask,
    Catalog, DatasetStatus, Scores,
};
use serde::Serialize;
use tauri::Manager;

static BENCHMARK_RUNNING: AtomicBool = AtomicBool::new(false);
const MAX_LISTED_RUNS: usize = 50;

/// Where the installers put the dataset pack: `%LOCALAPPDATA%\CodeTwinML\datasets` on Windows
/// (NSIS hook), and the matching per-user data directory elsewhere
/// (`scripts/install_openmindai_datasets.py`).
fn default_datasets_root() -> Option<PathBuf> {
    if cfg!(windows) {
        return std::env::var_os("LOCALAPPDATA")
            .map(|base| PathBuf::from(base).join("CodeTwinML").join("datasets"));
    }
    let home = std::env::var_os("HOME").map(PathBuf::from);
    if cfg!(target_os = "macos") {
        return home.map(|home| {
            home.join("Library")
                .join("Application Support")
                .join("CodeTwinML")
                .join("datasets")
        });
    }
    std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .or_else(|| home.map(|home| home.join(".local").join("share")))
        .map(|base| base.join("CodeTwinML").join("datasets"))
}

fn benchmarks_dir(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|error| error.to_string())?
        .join("benchmarks");
    fs::create_dir_all(&dir).map_err(|error| error.to_string())?;
    Ok(dir)
}

fn resolve_root(datasets_root: Option<String>) -> Result<PathBuf, String> {
    match datasets_root
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    {
        Some(value) => {
            let path = PathBuf::from(value);
            if !path.is_absolute() {
                return Err("choose an absolute dataset directory".to_string());
            }
            fs::canonicalize(&path).map_err(|error| format!("{}: {error}", path.display()))
        }
        None => default_datasets_root()
            .ok_or_else(|| "no default dataset directory on this system; choose one".to_string()),
    }
}

fn valid_run_id(run_id: &str) -> bool {
    !run_id.is_empty()
        && run_id.len() <= 64
        && run_id
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '-')
}

#[derive(Debug, Serialize)]
pub struct CatalogDataset {
    pub id: String,
    pub name: String,
    pub repository: String,
    pub license: String,
    pub license_url: String,
    pub task: Option<BenchmarkTask>,
    pub splits: Vec<String>,
    pub download_bytes: u64,
    /// The pinned revision directory exists. Hashes are checked when a benchmark runs.
    pub installed: bool,
}

#[derive(Debug, Serialize)]
pub struct DatasetBenchmarkStatus {
    pub datasets_root: Option<String>,
    pub root_exists: bool,
    pub datasets: Vec<CatalogDataset>,
}

#[tauri::command]
pub fn dataset_benchmark_status(
    datasets_root: Option<String>,
) -> Result<DatasetBenchmarkStatus, String> {
    let catalog = Catalog::embedded().map_err(|error| error.to_string())?;
    let root = resolve_root(datasets_root).ok();
    let datasets = catalog
        .datasets
        .iter()
        .map(|spec| CatalogDataset {
            id: spec.id.clone(),
            name: spec.name.clone(),
            repository: spec.repository.clone(),
            license: spec.license.clone(),
            license_url: spec.license_url.clone(),
            task: spec.benchmark.as_ref().map(|profile| profile.task),
            splits: spec.splits(),
            download_bytes: spec.files.iter().filter_map(|file| file.size_bytes).sum(),
            installed: root
                .as_ref()
                .is_some_and(|root| spec.revision_root(root).is_dir()),
        })
        .collect();
    Ok(DatasetBenchmarkStatus {
        root_exists: root.as_ref().is_some_and(|root| root.is_dir()),
        datasets_root: root.map(|root| root.to_string_lossy().to_string()),
        datasets,
    })
}

#[derive(Debug, Serialize)]
pub struct BenchmarkDatasetSummary {
    pub id: String,
    pub name: String,
    pub status: DatasetStatus,
    pub message: Option<String>,
    pub scored: u64,
    pub scores: Option<Scores>,
    pub secret_hits_per_thousand: Option<f64>,
    pub pairs_evaluated: Option<u64>,
    pub pairs_cleared_by_fix: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct BenchmarkRunSummary {
    pub run_id: String,
    pub generated_at: String,
    pub split: String,
    pub max_samples: usize,
    pub duration_ms: u64,
    pub evaluated: usize,
    pub datasets: Vec<BenchmarkDatasetSummary>,
}

fn summarize(run_id: &str, report: &BenchmarkReport) -> BenchmarkRunSummary {
    BenchmarkRunSummary {
        run_id: run_id.to_string(),
        generated_at: report.generated_at.clone(),
        split: report.options.split.clone(),
        max_samples: report.options.max_samples,
        duration_ms: report.duration_ms,
        evaluated: report.evaluated(),
        datasets: report
            .datasets
            .iter()
            .map(|dataset| BenchmarkDatasetSummary {
                id: dataset.id.clone(),
                name: dataset.name.clone(),
                status: dataset.status,
                message: dataset.message.clone(),
                scored: dataset
                    .vulnerability
                    .as_ref()
                    .map(|metrics| metrics.evaluated)
                    .or_else(|| {
                        dataset
                            .repair_pairs
                            .as_ref()
                            .map(|pairs| pairs.pairs_evaluated)
                    })
                    .or_else(|| {
                        dataset
                            .secret_probe
                            .as_ref()
                            .map(|probe| probe.texts_scanned)
                    })
                    .unwrap_or(0),
                scores: dataset.vulnerability.as_ref().map(|metrics| metrics.scores),
                secret_hits_per_thousand: dataset
                    .secret_probe
                    .as_ref()
                    .and_then(|probe| probe.hit_texts_per_thousand),
                pairs_evaluated: dataset
                    .repair_pairs
                    .as_ref()
                    .map(|pairs| pairs.pairs_evaluated),
                pairs_cleared_by_fix: dataset
                    .repair_pairs
                    .as_ref()
                    .map(|pairs| pairs.pairs_cleared_by_fix),
            })
            .collect(),
    }
}

/// Runs the offline benchmark and stores `report.{json,md,html}` under
/// `<app data>/benchmarks/<run id>/`. Reads only installed files that match the catalog pins;
/// nothing is downloaded.
#[tauri::command]
pub async fn run_dataset_benchmark(
    datasets_root: Option<String>,
    dataset_ids: Vec<String>,
    split: String,
    max_samples: usize,
    app: tauri::AppHandle,
) -> Result<BenchmarkRunSummary, String> {
    let root = resolve_root(datasets_root)?;
    if !root.is_dir() {
        return Err(format!(
            "no datasets installed at {}; install the OpenMindAI Dataset pack first",
            root.display()
        ));
    }
    let split = split.trim().to_string();
    if split.is_empty()
        || !split
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "_-/".contains(character))
    {
        return Err("invalid split name".to_string());
    }
    let catalog = Catalog::embedded().map_err(|error| error.to_string())?;
    if let Some(unknown) = dataset_ids.iter().find(|id| catalog.dataset(id).is_none()) {
        return Err(format!("unknown dataset: {unknown}"));
    }
    let output_root = benchmarks_dir(&app)?;
    if BENCHMARK_RUNNING.swap(true, Ordering::SeqCst) {
        return Err("a dataset benchmark is already running".to_string());
    }
    let task = tauri::async_runtime::spawn_blocking(move || {
        let mut options = BenchmarkOptions::new(root);
        options.dataset_ids = dataset_ids;
        options.split = split;
        options.max_samples = max_samples.clamp(1, dataset_benchmark::MAX_SAMPLES_LIMIT);
        let report = run_benchmark(&catalog, &options);
        let seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0);
        let stamp: String = rfc3339(seconds)
            .chars()
            .filter(|character| character.is_ascii_alphanumeric())
            .collect();
        let run_id = format!("{stamp}-{:04x}", std::process::id() & 0xffff);
        write_report(&report, &output_root.join(&run_id)).map_err(|error| error.to_string())?;
        Ok::<_, String>(summarize(&run_id, &report))
    })
    .await;
    BENCHMARK_RUNNING.store(false, Ordering::SeqCst);
    task.map_err(|error| error.to_string())?
}

fn read_report(dir: &Path) -> Result<BenchmarkReport, String> {
    let text = fs::read_to_string(dir.join("report.json")).map_err(|error| error.to_string())?;
    serde_json::from_str(&text).map_err(|error| error.to_string())
}

#[tauri::command]
pub fn list_dataset_benchmarks(app: tauri::AppHandle) -> Result<Vec<BenchmarkRunSummary>, String> {
    let dir = benchmarks_dir(&app)?;
    let mut runs: Vec<(String, PathBuf)> = fs::read_dir(&dir)
        .map_err(|error| error.to_string())?
        .filter_map(Result::ok)
        .filter(|entry| entry.path().is_dir())
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().to_string();
            valid_run_id(&name).then(|| (name, entry.path()))
        })
        .collect();
    runs.sort_by(|left, right| right.0.cmp(&left.0));
    Ok(runs
        .into_iter()
        .take(MAX_LISTED_RUNS)
        .filter_map(|(run_id, path)| {
            read_report(&path)
                .ok()
                .map(|report| summarize(&run_id, &report))
        })
        .collect())
}

/// Copies one of a run's report files to a user-chosen path. `format` is html, markdown or json.
#[tauri::command]
pub fn export_dataset_benchmark(
    run_id: String,
    format: String,
    path: String,
    app: tauri::AppHandle,
) -> Result<String, String> {
    if !valid_run_id(&run_id) {
        return Err("invalid benchmark run id".to_string());
    }
    let (file, extension) = match format.as_str() {
        "html" => ("report.html", "html"),
        "markdown" => ("report.md", "md"),
        "json" => ("report.json", "json"),
        _ => return Err("report format must be html, markdown or json".to_string()),
    };
    let source = benchmarks_dir(&app)?.join(&run_id).join(file);
    if !source.is_file() {
        return Err("benchmark report not found".to_string());
    }
    let destination = PathBuf::from(path);
    if !destination
        .extension()
        .and_then(|value| value.to_str())
        .is_some_and(|value| value.eq_ignore_ascii_case(extension))
    {
        return Err(format!("report path must use .{extension}"));
    }
    if !destination.parent().is_some_and(Path::is_dir) {
        return Err("report destination directory does not exist".to_string());
    }
    fs::copy(&source, &destination).map_err(|error| error.to_string())?;
    Ok(destination.to_string_lossy().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_ids_reject_traversal() {
        assert!(valid_run_id("20260927T180405Z-00ab"));
        assert!(!valid_run_id("../etc"));
        assert!(!valid_run_id("a/b"));
        assert!(!valid_run_id(""));
    }
}
