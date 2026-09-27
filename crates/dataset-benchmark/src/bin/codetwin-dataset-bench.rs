//! Offline benchmark of CodeTwin's analyzers against installed, pinned datasets.
//!
//! codetwin-dataset-bench --datasets-root DIR [--dataset ID]... [--split test]
//!                        [--max-samples 2000] [--catalog FILE] [--out DIR]

use std::{path::PathBuf, process::ExitCode};

use dataset_benchmark::{run_benchmark, write_report, BenchmarkOptions, Catalog};

fn usage() -> ExitCode {
    eprintln!(
        "usage: codetwin-dataset-bench --datasets-root DIR [--dataset ID]... [--split NAME] \
         [--max-samples N] [--catalog FILE] [--out DIR]"
    );
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let mut root: Option<PathBuf> = None;
    let mut catalog_path: Option<PathBuf> = None;
    let mut out = PathBuf::from("benchmark-report");
    let mut datasets = Vec::new();
    let mut split = None;
    let mut max_samples = None;
    while let Some(flag) = args.next() {
        let Some(value) = args.next() else {
            return usage();
        };
        match flag.as_str() {
            "--datasets-root" => root = Some(value.into()),
            "--catalog" => catalog_path = Some(value.into()),
            "--out" => out = value.into(),
            "--dataset" => datasets.push(value),
            "--split" => split = Some(value),
            "--max-samples" => match value.parse() {
                Ok(value) => max_samples = Some(value),
                Err(_) => return usage(),
            },
            _ => return usage(),
        }
    }
    let Some(root) = root else {
        return usage();
    };
    let catalog = match catalog_path {
        Some(path) => std::fs::read_to_string(&path)
            .map_err(|error| error.to_string())
            .and_then(|text| Catalog::parse(&text).map_err(|error| error.to_string())),
        None => Catalog::embedded().map_err(|error| error.to_string()),
    };
    let catalog = match catalog {
        Ok(catalog) => catalog,
        Err(error) => {
            eprintln!("error: {error}");
            return ExitCode::FAILURE;
        }
    };
    let mut options = BenchmarkOptions::new(root);
    options.dataset_ids = datasets;
    if let Some(split) = split {
        options.split = split;
    }
    if let Some(max_samples) = max_samples {
        options.max_samples = max_samples;
    }
    let report = run_benchmark(&catalog, &options);
    for dataset in &report.datasets {
        let detail = dataset
            .vulnerability
            .as_ref()
            .map(|metrics| {
                format!(
                    " scored={} precision={:?} recall={:?} f1={:?}",
                    metrics.evaluated,
                    metrics.scores.precision,
                    metrics.scores.recall,
                    metrics.scores.f1
                )
            })
            .unwrap_or_default();
        println!(
            "{:<32} {:?}{}{}",
            dataset.id,
            dataset.status,
            detail,
            dataset
                .message
                .as_ref()
                .map(|m| format!(" ({m})"))
                .unwrap_or_default()
        );
    }
    match write_report(&report, &out) {
        Ok(files) => {
            println!("report: {}", files.html.display());
            if report.evaluated() == 0 {
                ExitCode::FAILURE
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}
