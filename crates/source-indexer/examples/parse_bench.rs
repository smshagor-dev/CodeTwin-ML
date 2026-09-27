//! Times parse-only indexing (no database) of a repository.
//! Usage: cargo run --release -p source-indexer --example parse_bench -- <repo>
fn main() {
    let repo = std::env::args().nth(1).expect("usage: parse_bench <repo>");
    let started = std::time::Instant::now();
    let result = source_indexer::index_project(&repo, &Default::default()).expect("index");
    println!(
        "parsed {} files ({} skipped) in {:.2?}",
        result.indexed_files.len(),
        result.skipped_files.len(),
        started.elapsed()
    );
}
