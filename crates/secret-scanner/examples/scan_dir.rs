//! Prints redacted secret findings for a directory (manual false-positive review).
//! Usage: cargo run -p secret-scanner --example scan_dir -- <dir>
fn main() {
    let root = std::env::args().nth(1).expect("usage: scan_dir <dir>");
    let skip = [
        ".git",
        "node_modules",
        "target",
        "dist",
        "build",
        "vendor",
        ".venv",
        "venv",
    ];
    for entry in walkdir::WalkDir::new(&root)
        .into_iter()
        .filter_entry(|e| !skip.contains(&e.file_name().to_string_lossy().as_ref()))
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
    {
        let Ok(bytes) = std::fs::read(entry.path()) else {
            continue;
        };
        if bytes.len() > 1024 * 1024 || secret_scanner::looks_binary(&bytes) {
            continue;
        }
        let Ok(text) = String::from_utf8(bytes) else {
            continue;
        };
        let path = entry
            .path()
            .strip_prefix(&root)
            .unwrap()
            .display()
            .to_string();
        for item in secret_scanner::scan_text(&path, &text) {
            println!(
                "{}:{} {} {} conf={} test={}",
                path, item.line, item.rule_id, item.redacted, item.confidence, item.in_test_path
            );
        }
    }
}
