//! Live check against OSV.dev (network): cargo run -p dependency-audit --example osv_live
use dependency_audit::{summarize, Dependency, Ecosystem, OsvClient, DEFAULT_OSV_API};

fn main() {
    let client = OsvClient::new(DEFAULT_OSV_API).expect("client");
    let deps = vec![
        Dependency {
            ecosystem: Ecosystem::Npm,
            name: "lodash".into(),
            version: "4.17.20".into(),
            is_dev: false,
            line: None,
        },
        Dependency {
            ecosystem: Ecosystem::PyPI,
            name: "django".into(),
            version: "3.2.0".into(),
            is_dev: false,
            line: None,
        },
        Dependency {
            ecosystem: Ecosystem::CratesIo,
            name: "serde".into(),
            version: "1.0.200".into(),
            is_dev: false,
            line: None,
        },
    ];
    let results = client.query_batch(&deps).expect("query");
    for (dep, ids) in deps.iter().zip(&results) {
        println!(
            "{} {}@{}: {} advisories",
            dep.ecosystem.osv_name(),
            dep.name,
            dep.version,
            ids.len()
        );
        if let Some(id) = ids.first() {
            let record = client.vulnerability(id).expect("vuln");
            let advisory = summarize(&record, dep).expect("summary");
            println!(
                "  {} [{}] severity={} cvss={:?} fixed={:?}",
                advisory.id,
                advisory.display_id(),
                advisory.severity,
                advisory.cvss_score,
                advisory.fixed_versions
            );
            println!("  {}", advisory.summary);
            println!(
                "  offline matcher agrees: {:?}",
                dependency_audit::affects(&record, dep)
            );
        }
    }
}
