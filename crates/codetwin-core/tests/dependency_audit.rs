use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::TcpListener,
    path::Path,
    thread,
};

use codetwin_core::{
    AdvisorySource, Database, DependencyAuditService, ProjectIndexService, SbomError, SbomService,
};
use serde_json::json;
use tempfile::tempdir;

fn lodash_record() -> serde_json::Value {
    json!({
        "id": "GHSA-35jh-r3h4-6jhm",
        "modified": "2024-01-01T00:00:00Z",
        "aliases": ["CVE-2021-23337"],
        "summary": "Command Injection in lodash",
        "database_specific": {"severity": "HIGH", "cwe_ids": ["CWE-77"]},
        "affected": [{"package": {"ecosystem": "npm", "name": "lodash"},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]}]
    })
}

fn django_record() -> serde_json::Value {
    json!({
        "id": "PYSEC-2021-98",
        "aliases": ["CVE-2021-33203"],
        "summary": "Directory traversal in Django admindocs",
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N"}],
        "affected": [{"package": {"ecosystem": "PyPI", "name": "django"},
            "versions": ["3.2.0", "3.2.1", "3.2.2", "3.2.3"],
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "3.2"}, {"fixed": "3.2.4"}]}]}]
    })
}

fn write_project(root: &Path, lodash_version: &str) {
    fs::write(
        root.join("package-lock.json"),
        json!({
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "app"},
                "node_modules/lodash": {"version": lodash_version},
                "node_modules/express": {"version": "4.18.2"}
            }
        })
        .to_string(),
    )
    .expect("package-lock");
    fs::write(root.join("requirements.txt"), "Django==3.2.0\nflask>=2.0\n").expect("requirements");
    fs::write(
        root.join("Cargo.lock"),
        "[[package]]\nname = \"serde\"\nversion = \"1.0.200\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n",
    )
    .expect("cargo lock");
}

fn osv_directory() -> tempfile::TempDir {
    let directory = tempdir().expect("osv dir");
    fs::create_dir_all(directory.path().join("npm")).expect("npm");
    fs::create_dir_all(directory.path().join("PyPI")).expect("pypi");
    fs::write(
        directory.path().join("npm/GHSA-35jh-r3h4-6jhm.json"),
        lodash_record().to_string(),
    )
    .expect("lodash");
    fs::write(
        directory.path().join("PyPI/PYSEC-2021-98.json"),
        django_record().to_string(),
    )
    .expect("django");
    fs::write(
        directory.path().join("npm/unrelated.json"),
        json!({"id": "GHSA-unrelated", "affected": [{"package": {"ecosystem": "npm", "name": "left-pad"},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]}]})
        .to_string(),
    )
    .expect("unrelated");
    directory
}

fn setup(lodash_version: &str) -> (tempfile::TempDir, Database, String) {
    let project = tempdir().expect("project");
    write_project(project.path(), lodash_version);
    let database = Database::open_in_memory().expect("database");
    let index = ProjectIndexService::new(&database)
        .index_project(project.path())
        .expect("index");
    (project, database, index.project_id)
}

#[test]
fn offline_audit_reports_vulnerable_packages_and_resolves_after_upgrade() {
    let (project, database, project_id) = setup("4.17.20");
    let osv = osv_directory();
    let source = AdvisorySource::OfflineDirectory {
        path: osv.path().to_path_buf(),
    };
    let service = DependencyAuditService::new(&database);

    let summary = service.audit_project(&project_id, &source).expect("audit");
    assert!(summary.coverage_complete, "{summary:?}");
    assert_eq!(summary.manifests, 3);
    assert_eq!(summary.packages, 4);
    assert_eq!(summary.unpinned_requirements, 1);
    assert_eq!(summary.vulnerable_packages, 2);
    assert_eq!(summary.findings_opened, 2);

    let findings = service
        .list_findings(&project_id, Some("open"), 50)
        .expect("findings");
    let lodash = findings
        .iter()
        .find(|item| item.package == "lodash")
        .expect("lodash");
    assert_eq!(lodash.display_id, "CVE-2021-23337");
    assert_eq!(lodash.severity, "high");
    assert_eq!(lodash.fixed_versions, vec!["4.17.21"]);
    assert_eq!(lodash.manifest_path, "package-lock.json");
    assert!(lodash.line.is_some());
    assert_eq!(lodash.match_basis, "range");
    let django = findings
        .iter()
        .find(|item| item.package == "Django")
        .expect("django");
    assert_eq!(django.display_id, "CVE-2021-33203");
    assert_eq!(
        django.severity, "medium",
        "severity derived from the CVSS vector (4.9)"
    );
    assert_eq!(django.match_basis, "exact_version");
    assert!(django.description.contains("3.2.4"));

    let inventory = service.list_inventory(&project_id, 100).expect("inventory");
    assert_eq!(inventory.len(), 4);
    assert_eq!(
        inventory
            .iter()
            .filter(|item| item.open_advisories > 0)
            .count(),
        2
    );

    // Upgrading lodash resolves only its finding.
    write_project(project.path(), "4.17.21");
    let after = service
        .audit_project(&project_id, &source)
        .expect("re-audit");
    assert_eq!(after.findings_resolved, 1);
    assert_eq!(after.findings_refreshed, 1);
    let open = service
        .list_findings(&project_id, Some("open"), 50)
        .expect("open");
    assert_eq!(open.len(), 1);
    assert_eq!(open[0].package, "Django");
    assert_eq!(service.history(&project_id, 10).expect("history").len(), 2);
}

#[test]
fn unreadable_manifest_keeps_existing_findings_open() {
    let (project, database, project_id) = setup("4.17.20");
    let osv = osv_directory();
    let source = AdvisorySource::OfflineDirectory {
        path: osv.path().to_path_buf(),
    };
    let service = DependencyAuditService::new(&database);
    service
        .audit_project(&project_id, &source)
        .expect("first audit");

    fs::write(project.path().join("package-lock.json"), "{ broken").expect("corrupt");
    let summary = service.audit_project(&project_id, &source).expect("audit");
    assert!(!summary.coverage_complete);
    assert_eq!(summary.findings_resolved, 0);
    assert_eq!(summary.manifest_errors.len(), 1);
    assert!(service
        .list_findings(&project_id, Some("open"), 50)
        .expect("open")
        .iter()
        .any(|item| item.package == "lodash"));
}

#[test]
fn online_audit_uses_osv_api_and_caches_advisories() {
    let (_project, database, project_id) = setup("4.17.20");
    let base_url = start_mock_osv();
    let service = DependencyAuditService::new(&database);
    let summary = service
        .audit_project(&project_id, &AdvisorySource::OsvApi { base_url })
        .expect("online audit");
    assert!(summary.coverage_complete);
    assert_eq!(summary.findings_opened, 1);
    let findings = service
        .list_findings(&project_id, Some("open"), 50)
        .expect("findings");
    assert_eq!(findings[0].match_basis, "osv_api");
    let cached: i64 = database
        .connection()
        .query_row("SELECT COUNT(*) FROM osv_advisories", [], |row| row.get(0))
        .expect("cache");
    assert_eq!(cached, 1);
}

#[test]
fn unreachable_advisory_service_fails_without_resolving_findings() {
    let (_project, database, project_id) = setup("4.17.20");
    let osv = osv_directory();
    let service = DependencyAuditService::new(&database);
    service
        .audit_project(
            &project_id,
            &AdvisorySource::OfflineDirectory {
                path: osv.path().to_path_buf(),
            },
        )
        .expect("seed findings");

    let error = service
        .audit_project(
            &project_id,
            &AdvisorySource::OsvApi {
                base_url: "http://127.0.0.1:9".into(),
            },
        )
        .expect_err("unreachable service must fail");
    assert!(error.to_string().contains("advisory lookup failed"));
    assert_eq!(
        service
            .list_findings(&project_id, Some("open"), 50)
            .expect("open")
            .len(),
        2
    );
    let history = service.history(&project_id, 10).expect("history");
    assert_eq!(history[0].status, "failed");
}

/// Minimal OSV API mock: lodash 4.17.20 is vulnerable, everything else is clean.
fn start_mock_osv() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let base_url = format!("http://{}", listener.local_addr().expect("addr"));
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut reader = BufReader::new(stream.try_clone().expect("clone"));
            let mut request_line = String::new();
            reader.read_line(&mut request_line).expect("line");
            let mut length = 0usize;
            loop {
                let mut header = String::new();
                reader.read_line(&mut header).expect("header");
                if header.trim().is_empty() {
                    break;
                }
                if let Some(value) = header.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = value.trim().parse().unwrap_or(0);
                }
            }
            let mut body = vec![0; length];
            reader.read_exact(&mut body).expect("body");
            let path = request_line
                .split_whitespace()
                .nth(1)
                .unwrap_or("")
                .to_string();
            let response = if path == "/v1/querybatch" {
                let request: serde_json::Value = serde_json::from_slice(&body).expect("json");
                let results: Vec<_> = request["queries"]
                    .as_array()
                    .expect("queries")
                    .iter()
                    .map(|query| {
                        if query["package"]["name"] == "lodash" && query["version"] == "4.17.20" {
                            json!({"vulns": [{"id": "GHSA-35jh-r3h4-6jhm"}]})
                        } else {
                            json!({})
                        }
                    })
                    .collect();
                json!({ "results": results })
            } else if path == "/v1/vulns/GHSA-35jh-r3h4-6jhm" {
                lodash_record()
            } else {
                json!({})
            };
            let payload = response.to_string();
            let mut stream = stream;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
                payload.len()
            )
            .expect("write");
        }
    });
    base_url
}

#[test]
fn offline_audit_covers_maven_gradle_and_nuget() {
    let project = tempdir().expect("project");
    let root = project.path();
    fs::create_dir_all(root.join("api")).expect("api");
    fs::create_dir_all(root.join("web")).expect("web");
    fs::write(
        root.join("api/pom.xml"),
        "<project><groupId>com.acme</groupId><artifactId>api</artifactId><version>1.0.0</version>\n\
         <properties><log4j.version>2.14.1</log4j.version></properties>\n\
         <dependencies>\n\
         <dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>${log4j.version}</version></dependency>\n\
         <dependency><groupId>org.slf4j</groupId><artifactId>slf4j-api</artifactId></dependency>\n\
         </dependencies></project>\n",
    )
    .expect("pom");
    fs::write(
        root.join("gradle.lockfile"),
        "com.google.guava:guava:31.1-jre=compileClasspath,runtimeClasspath\n\
         org.apache.logging.log4j:log4j-core:2.17.1=runtimeClasspath\n",
    )
    .expect("gradle");
    fs::write(
        root.join("web/Web.csproj"),
        "<Project Sdk=\"Microsoft.NET.Sdk.Web\"><ItemGroup>\n\
         <PackageReference Include=\"Newtonsoft.Json\" Version=\"12.0.1\" />\n\
         </ItemGroup></Project>\n",
    )
    .expect("csproj");

    let osv = tempdir().expect("osv");
    fs::write(
        osv.path().join("GHSA-jfh8-c2jp-5v3q.json"),
        json!({
            "id": "GHSA-jfh8-c2jp-5v3q", "aliases": ["CVE-2021-44228"],
            "summary": "Remote code injection in Log4j",
            "database_specific": {"severity": "CRITICAL"},
            "affected": [{"package": {"ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "2.0-beta9"}, {"fixed": "2.15.0"}]}]}]
        })
        .to_string(),
    )
    .expect("log4j record");
    fs::write(
        osv.path().join("GHSA-5crp-9r3c-p9vr.json"),
        json!({
            "id": "GHSA-5crp-9r3c-p9vr", "aliases": ["CVE-2024-21907"],
            "summary": "Improper handling of exceptional conditions in Newtonsoft.Json",
            "database_specific": {"severity": "HIGH"},
            "affected": [{"package": {"ecosystem": "NuGet", "name": "Newtonsoft.Json"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "13.0.1"}]}]}]
        })
        .to_string(),
    )
    .expect("newtonsoft record");

    let database = Database::open_in_memory().expect("database");
    let index = ProjectIndexService::new(&database)
        .index_project(root)
        .expect("index");
    let service = DependencyAuditService::new(&database);
    let summary = service
        .audit_project(
            &index.project_id,
            &AdvisorySource::OfflineDirectory {
                path: osv.path().to_path_buf(),
            },
        )
        .expect("audit");
    assert_eq!(summary.manifests, 3, "{summary:?}");
    assert_eq!(summary.packages, 4, "{summary:?}");
    assert_eq!(summary.unpinned_requirements, 1);
    assert_eq!(summary.vulnerable_packages, 2, "{summary:?}");

    let findings = service
        .list_findings(&index.project_id, Some("open"), 100)
        .expect("findings");
    let log4j = findings
        .iter()
        .find(|finding| finding.package == "org.apache.logging.log4j:log4j-core")
        .expect("log4j finding");
    assert_eq!(log4j.version, "2.14.1");
    assert_eq!(log4j.display_id, "CVE-2021-44228");
    assert_eq!(log4j.severity, "critical");
    assert_eq!(log4j.manifest_path, "api/pom.xml");
    assert_eq!(log4j.line, Some(4));
    let newtonsoft = findings
        .iter()
        .find(|finding| finding.ecosystem == "NuGet")
        .expect("nuget finding");
    assert_eq!(newtonsoft.fixed_versions, vec!["13.0.1"]);
    // The patched 2.17.1 in the Gradle lockfile is not reported.
    assert!(findings.iter().all(|finding| finding.version != "2.17.1"));

    let export = SbomService::new(&database)
        .export_cyclonedx(&index.project_id)
        .expect("sbom");
    if let Some(path) = std::env::var_os("CODETWIN_SBOM_OUT") {
        fs::write(path, &export.json).expect("write sbom");
    }
    assert_eq!((export.components, export.vulnerabilities), (4, 2));
    assert_eq!(export.components_without_purl, 0);
    let sbom: serde_json::Value = serde_json::from_str(&export.json).expect("json");
    assert_eq!(sbom["bomFormat"], "CycloneDX");
    assert_eq!(sbom["specVersion"], "1.5");
    let purls: Vec<&str> = sbom["components"]
        .as_array()
        .unwrap()
        .iter()
        .map(|component| component["purl"].as_str().unwrap())
        .collect();
    assert!(purls.contains(&"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"));
    assert!(purls.contains(&"pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1"));
    assert!(purls.contains(&"pkg:nuget/Newtonsoft.Json@12.0.1"));
    let log4shell = sbom["vulnerabilities"]
        .as_array()
        .unwrap()
        .iter()
        .find(|vulnerability| vulnerability["id"] == "CVE-2021-44228")
        .expect("log4shell entry");
    assert_eq!(log4shell["ratings"][0]["severity"], "critical");
    assert_eq!(
        log4shell["affects"][0]["ref"],
        "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
    );
    assert_eq!(log4shell["references"][0]["id"], "GHSA-jfh8-c2jp-5v3q");
    assert!(log4shell["recommendation"]
        .as_str()
        .unwrap()
        .contains("2.15.0"));
    // Every vulnerability reference resolves to a component in the same document.
    for vulnerability in sbom["vulnerabilities"].as_array().unwrap() {
        for affected in vulnerability["affects"].as_array().unwrap() {
            assert!(purls.contains(&affected["ref"].as_str().unwrap()));
        }
    }
}

#[test]
fn sbom_requires_an_inventory() {
    let project = tempdir().expect("project");
    fs::write(project.path().join("README.md"), "x\n").expect("readme");
    let database = Database::open_in_memory().expect("database");
    let index = ProjectIndexService::new(&database)
        .index_project(project.path())
        .expect("index");
    let error = SbomService::new(&database)
        .export_cyclonedx(&index.project_id)
        .expect_err("no inventory");
    assert!(matches!(error, SbomError::NoInventory));
}
