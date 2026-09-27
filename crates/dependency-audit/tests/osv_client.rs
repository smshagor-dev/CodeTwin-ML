//! Exercises the OSV client against a local mock of the OSV.dev API (no network).
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::TcpListener,
    sync::{Arc, Mutex},
    thread,
};

use dependency_audit::{summarize, Dependency, Ecosystem, OsvClient};
use serde_json::{json, Value};

struct MockOsv {
    base_url: String,
    requests: Arc<Mutex<Vec<(String, String)>>>,
}

fn start_mock() -> MockOsv {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let base_url = format!("http://{}", listener.local_addr().expect("addr"));
    let requests = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&requests);
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut reader = BufReader::new(stream.try_clone().expect("clone"));
            let mut request_line = String::new();
            reader.read_line(&mut request_line).expect("request line");
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
            let body = String::from_utf8(body).expect("utf8");
            let path = request_line
                .split_whitespace()
                .nth(1)
                .unwrap_or("")
                .to_string();
            log.lock().expect("log").push((path.clone(), body.clone()));
            let response = route(&path, &body);
            let mut stream = stream;
            let payload = response.to_string();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
                payload.len()
            )
            .expect("write");
        }
    });
    MockOsv { base_url, requests }
}

fn route(path: &str, body: &str) -> Value {
    match path {
        "/v1/querybatch" => {
            let request: Value = serde_json::from_str(body).expect("json body");
            let results: Vec<Value> = request["queries"]
                .as_array()
                .expect("queries")
                .iter()
                .map(
                    |query| match (query["package"]["name"].as_str(), query["version"].as_str()) {
                        (Some("lodash"), Some("4.17.20")) => {
                            json!({"vulns": [{"id": "GHSA-35jh-r3h4-6jhm"}]})
                        }
                        (Some("paged"), _) => {
                            json!({"vulns": [{"id": "OSV-PAGE-1"}], "next_page_token": "p2"})
                        }
                        _ => json!({}),
                    },
                )
                .collect();
            json!({ "results": results })
        }
        "/v1/query" => json!({"vulns": [{"id": "OSV-PAGE-2"}]}),
        "/v1/vulns/GHSA-35jh-r3h4-6jhm" => json!({
            "id": "GHSA-35jh-r3h4-6jhm",
            "aliases": ["CVE-2021-23337"],
            "summary": "Command Injection in lodash",
            "database_specific": {"severity": "HIGH"},
            "affected": [{"package": {"ecosystem": "npm", "name": "lodash"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]}]
        }),
        _ => json!({}),
    }
}

fn dep(name: &str, version: &str) -> Dependency {
    Dependency {
        ecosystem: Ecosystem::Npm,
        name: name.into(),
        version: version.into(),
        is_dev: false,
        line: None,
    }
}

#[test]
fn batch_query_fetch_and_summarize_against_mock_osv() {
    let mock = start_mock();
    let client = OsvClient::new(&mock.base_url).expect("client");
    let dependencies = vec![
        dep("lodash", "4.17.20"),
        dep("left-pad", "1.3.0"),
        dep("paged", "1.0.0"),
    ];
    let results = client.query_batch(&dependencies).expect("batch");
    assert_eq!(results[0], vec!["GHSA-35jh-r3h4-6jhm".to_string()]);
    assert!(results[1].is_empty());
    assert_eq!(
        results[2],
        vec!["OSV-PAGE-1".to_string(), "OSV-PAGE-2".to_string()],
        "pagination is followed"
    );

    let record = client.vulnerability("GHSA-35jh-r3h4-6jhm").expect("record");
    let advisory = summarize(&record, &dependencies[0]).expect("summary");
    assert_eq!(advisory.display_id(), "CVE-2021-23337");
    assert_eq!(advisory.fixed_versions, vec!["4.17.21"]);

    // Only ecosystem, name and version leave the machine.
    let requests = mock.requests.lock().expect("requests");
    let (_, body) = requests
        .iter()
        .find(|(path, _)| path == "/v1/querybatch")
        .expect("batch request");
    let sent: Value = serde_json::from_str(body).expect("json");
    let query = &sent["queries"][0];
    let mut keys: Vec<&str> = query
        .as_object()
        .expect("object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(keys, vec!["package", "version"]);
}

#[test]
fn rejects_unexpected_advisory_ids_before_building_a_url() {
    let client = OsvClient::new("http://127.0.0.1:9").expect("client");
    assert!(client.vulnerability("../../etc/passwd").is_err());
}
