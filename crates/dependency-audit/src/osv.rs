//! OSV advisory handling: offline matching of OSV records, advisory summaries, CVSS v3
//! scoring, and an explicit online client for the OSV.dev API.

use std::{cmp::Ordering, time::Duration};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use thiserror::Error;

use crate::manifest::{Dependency, Ecosystem};

pub const DEFAULT_OSV_API: &str = "https://api.osv.dev";
const QUERY_BATCH_SIZE: usize = 1_000;
const MAX_PAGES_PER_PACKAGE: usize = 20;
const MAX_RESPONSE_BYTES: usize = 32 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum OsvError {
    #[error("OSV request failed: {0}")]
    Http(String),
    #[error("OSV returned an unexpected response: {0}")]
    Protocol(String),
}

/// How an advisory was matched to the installed version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchBasis {
    /// OSV.dev evaluated the version server-side.
    OsvApi,
    /// The version is listed in the record's enumerated affected versions.
    ExactVersion,
    /// The version falls inside a SEMVER/ECOSYSTEM range evaluated locally.
    Range,
}

impl MatchBasis {
    pub const fn confidence(self) -> f64 {
        match self {
            Self::OsvApi | Self::ExactVersion => 0.95,
            Self::Range => 0.85,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OsvApi => "osv_api",
            Self::ExactVersion => "exact_version",
            Self::Range => "range",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Advisory {
    pub id: String,
    /// Aliases with CVE identifiers first.
    pub aliases: Vec<String>,
    pub summary: String,
    pub severity: String,
    pub cvss_score: Option<f64>,
    pub fixed_versions: Vec<String>,
    pub references: Vec<String>,
    pub cwe: Option<String>,
    pub modified: Option<String>,
}

impl Advisory {
    /// Preferred display identifier: the CVE alias when one exists.
    pub fn display_id(&self) -> &str {
        self.aliases
            .iter()
            .find(|alias| alias.starts_with("CVE-"))
            .map_or(self.id.as_str(), String::as_str)
    }
}

/// Builds an advisory summary for one dependency from a full OSV record.
pub fn summarize(record: &Value, dependency: &Dependency) -> Option<Advisory> {
    let id = record.get("id")?.as_str()?.to_string();
    let mut aliases: Vec<String> = record
        .get("aliases")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(ToString::to_string)
        .collect();
    aliases.sort_by_key(|alias| (!alias.starts_with("CVE-"), alias.clone()));
    let summary = record
        .get("summary")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .or_else(|| record.get("details").and_then(Value::as_str))
        .map(|value| value.chars().take(400).collect::<String>())
        .unwrap_or_else(|| format!("Security advisory {id}"));

    let cvss_score = record
        .get("severity")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|entry| {
            entry
                .get("type")
                .and_then(Value::as_str)
                .is_some_and(|kind| kind == "CVSS_V3")
        })
        .find_map(|entry| {
            entry
                .get("score")
                .and_then(Value::as_str)
                .and_then(cvss3_base_score)
        });
    let database_severity = record
        .pointer("/database_specific/severity")
        .and_then(Value::as_str)
        .map(|value| match value.to_ascii_lowercase().as_str() {
            "moderate" => "medium".to_string(),
            other => other.to_string(),
        })
        .filter(|value| matches!(value.as_str(), "critical" | "high" | "medium" | "low"));
    let severity = database_severity
        .or_else(|| cvss_score.map(cvss_severity))
        .unwrap_or_else(|| "medium".to_string());

    let mut fixed_versions = Vec::new();
    for affected in matching_affected(record, dependency) {
        for range in affected
            .get("ranges")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            for event in range
                .get("events")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                if let Some(fixed) = event.get("fixed").and_then(Value::as_str) {
                    if !fixed_versions.iter().any(|known| known == fixed) {
                        fixed_versions.push(fixed.to_string());
                    }
                }
            }
        }
    }
    let references = record
        .get("references")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|reference| reference.get("url").and_then(Value::as_str))
        .filter(|url| url.starts_with("https://"))
        .take(5)
        .map(ToString::to_string)
        .collect();
    let cwe = record
        .pointer("/database_specific/cwe_ids/0")
        .and_then(Value::as_str)
        .map(ToString::to_string);
    Some(Advisory {
        id,
        aliases,
        summary,
        severity,
        cvss_score,
        fixed_versions,
        references,
        cwe,
        modified: record
            .get("modified")
            .and_then(Value::as_str)
            .map(ToString::to_string),
    })
}

fn matching_affected<'a>(record: &'a Value, dependency: &Dependency) -> Vec<&'a Value> {
    let wanted = dependency.ecosystem.normalize_name(&dependency.name);
    record
        .get("affected")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|affected| {
            let package = affected.get("package");
            let ecosystem = package
                .and_then(|p| p.get("ecosystem"))
                .and_then(Value::as_str)
                // Ecosystem variants such as "Debian:11" never match our ecosystems.
                .and_then(Ecosystem::from_osv_name);
            let name = package.and_then(|p| p.get("name")).and_then(Value::as_str);
            ecosystem == Some(dependency.ecosystem)
                && name.is_some_and(|name| dependency.ecosystem.normalize_name(name) == wanted)
        })
        .collect()
}

/// Offline evaluation of whether `dependency` is affected by `record`.
pub fn affects(record: &Value, dependency: &Dependency) -> Option<MatchBasis> {
    if record.get("withdrawn").and_then(Value::as_str).is_some() {
        return None;
    }
    let mut basis = None;
    for affected in matching_affected(record, dependency) {
        let listed = affected
            .get("versions")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .any(|version| version == dependency.version);
        if listed {
            return Some(MatchBasis::ExactVersion);
        }
        for range in affected
            .get("ranges")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let kind = range.get("type").and_then(Value::as_str).unwrap_or("");
            if !matches!(kind, "SEMVER" | "ECOSYSTEM") {
                continue; // GIT ranges need commit history
            }
            let events: Vec<&Value> = range
                .get("events")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .collect();
            if version_in_events(&dependency.version, &events) {
                basis = Some(MatchBasis::Range);
            }
        }
    }
    basis
}

/// OSV range semantics: `introduced` opens an interval, `fixed` closes it (exclusive),
/// `last_affected` closes it (inclusive), `limit` bounds it (exclusive).
fn version_in_events(version: &str, events: &[&Value]) -> bool {
    let mut open: Option<String> = None;
    for event in events {
        if let Some(introduced) = event.get("introduced").and_then(Value::as_str) {
            open = Some(introduced.to_string());
        } else if let Some(fixed) = event
            .get("fixed")
            .or_else(|| event.get("limit"))
            .and_then(Value::as_str)
        {
            if let Some(start) = open.take() {
                if at_or_after(version, &start)
                    && compare_versions(version, fixed) == Ordering::Less
                {
                    return true;
                }
            }
        } else if let Some(last) = event.get("last_affected").and_then(Value::as_str) {
            if let Some(start) = open.take() {
                if at_or_after(version, &start)
                    && compare_versions(version, last) != Ordering::Greater
                {
                    return true;
                }
            }
        }
    }
    open.is_some_and(|start| at_or_after(version, &start))
}

fn at_or_after(version: &str, start: &str) -> bool {
    start == "0" || compare_versions(version, start) != Ordering::Less
}

/// Ecosystem-agnostic version ordering: numeric release components compared
/// numerically; a pre-release (`-rc1`, `a1`, `.dev0`) sorts before its release.
pub fn compare_versions(left: &str, right: &str) -> Ordering {
    let (left_release, left_pre) = split_version(left);
    let (right_release, right_pre) = split_version(right);
    let length = left_release.len().max(right_release.len());
    for index in 0..length {
        let a = left_release.get(index).copied().unwrap_or(0);
        let b = right_release.get(index).copied().unwrap_or(0);
        match a.cmp(&b) {
            Ordering::Equal => {}
            other => return other,
        }
    }
    match (left_pre, right_pre) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Greater,
        (Some(_), None) => Ordering::Less,
        (Some(a), Some(b)) => compare_prerelease(&a, &b),
    }
}

fn split_version(version: &str) -> (Vec<u64>, Option<String>) {
    let version = version.trim().trim_start_matches(['v', 'V']);
    let version = version.split('+').next().unwrap_or(version);
    let mut release = Vec::new();
    let mut rest = version;
    loop {
        let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
        if digits.is_empty() {
            break;
        }
        release.push(digits.parse().unwrap_or(u64::MAX));
        rest = &rest[digits.len()..];
        match rest.strip_prefix('.') {
            Some(next) if next.starts_with(|c: char| c.is_ascii_digit()) => rest = next,
            _ => break,
        }
    }
    let pre = rest.trim_start_matches(['-', '.', '_']);
    let lower = pre.to_ascii_lowercase();
    // PEP 440 post-releases sort after the release, not before. Maven's `Final`, `GA` and
    // `RELEASE` qualifiers name the release itself, and `SP` service packs come after it.
    if pre.is_empty()
        || lower.starts_with("post")
        || matches!(lower.as_str(), "final" | "ga" | "release")
        || lower.starts_with("sp")
    {
        (release, None)
    } else {
        (release, Some(pre.to_ascii_lowercase()))
    }
}

fn compare_prerelease(left: &str, right: &str) -> Ordering {
    let left_parts: Vec<&str> = left.split(['.', '-']).collect();
    let right_parts: Vec<&str> = right.split(['.', '-']).collect();
    for (a, b) in left_parts.iter().zip(&right_parts) {
        let ordering = match (a.parse::<u64>(), b.parse::<u64>()) {
            (Ok(x), Ok(y)) => x.cmp(&y),
            (Ok(_), Err(_)) => Ordering::Less,
            (Err(_), Ok(_)) => Ordering::Greater,
            (Err(_), Err(_)) => a.cmp(b),
        };
        if ordering != Ordering::Equal {
            return ordering;
        }
    }
    left_parts.len().cmp(&right_parts.len())
}

/// CVSS v3.x base score from a vector such as `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`.
pub fn cvss3_base_score(vector: &str) -> Option<f64> {
    if !vector.starts_with("CVSS:3.") {
        return None;
    }
    let metric = |name: &str| -> Option<&str> {
        vector.split('/').find_map(|part| {
            part.strip_prefix(name)
                .and_then(|rest| rest.strip_prefix(':'))
        })
    };
    let scope_changed = metric("S")? == "C";
    let attack_vector = match metric("AV")? {
        "N" => 0.85,
        "A" => 0.62,
        "L" => 0.55,
        "P" => 0.2,
        _ => return None,
    };
    let attack_complexity = match metric("AC")? {
        "L" => 0.77,
        "H" => 0.44,
        _ => return None,
    };
    let privileges = match (metric("PR")?, scope_changed) {
        ("N", _) => 0.85,
        ("L", false) => 0.62,
        ("L", true) => 0.68,
        ("H", false) => 0.27,
        ("H", true) => 0.5,
        _ => return None,
    };
    let interaction = match metric("UI")? {
        "N" => 0.85,
        "R" => 0.62,
        _ => return None,
    };
    let cia = |name: &str| -> Option<f64> {
        Some(match metric(name)? {
            "H" => 0.56,
            "L" => 0.22,
            "N" => 0.0,
            _ => return None,
        })
    };
    let (c, i, a) = (cia("C")?, cia("I")?, cia("A")?);
    let iss = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a);
    let impact = if scope_changed {
        7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).powi(15)
    } else {
        6.42 * iss
    };
    if impact <= 0.0 {
        return Some(0.0);
    }
    let exploitability = 8.22 * attack_vector * attack_complexity * privileges * interaction;
    let raw = if scope_changed {
        (1.08 * (impact + exploitability)).min(10.0)
    } else {
        (impact + exploitability).min(10.0)
    };
    Some(round_up(raw))
}

/// CVSS v3.1 "Roundup": smallest one-decimal value >= input, using integer math.
fn round_up(value: f64) -> f64 {
    let scaled = (value * 100_000.0).round() as i64;
    if scaled % 10_000 == 0 {
        scaled as f64 / 100_000.0
    } else {
        ((scaled / 10_000) + 1) as f64 / 10.0
    }
}

pub fn cvss_severity(score: f64) -> String {
    match score {
        s if s >= 9.0 => "critical",
        s if s >= 7.0 => "high",
        s if s >= 4.0 => "medium",
        s if s > 0.0 => "low",
        _ => "low",
    }
    .to_string()
}

/// Online client for the OSV.dev API. Only package ecosystem, name and version are sent.
pub struct OsvClient {
    base_url: String,
    client: reqwest::blocking::Client,
}

impl OsvClient {
    pub fn new(base_url: &str) -> Result<Self, OsvError> {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("CodeTwin-Dependency-Audit/1.0")
            .build()
            .map_err(|error| OsvError::Http(error.to_string()))?;
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client,
        })
    }

    /// Advisory IDs affecting each dependency, in input order.
    pub fn query_batch(&self, dependencies: &[Dependency]) -> Result<Vec<Vec<String>>, OsvError> {
        let mut results = Vec::with_capacity(dependencies.len());
        for chunk in dependencies.chunks(QUERY_BATCH_SIZE) {
            let queries: Vec<Value> = chunk
                .iter()
                .map(|dependency| query_for(dependency, None))
                .collect();
            let response = self.post("/v1/querybatch", &json!({ "queries": queries }))?;
            let entries = response
                .get("results")
                .and_then(Value::as_array)
                .ok_or_else(|| OsvError::Protocol("missing results".into()))?;
            if entries.len() != chunk.len() {
                return Err(OsvError::Protocol(format!(
                    "expected {} results, got {}",
                    chunk.len(),
                    entries.len()
                )));
            }
            for (dependency, entry) in chunk.iter().zip(entries) {
                let mut ids = vuln_ids(entry);
                let mut token = entry
                    .get("next_page_token")
                    .and_then(Value::as_str)
                    .map(String::from);
                let mut pages = 0;
                while let Some(page_token) = token.take() {
                    pages += 1;
                    if pages > MAX_PAGES_PER_PACKAGE {
                        return Err(OsvError::Protocol("too many result pages".into()));
                    }
                    let page = self.post("/v1/query", &query_for(dependency, Some(&page_token)))?;
                    ids.extend(vuln_ids(&page));
                    token = page
                        .get("next_page_token")
                        .and_then(Value::as_str)
                        .map(String::from);
                }
                ids.sort();
                ids.dedup();
                results.push(ids);
            }
        }
        Ok(results)
    }

    pub fn vulnerability(&self, id: &str) -> Result<Value, OsvError> {
        if !id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':'))
        {
            return Err(OsvError::Protocol(format!("unexpected advisory id: {id}")));
        }
        let response = self
            .client
            .get(format!("{}/v1/vulns/{id}", self.base_url))
            .send()
            .map_err(|error| OsvError::Http(error.to_string()))?;
        read_json(response)
    }

    fn post(&self, path: &str, body: &Value) -> Result<Value, OsvError> {
        let payload =
            serde_json::to_vec(body).map_err(|error| OsvError::Protocol(error.to_string()))?;
        let response = self
            .client
            .post(format!("{}{path}", self.base_url))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(payload)
            .send()
            .map_err(|error| OsvError::Http(error.to_string()))?;
        read_json(response)
    }
}

fn read_json(response: reqwest::blocking::Response) -> Result<Value, OsvError> {
    let status = response.status();
    if !status.is_success() {
        return Err(OsvError::Http(format!("HTTP {status}")));
    }
    let bytes = response
        .bytes()
        .map_err(|error| OsvError::Http(error.to_string()))?;
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(OsvError::Protocol(format!(
            "response exceeds {MAX_RESPONSE_BYTES} bytes"
        )));
    }
    serde_json::from_slice(&bytes).map_err(|error| OsvError::Protocol(error.to_string()))
}

fn query_for(dependency: &Dependency, page_token: Option<&str>) -> Value {
    let mut query = json!({
        "package": { "ecosystem": dependency.ecosystem.osv_name(), "name": dependency.name },
        "version": dependency.version,
    });
    if let Some(token) = page_token {
        query["page_token"] = json!(token);
    }
    query
}

fn vuln_ids(entry: &Value) -> Vec<String> {
    entry
        .get("vulns")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|vuln| vuln.get("id").and_then(Value::as_str))
        .map(ToString::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dep(ecosystem: Ecosystem, name: &str, version: &str) -> Dependency {
        Dependency {
            ecosystem,
            name: name.into(),
            version: version.into(),
            is_dev: false,
            line: None,
        }
    }

    fn lodash_record() -> Value {
        json!({
            "id": "GHSA-35jh-r3h4-6jhm",
            "aliases": ["CVE-2021-23337"],
            "summary": "Command Injection in lodash",
            "modified": "2024-01-01T00:00:00Z",
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"}],
            "database_specific": {"severity": "HIGH", "cwe_ids": ["CWE-77"]},
            "affected": [{
                "package": {"ecosystem": "npm", "name": "lodash"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]
            }],
            "references": [{"type": "ADVISORY", "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-23337"}]
        })
    }

    #[test]
    fn maven_and_nuget_records_match_offline() {
        let log4shell = json!({
            "id": "GHSA-jfh8-c2jp-5v3q",
            "aliases": ["CVE-2021-44228"],
            "affected": [{
                "package": {"ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "2.0-beta9"}, {"fixed": "2.15.0"}]}]
            }]
        });
        let log4j = |version: &str| {
            dep(
                Ecosystem::Maven,
                "org.apache.logging.log4j:log4j-core",
                version,
            )
        };
        assert_eq!(
            affects(&log4shell, &log4j("2.14.1")),
            Some(MatchBasis::Range)
        );
        assert_eq!(affects(&log4shell, &log4j("2.15.0")), None);
        assert_eq!(affects(&log4shell, &log4j("1.2.17")), None);

        let spring = json!({
            "id": "GHSA-36p3-wjmg-h94x",
            "affected": [{
                "package": {"ecosystem": "Maven", "name": "org.springframework:spring-beans"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "5.3.0"}, {"fixed": "5.3.18"}]}]
            }]
        });
        let beans = |version: &str| {
            dep(
                Ecosystem::Maven,
                "org.springframework:spring-beans",
                version,
            )
        };
        assert_eq!(
            affects(&spring, &beans("5.3.17.RELEASE")),
            Some(MatchBasis::Range)
        );
        // 5.3.18.RELEASE is the fixed release itself, not a pre-release of it.
        assert_eq!(affects(&spring, &beans("5.3.18.RELEASE")), None);

        let nuget = json!({
            "id": "GHSA-5crp-9r3c-p9vr",
            "affected": [{
                "package": {"ecosystem": "NuGet", "name": "Newtonsoft.Json"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "13.0.1"}]}]
            }]
        });
        // NuGet ids are case-insensitive.
        assert_eq!(
            affects(&nuget, &dep(Ecosystem::NuGet, "newtonsoft.json", "12.0.1")),
            Some(MatchBasis::Range)
        );
        assert_eq!(
            affects(&nuget, &dep(Ecosystem::NuGet, "Newtonsoft.Json", "13.0.1")),
            None
        );
    }

    #[test]
    fn maven_release_qualifiers() {
        assert_eq!(
            compare_versions("5.3.18.RELEASE", "5.3.18"),
            Ordering::Equal
        );
        assert_eq!(compare_versions("4.1.0.Final", "4.1.0"), Ordering::Equal);
        assert_eq!(compare_versions("2.0-beta9", "2.0"), Ordering::Less);
        assert_eq!(
            compare_versions("5.3.18.RELEASE", "5.3.17.RELEASE"),
            Ordering::Greater
        );
        assert_eq!(compare_versions("2.13.4.2", "2.13.4"), Ordering::Greater);
    }

    #[test]
    fn semver_ranges_match_only_affected_versions() {
        let record = lodash_record();
        assert_eq!(
            affects(&record, &dep(Ecosystem::Npm, "lodash", "4.17.20")),
            Some(MatchBasis::Range)
        );
        assert_eq!(
            affects(&record, &dep(Ecosystem::Npm, "lodash", "4.17.21")),
            None
        );
        assert_eq!(
            affects(&record, &dep(Ecosystem::Npm, "lodash", "5.0.0")),
            None
        );
        assert_eq!(
            affects(&record, &dep(Ecosystem::Npm, "underscore", "1.0.0")),
            None
        );
        assert_eq!(
            affects(&record, &dep(Ecosystem::PyPI, "lodash", "1.0.0")),
            None
        );
    }

    #[test]
    fn enumerated_versions_last_affected_and_withdrawn_records() {
        let listed = json!({"id": "X-1", "affected": [{"package": {"ecosystem": "PyPI", "name": "Django"},
            "versions": ["3.2.0"], "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "3.0"}, {"last_affected": "3.2.4"}]}]}]});
        assert_eq!(
            affects(&listed, &dep(Ecosystem::PyPI, "django", "3.2.0")),
            Some(MatchBasis::ExactVersion)
        );
        assert_eq!(
            affects(&listed, &dep(Ecosystem::PyPI, "django", "3.2.4")),
            Some(MatchBasis::Range)
        );
        assert_eq!(
            affects(&listed, &dep(Ecosystem::PyPI, "django", "3.2.5")),
            None
        );
        assert_eq!(
            affects(&listed, &dep(Ecosystem::PyPI, "django", "2.2.0")),
            None
        );
        let mut withdrawn = listed.clone();
        withdrawn["withdrawn"] = json!("2024-01-01T00:00:00Z");
        assert_eq!(
            affects(&withdrawn, &dep(Ecosystem::PyPI, "django", "3.2.0")),
            None
        );
    }

    #[test]
    fn multiple_intervals_in_one_range() {
        let record = json!({"id": "X-2", "affected": [{"package": {"ecosystem": "crates.io", "name": "time"},
            "ranges": [{"type": "SEMVER", "events": [
                {"introduced": "0"}, {"fixed": "0.1.44"}, {"introduced": "0.2.0"}, {"fixed": "0.2.23"}]}]}]});
        for (version, affected) in [
            ("0.1.43", true),
            ("0.1.44", false),
            ("0.2.22", true),
            ("0.2.23", false),
            ("0.3.0", false),
        ] {
            assert_eq!(
                affects(&record, &dep(Ecosystem::CratesIo, "time", version)).is_some(),
                affected,
                "{version}"
            );
        }
    }

    #[test]
    fn version_ordering_handles_prereleases_and_prefixes() {
        assert_eq!(compare_versions("1.10.0", "1.9.9"), Ordering::Greater);
        assert_eq!(compare_versions("2.0.0-rc.1", "2.0.0"), Ordering::Less);
        assert_eq!(compare_versions("2.0.0rc1", "2.0.0"), Ordering::Less);
        assert_eq!(compare_versions("v1.2.3", "1.2.3"), Ordering::Equal);
        assert_eq!(compare_versions("1.2", "1.2.0"), Ordering::Equal);
        assert_eq!(
            compare_versions("1.0.0-alpha.2", "1.0.0-alpha.10"),
            Ordering::Less
        );
        assert_eq!(compare_versions("1.0.post1", "1.0"), Ordering::Equal);
    }

    #[test]
    fn summarizes_advisories_with_cve_alias_fixed_versions_and_severity() {
        let advisory = summarize(&lodash_record(), &dep(Ecosystem::Npm, "lodash", "4.17.20"))
            .expect("advisory");
        assert_eq!(advisory.display_id(), "CVE-2021-23337");
        assert_eq!(advisory.severity, "high");
        assert_eq!(advisory.fixed_versions, vec!["4.17.21"]);
        assert_eq!(advisory.cwe.as_deref(), Some("CWE-77"));
        assert_eq!(advisory.cvss_score, Some(7.2));
    }

    #[test]
    fn cvss3_scores_match_reference_values() {
        assert_eq!(
            cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            Some(9.8)
        );
        assert_eq!(
            cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
            Some(6.1)
        );
        assert_eq!(
            cvss3_base_score("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"),
            Some(5.5)
        );
        assert_eq!(
            cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
            Some(10.0)
        );
        assert_eq!(
            cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"),
            Some(0.0)
        );
        assert_eq!(cvss3_base_score("CVSS:4.0/AV:N"), None);
        assert_eq!(cvss_severity(9.8), "critical");
        assert_eq!(cvss_severity(6.1), "medium");
    }

    #[test]
    fn severity_falls_back_to_cvss_then_medium() {
        let mut record = lodash_record();
        record["database_specific"] = json!({});
        let dependency = dep(Ecosystem::Npm, "lodash", "4.17.20");
        assert_eq!(summarize(&record, &dependency).expect("a").severity, "high");
        record["severity"] = json!([]);
        assert_eq!(
            summarize(&record, &dependency).expect("b").severity,
            "medium"
        );
    }
}
