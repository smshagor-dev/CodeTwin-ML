//! CycloneDX 1.5 SBOM export from the dependency inventory.
//!
//! Components come from the last dependency audit's active inventory, one per package URL, with
//! the manifests that declare them. Open dependency findings become `vulnerabilities` entries that
//! reference the affected components. Nothing is fetched; the SBOM reflects what CodeTwin already
//! recorded.

use std::{
    collections::{BTreeMap, BTreeSet},
    time::{SystemTime, UNIX_EPOCH},
};

use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::Database;

const DEPENDENCY_ANALYZER: &str = "dependency_audit";
const MAX_COMPONENTS: i64 = 200_000;

#[derive(Debug, Error)]
pub enum SbomError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("project not found: {0}")]
    ProjectNotFound(String),
    #[error("no dependency inventory yet; run a dependency audit first")]
    NoInventory,
    #[error("could not serialize SBOM: {0}")]
    Serialize(#[from] serde_json::Error),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SbomExport {
    pub json: String,
    pub components: usize,
    pub vulnerabilities: usize,
    /// Inventory entries whose ecosystem has no package-URL type (kept without a purl).
    pub components_without_purl: usize,
}

/// Percent-encodes a package-URL segment (letters, digits and `.-_~` stay as they are).
fn encode(segment: &str) -> String {
    let mut out = String::with_capacity(segment.len());
    for byte in segment.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// Package URL (<https://github.com/package-url/purl-spec>) plus CycloneDX `group`/`name`.
pub fn purl(
    ecosystem: &str,
    name: &str,
    version: &str,
) -> Option<(String, Option<String>, String)> {
    let version = encode(version);
    let path = |namespace: &str, leaf: &str| {
        let namespace: Vec<String> = namespace.split('/').map(encode).collect();
        format!("{}/{}", namespace.join("/"), encode(leaf))
    };
    Some(match ecosystem {
        "npm" => match name.strip_prefix('@').and_then(|rest| rest.split_once('/')) {
            Some((scope, leaf)) => (
                format!("pkg:npm/%40{}/{}@{version}", encode(scope), encode(leaf)),
                Some(format!("@{scope}")),
                leaf.to_string(),
            ),
            None => (
                format!("pkg:npm/{}@{version}", encode(name)),
                None,
                name.to_string(),
            ),
        },
        "crates.io" => (
            format!("pkg:cargo/{}@{version}", encode(name)),
            None,
            name.to_string(),
        ),
        "PyPI" => {
            let normalized = name.to_ascii_lowercase().replace(['_', '.'], "-");
            (
                format!("pkg:pypi/{}@{version}", encode(&normalized)),
                None,
                name.to_string(),
            )
        }
        "Go" => match name.rsplit_once('/') {
            Some((namespace, leaf)) => (
                format!("pkg:golang/{}@{version}", path(namespace, leaf)),
                Some(namespace.to_string()),
                leaf.to_string(),
            ),
            None => (
                format!("pkg:golang/{}@{version}", encode(name)),
                None,
                name.to_string(),
            ),
        },
        "Packagist" => match name.split_once('/') {
            Some((vendor, leaf)) => (
                format!("pkg:composer/{}/{}@{version}", encode(vendor), encode(leaf)),
                Some(vendor.to_string()),
                leaf.to_string(),
            ),
            None => (
                format!("pkg:composer/{}@{version}", encode(name)),
                None,
                name.to_string(),
            ),
        },
        "RubyGems" => (
            format!("pkg:gem/{}@{version}", encode(name)),
            None,
            name.to_string(),
        ),
        "Maven" => {
            let (group, artifact) = name.split_once(':')?;
            (
                format!("pkg:maven/{}/{}@{version}", encode(group), encode(artifact)),
                Some(group.to_string()),
                artifact.to_string(),
            )
        }
        "NuGet" => (
            format!("pkg:nuget/{}@{version}", encode(name)),
            None,
            name.to_string(),
        ),
        _ => return None,
    })
}

fn severity(value: &str) -> &'static str {
    match value.to_ascii_lowercase().as_str() {
        "critical" => "critical",
        "high" => "high",
        "medium" | "moderate" => "medium",
        "low" => "low",
        "info" | "informational" => "info",
        _ => "unknown",
    }
}

fn cwe_numbers(value: Option<&str>) -> Vec<u32> {
    let mut numbers: Vec<u32> = value
        .unwrap_or_default()
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '-')
        .filter_map(|token| token.strip_prefix("CWE-")?.parse().ok())
        .collect();
    numbers.sort_unstable();
    numbers.dedup();
    numbers
}

/// RFC 4122 version-4 layout over a SHA-256 of the project and the current time.
fn serial_number(project_id: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let digest = Sha256::digest(format!("{project_id}\0{nanos}").as_bytes());
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    format!(
        "urn:uuid:{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

struct Component {
    purl: Option<String>,
    group: Option<String>,
    name: String,
    version: String,
    ecosystem: String,
    manifests: BTreeSet<String>,
    all_dev: bool,
}

pub struct SbomService<'a> {
    database: &'a Database,
}

impl<'a> SbomService<'a> {
    pub const fn new(database: &'a Database) -> Self {
        Self { database }
    }

    pub fn export_cyclonedx(&self, project_id: &str) -> Result<SbomExport, SbomError> {
        let connection = self.database.connection();
        let project_name: String = connection
            .query_row(
                "SELECT COALESCE(display_name, root_path) FROM projects WHERE id = ?1",
                [project_id],
                |row| row.get(0),
            )
            .optional()?
            .ok_or_else(|| SbomError::ProjectNotFound(project_id.to_string()))?;
        let timestamp: String =
            connection.query_row("SELECT strftime('%Y-%m-%dT%H:%M:%SZ', 'now')", [], |row| {
                row.get(0)
            })?;

        let mut statement = connection.prepare(
            "SELECT ecosystem, name, version, manifest_path, is_dev FROM dependency_inventory \
             WHERE project_id = ?1 AND is_active = 1 ORDER BY ecosystem, name, version, manifest_path LIMIT ?2",
        )?;
        let rows = statement.query_map(params![project_id, MAX_COMPONENTS], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)? == 1,
            ))
        })?;
        let mut components: BTreeMap<(String, String, String), Component> = BTreeMap::new();
        for row in rows {
            let (ecosystem, name, version, manifest, is_dev) = row?;
            let key = (ecosystem.clone(), name.clone(), version.clone());
            let entry = components.entry(key).or_insert_with(|| {
                let (purl, group, short) = match purl(&ecosystem, &name, &version) {
                    Some((purl, group, short)) => (Some(purl), group, short),
                    None => (None, None, name.clone()),
                };
                Component {
                    purl,
                    group,
                    name: short,
                    version: version.clone(),
                    ecosystem: ecosystem.clone(),
                    manifests: BTreeSet::new(),
                    all_dev: true,
                }
            });
            entry.manifests.insert(manifest);
            entry.all_dev &= is_dev;
        }
        if components.is_empty() {
            return Err(SbomError::NoInventory);
        }

        let bom_ref = |key: &(String, String, String), component: &Component| {
            component
                .purl
                .clone()
                .unwrap_or_else(|| format!("codetwin:{}:{}@{}", key.0, key.1, key.2))
        };
        let refs: BTreeMap<(String, String, String), String> = components
            .iter()
            .map(|(key, component)| (key.clone(), bom_ref(key, component)))
            .collect();

        // Open findings grouped by advisory, each pointing at every affected component.
        let mut statement = connection.prepare(
            "SELECT f.severity, f.cwe, f.title, COALESCE(e.metadata_json, '{}') \
             FROM findings f JOIN finding_evidence e ON e.finding_id = f.id \
             WHERE f.project_id = ?1 AND f.analyzer_key = ?2 AND f.status = 'open' \
             ORDER BY f.id",
        )?;
        let rows = statement.query_map(params![project_id, DEPENDENCY_ANALYZER], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?;
        let mut vulnerabilities: BTreeMap<String, (Value, BTreeSet<String>)> = BTreeMap::new();
        for row in rows {
            let (level, cwe, title, metadata) = row?;
            let metadata: Value = serde_json::from_str(&metadata).unwrap_or_default();
            let text = |key: &str| metadata[key].as_str().unwrap_or_default().to_string();
            let strings = |key: &str| -> Vec<String> {
                metadata[key]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            };
            let advisory_id = text("advisory_id");
            if advisory_id.is_empty() {
                continue;
            }
            let key = (text("ecosystem"), text("package"), text("version"));
            let Some(affected) = refs.get(&key) else {
                continue; // component no longer in the active inventory
            };
            let entry = vulnerabilities.entry(advisory_id.clone()).or_insert_with(|| {
                let display = text("display_id");
                let id = if display.is_empty() { advisory_id.clone() } else { display };
                let mut rating = json!({"severity": severity(&level)});
                if let Some(score) = metadata["cvss_score"].as_f64() {
                    rating["score"] = json!(score);
                    rating["method"] = json!("CVSSv3");
                }
                let aliases: Vec<Value> = std::iter::once(advisory_id.clone())
                    .chain(strings("aliases"))
                    .filter(|alias| *alias != id)
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .map(|alias| json!({"id": alias, "source": {"name": "OSV", "url": format!("https://osv.dev/vulnerability/{alias}")}}))
                    .collect();
                let fixed = strings("fixed_versions");
                let mut vulnerability = json!({
                    "bom-ref": format!("vuln:{advisory_id}"),
                    "id": id,
                    "source": {"name": "OSV", "url": format!("https://osv.dev/vulnerability/{advisory_id}")},
                    "ratings": [rating],
                    "description": title,
                    "recommendation": if fixed.is_empty() {
                        "No fixed version is published; consider replacing the package or mitigating.".to_string()
                    } else {
                        format!("Upgrade to a fixed version: {}.", fixed.join(", "))
                    },
                    "advisories": strings("references").into_iter().take(10).map(|url| json!({"url": url})).collect::<Vec<_>>(),
                    "properties": [{"name": "codetwin:match_basis", "value": text("match_basis")}],
                });
                if !aliases.is_empty() {
                    vulnerability["references"] = json!(aliases);
                }
                let cwes = cwe_numbers(cwe.as_deref());
                if !cwes.is_empty() {
                    vulnerability["cwes"] = json!(cwes);
                }
                (vulnerability, BTreeSet::new())
            });
            entry.1.insert(affected.clone());
        }

        let components_without_purl = components.values().filter(|c| c.purl.is_none()).count();
        let component_json: Vec<Value> = components
            .iter()
            .map(|(key, component)| {
                let mut value = json!({
                    "type": "library",
                    "bom-ref": refs[key],
                    "name": component.name,
                    "version": component.version,
                    "scope": if component.all_dev { "optional" } else { "required" },
                    "properties": std::iter::once(json!({"name": "codetwin:ecosystem", "value": component.ecosystem}))
                        .chain(component.manifests.iter().map(|path| json!({"name": "codetwin:manifest", "value": path})))
                        .collect::<Vec<_>>(),
                });
                if let Some(group) = &component.group {
                    value["group"] = json!(group);
                }
                if let Some(purl) = &component.purl {
                    value["purl"] = json!(purl);
                }
                value
            })
            .collect();
        let vulnerability_json: Vec<Value> = vulnerabilities
            .into_values()
            .map(|(mut vulnerability, affected)| {
                vulnerability["affects"] = json!(affected
                    .into_iter()
                    .map(|reference| json!({"ref": reference}))
                    .collect::<Vec<_>>());
                vulnerability
            })
            .collect();

        let document = json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": serial_number(project_id),
            "version": 1,
            "metadata": {
                "timestamp": timestamp,
                "tools": {"components": [{
                    "type": "application",
                    "name": "CodeTwin ML",
                    "version": env!("CARGO_PKG_VERSION"),
                }]},
                "component": {"type": "application", "bom-ref": "codetwin:project", "name": project_name},
                "properties": [{
                    "name": "codetwin:coverage",
                    "value": "Resolved versions from supported lockfiles and manifests; packages with unpinned versions are not listed.",
                }],
            },
            "components": component_json,
            "vulnerabilities": vulnerability_json,
        });
        Ok(SbomExport {
            components: component_json.len(),
            vulnerabilities: vulnerability_json.len(),
            components_without_purl,
            json: serde_json::to_string_pretty(&document)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn purls_follow_the_spec() {
        let cases = [
            (
                "npm",
                "@babel/core",
                "7.24.0",
                "pkg:npm/%40babel/core@7.24.0",
            ),
            ("npm", "lodash", "4.17.20", "pkg:npm/lodash@4.17.20"),
            ("crates.io", "serde", "1.0.200", "pkg:cargo/serde@1.0.200"),
            (
                "PyPI",
                "Django_Rest.framework",
                "3.2.0",
                "pkg:pypi/django-rest-framework@3.2.0",
            ),
            (
                "Go",
                "github.com/gin-gonic/gin",
                "v1.9.1",
                "pkg:golang/github.com/gin-gonic/gin@v1.9.1",
            ),
            (
                "Packagist",
                "laravel/framework",
                "10.0.0",
                "pkg:composer/laravel/framework@10.0.0",
            ),
            ("RubyGems", "rails", "7.0.0", "pkg:gem/rails@7.0.0"),
            (
                "Maven",
                "org.apache.logging.log4j:log4j-core",
                "2.14.1",
                "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
            ),
            (
                "NuGet",
                "Newtonsoft.Json",
                "13.0.1",
                "pkg:nuget/Newtonsoft.Json@13.0.1",
            ),
            (
                "npm",
                "left-pad",
                "1.0.0+build",
                "pkg:npm/left-pad@1.0.0%2Bbuild",
            ),
        ];
        for (ecosystem, name, version, expected) in cases {
            assert_eq!(
                purl(ecosystem, name, version).unwrap().0,
                expected,
                "{ecosystem} {name}"
            );
        }
        let (_, group, name) = purl("Maven", "org.slf4j:slf4j-api", "2.0.0").unwrap();
        assert_eq!(
            (group.as_deref(), name.as_str()),
            (Some("org.slf4j"), "slf4j-api")
        );
        assert!(purl("Maven", "no-colon", "1").is_none());
        assert!(purl("Hex", "phoenix", "1").is_none());
    }

    #[test]
    fn serial_numbers_are_uuid_v4_shaped() {
        let serial = serial_number("project:x");
        let uuid = serial.strip_prefix("urn:uuid:").unwrap();
        let parts: Vec<&str> = uuid.split('-').collect();
        assert_eq!(
            parts.iter().map(|p| p.len()).collect::<Vec<_>>(),
            vec![8, 4, 4, 4, 12]
        );
        assert!(parts[2].starts_with('4'));
        assert!(matches!(
            parts[3].chars().next(),
            Some('8' | '9' | 'a' | 'b')
        ));
    }

    #[test]
    fn cwe_parsing() {
        assert_eq!(cwe_numbers(Some("CWE-79, CWE-89")), vec![79, 89]);
        assert_eq!(cwe_numbers(None), Vec::<u32>::new());
    }
}
