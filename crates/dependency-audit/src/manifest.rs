//! Lockfile / manifest parsers producing a pinned dependency inventory.
//!
//! Only exact, resolved versions are reported: a range such as `requests>=2` cannot be
//! matched against an advisory and is counted as unpinned instead of guessed.

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Ecosystem {
    Npm,
    CratesIo,
    PyPI,
    Go,
    Packagist,
    RubyGems,
}

impl Ecosystem {
    /// Ecosystem name as used by OSV.
    pub const fn osv_name(self) -> &'static str {
        match self {
            Self::Npm => "npm",
            Self::CratesIo => "crates.io",
            Self::PyPI => "PyPI",
            Self::Go => "Go",
            Self::Packagist => "Packagist",
            Self::RubyGems => "RubyGems",
        }
    }

    pub fn from_osv_name(value: &str) -> Option<Self> {
        [
            Self::Npm,
            Self::CratesIo,
            Self::PyPI,
            Self::Go,
            Self::Packagist,
            Self::RubyGems,
        ]
        .into_iter()
        .find(|ecosystem| ecosystem.osv_name() == value)
    }

    /// Package-name normalization used for matching (PEP 503 for PyPI).
    pub fn normalize_name(self, name: &str) -> String {
        match self {
            Self::PyPI => {
                let mut output = String::with_capacity(name.len());
                let mut last_separator = false;
                for character in name.chars() {
                    if matches!(character, '-' | '_' | '.') {
                        if !last_separator {
                            output.push('-');
                        }
                        last_separator = true;
                    } else {
                        output.push(character.to_ascii_lowercase());
                        last_separator = false;
                    }
                }
                output
            }
            Self::Packagist => name.to_ascii_lowercase(),
            _ => name.to_string(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ManifestKind {
    NpmPackageLock,
    YarnLock,
    PnpmLock,
    BunLock,
    CargoLock,
    PoetryLock,
    PipfileLock,
    UvLock,
    Requirements,
    GoMod,
    ComposerLock,
    GemfileLock,
}

impl ManifestKind {
    pub const fn ecosystem(self) -> Ecosystem {
        match self {
            Self::NpmPackageLock | Self::YarnLock | Self::PnpmLock | Self::BunLock => {
                Ecosystem::Npm
            }
            Self::CargoLock => Ecosystem::CratesIo,
            Self::PoetryLock | Self::PipfileLock | Self::UvLock | Self::Requirements => {
                Ecosystem::PyPI
            }
            Self::GoMod => Ecosystem::Go,
            Self::ComposerLock => Ecosystem::Packagist,
            Self::GemfileLock => Ecosystem::RubyGems,
        }
    }
}

/// Recognizes supported manifests by file name.
pub fn manifest_kind(file_name: &str) -> Option<ManifestKind> {
    let lower = file_name.to_ascii_lowercase();
    Some(match lower.as_str() {
        "package-lock.json" | "npm-shrinkwrap.json" => ManifestKind::NpmPackageLock,
        "yarn.lock" => ManifestKind::YarnLock,
        "pnpm-lock.yaml" => ManifestKind::PnpmLock,
        "bun.lock" => ManifestKind::BunLock,
        "uv.lock" => ManifestKind::UvLock,
        "cargo.lock" => ManifestKind::CargoLock,
        "poetry.lock" => ManifestKind::PoetryLock,
        "pipfile.lock" => ManifestKind::PipfileLock,
        "go.mod" => ManifestKind::GoMod,
        "composer.lock" => ManifestKind::ComposerLock,
        "gemfile.lock" => ManifestKind::GemfileLock,
        _ if lower.starts_with("requirements") && lower.ends_with(".txt") => {
            ManifestKind::Requirements
        }
        _ => return None,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dependency {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub version: String,
    pub is_dev: bool,
    /// 1-based line in the manifest where the package appears, when known.
    pub line: Option<usize>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedManifest {
    pub dependencies: Vec<Dependency>,
    /// Requirements that are not pinned to one version and so cannot be audited.
    pub unpinned: usize,
}

pub fn parse_manifest(kind: ManifestKind, text: &str) -> Result<ParsedManifest, String> {
    let mut parsed = match kind {
        ManifestKind::NpmPackageLock => parse_package_lock(text)?,
        ManifestKind::YarnLock => parse_yarn_lock(text),
        ManifestKind::PnpmLock => parse_pnpm_lock(text),
        ManifestKind::BunLock => parse_bun_lock(text),
        // Only packages resolved from a registry are audited; path/git/workspace
        // members are local code, not published package versions.
        ManifestKind::CargoLock => parse_toml_packages(text, Ecosystem::CratesIo, |source| {
            source.is_some_and(|value| value.starts_with("registry+"))
        }),
        ManifestKind::UvLock => parse_toml_packages(text, Ecosystem::PyPI, |source| {
            source.is_some_and(|value| value.contains("registry"))
        }),
        ManifestKind::PoetryLock => parse_toml_packages(text, Ecosystem::PyPI, |_| true),
        ManifestKind::PipfileLock => parse_pipfile_lock(text)?,
        ManifestKind::Requirements => parse_requirements(text),
        ManifestKind::GoMod => parse_go_mod(text),
        ManifestKind::ComposerLock => parse_composer_lock(text)?,
        ManifestKind::GemfileLock => parse_gemfile_lock(text),
    };
    for dependency in &mut parsed.dependencies {
        if dependency.line.is_none() {
            dependency.line = find_line(text, &dependency.name);
        }
    }
    parsed
        .dependencies
        .sort_by(|a, b| (&a.name, &a.version, a.is_dev).cmp(&(&b.name, &b.version, b.is_dev)));
    // The same package@version reachable through several paths is one inventory entry;
    // it counts as a production dependency if any path is non-dev.
    let mut deduped: Vec<Dependency> = Vec::new();
    for dependency in parsed.dependencies {
        match deduped.last_mut() {
            Some(last) if last.name == dependency.name && last.version == dependency.version => {
                last.is_dev &= dependency.is_dev;
            }
            _ => deduped.push(dependency),
        }
    }
    parsed.dependencies = deduped;
    Ok(parsed)
}

fn dependency(ecosystem: Ecosystem, name: &str, version: &str, is_dev: bool) -> Option<Dependency> {
    let name = name.trim();
    let version = version.trim();
    if name.is_empty() || version.is_empty() {
        return None;
    }
    // Local paths, git URLs and aliases are not registry versions.
    if version.contains(':') || version.contains('/') || version.starts_with('.') {
        return None;
    }
    Some(Dependency {
        ecosystem,
        name: name.to_string(),
        version: version.to_string(),
        is_dev,
        line: None,
    })
}

fn find_line(text: &str, name: &str) -> Option<usize> {
    let quoted = format!("\"{name}\"");
    let nested = format!("node_modules/{name}\"");
    text.lines()
        .position(|line| line.contains(&nested))
        .or_else(|| text.lines().position(|line| line.contains(&quoted)))
        .or_else(|| {
            text.lines().position(|line| {
                line.trim_start().starts_with(name)
                    || line
                        .split_whitespace()
                        .any(|token| token.trim_matches('"') == name)
            })
        })
        .map(|index| index + 1)
}

fn parse_package_lock(text: &str) -> Result<ParsedManifest, String> {
    let root: Value =
        serde_json::from_str(text).map_err(|error| format!("invalid JSON: {error}"))?;
    let mut parsed = ParsedManifest::default();
    if let Some(packages) = root.get("packages").and_then(Value::as_object) {
        for (key, entry) in packages {
            if key.is_empty() || entry.get("link").and_then(Value::as_bool) == Some(true) {
                continue;
            }
            let Some(installed_name) = key.rsplit("node_modules/").next() else {
                continue;
            };
            if !key.contains("node_modules/") {
                continue; // workspace member source directory
            }
            let name = entry
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or(installed_name);
            let version = entry.get("version").and_then(Value::as_str).unwrap_or("");
            let is_dev = entry.get("dev").and_then(Value::as_bool) == Some(true)
                || entry.get("devOptional").and_then(Value::as_bool) == Some(true);
            parsed
                .dependencies
                .extend(dependency(Ecosystem::Npm, name, version, is_dev));
        }
    } else if let Some(dependencies) = root.get("dependencies").and_then(Value::as_object) {
        // lockfileVersion 1
        fn walk(map: &serde_json::Map<String, Value>, output: &mut Vec<Dependency>) {
            for (name, entry) in map {
                let version = entry.get("version").and_then(Value::as_str).unwrap_or("");
                let is_dev = entry.get("dev").and_then(Value::as_bool) == Some(true);
                output.extend(dependency(Ecosystem::Npm, name, version, is_dev));
                if let Some(nested) = entry.get("dependencies").and_then(Value::as_object) {
                    walk(nested, output);
                }
            }
        }
        walk(dependencies, &mut parsed.dependencies);
    }
    Ok(parsed)
}

fn parse_yarn_lock(text: &str) -> ParsedManifest {
    let mut parsed = ParsedManifest::default();
    let mut current: Option<(String, usize)> = None;
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        if !line.starts_with(' ') {
            current = None;
            let header = line.trim_end_matches(':').trim();
            if header.starts_with("__metadata") {
                continue;
            }
            let first = header
                .split(',')
                .next()
                .unwrap_or("")
                .trim()
                .trim_matches('"');
            // `@scope/name@range` or `name@npm:range`: the name ends at the last '@'
            // that is not the scope prefix.
            let at = first.rfind('@').filter(|&position| position > 0);
            if let Some(position) = at {
                current = Some((first[..position].to_string(), index + 1));
            }
            continue;
        }
        if let Some((name, header_line)) = &current {
            let trimmed = line.trim();
            if let Some(rest) = trimmed
                .strip_prefix("version:")
                .or_else(|| trimmed.strip_prefix("version "))
            {
                let version = rest.trim().trim_matches('"');
                if let Some(mut found) = dependency(Ecosystem::Npm, name, version, false) {
                    found.line = Some(*header_line);
                    parsed.dependencies.push(found);
                }
            }
        }
    }
    parsed
}

/// `[[package]]` tables with `name`/`version` keys (Cargo.lock, poetry.lock).
fn parse_toml_packages(
    text: &str,
    ecosystem: Ecosystem,
    include_source: impl Fn(Option<&str>) -> bool,
) -> ParsedManifest {
    let mut parsed = ParsedManifest::default();
    let mut block: Option<(Option<String>, Option<String>, Option<String>, bool, usize)> = None;
    let flush =
        |block: &mut Option<(Option<String>, Option<String>, Option<String>, bool, usize)>,
         output: &mut Vec<Dependency>| {
            if let Some((Some(name), Some(version), source, is_dev, line)) = block.take() {
                if include_source(source.as_deref()) {
                    if let Some(mut found) = dependency(ecosystem, &name, &version, is_dev) {
                        found.line = Some(line);
                        output.push(found);
                    }
                }
            }
        };
    for (index, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed == "[[package]]" {
            flush(&mut block, &mut parsed.dependencies);
            block = Some((None, None, None, false, index + 1));
            continue;
        }
        if trimmed.starts_with('[') && !trimmed.starts_with("[package.") {
            flush(&mut block, &mut parsed.dependencies);
            continue;
        }
        let Some(entry) = block.as_mut() else {
            continue;
        };
        if let Some((key, value)) = trimmed.split_once('=') {
            let value = value.trim().trim_matches('"').to_string();
            match key.trim() {
                "name" => entry.0 = Some(value),
                "version" => entry.1 = Some(value),
                "source" => entry.2 = Some(value),
                // poetry: category = "dev" (older) marks development-only packages
                "category" => entry.3 = value == "dev",
                _ => {}
            }
        }
    }
    flush(&mut block, &mut parsed.dependencies);
    parsed
}

/// pnpm-lock.yaml v5 (`/name/1.0.0:`), v6 (`/name@1.0.0:`) and v9 (`name@1.0.0:`),
/// with peer suffixes such as `(react@18.0.0)` removed.
fn parse_pnpm_lock(text: &str) -> ParsedManifest {
    let mut parsed = ParsedManifest::default();
    let mut in_packages = false;
    for (index, line) in text.lines().enumerate() {
        if !line.starts_with(' ') && !line.trim().is_empty() {
            in_packages = line.trim_end() == "packages:";
            continue;
        }
        if !in_packages {
            continue;
        }
        if line.starts_with("  ") && !line.starts_with("   ") && line.trim_end().ends_with(':') {
            let key = line.trim().trim_end_matches(':').trim_matches(['\'', '"']);
            let key = key.trim_start_matches('/');
            let key = key.split('(').next().unwrap_or(key);
            let split = key
                .rfind('@')
                .filter(|&position| position > 0)
                .or_else(|| key.rfind('/').filter(|&position| position > 0));
            if let Some(position) = split {
                let (name, version) = (&key[..position], &key[position + 1..]);
                if let Some(mut found) = dependency(Ecosystem::Npm, name, version, false) {
                    found.line = Some(index + 1);
                    parsed.dependencies.push(found);
                }
            }
        } else if line.trim() == "dev: true" {
            if let Some(last) = parsed.dependencies.last_mut() {
                last.is_dev = true;
            }
        }
    }
    parsed
}

/// bun.lock (text format): `"key": ["name@version", ...]` entries under `"packages"`.
fn parse_bun_lock(text: &str) -> ParsedManifest {
    let mut parsed = ParsedManifest::default();
    let mut in_packages = false;
    for (index, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("\"packages\"") {
            in_packages = true;
            continue;
        }
        if !in_packages {
            continue;
        }
        if trimmed == "}" || trimmed == "}," {
            if line.starts_with("  }") && !line.starts_with("   ") {
                in_packages = false;
            }
            continue;
        }
        let Some((_, rest)) = trimmed.split_once(": [\"") else {
            continue;
        };
        let Some(spec) = rest.split('"').next() else {
            continue;
        };
        if let Some(position) = spec.rfind('@').filter(|&position| position > 0) {
            if let Some(mut found) = dependency(
                Ecosystem::Npm,
                &spec[..position],
                &spec[position + 1..],
                false,
            ) {
                found.line = Some(index + 1);
                parsed.dependencies.push(found);
            }
        }
    }
    parsed
}

fn parse_pipfile_lock(text: &str) -> Result<ParsedManifest, String> {
    let root: Value =
        serde_json::from_str(text).map_err(|error| format!("invalid JSON: {error}"))?;
    let mut parsed = ParsedManifest::default();
    for (section, is_dev) in [("default", false), ("develop", true)] {
        let Some(packages) = root.get(section).and_then(Value::as_object) else {
            continue;
        };
        for (name, entry) in packages {
            match entry.get("version").and_then(Value::as_str) {
                Some(version) if version.starts_with("==") => {
                    parsed.dependencies.extend(dependency(
                        Ecosystem::PyPI,
                        name,
                        version.trim_start_matches('='),
                        is_dev,
                    ))
                }
                _ => parsed.unpinned += 1,
            }
        }
    }
    Ok(parsed)
}

fn parse_requirements(text: &str) -> ParsedManifest {
    let mut parsed = ParsedManifest::default();
    for (index, raw) in text.lines().enumerate() {
        let line = raw.split(" #").next().unwrap_or(raw).trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('-') || line.contains("://")
        {
            continue;
        }
        let requirement = line.split(';').next().unwrap_or(line).trim();
        let pinned = requirement
            .split_once("===")
            .or_else(|| requirement.split_once("=="));
        match pinned {
            Some((name, version)) if !version.contains(['*', ',', '<', '>']) => {
                let name = name.split('[').next().unwrap_or(name);
                if let Some(mut found) = dependency(Ecosystem::PyPI, name, version, false) {
                    found.line = Some(index + 1);
                    parsed.dependencies.push(found);
                }
            }
            _ => parsed.unpinned += 1,
        }
    }
    parsed
}

fn parse_go_mod(text: &str) -> ParsedManifest {
    let mut parsed = ParsedManifest::default();
    let mut in_block = false;
    for (index, raw) in text.lines().enumerate() {
        let line = raw.split("//").next().unwrap_or(raw).trim();
        if line.starts_with("require (") || line == "require(" {
            in_block = true;
            continue;
        }
        if in_block && line == ")" {
            in_block = false;
            continue;
        }
        let spec = if in_block {
            line
        } else if let Some(rest) = line.strip_prefix("require ") {
            rest.trim()
        } else {
            continue;
        };
        let mut parts = spec.split_whitespace();
        if let (Some(module), Some(version)) = (parts.next(), parts.next()) {
            // OSV Go ranges use versions without the leading "v".
            let version = version
                .trim_start_matches('v')
                .trim_end_matches("+incompatible");
            if let Some(mut found) = dependency(Ecosystem::Go, module, version, false) {
                found.line = Some(index + 1);
                parsed.dependencies.push(found);
            }
        }
    }
    parsed
}

fn parse_composer_lock(text: &str) -> Result<ParsedManifest, String> {
    let root: Value =
        serde_json::from_str(text).map_err(|error| format!("invalid JSON: {error}"))?;
    let mut parsed = ParsedManifest::default();
    for (section, is_dev) in [("packages", false), ("packages-dev", true)] {
        for entry in root
            .get(section)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let name = entry.get("name").and_then(Value::as_str).unwrap_or("");
            let version = entry
                .get("version")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim_start_matches('v');
            if version.starts_with("dev-") {
                parsed.unpinned += 1;
                continue;
            }
            parsed
                .dependencies
                .extend(dependency(Ecosystem::Packagist, name, version, is_dev));
        }
    }
    Ok(parsed)
}

fn parse_gemfile_lock(text: &str) -> ParsedManifest {
    let mut parsed = ParsedManifest::default();
    let mut in_gem = false;
    let mut in_specs = false;
    for (index, line) in text.lines().enumerate() {
        if !line.starts_with(' ') {
            in_gem = line.trim() == "GEM";
            in_specs = false;
            continue;
        }
        if in_gem && line.trim() == "specs:" {
            in_specs = true;
            continue;
        }
        // Top-level specs are indented exactly four spaces; deeper lines are their
        // dependency constraints.
        if !in_specs || !line.starts_with("    ") || line.starts_with("     ") {
            continue;
        }
        let Some((name, rest)) = line.trim().split_once(" (") else {
            continue;
        };
        let version = rest.trim_end_matches(')');
        // Drop platform suffixes such as `-x86_64-linux`.
        let version = match version.split_once('-') {
            Some((base, platform))
                if [
                    "linux",
                    "darwin",
                    "mingw",
                    "java",
                    "x86",
                    "arm",
                    "universal",
                ]
                .iter()
                .any(|marker| platform.contains(marker)) =>
            {
                base
            }
            _ => version,
        };
        if let Some(mut found) = dependency(Ecosystem::RubyGems, name, version, false) {
            found.line = Some(index + 1);
            parsed.dependencies.push(found);
        }
    }
    parsed
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(parsed: &ParsedManifest) -> Vec<(String, String, bool)> {
        parsed
            .dependencies
            .iter()
            .map(|d| (d.name.clone(), d.version.clone(), d.is_dev))
            .collect()
    }

    #[test]
    fn recognizes_manifest_file_names() {
        assert_eq!(
            manifest_kind("package-lock.json"),
            Some(ManifestKind::NpmPackageLock)
        );
        assert_eq!(
            manifest_kind("requirements-dev.txt"),
            Some(ManifestKind::Requirements)
        );
        assert_eq!(manifest_kind("Cargo.lock"), Some(ManifestKind::CargoLock));
        assert_eq!(manifest_kind("package.json"), None);
    }

    #[test]
    fn parses_npm_package_lock_v3_with_nested_and_dev_packages() {
        let text = r#"{"lockfileVersion":3,"packages":{
            "":{"name":"app"},
            "node_modules/lodash":{"version":"4.17.20"},
            "node_modules/a/node_modules/@scope/b":{"version":"1.0.0","dev":true},
            "node_modules/local":{"link":true},
            "packages/web":{"version":"0.1.0"}
        }}"#;
        let parsed = parse_manifest(ManifestKind::NpmPackageLock, text).expect("parse");
        assert_eq!(
            names(&parsed),
            vec![
                ("@scope/b".into(), "1.0.0".into(), true),
                ("lodash".into(), "4.17.20".into(), false)
            ]
        );
        assert!(parsed.dependencies[1].line.is_some());
    }

    #[test]
    fn parses_npm_package_lock_v1() {
        let text = r#"{"lockfileVersion":1,"dependencies":{
            "express":{"version":"4.17.1","dependencies":{"qs":{"version":"6.7.0"}}},
            "jest":{"version":"26.0.0","dev":true}}}"#;
        let parsed = parse_manifest(ManifestKind::NpmPackageLock, text).expect("parse");
        assert_eq!(parsed.dependencies.len(), 3);
    }

    #[test]
    fn parses_yarn_classic_and_berry_locks() {
        let classic = "# yarn lockfile v1\n\n\"@babel/core@^7.0.0\", \"@babel/core@^7.1.0\":\n  version \"7.1.2\"\n\nlodash@^4.17.0:\n  version \"4.17.15\"\n";
        let parsed = parse_manifest(ManifestKind::YarnLock, classic).expect("parse");
        assert_eq!(
            names(&parsed),
            vec![
                ("@babel/core".into(), "7.1.2".into(), false),
                ("lodash".into(), "4.17.15".into(), false)
            ]
        );
        let berry = "__metadata:\n  version: 6\n\n\"lodash@npm:^4.17.21\":\n  version: 4.17.21\n";
        let parsed = parse_manifest(ManifestKind::YarnLock, berry).expect("parse");
        assert_eq!(
            names(&parsed),
            vec![("lodash".into(), "4.17.21".into(), false)]
        );
    }

    #[test]
    fn cargo_lock_reports_only_registry_packages() {
        let text = "[[package]]\nname = \"app\"\nversion = \"0.1.0\"\n\n[[package]]\nname = \"time\"\nversion = \"0.1.43\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n\n[[package]]\nname = \"gitdep\"\nversion = \"1.0.0\"\nsource = \"git+https://example.org/x\"\n";
        let parsed = parse_manifest(ManifestKind::CargoLock, text).expect("parse");
        assert_eq!(
            names(&parsed),
            vec![("time".into(), "0.1.43".into(), false)]
        );
        assert_eq!(parsed.dependencies[0].line, Some(5));
    }

    #[test]
    fn requirements_only_accept_exact_pins() {
        let text = "Django==3.2.0\nrequests[security]==2.19.0 ; python_version > '3'\nflask>=2.0\n-r base.txt\n# comment\nurllib3\n";
        let parsed = parse_manifest(ManifestKind::Requirements, text).expect("parse");
        assert_eq!(
            names(&parsed),
            vec![
                ("Django".into(), "3.2.0".into(), false),
                ("requests".into(), "2.19.0".into(), false)
            ]
        );
        assert_eq!(parsed.unpinned, 2);
    }

    #[test]
    fn parses_go_mod_blocks_and_single_requires() {
        let text = "module example.com/app\n\ngo 1.21\n\nrequire github.com/gin-gonic/gin v1.6.0\n\nrequire (\n\tgolang.org/x/net v0.7.0 // indirect\n\tgithub.com/x/y v2.0.0+incompatible\n)\n";
        let parsed = parse_manifest(ManifestKind::GoMod, text).expect("parse");
        assert_eq!(
            names(&parsed),
            vec![
                ("github.com/gin-gonic/gin".into(), "1.6.0".into(), false),
                ("github.com/x/y".into(), "2.0.0".into(), false),
                ("golang.org/x/net".into(), "0.7.0".into(), false)
            ]
        );
    }

    #[test]
    fn parses_composer_pipfile_poetry_and_gemfile_locks() {
        let composer = r#"{"packages":[{"name":"laravel/framework","version":"v8.0.0"}],"packages-dev":[{"name":"phpunit/phpunit","version":"9.5.0"},{"name":"x/y","version":"dev-main"}]}"#;
        let parsed = parse_manifest(ManifestKind::ComposerLock, composer).expect("parse");
        assert_eq!(parsed.dependencies.len(), 2);
        assert_eq!(parsed.unpinned, 1);
        assert_eq!(parsed.dependencies[0].version, "8.0.0");

        let pipfile = r#"{"default":{"django":{"version":"==3.2.0"}},"develop":{"pytest":{"version":"==7.0.0"},"black":{"version":"*"}}}"#;
        let parsed = parse_manifest(ManifestKind::PipfileLock, pipfile).expect("parse");
        assert_eq!(parsed.dependencies.len(), 2);
        assert_eq!(parsed.unpinned, 1);

        let poetry = "[[package]]\nname = \"jinja2\"\nversion = \"2.10\"\ncategory = \"main\"\n\n[package.dependencies]\nmarkupsafe = \">=0.23\"\n\n[metadata]\nlock-version = \"1.1\"\n";
        let parsed = parse_manifest(ManifestKind::PoetryLock, poetry).expect("parse");
        assert_eq!(
            names(&parsed),
            vec![("jinja2".into(), "2.10".into(), false)]
        );

        let gemfile = "GEM\n  remote: https://rubygems.org/\n  specs:\n    nokogiri (1.13.10-x86_64-linux)\n      racc (~> 1.4)\n    rails (6.0.0)\n\nPLATFORMS\n  x86_64-linux\n";
        let parsed = parse_manifest(ManifestKind::GemfileLock, gemfile).expect("parse");
        assert_eq!(
            names(&parsed),
            vec![
                ("nokogiri".into(), "1.13.10".into(), false),
                ("rails".into(), "6.0.0".into(), false)
            ]
        );
    }

    #[test]
    fn parses_pnpm_bun_and_uv_locks() {
        let pnpm_v6 = "lockfileVersion: '6.0'\n\npackages:\n\n  /lodash@4.17.20:\n    resolution: {integrity: sha512-x}\n    dev: false\n\n  /@types/node@20.1.0:\n    dev: true\n\n  /react-dom@18.2.0(react@18.2.0):\n    dev: false\n";
        let parsed = parse_manifest(ManifestKind::PnpmLock, pnpm_v6).expect("pnpm v6");
        assert_eq!(
            names(&parsed),
            vec![
                ("@types/node".into(), "20.1.0".into(), true),
                ("lodash".into(), "4.17.20".into(), false),
                ("react-dom".into(), "18.2.0".into(), false)
            ]
        );
        let pnpm_v9 = "lockfileVersion: '9.0'\n\npackages:\n\n  lodash@4.17.21:\n    resolution: {integrity: sha512-x}\n\nsnapshots:\n\n  lodash@4.17.21: {}\n";
        let parsed = parse_manifest(ManifestKind::PnpmLock, pnpm_v9).expect("pnpm v9");
        assert_eq!(
            names(&parsed),
            vec![("lodash".into(), "4.17.21".into(), false)]
        );
        let pnpm_v5 = "lockfileVersion: 5.4\n\npackages:\n\n  /lodash/4.17.19:\n    dev: false\n";
        let parsed = parse_manifest(ManifestKind::PnpmLock, pnpm_v5).expect("pnpm v5");
        assert_eq!(
            names(&parsed),
            vec![("lodash".into(), "4.17.19".into(), false)]
        );

        let bun = "{\n  \"lockfileVersion\": 1,\n  \"workspaces\": {\n    \"\": { \"name\": \"app\" },\n  },\n  \"packages\": {\n    \"@babel/core\": [\"@babel/core@7.28.0\", \"\", {}, \"sha512-x\"],\n\n    \"lodash\": [\"lodash@4.17.20\", \"\", {}, \"sha512-y\"],\n    \"local\": [\"local@workspace:packages/local\"],\n  }\n}\n";
        let parsed = parse_manifest(ManifestKind::BunLock, bun).expect("bun");
        assert_eq!(
            names(&parsed),
            vec![
                ("@babel/core".into(), "7.28.0".into(), false),
                ("lodash".into(), "4.17.20".into(), false)
            ]
        );

        let uv = "version = 1\n\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\nsource = { editable = \".\" }\ndependencies = [\n    { name = \"jinja2\" },\n]\n\n[[package]]\nname = \"jinja2\"\nversion = \"3.1.2\"\nsource = { registry = \"https://pypi.org/simple\" }\n\n[package.optional-dependencies]\ni18n = [\n    { name = \"babel\" },\n]\n";
        let parsed = parse_manifest(ManifestKind::UvLock, uv).expect("uv");
        assert_eq!(
            names(&parsed),
            vec![("jinja2".into(), "3.1.2".into(), false)]
        );
    }

    #[test]
    fn pypi_names_are_normalized_for_matching() {
        assert_eq!(
            Ecosystem::PyPI.normalize_name("Flask_SQLAlchemy"),
            "flask-sqlalchemy"
        );
        assert_eq!(
            Ecosystem::PyPI.normalize_name("zope.interface"),
            "zope-interface"
        );
        assert_eq!(Ecosystem::Npm.normalize_name("Lodash"), "Lodash");
    }

    #[test]
    fn malformed_json_is_an_error_not_an_empty_inventory() {
        assert!(parse_manifest(ManifestKind::NpmPackageLock, "{not json").is_err());
    }
}
