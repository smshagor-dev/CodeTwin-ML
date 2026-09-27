//! Maven, Gradle and NuGet manifests.
//!
//! Only versions that name one exact release are audited. `pom.xml` and MSBuild project files
//! list direct dependencies only; lockfiles (`gradle.lockfile`, `packages.lock.json`) also cover
//! transitive ones.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::manifest::{Dependency, Ecosystem, ParsedManifest};

/// XML manifests never need a DTD; refusing one rules out entity-expansion attacks.
fn parse_xml(text: &str) -> Result<roxmltree::Document<'_>, String> {
    let lower = text.to_ascii_lowercase();
    if lower.contains("<!doctype") || lower.contains("<!entity") {
        return Err("XML with a DTD or entity declarations is not accepted".to_string());
    }
    roxmltree::Document::parse(text).map_err(|error| format!("invalid XML: {error}"))
}

fn child<'a, 'input>(
    node: roxmltree::Node<'a, 'input>,
    name: &str,
) -> Option<roxmltree::Node<'a, 'input>> {
    node.children()
        .find(|child| child.is_element() && child.tag_name().name() == name)
}

fn child_text<'a>(node: roxmltree::Node<'a, '_>, name: &str) -> Option<&'a str> {
    child(node, name)
        .and_then(|child| child.text())
        .map(str::trim)
}

fn line_of(document: &roxmltree::Document<'_>, node: roxmltree::Node<'_, '_>) -> usize {
    document.text_pos_at(node.range().start).row as usize
}

fn make(
    ecosystem: Ecosystem,
    name: &str,
    version: &str,
    is_dev: bool,
    line: Option<usize>,
) -> Dependency {
    Dependency {
        ecosystem,
        name: name.to_string(),
        version: version.to_string(),
        is_dev,
        line,
    }
}

/// A Maven or NuGet version string that names exactly one release (no range, wildcard,
/// property or dynamic keyword).
fn is_exact(version: &str) -> bool {
    !version.is_empty()
        && version.chars().next().is_some_and(|c| c.is_ascii_digit())
        && !version.contains(['[', ']', '(', ')', ',', '*', '$', '{', '}', ' '])
        && !version.eq_ignore_ascii_case("latest")
        && !version.to_ascii_uppercase().ends_with("SNAPSHOT")
}

// ---------------------------------------------------------------------------------------------
// Gradle

/// `gradle.lockfile` (`group:artifact:version=conf1,conf2`) and the older per-configuration
/// `gradle/dependency-locks/<conf>.lockfile` (`group:artifact:version`).
pub fn parse_gradle_lockfile(text: &str) -> ParsedManifest {
    let mut parsed = ParsedManifest::default();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("empty=") {
            continue;
        }
        let (coordinate, configurations) = line.split_once('=').unwrap_or((line, ""));
        let parts: Vec<&str> = coordinate.split(':').collect();
        let [group, artifact, version] = parts.as_slice() else {
            continue;
        };
        if !is_exact(version) {
            parsed.unpinned += 1;
            continue;
        }
        let is_dev = !configurations.is_empty()
            && configurations
                .split(',')
                .all(|conf| conf.trim().to_ascii_lowercase().starts_with("test"));
        parsed.dependencies.push(make(
            Ecosystem::Maven,
            &format!("{group}:{artifact}"),
            version,
            is_dev,
            Some(index + 1),
        ));
    }
    parsed
}

// ---------------------------------------------------------------------------------------------
// Maven

fn resolve_properties(value: &str, properties: &BTreeMap<String, String>) -> Option<String> {
    let mut current = value.to_string();
    // A few rounds for properties defined in terms of other properties; cycles give up.
    for _ in 0..5 {
        let Some(start) = current.find("${") else {
            return Some(current);
        };
        let end = current[start..].find('}')? + start;
        let key = &current[start + 2..end];
        let replacement = properties.get(key)?;
        current.replace_range(start..=end, replacement);
    }
    (!current.contains("${")).then_some(current)
}

/// Direct and managed dependencies of a `pom.xml`. Versions inherited from a parent POM or
/// imported BOM are not visible here and are counted as unpinned.
pub fn parse_pom(text: &str) -> Result<ParsedManifest, String> {
    let document = parse_xml(text)?;
    let project = document.root_element();
    if project.tag_name().name() != "project" {
        return Err("not a Maven POM (root element is not <project>)".to_string());
    }
    let mut properties = BTreeMap::new();
    if let Some(node) = child(project, "properties") {
        for property in node.children().filter(|child| child.is_element()) {
            if let Some(value) = property.text() {
                properties.insert(
                    property.tag_name().name().to_string(),
                    value.trim().to_string(),
                );
            }
        }
    }
    let parent_version = child(project, "parent").and_then(|parent| child_text(parent, "version"));
    let project_version = child_text(project, "version").or(parent_version);
    let project_group = child_text(project, "groupId")
        .or_else(|| child(project, "parent").and_then(|parent| child_text(parent, "groupId")));
    for (key, value) in [
        ("project.version", project_version),
        ("pom.version", project_version),
        ("version", project_version),
        ("project.groupId", project_group),
        ("project.parent.version", parent_version),
    ] {
        if let Some(value) = value {
            properties
                .entry(key.to_string())
                .or_insert_with(|| value.to_string());
        }
    }

    let mut parsed = ParsedManifest::default();
    let lists = [
        child(project, "dependencies"),
        child(project, "dependencyManagement").and_then(|node| child(node, "dependencies")),
    ];
    for list in lists.into_iter().flatten() {
        for node in list
            .children()
            .filter(|child| child.is_element() && child.tag_name().name() == "dependency")
        {
            let (Some(group), Some(artifact)) =
                (child_text(node, "groupId"), child_text(node, "artifactId"))
            else {
                continue;
            };
            let group = resolve_properties(group, &properties).unwrap_or_default();
            let scope = child_text(node, "scope").unwrap_or("compile");
            if scope == "import" || scope == "system" {
                continue; // BOM imports and local jars are not packages to audit
            }
            let version =
                child_text(node, "version").and_then(|v| resolve_properties(v, &properties));
            match version {
                Some(version) if is_exact(&version) && !group.is_empty() => {
                    parsed.dependencies.push(make(
                        Ecosystem::Maven,
                        &format!("{group}:{artifact}"),
                        &version,
                        scope == "test",
                        Some(line_of(&document, node)),
                    ));
                }
                _ => parsed.unpinned += 1,
            }
        }
    }
    Ok(parsed)
}

// ---------------------------------------------------------------------------------------------
// NuGet

/// `packages.lock.json`: every resolved package per target framework. `Project` entries are
/// other projects in the solution, not packages.
pub fn parse_packages_lock(text: &str) -> Result<ParsedManifest, String> {
    let root: Value =
        serde_json::from_str(text).map_err(|error| format!("invalid JSON: {error}"))?;
    let frameworks = root
        .get("dependencies")
        .and_then(Value::as_object)
        .ok_or("packages.lock.json has no dependencies object")?;
    let mut parsed = ParsedManifest::default();
    for packages in frameworks.values().filter_map(Value::as_object) {
        for (name, entry) in packages {
            let kind = entry.get("type").and_then(Value::as_str).unwrap_or("");
            if kind.eq_ignore_ascii_case("project") {
                continue;
            }
            match entry.get("resolved").and_then(Value::as_str) {
                Some(version) if is_exact(version) => {
                    parsed
                        .dependencies
                        .push(make(Ecosystem::NuGet, name, version, false, None))
                }
                _ => parsed.unpinned += 1,
            }
        }
    }
    Ok(parsed)
}

/// `*.csproj`/`*.fsproj`/`*.vbproj` `PackageReference` items and `Directory.Packages.props`
/// `PackageVersion` items. A reference without a version (central package management) is
/// counted as unpinned here; its version is audited from `Directory.Packages.props`.
pub fn parse_msbuild(text: &str) -> Result<ParsedManifest, String> {
    let document = parse_xml(text)?;
    let mut parsed = ParsedManifest::default();
    for node in document.descendants().filter(|node| {
        node.is_element()
            && matches!(
                node.tag_name().name(),
                "PackageReference" | "PackageVersion"
            )
    }) {
        let Some(name) = node
            .attribute("Include")
            .or_else(|| node.attribute("Update"))
        else {
            continue;
        };
        let version = node
            .attribute("Version")
            .or_else(|| node.attribute("VersionOverride"))
            .map(str::trim)
            .or_else(|| child_text(node, "Version"));
        // Analyzers and build tooling marked PrivateAssets="all" do not ship with the app.
        let is_dev = node
            .attribute("PrivateAssets")
            .or_else(|| child_text(node, "PrivateAssets"))
            .is_some_and(|value| value.eq_ignore_ascii_case("all"));
        match version {
            Some(version) if is_exact(version) => parsed.dependencies.push(make(
                Ecosystem::NuGet,
                name.trim(),
                version,
                is_dev,
                Some(line_of(&document, node)),
            )),
            Some(_) => parsed.unpinned += 1,
            None if node.tag_name().name() == "PackageReference" => parsed.unpinned += 1,
            None => {}
        }
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(parsed: &ParsedManifest) -> Vec<String> {
        parsed
            .dependencies
            .iter()
            .map(|d| {
                format!(
                    "{}@{}{}",
                    d.name,
                    d.version,
                    if d.is_dev { " dev" } else { "" }
                )
            })
            .collect()
    }

    #[test]
    fn gradle_lockfiles() {
        let text = "# This is a Gradle generated file for dependency locking.\n\
                    com.fasterxml.jackson.core:jackson-databind:2.13.1=compileClasspath,runtimeClasspath\n\
                    junit:junit:4.13.2=testCompileClasspath,testRuntimeClasspath\n\
                    org.example:snap:1.0-SNAPSHOT=runtimeClasspath\n\
                    org.apache.logging.log4j:log4j-core:2.14.1\n\
                    empty=annotationProcessor\n";
        let parsed = parse_gradle_lockfile(text);
        assert_eq!(
            names(&parsed),
            vec![
                "com.fasterxml.jackson.core:jackson-databind@2.13.1",
                "junit:junit@4.13.2 dev",
                "org.apache.logging.log4j:log4j-core@2.14.1",
            ]
        );
        assert_eq!(parsed.unpinned, 1);
        assert_eq!(parsed.dependencies[0].line, Some(2));
    }

    #[test]
    fn pom_resolves_properties_and_skips_unpinned() {
        let text = r#"<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>com.acme</groupId>
  <artifactId>app</artifactId>
  <version>1.4.0</version>
  <properties>
    <log4j.version>2.14.1</log4j.version>
    <spring.version>5.3.18.RELEASE</spring.version>
    <alias>${log4j.version}</alias>
  </properties>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>org.springframework</groupId>
        <artifactId>spring-framework-bom</artifactId>
        <version>${spring.version}</version>
        <type>pom</type>
        <scope>import</scope>
      </dependency>
      <dependency>
        <groupId>org.springframework</groupId>
        <artifactId>spring-core</artifactId>
        <version>${spring.version}</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>${alias}</version>
    </dependency>
    <dependency>
      <groupId>${project.groupId}</groupId>
      <artifactId>shared</artifactId>
      <version>${project.version}</version>
    </dependency>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
    </dependency>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>[4.0,5.0)</version>
      <scope>test</scope>
    </dependency>
    <dependency>
      <groupId>org.mockito</groupId>
      <artifactId>mockito-core</artifactId>
      <version>4.5.1</version>
      <scope>test</scope>
    </dependency>
    <dependency>
      <groupId>x</groupId>
      <artifactId>y</artifactId>
      <version>${undefined.prop}</version>
    </dependency>
  </dependencies>
</project>"#;
        let parsed = parse_pom(text).unwrap();
        assert_eq!(
            names(&parsed),
            vec![
                "org.apache.logging.log4j:log4j-core@2.14.1",
                "com.acme:shared@1.4.0",
                "org.mockito:mockito-core@4.5.1 dev",
                "org.springframework:spring-core@5.3.18.RELEASE",
            ]
        );
        // inherited spring-core, ranged junit, undefined property
        assert_eq!(parsed.unpinned, 3);
        assert_eq!(parsed.dependencies[0].line, Some(28));
    }

    #[test]
    fn xml_with_entities_is_refused() {
        let bomb = "<?xml version=\"1.0\"?><!DOCTYPE project [<!ENTITY a \"aaaa\">]><project>&a;</project>";
        assert!(parse_pom(bomb).unwrap_err().contains("DTD"));
        assert!(parse_msbuild(bomb).is_err());
        assert!(parse_pom("<dependencies/>").is_err());
    }

    #[test]
    fn nuget_lockfile_skips_projects_and_dedupes_later() {
        let text = r#"{
  "version": 1,
  "dependencies": {
    "net8.0": {
      "Newtonsoft.Json": { "type": "Direct", "requested": "[13.0.1, )", "resolved": "13.0.1" },
      "System.Text.Json": { "type": "Transitive", "resolved": "8.0.0" },
      "MyApp.Core": { "type": "Project" }
    },
    "net6.0": {
      "Newtonsoft.Json": { "type": "Direct", "requested": "[13.0.1, )", "resolved": "13.0.1" }
    }
  }
}"#;
        let parsed = parse_packages_lock(text).unwrap();
        assert_eq!(parsed.dependencies.len(), 3);
        assert_eq!(parsed.unpinned, 0);
        assert!(parse_packages_lock("{}").is_err());
    }

    #[test]
    fn msbuild_package_references() {
        let text = r#"<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="12.0.1" />
    <PackageReference Include="Serilog">
      <Version>2.10.0</Version>
    </PackageReference>
    <PackageReference Include="StyleCop.Analyzers" Version="1.1.118" PrivateAssets="all" />
    <PackageReference Include="Floating" Version="6.*" />
    <PackageReference Include="Central" />
  </ItemGroup>
</Project>"#;
        let parsed = parse_msbuild(text).unwrap();
        assert_eq!(
            names(&parsed),
            vec![
                "Newtonsoft.Json@12.0.1",
                "Serilog@2.10.0",
                "StyleCop.Analyzers@1.1.118 dev"
            ]
        );
        assert_eq!(parsed.unpinned, 2);
        assert_eq!(parsed.dependencies[1].line, Some(4));

        let central = r#"<Project><ItemGroup><PackageVersion Include="Newtonsoft.Json" Version="13.0.3" /></ItemGroup></Project>"#;
        assert_eq!(
            names(&parse_msbuild(central).unwrap()),
            vec!["Newtonsoft.Json@13.0.3"]
        );
    }
}
