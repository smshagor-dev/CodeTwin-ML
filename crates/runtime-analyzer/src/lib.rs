use serde::{Deserialize, Serialize};
use serde_json::json;

pub const ANALYZER_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const RULESET_VERSION: &str = "runtime-reliability-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeArtifactKind {
    Dockerfile,
    DockerCompose,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeObservation {
    pub rule_id: String,
    pub severity: String,
    pub confidence: f64,
    pub title: String,
    pub description: String,
    pub start_line: usize,
    pub end_line: usize,
    pub anchor: String,
    pub evidence_summary: String,
    pub metadata_json: String,
}

pub fn analyze_artifact(kind: RuntimeArtifactKind, source: &str) -> Vec<RuntimeObservation> {
    let mut observations = match kind {
        RuntimeArtifactKind::Dockerfile => analyze_dockerfile(source),
        RuntimeArtifactKind::DockerCompose => analyze_compose(source),
    };
    observations.sort_by(|left, right| {
        (left.start_line, left.end_line, &left.rule_id, &left.anchor)
            .cmp(&(right.start_line, right.end_line, &right.rule_id, &right.anchor))
    });
    observations.dedup_by(|left, right| {
        left.rule_id == right.rule_id
            && left.start_line == right.start_line
            && left.end_line == right.end_line
            && left.anchor == right.anchor
    });
    observations
}

fn analyze_dockerfile(source: &str) -> Vec<RuntimeObservation> {
    let mut observations = Vec::new();
    let mut healthcheck_seen = false;
    let mut first_instruction_line = None;

    for (index, raw_line) in source.lines().enumerate() {
        let line_number = index + 1;
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        first_instruction_line.get_or_insert(line_number);
        let (instruction, rest) = split_instruction(line);
        match instruction.as_deref() {
            Some("FROM") => {
                if let Some(image) = rest.split_whitespace().next() {
                    if image_reference_is_mutable(image) {
                        observations.push(RuntimeObservation {
                            rule_id: "runtime.mutable_container_image".into(),
                            severity: "medium".into(),
                            confidence: 0.99,
                            title: "Mutable container image reference requires review".into(),
                            description: "The container base image is not pinned by digest and is either untagged or uses the mutable `latest` tag. This does not prove a reliability incident, but rebuilds can resolve to different image content over time.".into(),
                            start_line: line_number,
                            end_line: line_number,
                            anchor: format!("dockerfile-from:{}", normalized_image_anchor(image)),
                            evidence_summary: format!("Dockerfile FROM uses mutable image reference `{}`.", redact_image_credentials(image)),
                            metadata_json: json!({
                                "artifact_kind": "dockerfile",
                                "instruction": "FROM",
                                "image_reference": redact_image_credentials(image),
                                "digest_pinned": false,
                                "runtime_execution_observed": false
                            }).to_string(),
                        });
                    }
                }
            }
            Some("HEALTHCHECK") => {
                healthcheck_seen = true;
                if rest.trim().eq_ignore_ascii_case("NONE") {
                    observations.push(RuntimeObservation {
                        rule_id: "runtime.healthcheck_disabled".into(),
                        severity: "medium".into(),
                        confidence: 0.99,
                        title: "Container healthcheck is explicitly disabled".into(),
                        description: "The Dockerfile explicitly declares `HEALTHCHECK NONE`. External orchestration can still provide health monitoring, so this is a review signal rather than proof that health monitoring is absent in production.".into(),
                        start_line: line_number,
                        end_line: line_number,
                        anchor: "dockerfile-healthcheck-none".into(),
                        evidence_summary: "Dockerfile contains `HEALTHCHECK NONE`.".into(),
                        metadata_json: json!({
                            "artifact_kind": "dockerfile",
                            "healthcheck_declared": true,
                            "healthcheck_disabled": true,
                            "runtime_execution_observed": false
                        }).to_string(),
                    });
                }
            }
            _ => {}
        }
    }

    if !healthcheck_seen {
        observations.push(RuntimeObservation {
            rule_id: "runtime.healthcheck_not_declared".into(),
            severity: "low".into(),
            confidence: 0.99,
            title: "Dockerfile has no declared healthcheck".into(),
            description: "No Dockerfile HEALTHCHECK instruction was observed. Health monitoring may still be configured by Compose, Kubernetes, a platform load balancer, or another external runtime, so review the deployment path before acting.".into(),
            start_line: first_instruction_line.unwrap_or(1),
            end_line: first_instruction_line.unwrap_or(1),
            anchor: "dockerfile-healthcheck-absent".into(),
            evidence_summary: "No Dockerfile HEALTHCHECK instruction was observed in this artifact.".into(),
            metadata_json: json!({
                "artifact_kind": "dockerfile",
                "healthcheck_declared": false,
                "external_healthcheck_unknown": true,
                "runtime_execution_observed": false
            }).to_string(),
        });
    }

    observations
}

#[derive(Debug, Default)]
struct ComposeService {
    name: String,
    start_line: usize,
    image: Option<(String, usize)>,
    restart: Option<(String, usize)>,
    healthcheck_declared: bool,
    healthcheck_disabled: Option<usize>,
}

fn analyze_compose(source: &str) -> Vec<RuntimeObservation> {
    let mut observations = Vec::new();
    let mut in_services = false;
    let mut services_indent = 0usize;
    let mut current: Option<ComposeService> = None;
    let mut healthcheck_indent: Option<usize> = None;

    for (index, raw_line) in source.lines().enumerate() {
        let line_number = index + 1;
        let line_without_comment = strip_yaml_comment(raw_line);
        if line_without_comment.trim().is_empty() {
            continue;
        }
        let indent = leading_spaces(line_without_comment);
        let trimmed = line_without_comment.trim();

        if !in_services {
            if trimmed == "services:" {
                in_services = true;
                services_indent = indent;
            }
            continue;
        }

        if indent <= services_indent && trimmed != "services:" {
            flush_compose_service(&mut observations, current.take());
            in_services = false;
            healthcheck_indent = None;
            continue;
        }

        if indent == services_indent + 2 && trimmed.ends_with(':') && !trimmed.starts_with('-') {
            flush_compose_service(&mut observations, current.take());
            current = Some(ComposeService {
                name: trimmed.trim_end_matches(':').trim().to_string(),
                start_line: line_number,
                ..ComposeService::default()
            });
            healthcheck_indent = None;
            continue;
        }

        let Some(service) = current.as_mut() else {
            continue;
        };

        if let Some(check_indent) = healthcheck_indent {
            if indent <= check_indent {
                healthcheck_indent = None;
            } else if let Some((key, value)) = split_yaml_assignment(trimmed) {
                if key == "disable" && yaml_truthy(value) {
                    service.healthcheck_disabled = Some(line_number);
                }
            }
        }

        if let Some((key, value)) = split_yaml_assignment(trimmed) {
            match key {
                "image" => service.image = Some((unquote(value).to_string(), line_number)),
                "restart" => service.restart = Some((unquote(value).to_string(), line_number)),
                "healthcheck" => {
                    service.healthcheck_declared = true;
                    healthcheck_indent = Some(indent);
                }
                _ => {}
            }
        }
    }

    flush_compose_service(&mut observations, current.take());
    observations
}

fn flush_compose_service(output: &mut Vec<RuntimeObservation>, service: Option<ComposeService>) {
    let Some(service) = service else {
        return;
    };
    if let Some((image, line)) = service.image.as_ref() {
        if image_reference_is_mutable(image) {
            output.push(RuntimeObservation {
                rule_id: "runtime.mutable_container_image".into(),
                severity: "medium".into(),
                confidence: 0.99,
                title: "Mutable container image reference requires review".into(),
                description: "The Compose service image is not pinned by digest and is either untagged or uses the mutable `latest` tag. This can make later deployments resolve to different image content.".into(),
                start_line: *line,
                end_line: *line,
                anchor: format!("compose-image:{}:{}", service.name, normalized_image_anchor(image)),
                evidence_summary: format!("Compose service `{}` uses mutable image reference `{}`.", service.name, redact_image_credentials(image)),
                metadata_json: json!({
                    "artifact_kind": "docker_compose",
                    "service": service.name,
                    "image_reference": redact_image_credentials(image),
                    "digest_pinned": false,
                    "runtime_execution_observed": false
                }).to_string(),
            });
        }
    }

    if let Some((restart, line)) = service.restart.as_ref() {
        if restart.trim().eq_ignore_ascii_case("no") {
            output.push(RuntimeObservation {
                rule_id: "runtime.restart_disabled".into(),
                severity: "low".into(),
                confidence: 0.99,
                title: "Automatic restart is explicitly disabled".into(),
                description: "The Compose service sets `restart: no`. This can be intentional, especially for one-shot jobs, so review the service role before changing the policy.".into(),
                start_line: *line,
                end_line: *line,
                anchor: format!("compose-restart-no:{}", service.name),
                evidence_summary: format!("Compose service `{}` explicitly disables automatic restart.", service.name),
                metadata_json: json!({
                    "artifact_kind": "docker_compose",
                    "service": service.name,
                    "restart_policy": "no",
                    "runtime_execution_observed": false
                }).to_string(),
            });
        }
    }

    if let Some(line) = service.healthcheck_disabled {
        output.push(RuntimeObservation {
            rule_id: "runtime.healthcheck_disabled".into(),
            severity: "medium".into(),
            confidence: 0.99,
            title: "Container healthcheck is explicitly disabled".into(),
            description: "The Compose service explicitly disables its healthcheck. External orchestration may still monitor the service, so this remains a review signal rather than a live availability finding.".into(),
            start_line: line,
            end_line: line,
            anchor: format!("compose-healthcheck-disabled:{}", service.name),
            evidence_summary: format!("Compose service `{}` sets healthcheck.disable to true.", service.name),
            metadata_json: json!({
                "artifact_kind": "docker_compose",
                "service": service.name,
                "healthcheck_declared": true,
                "healthcheck_disabled": true,
                "runtime_execution_observed": false
            }).to_string(),
        });
    } else if service.image.is_some() && !service.healthcheck_declared {
        output.push(RuntimeObservation {
            rule_id: "runtime.healthcheck_not_declared".into(),
            severity: "low".into(),
            confidence: 0.95,
            title: "Compose service has no declared healthcheck".into(),
            description: "No Compose healthcheck was observed for this image-backed service. The deployed platform may supply health monitoring elsewhere, so verify the actual deployment before treating this as a gap.".into(),
            start_line: service.start_line,
            end_line: service.start_line,
            anchor: format!("compose-healthcheck-absent:{}", service.name),
            evidence_summary: format!("Compose service `{}` has no declared healthcheck block.", service.name),
            metadata_json: json!({
                "artifact_kind": "docker_compose",
                "service": service.name,
                "healthcheck_declared": false,
                "external_healthcheck_unknown": true,
                "runtime_execution_observed": false
            }).to_string(),
        });
    }
}

fn split_instruction(line: &str) -> (Option<String>, &str) {
    let mut parts = line.splitn(2, char::is_whitespace);
    let instruction = parts.next().map(|value| value.to_ascii_uppercase());
    let rest = parts.next().unwrap_or_default().trim();
    (instruction, rest)
}

fn image_reference_is_mutable(image: &str) -> bool {
    let image = image.trim();
    if image.is_empty() || image.contains("@sha256:") || image.contains("${") {
        return false;
    }
    let tail = image.rsplit('/').next().unwrap_or(image);
    match tail.rsplit_once(':') {
        Some((_, tag)) => tag.eq_ignore_ascii_case("latest") || tag.is_empty(),
        None => true,
    }
}

fn normalized_image_anchor(image: &str) -> String {
    redact_image_credentials(image).to_ascii_lowercase()
}

fn redact_image_credentials(image: &str) -> String {
    if let Some((prefix, suffix)) = image.split_once('@') {
        if prefix.contains(':') && prefix.contains('/') {
            return format!("[redacted-userinfo]@{suffix}");
        }
    }
    image.to_string()
}

fn leading_spaces(line: &str) -> usize {
    line.chars().take_while(|ch| *ch == ' ').count()
}

fn strip_yaml_comment(line: &str) -> &str {
    let mut single = false;
    let mut double = false;
    for (index, ch) in line.char_indices() {
        match ch {
            '\'' if !double => single = !single,
            '"' if !single => double = !double,
            '#' if !single && !double => return &line[..index],
            _ => {}
        }
    }
    line
}

fn split_yaml_assignment(line: &str) -> Option<(&str, &str)> {
    let (key, value) = line.split_once(':')?;
    let key = key.trim();
    if key.is_empty() {
        return None;
    }
    Some((key, value.trim()))
}

fn unquote(value: &str) -> &str {
    let value = value.trim();
    if value.len() >= 2 {
        let bytes = value.as_bytes();
        if (bytes[0] == b'"' && bytes[value.len() - 1] == b'"')
            || (bytes[0] == b'\'' && bytes[value.len() - 1] == b'\'')
        {
            return &value[1..value.len() - 1];
        }
    }
    value
}

fn yaml_truthy(value: &str) -> bool {
    matches!(unquote(value).to_ascii_lowercase().as_str(), "true" | "yes" | "on")
}

#[cfg(test)]
mod tests {
    use super::{analyze_artifact, RuntimeArtifactKind};

    #[test]
    fn dockerfile_reports_mutable_image_and_missing_healthcheck() {
        let findings = analyze_artifact(RuntimeArtifactKind::Dockerfile, "FROM node:latest\nRUN echo ok\n");
        assert!(findings.iter().any(|item| item.rule_id == "runtime.mutable_container_image"));
        assert!(findings.iter().any(|item| item.rule_id == "runtime.healthcheck_not_declared"));
    }

    #[test]
    fn digest_pinned_image_with_healthcheck_is_not_flagged_for_those_rules() {
        let findings = analyze_artifact(
            RuntimeArtifactKind::Dockerfile,
            "FROM node@sha256:0123456789abcdef\nHEALTHCHECK CMD node health.js\n",
        );
        assert!(findings.iter().all(|item| item.rule_id != "runtime.mutable_container_image"));
        assert!(findings.iter().all(|item| item.rule_id != "runtime.healthcheck_not_declared"));
    }

    #[test]
    fn compose_reports_explicit_restart_and_healthcheck_disable() {
        let source = "services:\n  api:\n    image: example/api:1.2.3\n    restart: \"no\"\n    healthcheck:\n      disable: true\n";
        let findings = analyze_artifact(RuntimeArtifactKind::DockerCompose, source);
        assert!(findings.iter().any(|item| item.rule_id == "runtime.restart_disabled"));
        assert!(findings.iter().any(|item| item.rule_id == "runtime.healthcheck_disabled"));
        assert!(findings.iter().all(|item| item.rule_id != "runtime.healthcheck_not_declared"));
    }

    #[test]
    fn compose_does_not_treat_hash_inside_quotes_as_comment() {
        let source = "services:\n  api:\n    image: \"registry.example/api:latest#candidate\"\n";
        let findings = analyze_artifact(RuntimeArtifactKind::DockerCompose, source);
        assert!(findings.iter().any(|item| item.rule_id == "runtime.healthcheck_not_declared"));
    }
}
