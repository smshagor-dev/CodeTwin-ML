//! Specialist workers for the workflow orchestrator. Each role has its own
//! contract (capability ceiling, input schema, permitted evidence class) and
//! reaches CodeTwin services only through the policy-checked tool gate.
use std::collections::BTreeSet;
use std::sync::Arc;

use serde_json::{json, Value};
use task_orchestrator::policy::Capability;
use task_orchestrator::state::{ErrorCategory, EvidenceClass};
use task_orchestrator::store::TaskSpec;
use task_orchestrator::worker::{
    DelegationRequest, EvidenceRef, SuccessCriterion, TaskContext, ToolCallError, Worker,
    WorkerContract, WorkerError, WorkerOutput, WorkerRegistry,
};

fn call(ctx: &TaskContext<'_>, tool: &str, args: Value) -> Result<Value, WorkerError> {
    ctx.checkpoint()?;
    ctx.tools.call(tool, &args).map_err(|e| match e {
        ToolCallError::Denied(why) => {
            WorkerError::new(ErrorCategory::Policy, format!("{tool}: {why}"))
        }
        ToolCallError::Cancelled => WorkerError::new(ErrorCategory::Cancelled, "cancelled"),
        ToolCallError::AlreadyApplied(d) => {
            WorkerError::permanent(format!("{tool} already applied ({d})"))
        }
        ToolCallError::Failed(why) if why.contains("network") || why.contains("timeout") => {
            WorkerError::transient(format!("{tool}: {why}"))
        }
        ToolCallError::Failed(why) => WorkerError::permanent(format!("{tool}: {why}")),
    })
}

fn project_ref(ctx: &TaskContext<'_>) -> EvidenceRef {
    EvidenceRef {
        kind: "project".into(),
        id: ctx.project_id.into(),
        sha256: None,
    }
}

fn str_of(v: &Value, key: &str) -> Option<String> {
    v.get(key).and_then(Value::as_str).map(str::to_owned)
}

fn upstream_refs(ctx: &TaskContext<'_>) -> Vec<Value> {
    ctx.upstream
        .iter()
        .flat_map(|(_, _, out)| {
            out.get("evidence_refs")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default()
        })
        .collect()
}

type Run = fn(&TaskContext<'_>) -> Result<WorkerOutput, WorkerError>;

/// A specialist defined by a contract and a plain function.
pub struct Specialist {
    contract: WorkerContract,
    run: Run,
}

impl Worker for Specialist {
    fn contract(&self) -> &WorkerContract {
        &self.contract
    }
    fn execute(&self, ctx: &TaskContext<'_>) -> Result<WorkerOutput, WorkerError> {
        (self.run)(ctx)
    }
}

fn contract(
    role: &str,
    name: &str,
    description: &str,
    caps: &[Capability],
    input: Value,
    class: EvidenceClass,
) -> WorkerContract {
    WorkerContract {
        role: role.into(),
        display_name: name.into(),
        description: description.into(),
        capabilities: caps.iter().copied().collect(),
        input_schema: json!({"type": "object", "additionalProperties": false, "properties": input}),
        output_class: class,
        default_timeout_ms: 120_000,
    }
}

fn repository_analyst(ctx: &TaskContext<'_>) -> Result<WorkerOutput, WorkerError> {
    let overview = call(ctx, "project.overview", json!({}))?;
    let git = call(ctx, "git.status", json!({}))?;
    let summary = format!(
        "{} files, {} symbols across {} languages; git: {}",
        overview["file_count"],
        overview["symbol_count"],
        overview["language_count"],
        if git["git"] == json!(true) {
            format!(
                "branch {} with {} changed file(s)",
                git["branch"].as_str().unwrap_or("?"),
                git["changed_files"]
            )
        } else {
            "not a Git repository".into()
        }
    );
    Ok(WorkerOutput::observation(
        summary,
        json!({"project": overview, "git": git}),
        vec![project_ref(ctx)],
    ))
}

fn source_intelligence(ctx: &TaskContext<'_>) -> Result<WorkerOutput, WorkerError> {
    let terms: Vec<String> = ctx
        .input
        .get("terms")
        .and_then(Value::as_array)
        .map(|t| {
            t.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let mut symbols = Vec::new();
    let mut refs = vec![project_ref(ctx)];
    for term in terms.iter().take(6) {
        let found = call(
            ctx,
            "code.search_symbols",
            json!({"query": term, "limit": 10}),
        )?;
        for s in found["symbols"].as_array().cloned().unwrap_or_default() {
            if let Some(id) = str_of(&s, "id") {
                refs.push(EvidenceRef {
                    kind: "symbol".into(),
                    id,
                    sha256: str_of(&s, "file_sha256"),
                });
            }
            symbols.push(s);
        }
    }
    let summary = format!(
        "{} symbol(s) matched {} goal term(s)",
        symbols.len(),
        terms.len()
    );
    Ok(WorkerOutput::observation(
        summary,
        json!({"terms": terms, "symbols": symbols}),
        refs,
    ))
}

fn dependency_analyst(ctx: &TaskContext<'_>) -> Result<WorkerOutput, WorkerError> {
    let inventory = call(ctx, "deps.inventory", json!({"limit": 500}))?;
    let sbom = call(ctx, "sbom.summary", json!({}))?;
    let mut refs = vec![project_ref(ctx)];
    refs.extend(
        inventory["findings"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|f| {
                str_of(f, "id").map(|id| EvidenceRef {
                    kind: "dependency_finding".into(),
                    id,
                    sha256: None,
                })
            }),
    );
    let sbom_text = if sbom["available"] == json!(true) {
        format!(
            "SBOM {} components (sha256 {})",
            sbom["components"],
            sbom["sha256"]
                .as_str()
                .map_or("?", |s| &s[..12.min(s.len())])
        )
    } else {
        "no SBOM: dependency audit has not been run".to_owned()
    };
    let summary = format!(
        "{} dependencies, {} with open advisories; {sbom_text}",
        inventory["dependencies"], inventory["with_open_advisories"]
    );
    Ok(WorkerOutput::observation(
        summary,
        json!({"inventory": inventory, "sbom": sbom}),
        refs,
    ))
}

fn security_reviewer(ctx: &TaskContext<'_>) -> Result<WorkerOutput, WorkerError> {
    let findings = call(ctx, "findings.security", json!({"limit": 100}))?;
    let mut refs = vec![project_ref(ctx)];
    for f in findings["security"].as_array().into_iter().flatten() {
        if let Some(id) = str_of(f, "id") {
            refs.push(EvidenceRef {
                kind: "security_finding".into(),
                id,
                sha256: None,
            });
        }
    }
    for f in findings["secrets"].as_array().into_iter().flatten() {
        if let Some(id) = str_of(f, "id") {
            refs.push(EvidenceRef {
                kind: "secret_finding".into(),
                id,
                sha256: None,
            });
        }
    }
    let summary = format!(
        "{} open AppSec finding(s) and {} open secret finding(s) from persisted passive analysis",
        findings["security"].as_array().map_or(0, Vec::len),
        findings["secrets"].as_array().map_or(0, Vec::len)
    );
    Ok(WorkerOutput::observation(summary, findings, refs))
}

fn qa_planner(ctx: &TaskContext<'_>) -> Result<WorkerOutput, WorkerError> {
    let tests = call(ctx, "tests.discovered", json!({"limit": 100}))?;
    let mut refs = vec![project_ref(ctx)];
    refs.extend(
        tests["artifacts"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|a| {
                str_of(a, "id").map(|id| EvidenceRef {
                    kind: "qa_artifact".into(),
                    id,
                    sha256: str_of(a, "sha256"),
                })
            }),
    );
    let summary = format!(
        "{} test framework(s), {} test artifact(s) discovered; execution requires the separate QA approval flow",
        tests["frameworks"].as_array().map_or(0, Vec::len),
        tests["artifacts"].as_array().map_or(0, Vec::len)
    );
    Ok(WorkerOutput::observation(summary, tests, refs))
}

fn research_analyst(ctx: &TaskContext<'_>) -> Result<WorkerOutput, WorkerError> {
    let urls: Vec<String> = ctx
        .input
        .get("urls")
        .and_then(Value::as_array)
        .map(|u| {
            u.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let mut sources = Vec::new();
    let mut errors = Vec::new();
    let mut refs = Vec::new();
    let mut seen = BTreeSet::new();
    for url in urls.iter().take(5) {
        match call(ctx, "research.fetch", json!({"url": url})) {
            Ok(doc) => {
                let sha = str_of(&doc, "sha256");
                if sha.as_ref().is_some_and(|s| !seen.insert(s.clone())) {
                    continue; // duplicate content
                }
                if let Some(id) = str_of(&doc, "source_id") {
                    refs.push(EvidenceRef {
                        kind: "research_source".into(),
                        id,
                        sha256: sha,
                    });
                }
                sources.push(doc);
            }
            Err(e) if e.category == ErrorCategory::Policy => return Err(e),
            Err(e) => errors.push(json!({"url": url, "error": e.detail})),
        }
    }
    if sources.is_empty() {
        return Err(WorkerError::permanent(format!(
            "no source could be retrieved ({} error(s))",
            errors.len()
        )));
    }
    let flagged: u64 = sources
        .iter()
        .filter_map(|s| s["instruction_like_phrases"].as_u64())
        .sum();
    let summary = format!(
        "{} source(s) retrieved and hashed, {} retrieval error(s); {} instruction-like phrase(s) treated as untrusted text",
        sources.len(), errors.len(), flagged
    );
    Ok(WorkerOutput::observation(
        summary,
        json!({"sources": sources, "errors": errors}),
        refs,
    ))
}

fn cloud_reviewer(ctx: &TaskContext<'_>) -> Result<WorkerOutput, WorkerError> {
    // Only role/summary text from upstream tasks is sent; never source code.
    let material: String = ctx
        .upstream
        .iter()
        .map(|(key, role, out)| {
            format!(
                "[{key} / {role}] {}",
                out.get("data")
                    .map(|d| d.to_string())
                    .unwrap_or_default()
                    .chars()
                    .take(1_500)
                    .collect::<String>()
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
        .chars()
        .take(11_000)
        .collect();
    let review = call(ctx, "model.summarize", json!({"material": material}))?;
    let credits = review["credits"].as_u64().unwrap_or(0) as u32;
    Ok(WorkerOutput {
        summary: "Cloud model review (unverified hypotheses and recommendations)".into(),
        evidence_class: EvidenceClass::Hypothesis,
        data: json!({"review": review["content"], "model": review["model"], "request_id": review["request_id"],
            "payload_sha256": review["payload_sha256"], "redactions": review["redactions"]}),
        evidence_refs: vec![],
        credits_used: credits,
        delegations: vec![],
    })
}

fn evidence_verifier(ctx: &TaskContext<'_>) -> Result<WorkerOutput, WorkerError> {
    let refs: Vec<Value> = upstream_refs(ctx)
        .into_iter()
        .map(|r| {
            let mut v = json!({"kind": r["kind"], "id": r["id"]});
            if let Some(s) = r.get("sha256").and_then(Value::as_str) {
                v["sha256"] = json!(s);
            }
            v
        })
        .take(200)
        .collect();
    let report = call(ctx, "evidence.verify", json!({"refs": refs}))?;
    let verified = report["verified"].as_u64().unwrap_or(0);
    let problems =
        report["drifted"].as_u64().unwrap_or(0) + report["missing"].as_u64().unwrap_or(0);
    let evidence: Vec<EvidenceRef> = report["results"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|r| r["status"] == "verified")
        .filter_map(|r| {
            Some(EvidenceRef {
                kind: str_of(r, "kind")?,
                id: str_of(r, "id")?,
                sha256: None,
            })
        })
        .collect();
    if verified > 0 && problems == 0 {
        Ok(WorkerOutput {
            summary: format!("{verified} evidence reference(s) re-verified against persisted records; none drifted"),
            evidence_class: EvidenceClass::ValidatedResult,
            ..WorkerOutput::observation("", report, evidence)
        })
    } else {
        Ok(WorkerOutput {
            summary: format!(
                "Verification incomplete: {verified} verified, {problems} drifted or missing"
            ),
            evidence_class: EvidenceClass::Hypothesis,
            ..WorkerOutput::observation("", report, vec![])
        })
    }
}

fn report_composer(ctx: &TaskContext<'_>) -> Result<WorkerOutput, WorkerError> {
    let prior = call(
        ctx,
        "memory.retrieve",
        json!({"query": ctx.goal.chars().take(300).collect::<String>(), "limit": 5}),
    )?;
    let sections: Vec<Value> = ctx
        .upstream
        .iter()
        .map(|(key, role, out)| json!({"task": key, "role": role, "data_keys": out.get("data").and_then(Value::as_object).map(|o| o.keys().cloned().collect::<Vec<_>>())}))
        .collect();
    let note = format!(
        "Investigation of: {}",
        ctx.goal.chars().take(160).collect::<String>()
    );
    call(
        ctx,
        "memory.record",
        json!({"title": note, "body": format!("{} upstream sections composed", sections.len()), "source_ref": format!("workflow_runs:{}", ctx.run_id)}),
    )?;
    Ok(WorkerOutput {
        summary: format!(
            "Composed {} section(s); {} prior memory item(s) consulted, {} omitted by budget",
            sections.len(),
            prior["items"].as_array().map_or(0, Vec::len),
            prior["omitted"]
        ),
        evidence_class: EvidenceClass::Recommendation,
        data: json!({"sections": sections, "prior_context": prior["items"], "prior_omitted": prior["omitted"]}),
        evidence_refs: vec![],
        credits_used: 0,
        delegations: vec![],
    })
}

/// Flags unsupported conclusions. It can request a bounded, read-only
/// re-verification, but it cannot approve anything or verify itself.
fn quality_reviewer(ctx: &TaskContext<'_>) -> Result<WorkerOutput, WorkerError> {
    let verifier_ran = ctx
        .upstream
        .iter()
        .any(|(_, role, _)| role == "evidence_verifier");
    let unsupported: Vec<String> = ctx
        .upstream
        .iter()
        .filter(|(_, _, out)| {
            out.get("evidence_refs")
                .and_then(Value::as_array)
                .is_none_or(Vec::is_empty)
        })
        .map(|(key, role, _)| format!("{key} ({role})"))
        .collect();
    let mut out = WorkerOutput {
        summary: if unsupported.is_empty() {
            "All upstream sections cite evidence references".into()
        } else {
            format!(
                "{} upstream section(s) cite no evidence: {}",
                unsupported.len(),
                unsupported.join(", ")
            )
        },
        evidence_class: EvidenceClass::Recommendation,
        data: json!({"unsupported_sections": unsupported, "verifier_ran": verifier_ran}),
        evidence_refs: vec![],
        credits_used: 0,
        delegations: vec![],
    };
    if !verifier_ran && !ctx.upstream.is_empty() {
        out.delegations.push(DelegationRequest {
            role: "evidence_verifier".into(),
            title: "Re-verify evidence requested by quality review".into(),
            input: json!({}),
            capabilities: [Capability::ReadEvidence].into(),
            reason: "no deterministic verification found upstream".into(),
        });
    }
    Ok(out)
}

/// All registered specialists.
pub fn registry() -> WorkerRegistry {
    use Capability as C;
    let terms = json!({"terms": {"type": "array", "maxItems": 6, "items": {"type": "string", "maxLength": 80}}});
    let urls = json!({"urls": {"type": "array", "maxItems": 5, "items": {"type": "string", "maxLength": 2048}}});
    let specs: Vec<(WorkerContract, Run)> = vec![
        (
            contract(
                "repository_analyst",
                "Repository Analyst",
                "Project metadata and read-only Git state",
                &[C::ReadProject, C::ReadGit],
                json!({}),
                EvidenceClass::Observation,
            ),
            repository_analyst,
        ),
        (
            contract(
                "source_intelligence",
                "Source Intelligence",
                "Symbol search over the indexed digital twin",
                &[C::SearchCode],
                terms,
                EvidenceClass::Observation,
            ),
            source_intelligence,
        ),
        (
            contract(
                "dependency_analyst",
                "Dependency/SBOM Analyst",
                "Dependency inventory, OSV findings and CycloneDX summary",
                &[C::ReadDependencies],
                json!({}),
                EvidenceClass::Observation,
            ),
            dependency_analyst,
        ),
        (
            contract(
                "security_reviewer",
                "Security Reviewer",
                "Persisted passive AppSec and secret findings",
                &[C::ReadFindings],
                json!({}),
                EvidenceClass::Observation,
            ),
            security_reviewer,
        ),
        (
            contract(
                "qa_planner",
                "QA/Test Planner",
                "Discovered test frameworks and files",
                &[C::ReadTests],
                json!({}),
                EvidenceClass::Observation,
            ),
            qa_planner,
        ),
        (
            contract(
                "research_analyst",
                "Documentation/Research",
                "Consented retrieval of operator-listed public sources",
                &[C::WebResearch],
                urls,
                EvidenceClass::Observation,
            ),
            research_analyst,
        ),
        (
            contract(
                "cloud_reviewer",
                "Cloud Reviewer",
                "Consented OpenMindAI review of redacted summaries",
                &[C::CloudInference],
                json!({}),
                EvidenceClass::Hypothesis,
            ),
            cloud_reviewer,
        ),
        (
            contract(
                "evidence_verifier",
                "Evidence Verifier",
                "Deterministic re-check of evidence against persisted hashes",
                &[C::ReadEvidence],
                json!({}),
                EvidenceClass::ValidatedResult,
            ),
            evidence_verifier,
        ),
        (
            contract(
                "report_composer",
                "Report Composer",
                "Composes the run summary with bounded prior context",
                &[C::ReadMemory, C::RecordMemory],
                json!({}),
                EvidenceClass::Recommendation,
            ),
            report_composer,
        ),
        (
            contract(
                "quality_reviewer",
                "Quality Reviewer",
                "Flags unsupported conclusions; may request bounded re-verification",
                &[C::ReadEvidence],
                json!({}),
                EvidenceClass::Recommendation,
            ),
            quality_reviewer,
        ),
    ];
    let mut registry = WorkerRegistry::new();
    for (contract, run) in specs {
        registry.register(Arc::new(Specialist { contract, run }));
    }
    registry
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct InvestigationOptions {
    #[serde(default)]
    pub research_urls: Vec<String>,
    #[serde(default)]
    pub cloud_review: bool,
}

const STOPWORDS: &[&str] = &[
    "the",
    "and",
    "for",
    "with",
    "that",
    "this",
    "from",
    "into",
    "what",
    "which",
    "where",
    "when",
    "does",
    "have",
    "about",
    "check",
    "review",
    "find",
    "show",
    "please",
    "project",
    "code",
    "investigate",
    "should",
    "there",
];

/// Extract up to six search terms from a free-text goal.
pub fn goal_terms(goal: &str) -> Vec<String> {
    let mut seen = BTreeSet::new();
    goal.split(|c: char| !c.is_alphanumeric() && c != '_')
        .map(str::to_lowercase)
        .filter(|w| w.chars().count() >= 4 && !STOPWORDS.contains(&w.as_str()))
        .filter(|w| seen.insert(w.clone()))
        .take(6)
        .collect()
}

/// Deterministic plan for the read-only engineering investigation workflow.
pub fn plan_investigation(goal: &str, options: &InvestigationOptions) -> Vec<TaskSpec> {
    use Capability as C;
    let task = |key: &str,
                role: &str,
                title: &str,
                caps: &[C],
                deps: &[&str],
                input: Value,
                criteria: Vec<SuccessCriterion>| TaskSpec {
        key: key.into(),
        role: role.into(),
        title: title.into(),
        input,
        success_criteria: criteria,
        capabilities: caps.iter().copied().collect(),
        resource_key: None,
        priority: 0,
        timeout_ms: None,
        depends_on: deps.iter().map(|d| (*d).to_owned()).collect(),
    };
    let tool = |n| SuccessCriterion::ToolCallsAtLeast { min: n };
    let refs = |n| SuccessCriterion::EvidenceRefsAtLeast { min: n };
    let mut plan = vec![
        task(
            "repo",
            "repository_analyst",
            "Map repository and Git state",
            &[C::ReadProject, C::ReadGit],
            &[],
            json!({}),
            vec![
                tool(2),
                SuccessCriterion::OutputFieldPresent {
                    field: "project".into(),
                },
            ],
        ),
        task(
            "source",
            "source_intelligence",
            "Locate code related to the goal",
            &[C::SearchCode],
            &["repo"],
            json!({"terms": goal_terms(goal)}),
            vec![refs(1)],
        ),
        task(
            "deps",
            "dependency_analyst",
            "Review dependencies and SBOM",
            &[C::ReadDependencies],
            &["repo"],
            json!({}),
            vec![tool(2)],
        ),
        task(
            "security",
            "security_reviewer",
            "Review persisted security findings",
            &[C::ReadFindings],
            &["repo"],
            json!({}),
            vec![tool(1)],
        ),
        task(
            "qa",
            "qa_planner",
            "Inventory tests for targeted verification",
            &[C::ReadTests],
            &["repo"],
            json!({}),
            vec![tool(1)],
        ),
    ];
    let mut evidence = vec!["source", "deps", "security", "qa"];
    if !options.research_urls.is_empty() {
        let urls: Vec<String> = options.research_urls.iter().take(5).cloned().collect();
        plan.push(task(
            "research",
            "research_analyst",
            "Retrieve operator-listed sources",
            &[C::WebResearch],
            &["repo"],
            json!({"urls": urls}),
            vec![refs(1)],
        ));
        evidence.push("research");
    }
    plan.push(task(
        "verify",
        "evidence_verifier",
        "Re-verify cited evidence",
        &[C::ReadEvidence],
        &evidence,
        json!({}),
        vec![tool(1)],
    ));
    let mut report_deps = vec!["verify"];
    if options.cloud_review {
        plan.push(task(
            "cloud",
            "cloud_reviewer",
            "Cloud review of redacted summaries",
            &[C::CloudInference],
            &["verify"],
            json!({}),
            vec![tool(1)],
        ));
        report_deps.push("cloud");
    }
    plan.push(task(
        "report",
        "report_composer",
        "Compose cited report",
        &[C::ReadMemory, C::RecordMemory],
        &report_deps,
        json!({}),
        vec![],
    ));
    plan.push(task(
        "quality",
        "quality_reviewer",
        "Quality review of conclusions",
        &[C::ReadEvidence],
        &["report", "verify"],
        json!({}),
        vec![],
    ));
    plan
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn plan_is_a_valid_dag_within_role_contracts() {
        let contracts: BTreeMap<String, WorkerContract> = registry()
            .contracts()
            .into_iter()
            .map(|c| (c.role.clone(), c))
            .collect();
        let plan = plan_investigation(
            "Check authentication token handling",
            &InvestigationOptions {
                research_urls: vec!["https://example.org/".into()],
                cloud_review: true,
            },
        );
        let keys: Vec<String> = plan.iter().map(|t| t.key.clone()).collect();
        let edges: Vec<(String, String)> = plan
            .iter()
            .flat_map(|t| t.depends_on.iter().map(|d| (t.key.clone(), d.clone())))
            .collect();
        task_orchestrator::dag::topological_order(&keys, &edges, &BTreeSet::new()).unwrap();
        for t in &plan {
            let c = &contracts[&t.role];
            assert!(t.capabilities.is_subset(&c.capabilities), "{}", t.role);
            task_orchestrator::policy::validate_schema(&c.input_schema, &t.input).unwrap();
        }
        assert_eq!(
            goal_terms("Check authentication token handling"),
            vec!["authentication", "token", "handling"]
        );
    }
}
