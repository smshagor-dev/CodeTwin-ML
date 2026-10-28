//! Truthful outcome classification and reproducible run reports.
use serde::Serialize;
use serde_json::Value;

use crate::state::{EvidenceClass, Outcome, RunState, TaskState};
use crate::store::{
    ApprovalRequest, AttemptRecord, RunRecord, Store, StoreResult, TaskRecord, ToolInvocationRecord,
};

/// Decide the terminal run state and outcome from the current plan's tasks.
///
/// * any failed task → `failed`
/// * any blocked / still-awaiting-approval task → `blocked`
/// * otherwise completed; `verified` only when every evidence-class task cites
///   evidence and at least one deterministic verifier produced a
///   `validated_result`. Hypotheses and recommendations (all model text) never
///   make a run verified. Cancelled tasks make it `unverified`.
pub fn classify_outcome(tasks: &[TaskRecord]) -> (RunState, Outcome) {
    let current: Vec<&TaskRecord> = tasks.iter().filter(|t| !t.is_superseded()).collect();
    if current.iter().any(|t| t.state == TaskState::Failed) {
        return (RunState::Failed, Outcome::Failed);
    }
    if current
        .iter()
        .any(|t| matches!(t.state, TaskState::Blocked | TaskState::AwaitingApproval))
    {
        return (RunState::Blocked, Outcome::Blocked);
    }
    if current.iter().any(|t| t.state == TaskState::Cancelled) {
        return (RunState::Completed, Outcome::Unverified);
    }
    let evidence_backed = current.iter().all(|t| match t.evidence_class {
        Some(class) if class.is_evidence() => t
            .output
            .as_ref()
            .and_then(|o| o.get("evidence_refs"))
            .and_then(Value::as_array)
            .is_some_and(|refs| !refs.is_empty()),
        _ => true,
    });
    let validated = current
        .iter()
        .any(|t| t.evidence_class == Some(EvidenceClass::ValidatedResult));
    if evidence_backed && validated {
        (RunState::Completed, Outcome::Verified)
    } else {
        (RunState::Completed, Outcome::Unverified)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct RunReport {
    pub schema: &'static str,
    pub run: RunRecord,
    pub tasks: Vec<TaskRecord>,
    pub attempts: Vec<AttemptRecord>,
    pub approvals: Vec<ApprovalRequest>,
    pub tool_invocations: Vec<ToolInvocationRecord>,
    pub limitations: Vec<String>,
}

pub fn build_report(store: &Store<'_>, run_id: &str) -> StoreResult<RunReport> {
    let run = store.get_run(run_id)?;
    let tasks = store.list_tasks(run_id)?;
    let mut limitations = vec![
        "Model-generated text is classified as hypothesis or recommendation and is not evidence."
            .to_owned(),
        "Worker time limits are cooperative; an analyzer call is not forcibly terminated mid-call."
            .to_owned(),
    ];
    if run.outcome != Some(Outcome::Verified) {
        limitations.push(
            "Outcome is not `verified`: no deterministic verifier confirmed every evidence-bearing result.".to_owned(),
        );
    }
    Ok(RunReport {
        schema: "codetwin.workflow-report.v1",
        attempts: store.list_attempts(run_id)?,
        approvals: store.list_approvals(Some(run_id), false)?,
        tool_invocations: store.tool_invocations(run_id)?,
        run,
        tasks,
        limitations,
    })
}

fn section(out: &mut String, title: &str, tasks: &[&TaskRecord]) {
    out.push_str(&format!("\n## {title}\n\n"));
    if tasks.is_empty() {
        out.push_str("_None._\n");
        return;
    }
    for task in tasks {
        out.push_str(&format!(
            "- **{}** (`{}`, {}): {}\n",
            md_escape(&task.title),
            task.role,
            task.state,
            md_escape(task.summary.as_deref().unwrap_or("no summary"))
        ));
        if let Some(refs) = task
            .output
            .as_ref()
            .and_then(|o| o.get("evidence_refs"))
            .and_then(Value::as_array)
        {
            for r in refs.iter().take(20) {
                out.push_str(&format!(
                    "  - evidence `{}` `{}`{}\n",
                    md_escape(r.get("kind").and_then(Value::as_str).unwrap_or("?")),
                    md_escape(r.get("id").and_then(Value::as_str).unwrap_or("?")),
                    r.get("sha256")
                        .and_then(Value::as_str)
                        .map(|h| format!(" sha256 `{}`", &h[..h.len().min(16)]))
                        .unwrap_or_default()
                ));
            }
            if refs.len() > 20 {
                out.push_str(&format!(
                    "  - … {} more evidence references omitted\n",
                    refs.len() - 20
                ));
            }
        }
        if let Some(digest) = &task.output_sha256 {
            out.push_str(&format!("  - output sha256 `{digest}`\n"));
        }
    }
}

/// Neutralise Markdown/HTML control characters in untrusted text.
pub fn md_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '`' | '*' | '_' | '[' | ']' | '|' | '#' => {
                out.push('\\');
                out.push(ch);
            }
            '\n' | '\r' => out.push(' '),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

pub fn render_markdown(report: &RunReport) -> String {
    let run = &report.run;
    let mut out = format!(
        "# CodeTwin workflow report\n\n- Run: `{}`\n- Project: `{}`\n- Goal: {}\n- State: **{}**\n- Outcome: **{}**\n- Reason: `{}`\n- Plan revision: {} (approved: {})\n- Replans: {} / {}\n- Provider credits used: {} / {}\n- Cloud mode: {}\n",
        run.id,
        run.project_id,
        md_escape(&run.goal),
        run.state,
        run.outcome.map_or("pending", |o| o.as_str()),
        run.reason_code.as_deref().unwrap_or("-"),
        run.plan_revision,
        run.approved_revision.map_or("no".to_owned(), |r| r.to_string()),
        run.replan_count,
        run.budgets.max_replans,
        run.credits_used,
        run.budgets.max_credits,
        if run.cloud_consented { "cloud disclosure consented" } else { "offline only" },
    );
    let current: Vec<&TaskRecord> = report.tasks.iter().filter(|t| !t.is_superseded()).collect();
    let by = |class: EvidenceClass| -> Vec<&TaskRecord> {
        current
            .iter()
            .copied()
            .filter(|t| t.evidence_class == Some(class))
            .collect()
    };
    section(
        &mut out,
        "Observations (tool-derived)",
        &by(EvidenceClass::Observation),
    );
    section(
        &mut out,
        "Validated results (deterministic verification)",
        &by(EvidenceClass::ValidatedResult),
    );
    section(
        &mut out,
        "Applied changes",
        &by(EvidenceClass::AppliedChange),
    );
    section(
        &mut out,
        "Hypotheses (unverified)",
        &by(EvidenceClass::Hypothesis),
    );
    section(
        &mut out,
        "Recommendations (not evidence)",
        &by(EvidenceClass::Recommendation),
    );
    let unresolved: Vec<&TaskRecord> = current
        .iter()
        .copied()
        .filter(|t| t.state != TaskState::Completed)
        .collect();
    out.push_str("\n## Unresolved tasks\n\n");
    if unresolved.is_empty() {
        out.push_str("_None._\n");
    }
    for task in unresolved {
        out.push_str(&format!(
            "- **{}** (`{}`): {} — `{}`\n",
            md_escape(&task.title),
            task.role,
            task.state,
            task.reason_code.as_deref().unwrap_or("-")
        ));
    }
    out.push_str("\n## Approvals\n\n");
    for a in &report.approvals {
        out.push_str(&format!(
            "- `{}` {} r{} — {} by {} (scope `{}`)\n",
            a.id,
            a.kind,
            a.plan_revision,
            a.status,
            md_escape(a.decided_by.as_deref().unwrap_or("-")),
            &a.scope_digest[..16]
        ));
    }
    out.push_str("\n## Tool invocations\n\n");
    if report.tool_invocations.is_empty() {
        out.push_str("_None._\n");
    }
    for t in &report.tool_invocations {
        out.push_str(&format!(
            "- `{}` ({}, {}): {} — {}\n",
            t.tool_id, t.capability, t.side_effect, t.status, t.decision_reason
        ));
    }
    out.push_str("\n## Attempts\n\n");
    for a in &report.attempts {
        out.push_str(&format!(
            "- task `{}` attempt {}: {}{}\n",
            a.task_id,
            a.attempt_no,
            a.status,
            a.error_category
                .as_deref()
                .map(|c| format!(
                    " ({c}: {})",
                    md_escape(a.error_detail.as_deref().unwrap_or(""))
                ))
                .unwrap_or_default()
        ));
    }
    out.push_str("\n## Limitations\n\n");
    for l in &report.limitations {
        out.push_str(&format!("- {l}\n"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::SideEffect;
    use serde_json::json;

    fn task(state: TaskState, class: Option<EvidenceClass>, refs: usize) -> TaskRecord {
        TaskRecord {
            id: "t".into(),
            run_id: "r".into(),
            plan_revision: 1,
            key: "k".into(),
            parent_task_id: None,
            delegation_depth: 0,
            role: "x".into(),
            title: "t".into(),
            input: json!({}),
            success_criteria: vec![],
            side_effect: SideEffect::ReadOnly,
            capabilities: Default::default(),
            scope_digest: "0".repeat(64),
            resource_key: None,
            priority: 0,
            state,
            reason_code: None,
            attempt_count: 1,
            max_attempts: 1,
            timeout_ms: 1000,
            not_before_ms: None,
            output: Some(json!({"evidence_refs": vec![json!({"kind":"f","id":"1"}); refs]})),
            output_sha256: None,
            summary: None,
            evidence_class: class,
            depends_on: vec![],
            created_ms: 0,
            updated_ms: 0,
            started_ms: None,
            finished_ms: None,
        }
    }

    #[test]
    fn model_text_never_verifies_a_run() {
        let tasks = vec![
            task(TaskState::Completed, Some(EvidenceClass::Observation), 2),
            task(TaskState::Completed, Some(EvidenceClass::Recommendation), 0),
        ];
        assert_eq!(classify_outcome(&tasks).1, Outcome::Unverified);
    }

    #[test]
    fn verified_requires_backed_evidence_and_a_verifier() {
        let tasks = vec![
            task(TaskState::Completed, Some(EvidenceClass::Observation), 1),
            task(
                TaskState::Completed,
                Some(EvidenceClass::ValidatedResult),
                1,
            ),
        ];
        assert_eq!(
            classify_outcome(&tasks),
            (RunState::Completed, Outcome::Verified)
        );
        let unbacked = vec![
            task(TaskState::Completed, Some(EvidenceClass::Observation), 0),
            task(
                TaskState::Completed,
                Some(EvidenceClass::ValidatedResult),
                1,
            ),
        ];
        assert_eq!(classify_outcome(&unbacked).1, Outcome::Unverified);
    }

    #[test]
    fn failures_and_blocks_dominate() {
        let tasks = vec![
            task(
                TaskState::Completed,
                Some(EvidenceClass::ValidatedResult),
                1,
            ),
            task(TaskState::Blocked, None, 0),
        ];
        assert_eq!(
            classify_outcome(&tasks),
            (RunState::Blocked, Outcome::Blocked)
        );
        let tasks = vec![
            task(TaskState::Failed, None, 0),
            task(TaskState::Blocked, None, 0),
        ];
        assert_eq!(
            classify_outcome(&tasks),
            (RunState::Failed, Outcome::Failed)
        );
    }

    #[test]
    fn markdown_escapes_untrusted_text() {
        assert_eq!(
            md_escape("<script>`x`\n[a](b)"),
            "&lt;script&gt;\\`x\\` \\[a\\](b)"
        );
    }
}
