//! Read-only run analysis: side-by-side comparison of two runs and
//! detection of runs that can no longer make progress.
//!
//! Both are pure functions over persisted records, so they work on any
//! historical run and never change state.
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::state::{RunState, TaskState};
use crate::store::{RunRecord, TaskRecord};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TaskDiff {
    pub key: String,
    pub role: String,
    pub left_state: Option<TaskState>,
    pub right_state: Option<TaskState>,
    /// Both ran and their recorded outputs differ by hash.
    pub output_changed: bool,
    pub left_attempts: u32,
    pub right_attempts: u32,
    pub duration_delta_ms: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RunComparison {
    pub left_run: String,
    pub right_run: String,
    pub same_goal: bool,
    pub left_outcome: Option<String>,
    pub right_outcome: Option<String>,
    pub duration_delta_ms: Option<i64>,
    pub credits_delta: i64,
    pub only_left: Vec<String>,
    pub only_right: Vec<String>,
    /// Tasks present in both whose state, output or attempts differ.
    pub changed: Vec<TaskDiff>,
    pub unchanged: usize,
}

fn duration(start: Option<i64>, end: Option<i64>) -> Option<i64> {
    Some(end? - start?)
}

fn current(tasks: &[TaskRecord]) -> BTreeMap<&str, &TaskRecord> {
    tasks
        .iter()
        .filter(|t| !t.is_superseded())
        .map(|t| (t.key.as_str(), t))
        .collect()
}

/// Compare two runs task-by-task, matching tasks by their plan key.
pub fn compare_runs(
    left: &RunRecord,
    left_tasks: &[TaskRecord],
    right: &RunRecord,
    right_tasks: &[TaskRecord],
) -> RunComparison {
    let l = current(left_tasks);
    let r = current(right_tasks);
    let mut changed = Vec::new();
    let mut unchanged = 0;
    for (key, lt) in &l {
        let Some(rt) = r.get(key) else { continue };
        let output_changed = lt.output_sha256.is_some()
            && rt.output_sha256.is_some()
            && lt.output_sha256 != rt.output_sha256;
        if lt.state != rt.state || output_changed || lt.attempt_count != rt.attempt_count {
            changed.push(TaskDiff {
                key: (*key).to_owned(),
                role: rt.role.clone(),
                left_state: Some(lt.state),
                right_state: Some(rt.state),
                output_changed,
                left_attempts: lt.attempt_count,
                right_attempts: rt.attempt_count,
                duration_delta_ms: duration(rt.started_ms, rt.finished_ms)
                    .zip(duration(lt.started_ms, lt.finished_ms))
                    .map(|(b, a)| b - a),
            });
        } else {
            unchanged += 1;
        }
    }
    RunComparison {
        left_run: left.id.clone(),
        right_run: right.id.clone(),
        same_goal: left.goal.trim() == right.goal.trim(),
        left_outcome: left.outcome.map(|o| o.as_str().to_owned()),
        right_outcome: right.outcome.map(|o| o.as_str().to_owned()),
        duration_delta_ms: duration(right.started_ms, right.finished_ms)
            .zip(duration(left.started_ms, left.finished_ms))
            .map(|(b, a)| b - a),
        credits_delta: i64::from(right.credits_used) - i64::from(left.credits_used),
        only_left: l
            .keys()
            .filter(|k| !r.contains_key(*k))
            .map(|k| (*k).to_owned())
            .collect(),
        only_right: r
            .keys()
            .filter(|k| !l.contains_key(*k))
            .map(|k| (*k).to_owned())
            .collect(),
        changed,
        unchanged,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StallReport {
    pub run_id: String,
    /// Pending tasks that can never become ready.
    pub stuck: Vec<String>,
    /// The failed / cancelled / blocked tasks they ultimately wait on.
    pub root_causes: Vec<String>,
}

/// A non-terminal run is stalled when nothing is running, queued or
/// retrying, it is not waiting for a person (paused / awaiting approval),
/// and every pending task transitively depends on a dead task.
pub fn diagnose_stall(run: &RunRecord, tasks: &[TaskRecord]) -> Option<StallReport> {
    if run.state.is_terminal()
        || matches!(
            run.state,
            RunState::Paused | RunState::AwaitingApproval | RunState::Draft
        )
    {
        return None;
    }
    let live: Vec<&TaskRecord> = tasks.iter().filter(|t| !t.is_superseded()).collect();
    let by_key: BTreeMap<&str, &TaskRecord> = live.iter().map(|t| (t.key.as_str(), *t)).collect();
    let progressing = live.iter().any(|t| {
        matches!(
            t.state,
            TaskState::Running
                | TaskState::Validating
                | TaskState::RetryWait
                | TaskState::AwaitingApproval
        ) || (t.state == TaskState::Queued
            && t.depends_on.iter().all(|d| {
                by_key
                    .get(d.as_str())
                    .is_none_or(|x| x.state == TaskState::Completed)
            }))
    });
    if progressing {
        return None;
    }
    let dead = |t: &TaskRecord| {
        matches!(
            t.state,
            TaskState::Failed | TaskState::Cancelled | TaskState::Blocked
        )
    };
    let mut stuck = Vec::new();
    let mut roots = BTreeSet::new();
    for t in live
        .iter()
        .filter(|t| !t.state.is_terminal() && t.state != TaskState::Blocked)
    {
        // Walk dependencies (bounded by the DAG size) looking for dead roots.
        let mut stack: Vec<&str> = t.depends_on.iter().map(String::as_str).collect();
        let mut seen = BTreeSet::new();
        let mut found = false;
        while let Some(k) = stack.pop() {
            if !seen.insert(k) {
                continue;
            }
            if let Some(dep) = by_key.get(k) {
                if dead(dep) {
                    roots.insert(dep.key.clone());
                    found = true;
                } else {
                    stack.extend(dep.depends_on.iter().map(String::as_str));
                }
            }
        }
        if found {
            stuck.push(t.key.clone());
        }
    }
    (!stuck.is_empty()).then(|| StallReport {
        run_id: run.id.clone(),
        stuck,
        root_causes: roots.into_iter().collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{Outcome, SideEffect};
    use crate::store::RunBudgets;
    use serde_json::json;

    fn run(id: &str, state: RunState) -> RunRecord {
        RunRecord {
            id: id.into(),
            project_id: "p".into(),
            goal: "audit".into(),
            owner: "o".into(),
            state,
            outcome: None,
            reason_code: None,
            plan_revision: 1,
            approved_revision: Some(1),
            approved_capabilities: Default::default(),
            replan_count: 0,
            budgets: RunBudgets::default(),
            credits_used: 0,
            cancel_requested: false,
            pause_requested: false,
            cloud_consented: false,
            created_ms: 0,
            updated_ms: 0,
            started_ms: Some(0),
            finished_ms: None,
        }
    }

    fn task(key: &str, state: TaskState, deps: &[&str]) -> TaskRecord {
        TaskRecord {
            id: format!("t-{key}"),
            run_id: "r".into(),
            plan_revision: 1,
            key: key.into(),
            parent_task_id: None,
            delegation_depth: 0,
            role: "repository_analyst".into(),
            title: key.into(),
            input: json!({}),
            success_criteria: vec![],
            side_effect: SideEffect::ReadOnly,
            capabilities: Default::default(),
            scope_digest: String::new(),
            resource_key: None,
            priority: 0,
            state,
            reason_code: None,
            attempt_count: 1,
            max_attempts: 3,
            timeout_ms: 1000,
            not_before_ms: None,
            output: None,
            output_sha256: None,
            summary: None,
            evidence_class: None,
            depends_on: deps.iter().map(|d| (*d).to_owned()).collect(),
            created_ms: 0,
            updated_ms: 0,
            started_ms: Some(0),
            finished_ms: Some(100),
        }
    }

    #[test]
    fn compares_runs_by_task_key() {
        let mut left = run("a", RunState::Completed);
        left.outcome = Some(Outcome::Unverified);
        left.finished_ms = Some(1000);
        let mut right = run("b", RunState::Completed);
        right.outcome = Some(Outcome::Verified);
        right.finished_ms = Some(700);
        right.credits_used = 3;
        let mut map_l = task("map", TaskState::Completed, &[]);
        map_l.output_sha256 = Some("x".into());
        let mut map_r = map_l.clone();
        map_r.output_sha256 = Some("y".into());
        map_r.finished_ms = Some(250);
        let review_l = task("review", TaskState::Failed, &["map"]);
        let mut review_r = task("review", TaskState::Completed, &["map"]);
        review_r.attempt_count = 2;
        let c = compare_runs(
            &left,
            &[map_l, review_l, task("old", TaskState::Completed, &[])],
            &right,
            &[map_r, review_r, task("new", TaskState::Completed, &[])],
        );
        assert!(c.same_goal);
        assert_eq!(c.right_outcome.as_deref(), Some("verified"));
        assert_eq!(c.duration_delta_ms, Some(-300));
        assert_eq!(c.credits_delta, 3);
        assert_eq!(c.only_left, vec!["old"]);
        assert_eq!(c.only_right, vec!["new"]);
        assert_eq!(c.changed.len(), 2);
        let map = c.changed.iter().find(|d| d.key == "map").unwrap();
        assert!(map.output_changed);
        assert_eq!(map.duration_delta_ms, Some(150));
        let review = c.changed.iter().find(|d| d.key == "review").unwrap();
        assert_eq!(review.left_state, Some(TaskState::Failed));
        assert_eq!(review.right_attempts, 2);
        assert_eq!(c.unchanged, 0);
    }

    #[test]
    fn detects_runs_that_cannot_progress() {
        let r = run("r", RunState::Running);
        // a failed → b waits on a → c waits on b: both stuck, root cause a.
        let tasks = vec![
            task("a", TaskState::Failed, &[]),
            task("b", TaskState::Queued, &["a"]),
            task("c", TaskState::Planned, &["b"]),
            task("ok", TaskState::Completed, &[]),
        ];
        let report = diagnose_stall(&r, &tasks).unwrap();
        assert_eq!(report.stuck, vec!["b", "c"]);
        assert_eq!(report.root_causes, vec!["a"]);

        // Anything still able to run means the run is not stalled.
        let mut moving = tasks.clone();
        moving.push(task("d", TaskState::Queued, &["ok"]));
        assert!(diagnose_stall(&r, &moving).is_none());
        let mut retrying = tasks.clone();
        retrying.push(task("e", TaskState::RetryWait, &[]));
        assert!(diagnose_stall(&r, &retrying).is_none());
        // Waiting for a person is not a stall.
        assert!(diagnose_stall(&run("r", RunState::Paused), &tasks).is_none());
        assert!(diagnose_stall(&run("r", RunState::Completed), &tasks).is_none());
    }
}
