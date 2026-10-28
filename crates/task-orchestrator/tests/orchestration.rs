//! End-to-end orchestration tests against a real SQLite schema.
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rusqlite::Connection;
use serde_json::{json, Value};
use task_orchestrator::policy::{Capability, PolicyContext, ToolAvailability, ToolDescriptor};
use task_orchestrator::state::{
    ErrorCategory, EvidenceClass, Outcome, RunState, SideEffect, TaskState,
};
use task_orchestrator::store::{
    OverrideResolution, RunBudgets, RunSpec, Store, StoreError, TaskSpec, ToolBegin,
};
use task_orchestrator::worker::{
    DelegationRequest, EvidenceRef, SuccessCriterion, TaskContext, ToolCallError, Worker,
    WorkerContract, WorkerError, WorkerOutput, WorkerRegistry,
};
use task_orchestrator::{GlobalLimits, Orchestrator, OrchestratorConfig, ToolRuntime, SCHEMA_SQL};

fn connection(path: &std::path::Path) -> Connection {
    let conn = Connection::open(path).unwrap();
    conn.pragma_update(None, "journal_mode", "WAL").unwrap();
    conn.pragma_update(None, "foreign_keys", "ON").unwrap();
    conn.busy_timeout(Duration::from_secs(5)).unwrap();
    conn
}

fn fresh_db() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wf.sqlite3");
    let conn = connection(&path);
    conn.execute_batch(
        "CREATE TABLE projects(id TEXT PRIMARY KEY); INSERT INTO projects VALUES ('p1');",
    )
    .unwrap();
    conn.execute_batch(SCHEMA_SQL).unwrap();
    (dir, path)
}

#[derive(Default)]
struct MockTools {
    calls: Mutex<Vec<String>>,
}

impl ToolRuntime for MockTools {
    fn descriptors(&self) -> Vec<ToolDescriptor> {
        let d = |id: &str, cap: Capability| ToolDescriptor {
            id: id.into(),
            description: id.into(),
            capability: cap,
            side_effect: cap.side_effect(),
            input_schema: json!({"type":"object","additionalProperties":false,
                "properties":{"q":{"type":"string","maxLength":64}}}),
            output_kind: "json".into(),
            timeout_ms: 1000,
            max_output_bytes: 10_000,
            network_destinations: vec![],
            filesystem_roots: vec!["project_root".into()],
            audit: "digest".into(),
            availability: ToolAvailability {
                available: true,
                reason: None,
            },
        };
        vec![
            d("read_thing", Capability::ReadProject),
            d("write_thing", Capability::LocalMutation),
        ]
    }
    fn invoke(
        &self,
        project: &str,
        tool: &str,
        args: &Value,
        _: &task_orchestrator::CancelToken,
    ) -> Result<Value, String> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("{project}:{tool}:{args}"));
        Ok(json!({"tool": tool, "project": project}))
    }
}

#[derive(Clone, Copy)]
enum Behavior {
    ReadAndObserve,
    Verify,
    Flaky,
    Slow,
    Inject,
    Mutate,
    Delegate,
    Hang,
}

struct TestWorker {
    contract: WorkerContract,
    behavior: Behavior,
    active: Arc<AtomicUsize>,
    peak: Arc<AtomicUsize>,
}

impl Worker for TestWorker {
    fn contract(&self) -> &WorkerContract {
        &self.contract
    }
    fn execute(&self, ctx: &TaskContext<'_>) -> Result<WorkerOutput, WorkerError> {
        let refs = vec![EvidenceRef {
            kind: "file".into(),
            id: "src/lib.rs".into(),
            sha256: Some("ab".repeat(32)),
        }];
        match self.behavior {
            Behavior::ReadAndObserve => {
                ctx.tools
                    .call("read_thing", &json!({"q": "x"}))
                    .map_err(|e| WorkerError::permanent(e.to_string()))?;
                Ok(WorkerOutput::observation(
                    "read",
                    json!({"items": [1, 2]}),
                    refs,
                ))
            }
            Behavior::Verify => {
                assert!(!ctx.upstream.is_empty(), "verifier sees upstream outputs");
                Ok(WorkerOutput {
                    evidence_class: EvidenceClass::ValidatedResult,
                    ..WorkerOutput::observation("verified", json!({"ok": true}), refs)
                })
            }
            Behavior::Flaky => {
                if ctx.attempt == 1 {
                    Err(WorkerError::transient("temporary"))
                } else {
                    Ok(WorkerOutput::observation("ok on retry", json!({}), refs))
                }
            }
            Behavior::Slow => {
                let now = self.active.fetch_add(1, Ordering::SeqCst) + 1;
                self.peak.fetch_max(now, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(120));
                self.active.fetch_sub(1, Ordering::SeqCst);
                Ok(WorkerOutput::observation("slow", json!({}), refs))
            }
            Behavior::Inject => {
                // Simulates a prompt-injected worker: tries an ungranted mutation
                // and claims a verified result its contract does not allow.
                let denied = ctx.tools.call("write_thing", &json!({"q": "pwn"}));
                assert!(matches!(denied, Err(ToolCallError::Denied(_))));
                let unknown = ctx.tools.call("shell", &json!({"cmd": "rm -rf /"}));
                assert!(matches!(unknown, Err(ToolCallError::Denied(_))));
                Ok(WorkerOutput {
                    evidence_class: EvidenceClass::ValidatedResult,
                    ..WorkerOutput::observation("trust me", json!({}), refs)
                })
            }
            Behavior::Mutate => {
                let out = ctx.tools.call("write_thing", &json!({"q": "patch"}));
                match out {
                    Ok(_) | Err(ToolCallError::AlreadyApplied(_)) => {}
                    Err(e) => return Err(WorkerError::new(ErrorCategory::Policy, e.to_string())),
                }
                Ok(WorkerOutput {
                    evidence_class: EvidenceClass::AppliedChange,
                    ..WorkerOutput::observation("applied", json!({}), refs)
                })
            }
            Behavior::Delegate => {
                let mut out = WorkerOutput::observation("delegating", json!({}), refs);
                out.delegations = vec![
                    DelegationRequest {
                        role: "reader".into(),
                        title: "follow-up read".into(),
                        input: json!({}),
                        capabilities: [Capability::ReadProject].into(),
                        reason: "need more context".into(),
                    },
                    DelegationRequest {
                        role: "mutator".into(),
                        title: "follow-up patch".into(),
                        input: json!({}),
                        capabilities: [Capability::LocalMutation].into(),
                        reason: "fix".into(),
                    },
                ];
                Ok(out)
            }
            Behavior::Hang => {
                while ctx.checkpoint().is_ok() {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(ctx.checkpoint().unwrap_err())
            }
        }
    }
}

struct Harness {
    _dir: tempfile::TempDir,
    path: std::path::PathBuf,
    tools: Arc<MockTools>,
    peak: Arc<AtomicUsize>,
}

fn contract(role: &str, caps: &[Capability], class: EvidenceClass) -> WorkerContract {
    WorkerContract {
        role: role.into(),
        display_name: role.into(),
        description: role.into(),
        capabilities: caps.iter().copied().collect(),
        input_schema: json!({"type":"object","additionalProperties":false,"properties":{"n":{"type":"integer"}}}),
        output_class: class,
        default_timeout_ms: 5_000,
    }
}

impl Harness {
    fn new() -> Self {
        let (dir, path) = fresh_db();
        Self {
            _dir: dir,
            path,
            tools: Arc::new(MockTools::default()),
            peak: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn orchestrator(&self, instance: &str, policy: PolicyContext) -> Orchestrator {
        let active = Arc::new(AtomicUsize::new(0));
        let mut registry = WorkerRegistry::new();
        let read = [Capability::ReadProject];
        for (role, caps, class, behavior) in [
            (
                "reader",
                &read[..],
                EvidenceClass::Observation,
                Behavior::ReadAndObserve,
            ),
            (
                "verifier",
                &read[..],
                EvidenceClass::ValidatedResult,
                Behavior::Verify,
            ),
            (
                "flaky",
                &read[..],
                EvidenceClass::Observation,
                Behavior::Flaky,
            ),
            (
                "slow",
                &read[..],
                EvidenceClass::Observation,
                Behavior::Slow,
            ),
            (
                "injected",
                &read[..],
                EvidenceClass::Observation,
                Behavior::Inject,
            ),
            (
                "mutator",
                &[Capability::LocalMutation][..],
                EvidenceClass::AppliedChange,
                Behavior::Mutate,
            ),
            (
                "delegator",
                &read[..],
                EvidenceClass::Observation,
                Behavior::Delegate,
            ),
            (
                "hang",
                &read[..],
                EvidenceClass::Observation,
                Behavior::Hang,
            ),
            (
                "cloud",
                &[Capability::CloudInference][..],
                EvidenceClass::Hypothesis,
                Behavior::ReadAndObserve,
            ),
        ] {
            registry.register(Arc::new(TestWorker {
                contract: contract(role, caps, class),
                behavior,
                active: active.clone(),
                peak: self.peak.clone(),
            }));
        }
        let config = OrchestratorConfig {
            instance_id: instance.into(),
            lease_ms: 2_000,
            retry_backoff_ms: 10,
            ..OrchestratorConfig::default()
        };
        Orchestrator::new(
            connection(&self.path),
            registry,
            self.tools.clone(),
            policy,
            config,
            Arc::new(GlobalLimits::new(8)),
        )
    }
}

fn spec(key: &str, role: &str, caps: &[Capability], deps: &[&str]) -> TaskSpec {
    TaskSpec {
        key: key.into(),
        role: role.into(),
        title: format!("task {key}"),
        input: json!({}),
        success_criteria: vec![],
        capabilities: caps.iter().copied().collect(),
        resource_key: None,
        priority: 0,
        timeout_ms: None,
        depends_on: deps.iter().map(|d| (*d).to_owned()).collect(),
    }
}

fn run_spec(budgets: RunBudgets) -> RunSpec {
    RunSpec {
        project_id: "p1".into(),
        goal: "Investigate the repository".into(),
        owner: "operator".into(),
        budgets,
        cloud_consented: false,
    }
}

const R: &[Capability] = &[Capability::ReadProject];

fn plan_and_approve(o: &Orchestrator, budgets: RunBudgets, tasks: &[TaskSpec]) -> String {
    let contracts = o.contracts();
    o.with_store(|s| {
        let run = s.create_run(&run_spec(budgets))?;
        let approvals = s.submit_plan(
            &run.id,
            tasks,
            &contracts,
            &PolicyContext::offline(),
            3_600_000,
        )?;
        let plan = approvals.iter().find(|a| a.kind == "plan").unwrap();
        s.decide_approval(&plan.id, true, "operator", &plan.scope_digest, None)?;
        Ok(run.id)
    })
    .unwrap()
}

#[test]
fn approved_investigation_runs_to_verified_with_report_and_replayable_events() {
    let h = Harness::new();
    let o = h.orchestrator("i1", PolicyContext::offline());
    let contracts = o.contracts();
    let mut a = spec("a", "reader", R, &[]);
    a.success_criteria = vec![
        SuccessCriterion::MinItems {
            field: "items".into(),
            min: 2,
        },
        SuccessCriterion::ToolCallsAtLeast { min: 1 },
    ];
    let tasks = vec![
        a,
        spec("b", "reader", R, &["a"]),
        spec("c", "reader", R, &["a"]),
        spec("v", "verifier", R, &["b", "c"]),
    ];
    let (run_id, approvals) = o
        .with_store(|s| {
            let run = s.create_run(&run_spec(RunBudgets::default()))?;
            let approvals = s.submit_plan(
                &run.id,
                &tasks,
                &contracts,
                &PolicyContext::offline(),
                3_600_000,
            )?;
            Ok((run.id, approvals))
        })
        .unwrap();
    assert_eq!(
        approvals.len(),
        1,
        "read-only plan needs only plan approval"
    );
    // Planning is not execution.
    assert!(o.run_until_settled(&run_id, None).is_err());
    let plan = &approvals[0];
    let stale =
        o.with_store(|s| s.decide_approval(&plan.id, true, "operator", &"0".repeat(64), None));
    assert!(
        matches!(stale, Err(StoreError::Stale(_))),
        "scope mismatch is rejected"
    );
    let bot = o.with_store(|s| {
        s.decide_approval(&plan.id, true, "model:planner", &plan.scope_digest, None)
    });
    assert!(
        matches!(bot, Err(StoreError::Rejected(_))),
        "automated principals cannot approve"
    );
    o.with_store(|s| s.decide_approval(&plan.id, true, "operator", &plan.scope_digest, Some("ok")))
        .unwrap();

    let run = o.run_until_settled(&run_id, None).unwrap();
    assert_eq!(run.state, RunState::Completed);
    assert_eq!(run.outcome, Some(Outcome::Verified));
    assert_eq!(h.tools.calls.lock().unwrap().len(), 3);

    let (md, js) = o
        .with_store(|s| {
            Ok((
                s.latest_report(&run_id, "markdown")?,
                s.latest_report(&run_id, "json")?,
            ))
        })
        .unwrap();
    let md = md.unwrap().1;
    assert!(md.contains("Outcome: **verified**"));
    assert!(md.contains("Validated results"));
    assert!(js.unwrap().1.contains("codetwin.workflow-report.v1"));

    let first = o.with_store(|s| s.events_since(&run_id, 0, 5)).unwrap();
    let rest = o
        .with_store(|s| s.events_since(&run_id, first.last().unwrap().seq, 1000))
        .unwrap();
    let all = o.with_store(|s| s.events_since(&run_id, 0, 1000)).unwrap();
    assert_eq!(
        first.len() + rest.len(),
        all.len(),
        "cursor replay is lossless"
    );
    assert!(all.windows(2).all(|w| w[0].seq < w[1].seq));
}

#[test]
fn independent_read_only_tasks_run_concurrently_within_budget() {
    let h = Harness::new();
    let o = h.orchestrator("i1", PolicyContext::offline());
    let tasks: Vec<TaskSpec> = (0..4)
        .map(|i| spec(&format!("s{i}"), "slow", R, &[]))
        .collect();
    let run_id = plan_and_approve(
        &o,
        RunBudgets {
            max_parallel: 2,
            ..RunBudgets::default()
        },
        &tasks,
    );
    let run = o.run_until_settled(&run_id, None).unwrap();
    assert_eq!(run.state, RunState::Completed);
    assert_eq!(run.outcome, Some(Outcome::Unverified), "no verifier ran");
    assert_eq!(h.peak.load(Ordering::SeqCst), 2);
}

#[test]
fn resource_keys_serialize_conflicting_work() {
    let h = Harness::new();
    let o = h.orchestrator("i1", PolicyContext::offline());
    let tasks: Vec<TaskSpec> = (0..3)
        .map(|i| TaskSpec {
            resource_key: Some("same-file".into()),
            ..spec(&format!("s{i}"), "slow", R, &[])
        })
        .collect();
    let run_id = plan_and_approve(
        &o,
        RunBudgets {
            max_parallel: 3,
            ..RunBudgets::default()
        },
        &tasks,
    );
    o.run_until_settled(&run_id, None).unwrap();
    assert_eq!(h.peak.load(Ordering::SeqCst), 1);
}

#[test]
fn transient_failures_retry_with_bounded_attempts() {
    let h = Harness::new();
    let o = h.orchestrator("i1", PolicyContext::offline());
    let run_id = plan_and_approve(&o, RunBudgets::default(), &[spec("f", "flaky", R, &[])]);
    let run = o.run_until_settled(&run_id, None).unwrap();
    assert_eq!(run.state, RunState::Completed);
    let attempts = o.with_store(|s| s.list_attempts(&run_id)).unwrap();
    assert_eq!(attempts.len(), 2);
    assert_eq!(attempts[0].error_category.as_deref(), Some("transient"));

    let h = Harness::new();
    let o = h.orchestrator("i1", PolicyContext::offline());
    let run_id = plan_and_approve(
        &o,
        RunBudgets {
            max_attempts_per_task: 1,
            ..RunBudgets::default()
        },
        &[
            spec("f", "flaky", R, &[]),
            spec("after", "reader", R, &["f"]),
        ],
    );
    let run = o.run_until_settled(&run_id, None).unwrap();
    assert_eq!(run.outcome, Some(Outcome::Failed));
    let tasks = o.with_store(|s| s.list_tasks(&run_id)).unwrap();
    let after = tasks.iter().find(|t| t.key == "after").unwrap();
    assert_eq!(after.state, TaskState::Blocked);
    assert_eq!(after.reason_code.as_deref(), Some("dependency_failed"));
}

#[test]
fn injected_worker_cannot_escalate_or_self_verify() {
    let h = Harness::new();
    let o = h.orchestrator("i1", PolicyContext::offline());
    let run_id = plan_and_approve(&o, RunBudgets::default(), &[spec("x", "injected", R, &[])]);
    let run = o.run_until_settled(&run_id, None).unwrap();
    assert_eq!(run.outcome, Some(Outcome::Failed));
    let tools = o.with_store(|s| s.tool_invocations(&run_id)).unwrap();
    assert_eq!(tools.iter().filter(|t| t.status == "denied").count(), 2);
    assert!(tools
        .iter()
        .any(|t| t.decision_reason == "capability_not_granted"));
    assert!(tools
        .iter()
        .any(|t| t.decision_reason == "tool_not_registered"));
    assert!(h.tools.calls.lock().unwrap().is_empty(), "no tool executed");
}

#[test]
fn mutations_need_scope_bound_task_approval_and_replans_stale_it() {
    let h = Harness::new();
    let o = h.orchestrator("i1", PolicyContext::offline());
    let contracts = o.contracts();
    let m = [Capability::LocalMutation];
    let (run_id, approvals) = o
        .with_store(|s| {
            let run = s.create_run(&run_spec(RunBudgets::default()))?;
            let a = s.submit_plan(
                &run.id,
                &[
                    spec("r", "reader", R, &[]),
                    spec("m", "mutator", &m, &["r"]),
                ],
                &contracts,
                &PolicyContext::offline(),
                3_600_000,
            )?;
            Ok((run.id, a))
        })
        .unwrap();
    assert_eq!(approvals.len(), 2);
    let task_approval = approvals
        .iter()
        .find(|a| a.kind == "task_capability")
        .unwrap()
        .clone();
    // Replan before deciding: the old task approval becomes stale.
    let mut changed = spec("m", "mutator", &m, &["r"]);
    changed.input = json!({"n": 2});
    let approvals2 = o
        .with_store(|s| {
            s.submit_plan(
                &run_id,
                &[spec("r", "reader", R, &[]), changed],
                &contracts,
                &PolicyContext::offline(),
                3_600_000,
            )
        })
        .unwrap();
    let stale = o.with_store(|s| {
        s.decide_approval(
            &task_approval.id,
            true,
            "operator",
            &task_approval.scope_digest,
            None,
        )
    });
    assert!(matches!(stale, Err(StoreError::Stale(_))));
    let plan = approvals2.iter().find(|a| a.kind == "plan").unwrap();
    o.with_store(|s| s.decide_approval(&plan.id, true, "operator", &plan.scope_digest, None))
        .unwrap();
    // Without task approval the mutation never runs; run settles as blocked.
    let run = o.run_until_settled(&run_id, None).unwrap();
    assert_eq!(run.outcome, Some(Outcome::Blocked));
    assert!(!h
        .tools
        .calls
        .lock()
        .unwrap()
        .iter()
        .any(|c| c.contains("write_thing")));

    let task2 = approvals2
        .iter()
        .find(|a| a.kind == "task_capability")
        .unwrap();
    o.with_store(|s| s.decide_approval(&task2.id, true, "operator", &task2.scope_digest, None))
        .unwrap();
    o.with_store(|s| s.resume(&run_id, "operator")).unwrap();
    let run = o.run_until_settled(&run_id, None).unwrap();
    assert_eq!(run.state, RunState::Completed);
    assert_eq!(
        h.tools
            .calls
            .lock()
            .unwrap()
            .iter()
            .filter(|c| c.contains("write_thing"))
            .count(),
        1
    );
}

#[test]
fn crash_recovery_blocks_uncertain_side_effects_and_retries_read_only_work() {
    let h = Harness::new();
    let old = h.orchestrator("old-instance", PolicyContext::offline());
    let contracts = old.contracts();
    let m = [Capability::LocalMutation];
    let run_id = old
        .with_store(|s| {
            let run = s.create_run(&run_spec(RunBudgets::default()))?;
            let approvals = s.submit_plan(
                &run.id,
                &[spec("r", "reader", R, &[]), spec("m", "mutator", &m, &[])],
                &contracts,
                &PolicyContext::offline(),
                3_600_000,
            )?;
            for a in &approvals {
                s.decide_approval(&a.id, true, "operator", &a.scope_digest, None)?;
            }
            s.transition_run(
                &run.id,
                RunState::Queued,
                RunState::Running,
                "execution_started",
                None,
            )?;
            // Simulate the old process: both tasks claimed, mutation started.
            for t in s.list_tasks(&run.id)? {
                s.claim(&t.id, "old-instance", "w", 60_000)?;
                if t.key == "m" {
                    let t = s.get_task(&t.id)?;
                    assert!(matches!(
                        s.begin_tool(
                            &t,
                            1,
                            "write_thing",
                            Capability::LocalMutation,
                            SideEffect::LocalMutation,
                            &json!({"q":"patch"})
                        )?,
                        ToolBegin::Proceed(_)
                    ));
                }
            }
            Ok(run.id)
        })
        .unwrap();
    drop(old); // "kill" the process

    let new = h.orchestrator("new-instance", PolicyContext::offline());
    let report = new.with_store(|s| s.recover("new-instance")).unwrap();
    assert_eq!(report.tasks_blocked, 1);
    assert_eq!(report.tasks_requeued, 1);
    assert_eq!(report.invocations_uncertain, 1);
    assert_eq!(report.runs_paused, 1);
    // Recovery is idempotent.
    assert_eq!(
        new.with_store(|s| s.recover("new-instance")).unwrap(),
        Default::default()
    );

    let tasks = new.with_store(|s| s.list_tasks(&run_id)).unwrap();
    let m_task = tasks.iter().find(|t| t.key == "m").unwrap().clone();
    assert_eq!(m_task.reason_code.as_deref(), Some("uncertain_side_effect"));
    // Requeue is refused until the operator resolves the side effect.
    assert!(new
        .with_store(|s| s.override_blocked_task(
            &m_task.id,
            OverrideResolution::Requeue,
            "operator",
            3_600_000
        ))
        .is_err());
    new.with_store(|s| {
        s.override_blocked_task(
            &m_task.id,
            OverrideResolution::SideEffectApplied,
            "operator",
            3_600_000,
        )
    })
    .unwrap();
    let requeued = new
        .with_store(|s| {
            s.override_blocked_task(
                &m_task.id,
                OverrideResolution::Requeue,
                "operator",
                3_600_000,
            )
        })
        .unwrap();
    assert_eq!(
        requeued.state,
        TaskState::AwaitingApproval,
        "side effects need re-approval"
    );
    let reapproval = new
        .with_store(|s| s.list_approvals(Some(&run_id), true))
        .unwrap();
    let a = &reapproval[0];
    new.with_store(|s| s.decide_approval(&a.id, true, "operator", &a.scope_digest, None))
        .unwrap();

    new.with_store(|s| s.resume(&run_id, "operator")).unwrap();
    let run = new.run_until_settled(&run_id, None).unwrap();
    assert_eq!(run.state, RunState::Completed);
    // The applied side effect was never executed a second time.
    assert!(!h
        .tools
        .calls
        .lock()
        .unwrap()
        .iter()
        .any(|c| c.contains("write_thing")));
}

#[test]
fn cancellation_and_timeouts_are_terminal_and_truthful() {
    let h = Harness::new();
    let o = h.orchestrator("i1", PolicyContext::offline());
    let run_id = plan_and_approve(&o, RunBudgets::default(), &[spec("r", "reader", R, &[])]);
    let run = o.with_store(|s| s.request_cancel(&run_id)).unwrap();
    assert_eq!(run.state, RunState::Cancelled);
    assert_eq!(run.outcome, Some(Outcome::Cancelled));
    assert!(o.run_until_settled(&run_id, None).is_err());

    let mut hang = spec("h", "hang", R, &[]);
    hang.timeout_ms = Some(150);
    let run_id = plan_and_approve(
        &o,
        RunBudgets {
            max_attempts_per_task: 1,
            ..RunBudgets::default()
        },
        &[hang],
    );
    let run = o.run_until_settled(&run_id, None).unwrap();
    assert_eq!(run.outcome, Some(Outcome::Failed));
    let task = &o.with_store(|s| s.list_tasks(&run_id)).unwrap()[0];
    assert_eq!(task.reason_code.as_deref(), Some("task_timeout"));
}

#[test]
fn replanning_is_bounded_and_rejects_identical_plans_and_cycles() {
    let h = Harness::new();
    let o = h.orchestrator("i1", PolicyContext::offline());
    let contracts = o.contracts();
    o.with_store(|s| {
        let run = s.create_run(&run_spec(RunBudgets {
            max_replans: 1,
            ..RunBudgets::default()
        }))?;
        let cyclic = s.submit_plan(
            &run.id,
            &[
                spec("a", "reader", R, &["b"]),
                spec("b", "reader", R, &["a"]),
            ],
            &contracts,
            &PolicyContext::offline(),
            3_600_000,
        );
        assert!(matches!(cyclic, Err(StoreError::Dag(_))));
        let plan = [spec("a", "reader", R, &[])];
        s.submit_plan(
            &run.id,
            &plan,
            &contracts,
            &PolicyContext::offline(),
            3_600_000,
        )?;
        assert!(matches!(
            s.submit_plan(
                &run.id,
                &plan,
                &contracts,
                &PolicyContext::offline(),
                3_600_000
            ),
            Err(StoreError::Rejected(_))
        ));
        s.submit_plan(
            &run.id,
            &[spec("b", "reader", R, &[])],
            &contracts,
            &PolicyContext::offline(),
            3_600_000,
        )?;
        let over = s.submit_plan(
            &run.id,
            &[spec("c", "reader", R, &[])],
            &contracts,
            &PolicyContext::offline(),
            3_600_000,
        );
        assert!(matches!(over, Err(StoreError::Rejected(m)) if m.contains("replan budget")));
        let other = s.create_run(&run_spec(RunBudgets::default()))?;
        assert!(s
            .submit_plan(
                &other.id,
                &[spec("a", "ghost", R, &[])],
                &contracts,
                &PolicyContext::offline(),
                3_600_000
            )
            .is_err());
        let mut bad = spec("a", "reader", R, &[]);
        bad.input = json!({"n": 1, "cmd": "curl evil"});
        assert!(s
            .submit_plan(
                &other.id,
                &[bad],
                &contracts,
                &PolicyContext::offline(),
                3_600_000
            )
            .is_err());
        let escalate = spec("a", "reader", &[Capability::Subprocess], &[]);
        assert!(s
            .submit_plan(
                &other.id,
                &[escalate],
                &contracts,
                &PolicyContext::offline(),
                3_600_000
            )
            .is_err());
        Ok(())
    })
    .unwrap();
}

#[test]
fn cloud_work_is_denied_without_consent() {
    let h = Harness::new();
    let o = h.orchestrator("i1", PolicyContext::offline());
    let contracts = o.contracts();
    let result = o.with_store(|s| {
        let run = s.create_run(&run_spec(RunBudgets::default()))?;
        s.submit_plan(
            &run.id,
            &[spec("c", "cloud", &[Capability::CloudInference], &[])],
            &contracts,
            &PolicyContext::offline(),
            3_600_000,
        )
    });
    assert!(
        matches!(result, Err(StoreError::Rejected(m)) if m.contains("cloud_disclosure_consent_missing"))
    );
}

#[test]
fn delegation_does_not_inherit_permissions() {
    let h = Harness::new();
    let o = h.orchestrator("i1", PolicyContext::offline());
    let run_id = plan_and_approve(&o, RunBudgets::default(), &[spec("d", "delegator", R, &[])]);
    let run = o.run_until_settled(&run_id, None).unwrap();
    let tasks = o.with_store(|s| s.list_tasks(&run_id)).unwrap();
    let follow_read = tasks.iter().find(|t| t.role == "reader").unwrap();
    assert_eq!(
        follow_read.state,
        TaskState::Completed,
        "read-only delegation within approved scope runs"
    );
    assert_eq!(follow_read.delegation_depth, 1);
    let follow_patch = tasks.iter().find(|t| t.role == "mutator").unwrap();
    assert_eq!(
        follow_patch.state,
        TaskState::AwaitingApproval,
        "mutating delegation waits for the operator"
    );
    assert_eq!(run.outcome, Some(Outcome::Blocked));
    let pending = o
        .with_store(|s| s.list_approvals(Some(&run_id), true))
        .unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(
        pending[0].task_id.as_deref(),
        Some(follow_patch.id.as_str())
    );
}

#[test]
fn concurrent_claims_never_double_execute() {
    let (_dir, path) = fresh_db();
    let conn = connection(&path);
    let store = Store::new(&conn);
    let contracts: BTreeMap<String, WorkerContract> = [(
        "reader".to_owned(),
        contract("reader", R, EvidenceClass::Observation),
    )]
    .into();
    let run = store.create_run(&run_spec(RunBudgets::default())).unwrap();
    let approvals = store
        .submit_plan(
            &run.id,
            &[spec("a", "reader", R, &[])],
            &contracts,
            &PolicyContext::offline(),
            3_600_000,
        )
        .unwrap();
    store
        .decide_approval(
            &approvals[0].id,
            true,
            "operator",
            &approvals[0].scope_digest,
            None,
        )
        .unwrap();
    let task_id = store.list_tasks(&run.id).unwrap()[0].id.clone();
    let wins = Arc::new(AtomicUsize::new(0));
    std::thread::scope(|scope| {
        for i in 0..8 {
            let path = path.clone();
            let task_id = task_id.clone();
            let wins = wins.clone();
            scope.spawn(move || {
                let conn = connection(&path);
                if let Ok(Some(_)) =
                    Store::new(&conn).claim(&task_id, &format!("inst{i}"), "w", 60_000)
                {
                    wins.fetch_add(1, Ordering::SeqCst);
                }
            });
        }
    });
    assert_eq!(wins.load(Ordering::SeqCst), 1);
}
