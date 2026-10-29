//! Bounded executor. One coordinator thread owns all state transitions;
//! workers run on scoped threads and touch SQLite only through the
//! policy-checked tool gate. Independent read-only tasks run concurrently up
//! to the run's `max_parallel` and a global worker limit; tasks with side
//! effects run alone, and tasks sharing a `resource_key` never overlap.
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rusqlite::Connection;
use serde_json::{json, Value};

use crate::policy::{
    deny, validate_schema, Capability, Decision, PolicyContext, PolicyEngine, ToolDescriptor,
};
use crate::report::{build_report, classify_outcome, render_markdown};
use crate::state::{reason, ErrorCategory, Outcome, RunState, TaskState};
use crate::store::{
    new_id, now_ms, sha256_hex, RunRecord, Store, StoreError, StoreResult, TaskRecord, ToolBegin,
};
use crate::worker::{
    CancelToken, TaskContext, ToolCallError, ToolGate, WorkerError, WorkerOutput, WorkerRegistry,
};

/// Concrete tool implementations (existing CodeTwin analyzers, research, ...).
pub trait ToolRuntime: Send + Sync {
    fn descriptors(&self) -> Vec<ToolDescriptor>;
    fn invoke(
        &self,
        project_id: &str,
        tool_id: &str,
        args: &Value,
        cancel: &CancelToken,
    ) -> Result<Value, String>;
}

#[derive(Debug, Clone)]
pub struct OrchestratorConfig {
    pub instance_id: String,
    pub lease_ms: i64,
    pub poll_ms: u64,
    pub retry_backoff_ms: i64,
    pub approval_ttl_ms: i64,
    pub max_delegations_per_task: usize,
}

impl Default for OrchestratorConfig {
    fn default() -> Self {
        Self {
            instance_id: new_id("instance"),
            lease_ms: 30_000,
            poll_ms: 20,
            retry_backoff_ms: 500,
            approval_ttl_ms: 24 * 3_600_000,
            max_delegations_per_task: 4,
        }
    }
}

/// Process-wide backpressure shared by all orchestrators.
#[derive(Debug)]
pub struct GlobalLimits {
    pub max_workers: usize,
    active: AtomicUsize,
}

impl GlobalLimits {
    pub const fn new(max_workers: usize) -> Self {
        Self {
            max_workers,
            active: AtomicUsize::new(0),
        }
    }
    fn try_acquire(&self) -> bool {
        // Explicit CAS loop: `fetch_update` is deprecated on newer toolchains
        // and its replacement `try_update` is unavailable on older ones.
        let mut n = self.active.load(Ordering::SeqCst);
        while n < self.max_workers {
            match self
                .active
                .compare_exchange(n, n + 1, Ordering::SeqCst, Ordering::SeqCst)
            {
                Ok(_) => return true,
                Err(current) => n = current,
            }
        }
        false
    }
    fn release(&self) {
        self.active.fetch_sub(1, Ordering::SeqCst);
    }
    pub fn active(&self) -> usize {
        self.active.load(Ordering::SeqCst)
    }
}

pub struct Orchestrator {
    conn: Mutex<Connection>,
    registry: WorkerRegistry,
    tools: Arc<dyn ToolRuntime>,
    policy: PolicyContext,
    config: OrchestratorConfig,
    limits: Arc<GlobalLimits>,
}

/// Identical (tool, arguments) calls allowed per task attempt before the
/// gate treats the worker as looping.
pub const MAX_IDENTICAL_TOOL_CALLS: usize = 3;

struct Gate<'a> {
    orchestrator: &'a Orchestrator,
    project_id: &'a str,
    task: &'a TaskRecord,
    attempt: u32,
    cancel: &'a CancelToken,
    descriptors: &'a BTreeMap<String, ToolDescriptor>,
}

impl ToolGate for Gate<'_> {
    fn descriptors(&self) -> Vec<ToolDescriptor> {
        self.descriptors
            .values()
            .filter(|d| self.task.capabilities.contains(&d.capability))
            .cloned()
            .collect()
    }

    fn call(&self, tool_id: &str, args: &Value) -> Result<Value, ToolCallError> {
        if self.cancel.is_cancelled() {
            return Err(ToolCallError::Cancelled);
        }
        let o = self.orchestrator;
        let deny_with = |cap: Option<Capability>, side, why: &str| {
            let conn = o.conn.lock().expect("store mutex");
            let _ =
                Store::new(&conn).deny_tool(self.task, self.attempt, tool_id, cap, side, args, why);
            ToolCallError::Denied(why.to_owned())
        };
        let Some(descriptor) = self.descriptors.get(tool_id) else {
            return Err(deny_with(
                None,
                crate::state::SideEffect::ReadOnly,
                deny::UNKNOWN_TOOL,
            ));
        };
        if !descriptor.availability.available {
            return Err(deny_with(
                Some(descriptor.capability),
                descriptor.side_effect,
                deny::TOOL_UNAVAILABLE,
            ));
        }
        if validate_schema(&descriptor.input_schema, args).is_err() {
            return Err(deny_with(
                Some(descriptor.capability),
                descriptor.side_effect,
                deny::INVALID_ARGUMENTS,
            ));
        }
        // Loop detection: an identical call repeated within one attempt means
        // the worker is not making progress.
        let repeats = {
            let conn = o.conn.lock().expect("store mutex");
            Store::new(&conn)
                .identical_tool_calls(&self.task.id, self.attempt, tool_id, args)
                .map_err(|e| ToolCallError::Failed(e.to_string()))?
        };
        if repeats >= MAX_IDENTICAL_TOOL_CALLS {
            return Err(deny_with(
                Some(descriptor.capability),
                descriptor.side_effect,
                deny::LOOP_DETECTED,
            ));
        }
        let begin = {
            let conn = o.conn.lock().expect("store mutex");
            let store = Store::new(&conn);
            let live = if descriptor.side_effect.is_read_only() {
                false
            } else {
                store
                    .has_live_task_approval(&self.task.id)
                    .map_err(|e| ToolCallError::Failed(e.to_string()))?
            };
            match PolicyEngine::authorize_call(
                &self.task.capabilities,
                descriptor.capability,
                live,
                &o.policy,
            ) {
                Decision::Allow => {}
                Decision::Deny(why) => {
                    let _ = store.deny_tool(
                        self.task,
                        self.attempt,
                        tool_id,
                        Some(descriptor.capability),
                        descriptor.side_effect,
                        args,
                        &why,
                    );
                    return Err(ToolCallError::Denied(why));
                }
            }
            store
                .begin_tool(
                    self.task,
                    self.attempt,
                    tool_id,
                    descriptor.capability,
                    descriptor.side_effect,
                    args,
                )
                .map_err(|e| ToolCallError::Failed(e.to_string()))?
        };
        let invocation = match begin {
            ToolBegin::AlreadyApplied(digest) => return Err(ToolCallError::AlreadyApplied(digest)),
            ToolBegin::Proceed(id) => id,
        };
        let result = o.tools.invoke(self.project_id, tool_id, args, self.cancel);
        let conn = o.conn.lock().expect("store mutex");
        let store = Store::new(&conn);
        match result {
            Ok(value) => {
                let text = value.to_string();
                if text.len() > descriptor.max_output_bytes {
                    let _ = store.finish_tool(&invocation, false, None, "output_exceeds_budget");
                    return Err(ToolCallError::Failed(
                        "tool output exceeds its budget".into(),
                    ));
                }
                let digest = sha256_hex(text.as_bytes());
                store
                    .finish_tool(&invocation, true, Some(&digest), "ok")
                    .map_err(|e| ToolCallError::Failed(e.to_string()))?;
                Ok(value)
            }
            Err(error) => {
                let _ = store.finish_tool(&invocation, false, None, "tool_error");
                Err(ToolCallError::Failed(error))
            }
        }
    }
}

enum Finished {
    Output(WorkerOutput),
    Error(WorkerError),
}

impl Orchestrator {
    pub fn new(
        conn: Connection,
        registry: WorkerRegistry,
        tools: Arc<dyn ToolRuntime>,
        policy: PolicyContext,
        config: OrchestratorConfig,
        limits: Arc<GlobalLimits>,
    ) -> Self {
        Self {
            conn: Mutex::new(conn),
            registry,
            tools,
            policy,
            config,
            limits,
        }
    }

    pub fn config(&self) -> &OrchestratorConfig {
        &self.config
    }

    pub fn registry(&self) -> &WorkerRegistry {
        &self.registry
    }

    /// Run a closure with the store. Keep closures short: workers share it.
    pub fn with_store<T>(&self, f: impl FnOnce(&Store<'_>) -> StoreResult<T>) -> StoreResult<T> {
        let conn = self.conn.lock().expect("store mutex");
        f(&Store::new(&conn))
    }

    pub fn contracts(&self) -> BTreeMap<String, crate::worker::WorkerContract> {
        self.registry
            .contracts()
            .into_iter()
            .map(|c| (c.role.clone(), c))
            .collect()
    }

    /// Execute an approved, queued run until every task settles, the run is
    /// paused/cancelled, or a budget is exhausted. Returns the final record.
    pub fn run_until_settled(
        &self,
        run_id: &str,
        external_cancel: Option<&CancelToken>,
    ) -> StoreResult<RunRecord> {
        let run = self.with_store(|s| s.get_run(run_id))?;
        match run.state {
            RunState::Queued => {
                if run.approved_revision != Some(run.plan_revision) {
                    return Err(StoreError::Rejected("plan is not approved".into()));
                }
                self.with_store(|s| {
                    s.transition_run(
                        run_id,
                        RunState::Queued,
                        RunState::Running,
                        "execution_started",
                        None,
                    )
                })?;
            }
            other => return Err(StoreError::Rejected(format!("run is {other}, not queued"))),
        }
        let descriptors: BTreeMap<String, ToolDescriptor> = self
            .tools
            .descriptors()
            .into_iter()
            .map(|d| (d.id.clone(), d))
            .collect();
        loop {
            let run = self.with_store(|s| s.get_run(run_id))?;
            if run.state != RunState::Running {
                return Ok(run);
            }
            if run.cancel_requested || external_cancel.is_some_and(CancelToken::is_cancelled) {
                return self.finish_cancelled(run_id);
            }
            if run.pause_requested {
                self.with_store(|s| {
                    s.transition_run(
                        run_id,
                        RunState::Running,
                        RunState::Paused,
                        reason::PAUSE_REQUESTED,
                        None,
                    )
                })?;
                return self.with_store(|s| s.get_run(run_id));
            }
            let elapsed = now_ms() - run.started_ms.unwrap_or_else(now_ms);
            if elapsed > run.budgets.max_runtime_ms as i64 {
                return self.fail_budget(run_id, reason::RUNTIME_BUDGET);
            }
            if run.credits_used > run.budgets.max_credits {
                return self.fail_budget(run_id, reason::CREDIT_BUDGET);
            }
            self.with_store(|s| s.expire_approvals())?;
            let ready = self.with_store(|s| s.ready_tasks(run_id))?;
            if ready.is_empty() {
                let tasks = self.with_store(|s| s.list_tasks(run_id))?;
                let waiting_retry = tasks
                    .iter()
                    .filter_map(|t| {
                        (t.state == TaskState::RetryWait).then_some(t.not_before_ms.unwrap_or(0))
                    })
                    .min();
                if let Some(due) = waiting_retry {
                    let wait = (due - now_ms()).clamp(1, 1_000) as u64;
                    std::thread::sleep(Duration::from_millis(wait));
                    continue;
                }
                return self.settle(run_id);
            }
            let batch = self.select_batch(&run, ready);
            if batch.is_empty() {
                std::thread::sleep(Duration::from_millis(self.config.poll_ms));
                continue;
            }
            self.execute_batch(&run, batch, &descriptors)?;
        }
    }

    fn select_batch(&self, run: &RunRecord, ready: Vec<TaskRecord>) -> Vec<TaskRecord> {
        let mut batch: Vec<TaskRecord> = Vec::new();
        let mut resources: BTreeSet<String> = BTreeSet::new();
        for task in ready {
            if batch.len() >= run.budgets.max_parallel as usize {
                break;
            }
            let mutating = !task.side_effect.is_read_only();
            if mutating && !batch.is_empty() {
                continue;
            }
            if batch.first().is_some_and(|t| !t.side_effect.is_read_only()) {
                break;
            }
            if let Some(key) = &task.resource_key {
                if !resources.insert(key.clone()) {
                    continue;
                }
            }
            batch.push(task);
            if mutating {
                break;
            }
        }
        batch
    }

    fn execute_batch(
        &self,
        run: &RunRecord,
        batch: Vec<TaskRecord>,
        descriptors: &BTreeMap<String, ToolDescriptor>,
    ) -> StoreResult<()> {
        let mut claimed: Vec<(TaskRecord, u32, CancelToken, Instant)> = Vec::new();
        for task in batch {
            if self.registry.get(&task.role).is_none() {
                self.with_store(|s| {
                    s.transition_task(
                        &task.id,
                        TaskState::Queued,
                        TaskState::Blocked,
                        reason::UNKNOWN_ROLE,
                    )
                })?;
                continue;
            }
            if !self.limits.try_acquire() {
                break;
            }
            let worker_id = format!("{}:{}", task.role, self.config.instance_id);
            match self.with_store(|s| {
                s.claim(
                    &task.id,
                    &self.config.instance_id,
                    &worker_id,
                    self.config.lease_ms,
                )
            }) {
                Ok(Some(attempt)) => {
                    let deadline = Instant::now() + Duration::from_millis(task.timeout_ms);
                    claimed.push((task, attempt, CancelToken::new(), deadline));
                }
                Ok(None) => self.limits.release(),
                Err(e) => {
                    self.limits.release();
                    return Err(e);
                }
            }
        }
        if claimed.is_empty() {
            std::thread::sleep(Duration::from_millis(self.config.poll_ms));
            return Ok(());
        }
        let upstream: BTreeMap<String, Vec<(String, String, Value)>> = {
            let tasks = self.with_store(|s| s.list_tasks(&run.id))?;
            let by_id: BTreeMap<&str, &TaskRecord> =
                tasks.iter().map(|t| (t.id.as_str(), t)).collect();
            claimed
                .iter()
                .map(|(task, ..)| {
                    let ups = task
                        .depends_on
                        .iter()
                        .filter_map(|d| by_id.get(d.as_str()))
                        .map(|t| {
                            (
                                t.key.clone(),
                                t.role.clone(),
                                t.output.clone().unwrap_or(Value::Null),
                            )
                        })
                        .collect();
                    (task.id.clone(), ups)
                })
                .collect()
        };
        let results: Vec<(usize, Finished)> = std::thread::scope(|scope| {
            let handles: Vec<_> = claimed
                .iter()
                .enumerate()
                .map(|(i, (task, attempt, cancel, deadline))| {
                    let worker = self.registry.get(&task.role).expect("checked").clone();
                    let ups = &upstream[&task.id];
                    let project = run.project_id.clone();
                    let goal = run.goal.as_str();
                    scope.spawn(move || {
                        let gate = Gate {
                            orchestrator: self,
                            project_id: &project,
                            task,
                            attempt: *attempt,
                            cancel,
                            descriptors,
                        };
                        let ctx = TaskContext {
                            run_id: &task.run_id,
                            task_id: &task.id,
                            project_id: &project,
                            goal,
                            input: &task.input,
                            attempt: *attempt,
                            cancel,
                            deadline: *deadline,
                            tools: &gate,
                            upstream: ups,
                        };
                        let outcome =
                            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                worker.execute(&ctx)
                            }));
                        let finished = match outcome {
                            Ok(Ok(output)) => Finished::Output(output),
                            Ok(Err(error)) => Finished::Error(error),
                            Err(_) => Finished::Error(WorkerError::new(
                                ErrorCategory::Crash,
                                "worker panicked",
                            )),
                        };
                        (i, finished)
                    })
                })
                .collect();
            let mut last_beat = Instant::now();
            loop {
                if handles.iter().all(|h| h.is_finished()) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(self.config.poll_ms));
                let now = Instant::now();
                let cancel_all = self
                    .with_store(|s| s.get_run(&run.id))
                    .map(|r| r.cancel_requested)
                    .unwrap_or(false);
                for (task, _, cancel, deadline) in &claimed {
                    if cancel_all || now >= *deadline {
                        cancel.cancel();
                    }
                    if now.duration_since(last_beat)
                        >= Duration::from_millis((self.config.lease_ms / 3) as u64)
                    {
                        let _ = self.with_store(|s| {
                            s.heartbeat(&task.id, &self.config.instance_id, self.config.lease_ms)
                        });
                    }
                }
                if now.duration_since(last_beat)
                    >= Duration::from_millis((self.config.lease_ms / 3) as u64)
                {
                    last_beat = now;
                }
            }
            handles
                .into_iter()
                .map(|h| h.join().expect("worker thread joined"))
                .collect()
        });
        for _ in &claimed {
            self.limits.release();
        }
        for (i, finished) in results {
            let (task, attempt, cancel, deadline) = &claimed[i];
            let timed_out = Instant::now() >= *deadline && cancel.is_cancelled();
            match finished {
                Finished::Output(output) => self.accept_output(run, task, *attempt, output)?,
                Finished::Error(mut error) => {
                    if timed_out && error.category == ErrorCategory::Cancelled {
                        error = WorkerError::new(ErrorCategory::Timeout, "deadline exceeded");
                    }
                    self.reject_attempt(task, *attempt, &error)?;
                }
            }
        }
        Ok(())
    }

    fn accept_output(
        &self,
        run: &RunRecord,
        task: &TaskRecord,
        attempt: u32,
        output: WorkerOutput,
    ) -> StoreResult<()> {
        let contract = self
            .registry
            .get(&task.role)
            .expect("checked")
            .contract()
            .clone();
        // A worker may emit its contracted class or a weaker, non-evidence class.
        let class_ok =
            output.evidence_class == contract.output_class || !output.evidence_class.is_evidence();
        let stored = json!({
            "data": output.data,
            "evidence_refs": output.evidence_refs,
            "delegations": output.delegations,
        });
        self.with_store(|s| {
            s.record_output(&task.id, &stored, &output.summary, output.evidence_class)
        })?;
        if output.credits_used > 0 {
            self.with_store(|s| s.add_credits(&run.id, output.credits_used))?;
        }
        let tool_successes = self.with_store(|s| s.successful_tool_calls(&task.id, attempt))?;
        let mut failure =
            (!class_ok).then(|| format!("role may not emit `{}`", output.evidence_class));
        if failure.is_none() {
            for criterion in &task.success_criteria {
                if let Err(why) = criterion.check(&output, tool_successes) {
                    failure = Some(why);
                    break;
                }
            }
        }
        match failure {
            None => {
                self.with_store(|s| {
                    s.transition_task(
                        &task.id,
                        TaskState::Validating,
                        TaskState::Completed,
                        "success_criteria_met",
                    )?;
                    s.finish_attempt(&task.id, attempt, "succeeded", None)
                })?;
                self.process_delegations(run, task, &output)?;
            }
            Some(why) => {
                self.with_store(|s| {
                    s.event(
                        &run.id,
                        Some(&task.id),
                        "validation_failed",
                        json!({"detail": why}),
                    )?;
                    s.transition_task(
                        &task.id,
                        TaskState::Validating,
                        TaskState::Failed,
                        reason::VALIDATION_FAILED,
                    )?;
                    s.finish_attempt(
                        &task.id,
                        attempt,
                        "failed",
                        Some((ErrorCategory::Validation, &why)),
                    )
                })?;
            }
        }
        Ok(())
    }

    fn reject_attempt(
        &self,
        task: &TaskRecord,
        attempt: u32,
        error: &WorkerError,
    ) -> StoreResult<()> {
        let retryable = matches!(
            error.category,
            ErrorCategory::Transient | ErrorCategory::Timeout | ErrorCategory::Crash
        );
        self.with_store(|s| {
            let current = s.get_task(&task.id)?;
            let attempt_status = if error.category == ErrorCategory::Cancelled {
                "cancelled"
            } else {
                "failed"
            };
            s.finish_attempt(
                &task.id,
                attempt,
                attempt_status,
                Some((error.category, &error.detail)),
            )?;
            if current.state != TaskState::Running {
                return Ok(());
            }
            if error.category == ErrorCategory::Cancelled {
                s.transition_task(
                    &task.id,
                    TaskState::Running,
                    TaskState::Cancelled,
                    reason::CANCEL_REQUESTED,
                )
            } else if error.category == ErrorCategory::Policy {
                s.transition_task(
                    &task.id,
                    TaskState::Running,
                    TaskState::Blocked,
                    reason::POLICY_DENIED,
                )
            } else if retryable && current.attempt_count < current.max_attempts {
                s.transition_task(
                    &task.id,
                    TaskState::Running,
                    TaskState::RetryWait,
                    reason::RETRY_SCHEDULED,
                )?;
                // Exponential backoff with deterministic jitter from the task id.
                let jitter = i64::from(
                    u8::from_str_radix(&sha256_hex(task.id.as_bytes())[..2], 16).unwrap_or(0),
                );
                let delay =
                    self.config.retry_backoff_ms * (1 << current.attempt_count.min(6)) + jitter;
                s.connection().execute(
                    "UPDATE workflow_tasks SET not_before_ms=?2 WHERE id=?1",
                    rusqlite::params![task.id, now_ms() + delay],
                )?;
                Ok(())
            } else {
                let why = if error.category == ErrorCategory::Timeout {
                    reason::TIMEOUT
                } else if retryable {
                    reason::ATTEMPTS_EXHAUSTED
                } else {
                    reason::WORKER_FAILED
                };
                s.transition_task(&task.id, TaskState::Running, TaskState::Failed, why)
            }
        })
    }

    /// Typed delegation. A delegated task never inherits the parent's grants:
    /// its capabilities are checked against its own role contract and the
    /// policy; only read-only work inside the already approved capability set
    /// is queued without a new operator approval.
    fn process_delegations(
        &self,
        run: &RunRecord,
        parent: &TaskRecord,
        output: &WorkerOutput,
    ) -> StoreResult<()> {
        let contracts = self.contracts();
        for (i, request) in output.delegations.iter().enumerate() {
            let denied = |why: &str| {
                self.with_store(|s| {
                    s.event(
                        &run.id,
                        Some(&parent.id),
                        "delegation_denied",
                        json!({"role": request.role, "reason": why}),
                    )
                })
            };
            if i >= self.config.max_delegations_per_task {
                denied("delegation_limit")?;
                continue;
            }
            if parent.delegation_depth >= 2 {
                denied("delegation_depth")?;
                continue;
            }
            let run_now = self.with_store(|s| s.get_run(&run.id))?;
            let live = self
                .with_store(|s| s.list_tasks(&run.id))?
                .iter()
                .filter(|t| !t.is_superseded())
                .count();
            if live as u32 >= run_now.budgets.max_tasks {
                denied("task_budget")?;
                continue;
            }
            let Some(contract) = contracts.get(&request.role) else {
                denied("unknown_role")?;
                continue;
            };
            if validate_schema(&contract.input_schema, &request.input).is_err() {
                denied("invalid_input")?;
                continue;
            }
            let need = match PolicyEngine::plan_requirement(
                &request.capabilities,
                &contract.capabilities,
                &self.policy,
            ) {
                Ok(need) => need,
                Err(why) => {
                    denied(why)?;
                    continue;
                }
            };
            let auto = need == crate::policy::ApprovalNeed::PlanApproval
                && request
                    .capabilities
                    .is_subset(&run_now.approved_capabilities);
            let key = format!(
                "delegated:{}",
                &sha256_hex(
                    format!("{}|{}|{}", parent.key, request.role, request.input).as_bytes()
                )[..24]
            );
            let inserted = self.with_store(|s| {
                s.insert_delegated_task(
                    &run_now,
                    parent,
                    &key,
                    &request.role,
                    &request.title,
                    &request.input,
                    &request.capabilities,
                    contract.default_timeout_ms,
                    auto,
                    self.config.approval_ttl_ms,
                )
            });
            match inserted {
                Ok(task) => self.with_store(|s| {
                    s.event(
                        &run.id,
                        Some(&task.id),
                        "delegated",
                        json!({"from": parent.id, "role": request.role, "auto_queued": auto}),
                    )
                })?,
                Err(StoreError::Sqlite(rusqlite::Error::SqliteFailure(e, _)))
                    if e.code == rusqlite::ErrorCode::ConstraintViolation =>
                {
                    denied("duplicate_delegation")?;
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    fn settle(&self, run_id: &str) -> StoreResult<RunRecord> {
        let tasks = self.with_store(|s| s.list_tasks(run_id))?;
        let (state, outcome) = classify_outcome(&tasks);
        self.with_store(|s| {
            s.transition_run(
                run_id,
                RunState::Running,
                RunState::Validating,
                reason::ALL_TASKS_SETTLED,
                None,
            )
        })?;
        let why = match outcome {
            Outcome::Blocked => reason::APPROVAL_PENDING,
            _ => reason::ALL_TASKS_SETTLED,
        };
        self.with_store(|s| {
            s.transition_run(run_id, RunState::Validating, state, why, Some(outcome))
        })?;
        self.write_reports(run_id)?;
        self.with_store(|s| s.get_run(run_id))
    }

    fn finish_cancelled(&self, run_id: &str) -> StoreResult<RunRecord> {
        self.with_store(|s| {
            let tasks = s.list_tasks(run_id)?;
            for task in tasks.iter().filter(|t| !t.state.is_terminal()) {
                let to = if task.state.can_transition_to(TaskState::Cancelled) {
                    TaskState::Cancelled
                } else {
                    TaskState::Failed
                };
                s.transition_task(&task.id, task.state, to, reason::CANCEL_REQUESTED)?;
            }
            s.transition_run(
                run_id,
                RunState::Running,
                RunState::Cancelled,
                reason::CANCEL_REQUESTED,
                Some(Outcome::Cancelled),
            )
        })?;
        self.write_reports(run_id)?;
        self.with_store(|s| s.get_run(run_id))
    }

    fn fail_budget(&self, run_id: &str, why: &str) -> StoreResult<RunRecord> {
        self.with_store(|s| {
            let tasks = s.list_tasks(run_id)?;
            for task in tasks.iter().filter(|t| !t.state.is_terminal()) {
                let to = if task.state.can_transition_to(TaskState::Cancelled) {
                    TaskState::Cancelled
                } else {
                    TaskState::Failed
                };
                s.transition_task(&task.id, task.state, to, why)?;
            }
            s.transition_run(
                run_id,
                RunState::Running,
                RunState::Failed,
                why,
                Some(Outcome::Failed),
            )
        })?;
        self.write_reports(run_id)?;
        self.with_store(|s| s.get_run(run_id))
    }

    pub fn write_reports(&self, run_id: &str) -> StoreResult<(String, String)> {
        self.with_store(|s| {
            let report = build_report(s, run_id)?;
            let markdown = render_markdown(&report);
            let json_text = serde_json::to_string_pretty(&report)?;
            let md = s.save_report(run_id, "markdown", &markdown)?;
            let js = s.save_report(run_id, "json", &json_text)?;
            Ok((md, js))
        })
    }
}
