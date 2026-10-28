//! Specialist worker contracts. A worker is a bounded Rust implementation of
//! one role; it receives a typed input, may request tool calls only through a
//! policy-checked [`ToolGate`], and returns a typed output. Delegation is a
//! typed request that the orchestrator re-evaluates; it never inherits the
//! delegating task's grants.
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::policy::{Capability, ToolDescriptor};
use crate::state::{ErrorCategory, EvidenceClass};

/// Cooperative cancellation shared by the orchestrator and a worker.
#[derive(Debug, Clone, Default)]
pub struct CancelToken(Arc<AtomicBool>);

impl CancelToken {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerContract {
    pub role: String,
    pub display_name: String,
    pub description: String,
    /// Upper bound of capabilities any task of this role can be granted.
    pub capabilities: BTreeSet<Capability>,
    /// Bounded JSON-Schema subset for the task input.
    pub input_schema: Value,
    /// Evidence class this role is allowed to emit.
    pub output_class: EvidenceClass,
    pub default_timeout_ms: u64,
}

/// A reference to persisted evidence (finding, symbol, file hash, citation...).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceRef {
    pub kind: String,
    pub id: String,
    /// SHA-256 of the referenced content when known.
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationRequest {
    pub role: String,
    pub title: String,
    pub input: Value,
    pub capabilities: BTreeSet<Capability>,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerOutput {
    pub summary: String,
    pub data: Value,
    pub evidence_class: EvidenceClass,
    pub evidence_refs: Vec<EvidenceRef>,
    /// Provider credits consumed (only when the provider reports them reliably).
    pub credits_used: u32,
    pub delegations: Vec<DelegationRequest>,
}

impl WorkerOutput {
    pub fn observation(summary: impl Into<String>, data: Value, refs: Vec<EvidenceRef>) -> Self {
        Self {
            summary: summary.into(),
            data,
            evidence_class: EvidenceClass::Observation,
            evidence_refs: refs,
            credits_used: 0,
            delegations: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, thiserror::Error)]
#[error("{category}: {detail}")]
pub struct WorkerError {
    pub category: ErrorCategory,
    pub detail: String,
}

impl WorkerError {
    pub fn new(category: ErrorCategory, detail: impl Into<String>) -> Self {
        let mut detail: String = detail.into();
        if detail.len() > 480 {
            let mut cut = 480;
            while !detail.is_char_boundary(cut) {
                cut -= 1;
            }
            detail.truncate(cut);
        }
        Self { category, detail }
    }
    pub fn permanent(detail: impl Into<String>) -> Self {
        Self::new(ErrorCategory::Permanent, detail)
    }
    pub fn transient(detail: impl Into<String>) -> Self {
        Self::new(ErrorCategory::Transient, detail)
    }
}

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum ToolCallError {
    #[error("denied by policy: {0}")]
    Denied(String),
    #[error("side effect already applied (output {0}); not repeated")]
    AlreadyApplied(String),
    #[error("tool failed: {0}")]
    Failed(String),
    #[error("cancelled")]
    Cancelled,
}

/// Policy-enforcing tool access handed to a running worker.
pub trait ToolGate: Send + Sync {
    fn descriptors(&self) -> Vec<ToolDescriptor>;
    fn call(&self, tool_id: &str, args: &Value) -> Result<Value, ToolCallError>;
}

/// Everything a worker may see about its task.
pub struct TaskContext<'a> {
    pub run_id: &'a str,
    pub task_id: &'a str,
    pub project_id: &'a str,
    pub goal: &'a str,
    pub input: &'a Value,
    pub attempt: u32,
    pub cancel: &'a CancelToken,
    pub deadline: Instant,
    pub tools: &'a dyn ToolGate,
    /// Outputs of completed dependency tasks, keyed by idempotency key.
    pub upstream: &'a [(String, String, Value)],
}

impl TaskContext<'_> {
    /// Return an error if cancelled or past deadline; call between steps.
    pub fn checkpoint(&self) -> Result<(), WorkerError> {
        if self.cancel.is_cancelled() {
            return Err(WorkerError::new(ErrorCategory::Cancelled, "cancelled"));
        }
        if Instant::now() >= self.deadline {
            return Err(WorkerError::new(
                ErrorCategory::Timeout,
                "deadline exceeded",
            ));
        }
        Ok(())
    }
}

pub trait Worker: Send + Sync {
    fn contract(&self) -> &WorkerContract;
    fn execute(&self, ctx: &TaskContext<'_>) -> Result<WorkerOutput, WorkerError>;
}

/// Registry of available specialist workers, keyed by role.
#[derive(Default)]
pub struct WorkerRegistry {
    workers: std::collections::BTreeMap<String, Arc<dyn Worker>>,
}

impl WorkerRegistry {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn register(&mut self, worker: Arc<dyn Worker>) {
        self.workers.insert(worker.contract().role.clone(), worker);
    }
    pub fn get(&self, role: &str) -> Option<&Arc<dyn Worker>> {
        self.workers.get(role)
    }
    pub fn contracts(&self) -> Vec<WorkerContract> {
        self.workers
            .values()
            .map(|w| w.contract().clone())
            .collect()
    }
}

/// Deterministic success criteria checked in the `validating` state.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SuccessCriterion {
    /// `data[field]` exists and is not null.
    OutputFieldPresent { field: String },
    /// `data[field]` is an array with at least `min` entries.
    MinItems { field: String, min: usize },
    /// At least `min` evidence references.
    EvidenceRefsAtLeast { min: usize },
    /// At least `min` successful tool invocations in this attempt.
    ToolCallsAtLeast { min: usize },
}

impl SuccessCriterion {
    pub fn check(&self, output: &WorkerOutput, tool_successes: usize) -> Result<(), String> {
        match self {
            Self::OutputFieldPresent { field } => match output.data.get(field) {
                Some(v) if !v.is_null() => Ok(()),
                _ => Err(format!("output field `{field}` missing")),
            },
            Self::MinItems { field, min } => {
                let n = output
                    .data
                    .get(field)
                    .and_then(Value::as_array)
                    .map_or(0, Vec::len);
                if n >= *min {
                    Ok(())
                } else {
                    Err(format!("`{field}` has {n} items, needs {min}"))
                }
            }
            Self::EvidenceRefsAtLeast { min } => {
                if output.evidence_refs.len() >= *min {
                    Ok(())
                } else {
                    Err(format!(
                        "{} evidence references, needs {min}",
                        output.evidence_refs.len()
                    ))
                }
            }
            Self::ToolCallsAtLeast { min } => {
                if tool_successes >= *min {
                    Ok(())
                } else {
                    Err(format!(
                        "{tool_successes} tool calls succeeded, needs {min}"
                    ))
                }
            }
        }
    }
}
