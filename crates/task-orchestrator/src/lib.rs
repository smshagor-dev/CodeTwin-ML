//! Durable, approval-gated, dependency-aware task orchestration.
//!
//! * [`state`] — typed run/task state machines and reason codes.
//! * [`dag`] — dependency validation and cycle detection.
//! * [`policy`] — deterministic capability policy and tool descriptors.
//! * [`worker`] — specialist worker contracts and the tool gate.
//! * [`store`] — SQLite persistence (migration 0047 in `codetwin-core`).
//! * [`executor`] — bounded concurrent execution, leases and recovery.
//! * [`report`] — truthful outcome classification and run reports.
pub mod compare;
pub mod dag;
pub mod executor;
pub mod policy;
pub mod report;
pub mod state;
pub mod store;
pub mod worker;

pub use executor::{GlobalLimits, Orchestrator, OrchestratorConfig, ToolRuntime};
pub use policy::{Capability, PolicyContext, SandboxSupport, ToolDescriptor};
pub use state::{EvidenceClass, Outcome, RunState, SideEffect, TaskState};
pub use store::{RunBudgets, RunSpec, Store, StoreError, TaskSpec};
pub use worker::{CancelToken, Worker, WorkerContract, WorkerOutput, WorkerRegistry};

/// The schema this crate expects. `codetwin-core` applies it as migration 47;
/// it is exposed here so isolated tests and tools can create a scratch store.
pub const SCHEMA_SQL: &str =
    include_str!("../../codetwin-core/migrations/0047_workflow_orchestration.sql");
