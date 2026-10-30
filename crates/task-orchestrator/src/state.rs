//! Typed finite-state machines for workflow runs and tasks.
//!
//! The transition tables here are the single authority for state changes.
//! The SQLite store applies a transition only with a compare-and-set on the
//! expected previous state, so a stale caller cannot overwrite newer state.
use serde::{Deserialize, Serialize};

macro_rules! string_enum {
    ($name:ident { $($variant:ident => $text:literal),+ $(,)? }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(rename_all = "snake_case")]
        pub enum $name { $($variant),+ }

        impl $name {
            pub const ALL: &'static [$name] = &[$($name::$variant),+];

            pub const fn as_str(self) -> &'static str {
                match self { $($name::$variant => $text),+ }
            }

            pub fn parse(value: &str) -> Option<Self> {
                match value { $($text => Some($name::$variant),)+ _ => None }
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(self.as_str())
            }
        }
    };
}
pub(crate) use string_enum;

string_enum!(TaskState {
    Draft => "draft",
    Planned => "planned",
    AwaitingApproval => "awaiting_approval",
    Queued => "queued",
    Running => "running",
    Validating => "validating",
    RetryWait => "retry_wait",
    Completed => "completed",
    Failed => "failed",
    Cancelled => "cancelled",
    Blocked => "blocked",
});

string_enum!(RunState {
    Draft => "draft",
    Planned => "planned",
    AwaitingApproval => "awaiting_approval",
    Queued => "queued",
    Running => "running",
    Paused => "paused",
    Validating => "validating",
    Completed => "completed",
    Failed => "failed",
    Cancelled => "cancelled",
    Blocked => "blocked",
});

// Truthful terminal outcome of a run. A successful tool or model response is
// never by itself `Verified`; see `report::classify_outcome`.
string_enum!(Outcome {
    Verified => "verified",
    Unverified => "unverified",
    Blocked => "blocked",
    Failed => "failed",
    Cancelled => "cancelled",
});

string_enum!(EvidenceClass {
    Observation => "observation",
    Hypothesis => "hypothesis",
    Recommendation => "recommendation",
    AppliedChange => "applied_change",
    ValidatedResult => "validated_result",
});

string_enum!(SideEffect {
    ReadOnly => "read_only",
    LocalMutation => "local_mutation",
    External => "external",
});

string_enum!(ErrorCategory {
    Transient => "transient",
    Permanent => "permanent",
    Policy => "policy",
    Timeout => "timeout",
    Cancelled => "cancelled",
    Validation => "validation",
    Budget => "budget",
    Crash => "crash",
});

impl TaskState {
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Cancelled)
    }

    /// Whether `self -> next` is a legal task transition.
    pub const fn can_transition_to(self, next: Self) -> bool {
        use TaskState::*;
        matches!(
            (self, next),
            (Draft, Planned | Cancelled)
                | (Planned, AwaitingApproval | Queued | Cancelled | Blocked)
                | (AwaitingApproval, Queued | Cancelled | Blocked)
                | (Queued, Running | Cancelled | Blocked)
                | (Running, Validating | RetryWait | Failed | Cancelled | Blocked)
                | (Validating, Completed | Failed | RetryWait | Blocked)
                | (RetryWait, Queued | Cancelled | Failed | Blocked)
                // Operator override after reviewing the blocking reason. Tasks
                // with side effects return to approval, never straight to the queue.
                | (Blocked, Queued | AwaitingApproval | Cancelled)
        )
    }
}

impl RunState {
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Cancelled)
    }

    pub const fn can_transition_to(self, next: Self) -> bool {
        use RunState::*;
        matches!(
            (self, next),
            (Draft, Planned | Cancelled)
                | (Planned, AwaitingApproval | Cancelled)
                | (AwaitingApproval, Planned | Queued | Cancelled)
                | (Queued, Running | Paused | Planned | Cancelled)
                | (
                    Running,
                    Validating | Paused | Planned | Failed | Cancelled | Blocked
                )
                | (Paused, Queued | Planned | Cancelled)
                | (Validating, Completed | Failed | Blocked | Planned | Running)
                | (Blocked, Queued | Planned | Cancelled)
        )
    }
}

impl SideEffect {
    pub const fn is_read_only(self) -> bool {
        matches!(self, Self::ReadOnly)
    }

    /// The most consequential of two side-effect classes.
    pub const fn max(self, other: Self) -> Self {
        match (self, other) {
            (Self::External, _) | (_, Self::External) => Self::External,
            (Self::LocalMutation, _) | (_, Self::LocalMutation) => Self::LocalMutation,
            _ => Self::ReadOnly,
        }
    }
}

impl EvidenceClass {
    /// Classes that may count as engineering evidence when backed by references.
    /// Hypotheses and recommendations (including all model-generated text) never do.
    pub const fn is_evidence(self) -> bool {
        matches!(
            self,
            Self::Observation | Self::AppliedChange | Self::ValidatedResult
        )
    }
}

/// Stable machine-readable reason codes recorded with state changes.
pub mod reason {
    pub const PLAN_SUBMITTED: &str = "plan_submitted";
    pub const PLAN_APPROVED: &str = "plan_approved";
    pub const PLAN_REJECTED: &str = "plan_rejected";
    pub const TASK_APPROVED: &str = "task_approved";
    pub const APPROVAL_REJECTED: &str = "approval_rejected";
    pub const APPROVAL_PENDING: &str = "approval_pending";
    pub const SUPERSEDED: &str = "superseded_by_replan";
    pub const DEPENDENCY_FAILED: &str = "dependency_failed";
    pub const CANCEL_REQUESTED: &str = "cancel_requested";
    pub const PAUSE_REQUESTED: &str = "pause_requested";
    pub const RESUMED: &str = "resumed_by_operator";
    pub const OPERATOR_OVERRIDE: &str = "operator_override";
    pub const RUNTIME_BUDGET: &str = "runtime_budget_exceeded";
    pub const CREDIT_BUDGET: &str = "credit_budget_exceeded";
    pub const ATTEMPTS_EXHAUSTED: &str = "attempts_exhausted";
    pub const TIMEOUT: &str = "task_timeout";
    pub const VALIDATION_FAILED: &str = "success_criteria_not_met";
    pub const WORKER_FAILED: &str = "worker_failed";
    pub const POLICY_DENIED: &str = "policy_denied";
    pub const RETRY_SCHEDULED: &str = "retry_scheduled";
    pub const RECOVERED_AFTER_RESTART: &str = "recovered_after_restart";
    pub const UNCERTAIN_SIDE_EFFECT: &str = "uncertain_side_effect";
    pub const STALE_LEASE: &str = "stale_lease";
    pub const UNKNOWN_ROLE: &str = "worker_role_unavailable";
    pub const ALL_TASKS_SETTLED: &str = "all_tasks_settled";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_task_states_have_no_exits() {
        for from in TaskState::ALL.iter().copied().filter(|s| s.is_terminal()) {
            for to in TaskState::ALL {
                assert!(!from.can_transition_to(*to), "{from} -> {to}");
            }
        }
    }

    #[test]
    fn terminal_run_states_have_no_exits() {
        for from in RunState::ALL.iter().copied().filter(|s| s.is_terminal()) {
            for to in RunState::ALL {
                assert!(!from.can_transition_to(*to), "{from} -> {to}");
            }
        }
    }

    #[test]
    fn execution_requires_queue_and_approval_cannot_be_skipped() {
        assert!(!TaskState::Planned.can_transition_to(TaskState::Running));
        assert!(!TaskState::AwaitingApproval.can_transition_to(TaskState::Running));
        assert!(!TaskState::Draft.can_transition_to(TaskState::Queued));
        assert!(!RunState::Planned.can_transition_to(RunState::Running));
        assert!(!RunState::AwaitingApproval.can_transition_to(RunState::Running));
        assert!(TaskState::Queued.can_transition_to(TaskState::Running));
        // A running task can only complete after validation.
        assert!(!TaskState::Running.can_transition_to(TaskState::Completed));
    }

    #[test]
    fn string_round_trip() {
        for state in TaskState::ALL {
            assert_eq!(TaskState::parse(state.as_str()), Some(*state));
        }
        for state in RunState::ALL {
            assert_eq!(RunState::parse(state.as_str()), Some(*state));
        }
        assert_eq!(TaskState::parse("bogus"), None);
    }

    #[test]
    fn llm_classes_are_never_evidence() {
        assert!(!EvidenceClass::Hypothesis.is_evidence());
        assert!(!EvidenceClass::Recommendation.is_evidence());
        assert!(EvidenceClass::ValidatedResult.is_evidence());
    }
}
