//! Opt-in live acceptance test: model-generated planning on OpenMindAI Cloud.
//!
//! Runs only with `CODETWIN_TEST_OPENMINDAI_LIVE=1`. The developer key comes
//! from `OPENMINDAI_API_KEY`, or from the OS credential store entry the
//! desktop app uses when `CODETWIN_TEST_OPENMINDAI_KEYRING=1`. Models are
//! taken from `OPENMINDAI_TEST_MODELS` (comma-separated, default
//! `openmindai-lite`). Only a synthetic fixture goal and repository are used;
//! source excerpts are never consented. Spends a few application credits.
//!
//! A 200 response is not success: the plan must be model-sourced, complete,
//! a valid DAG, inside every role contract, gated on operator approval, and
//! must execute to a verified outcome once approved.
use std::fs;
use std::sync::Arc;

use codetwin_core::cloud_settings::CloudSettings;
use codetwin_core::model_planner::{PlanSource, DEFAULT_PLANNER_OUTPUT_CEILING};
use codetwin_core::specialist_workers::{plan_investigation, registry, InvestigationOptions};
use codetwin_core::workflow_platform::{CloudProvider, WorkflowPlatform};
use codetwin_core::{Database, ProjectIndexService};
use model_gateway::client::{ChatClient, ClientConfig, ProviderProfile};
use model_gateway::credentials::{CredentialStore, EnvCredentialStore, KeyringStore, Secret};
use model_gateway::router::RoleModels;
use task_orchestrator::{CancelToken, GlobalLimits, Outcome, RunState};

const DESKTOP_KEY_ACCOUNT: &str = "openmindai-developer-key";

fn live_key() -> Option<Secret> {
    if std::env::var("CODETWIN_TEST_OPENMINDAI_LIVE").as_deref() != Ok("1") {
        eprintln!("skipped: set CODETWIN_TEST_OPENMINDAI_LIVE=1 to run");
        return None;
    }
    let from_env = EnvCredentialStore {
        variable: "OPENMINDAI_API_KEY".into(),
    }
    .get("openmindai")
    .expect("read env");
    let key = from_env.or_else(|| {
        (std::env::var("CODETWIN_TEST_OPENMINDAI_KEYRING").as_deref() == Ok("1"))
            .then(|| {
                KeyringStore
                    .get(DESKTOP_KEY_ACCOUNT)
                    .expect("credential store")
            })
            .flatten()
    });
    Some(key.expect("no OpenMindAI key in OPENMINDAI_API_KEY or the OS credential store"))
}

fn models() -> Vec<String> {
    std::env::var("OPENMINDAI_TEST_MODELS")
        .unwrap_or_else(|_| "openmindai-lite".into())
        .split(',')
        .map(|m| m.trim().to_owned())
        .filter(|m| !m.is_empty())
        .collect()
}

#[test]
fn reasoning_model_produces_a_complete_validated_approvable_plan() {
    let Some(key) = live_key() else { return };
    for model in models() {
        plan_and_execute(&key, &model);
    }
}

fn plan_and_execute(key: &Secret, model: &str) {
    let root = tempfile::tempdir().unwrap();
    fs::write(
        root.path().join("session.ts"),
        "export function createSession(user: string) { return { user, token: Math.random().toString(36), expires: Date.now() + 3600e3 }; }\n\
         export function isExpired(s: { expires: number }) { return Date.now() > s.expires; }\n",
    )
    .unwrap();
    fs::write(
        root.path().join("package.json"),
        r#"{"name":"fixture","dependencies":{"jsonwebtoken":"8.5.1"},"devDependencies":{"jest":"29.0.0"}}"#,
    )
    .unwrap();
    let data = tempfile::tempdir().unwrap();
    let db_path = data.path().join("codetwin.sqlite3");
    let db = Database::open(&db_path).unwrap();
    let project_id = ProjectIndexService::new(&db)
        .index_project(root.path())
        .unwrap()
        .project_id;
    // Cloud allowed for planning; no source excerpts, no local fallback.
    CloudSettings::new(&db)
        .grant_consent(
            &project_id,
            true,
            false,
            false,
            false,
            65_536,
            "live-operator",
        )
        .unwrap();

    let client = ChatClient::new(
        ProviderProfile::openmindai(model_gateway::OPENMINDAI_DEFAULT_BASE_URL).unwrap(),
        Some(key.clone()),
        ClientConfig::openmindai(),
    )
    .unwrap();
    let p = WorkflowPlatform::new(
        db_path.clone(),
        "live-test".into(),
        Arc::new(GlobalLimits::new(4)),
        Some(CloudProvider {
            client: Arc::new(client),
            model: model.into(),
        }),
    )
    .with_models(None, RoleModels::default());
    let goal = "Review how session tokens are created and expired in session.ts, \
                check the jsonwebtoken dependency for known advisories, and list the tests that cover sessions.";
    let options = InvestigationOptions {
        ai_planning: true,
        ..Default::default()
    };
    let (run, approvals, info) = p
        .create_planned_investigation(&project_id, goal, "live-operator", &options, None)
        .unwrap();
    for a in &info.attempts {
        eprintln!(
            "[{model}] attempt {} mode={} max_tokens={} finish={:?} completion_tokens={:?} reasoning_chars={} -> {}",
            a.attempt, a.mode, a.max_tokens, a.finish_reason, a.completion_tokens, a.reasoning_chars, a.outcome
        );
    }

    // 1. Model-sourced, not the template fallback.
    let PlanSource::Model {
        model: answered_by,
        route,
        ..
    } = &info.source
    else {
        panic!("[{model}] fell back to the template: {:?}", info.source);
    };
    assert_eq!(route, "cloud");
    eprintln!(
        "[{model}] plan by {answered_by}; rationale: {:?}; dropped: {:?}",
        info.rationale, info.rejected
    );
    let last = info.attempts.last().expect("attempts recorded");
    assert!(last.outcome.starts_with("accepted"), "{last:?}");
    assert_ne!(last.finish_reason.as_deref(), Some("length"));
    assert!(info
        .attempts
        .iter()
        .all(|a| a.max_tokens <= DEFAULT_PLANNER_OUTPUT_CEILING));

    // 2. Different from the deterministic template.
    let detail = p.detail(&run.id).unwrap();
    let keys: Vec<String> = detail.tasks.iter().map(|t| t.key.clone()).collect();
    let template: Vec<String> = plan_investigation(goal, &options)
        .into_iter()
        .map(|t| t.key)
        .collect();
    assert_ne!(keys, template, "[{model}] plan equals the template");

    // 3. Valid DAG; every task inside its role contract.
    // Stored dependencies reference task ids; compare by key.
    let key_of: std::collections::BTreeMap<&str, &str> = detail
        .tasks
        .iter()
        .map(|t| (t.id.as_str(), t.key.as_str()))
        .collect();
    let edges: Vec<(String, String)> = detail
        .tasks
        .iter()
        .flat_map(|t| {
            t.depends_on.iter().map(|d| {
                let dep = key_of
                    .get(d.as_str())
                    .expect("dependency is a task of this run");
                (t.key.clone(), (*dep).to_owned())
            })
        })
        .collect();
    task_orchestrator::dag::topological_order(&keys, &edges, &Default::default())
        .expect("plan is a DAG");
    // Detail lists tasks by priority, not plan order: `repo` must be the sole root.
    let roots: Vec<&str> = detail
        .tasks
        .iter()
        .filter(|t| t.depends_on.is_empty())
        .map(|t| t.key.as_str())
        .collect();
    assert_eq!(roots, ["repo"], "[{model}] repo must be the only root");
    for k in ["verify", "report", "quality"] {
        assert!(
            keys.iter().any(|x| x == k),
            "[{model}] mandatory tail task {k} missing"
        );
    }
    let contracts = registry();
    for t in &detail.tasks {
        let contract = contracts
            .get(&t.role)
            .expect("known role")
            .contract()
            .clone();
        assert!(
            t.capabilities.is_subset(&contract.capabilities),
            "{}",
            t.key
        );
        task_orchestrator::policy::validate_schema(&contract.input_schema, &t.input)
            .unwrap_or_else(|e| panic!("{}: {e}", t.key));
    }

    // 4. Gated on operator approval: nothing decided by the model.
    assert_eq!(run.state, RunState::AwaitingApproval);
    assert!(!approvals.is_empty());
    assert!(approvals
        .iter()
        .all(|a| a.status == "pending" && a.decided_by.is_none() && a.scope_digest.len() == 64));

    // 5. Budgets: planning credits are within the run budget.
    assert!(run.budgets.max_credits >= info.attempts.len() as u32);

    // 6. Digest-bound approval, then execution to a verified outcome.
    for a in &approvals {
        assert!(
            p.decide(&a.id, true, "live-operator", "0".repeat(64).as_str(), None)
                .is_err(),
            "a wrong digest must not approve"
        );
        p.decide(&a.id, true, "live-operator", &a.scope_digest, None)
            .unwrap();
    }
    let run = p.execute(&run.id, Some(&CancelToken::new())).unwrap();
    assert_eq!(run.state, RunState::Completed, "[{model}] {run:?}");
    assert_eq!(run.outcome, Some(Outcome::Verified), "[{model}] {run:?}");
    eprintln!(
        "[{model}] executed {} tasks to {:?}",
        keys.len(),
        run.outcome
    );
}
