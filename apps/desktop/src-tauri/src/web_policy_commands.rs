//! Testable policy execution/persistence shared by the desktop scan worker.
use codetwin_core::{AuthorizedWebSecurityStore, Database};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use web_security_testing::{
    object_policy_report_metadata, object_policy_scan_outcome, run_object_access_policy,
    AuthContext, ObjectAccessPolicy, ScanConfig, ScanError, ScanOutcome,
};

pub fn run_policy_scan(
    database: &Database,
    scan_id: &str,
    config: &ScanConfig,
    primary: &AuthContext,
    secondary: &AuthContext,
    policy: &ObjectAccessPolicy,
    cancelled: Arc<AtomicBool>,
) -> Result<ScanOutcome, ScanError> {
    let outcome =
        run_object_access_policy(config, primary, secondary, policy, Arc::clone(&cancelled))?;
    if cancelled.load(Ordering::SeqCst) {
        return Err(ScanError::Cancelled);
    }
    let metadata = object_policy_report_metadata(policy, &outcome, primary, secondary);
    AuthorizedWebSecurityStore::new(database)
        .record_object_policy_result(scan_id, &metadata)
        .map_err(|error| ScanError::Discovery(error.to_string()))?;
    let mut scan = object_policy_scan_outcome(policy, outcome);
    for endpoint in &mut scan.endpoints {
        endpoint.url = if endpoint.url == policy.identity_url {
            metadata["identity_url"].as_str()
        } else {
            metadata["object_url"].as_str()
        }
        .unwrap_or("")
        .into();
    }
    for finding in &mut scan.findings {
        finding.endpoint = metadata["object_url"].as_str().unwrap_or("").into();
    }
    Ok(scan)
}
