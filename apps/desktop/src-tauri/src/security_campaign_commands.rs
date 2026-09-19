use codetwin_core::{
    SecurityRemediationBeforeAfterItem, SecurityRemediationCampaignCreate,
    SecurityRemediationCampaignEventRecord, SecurityRemediationCampaignFindingRecord,
    SecurityRemediationCampaignRecord, SecurityRemediationCampaignService,
    SecurityRemediationCampaignSummary, SecurityRemediationDebtView,
    SecurityRemediationRegressionTracking, SecurityRemediationRelationshipRecord,
    SecurityRemediationRollbackAssessment,
};

use super::{with_database, AppState};

#[tauri::command]
pub(crate) fn create_security_remediation_campaign(
    input: SecurityRemediationCampaignCreate,
    state: tauri::State<'_, AppState>,
) -> Result<SecurityRemediationCampaignRecord, String> {
    with_database(&state, |database| {
        SecurityRemediationCampaignService::new(database)
            .create(&input)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
pub(crate) fn analyze_security_remediation_campaign(
    campaign_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<SecurityRemediationCampaignRecord, String> {
    with_database(&state, |database| {
        SecurityRemediationCampaignService::new(database)
            .analyze(&campaign_id)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
pub(crate) fn approve_security_remediation_campaign_plan(
    campaign_id: String,
    expected_plan_hash: String,
    state: tauri::State<'_, AppState>,
) -> Result<SecurityRemediationCampaignRecord, String> {
    with_database(&state, |database| {
        SecurityRemediationCampaignService::new(database)
            .approve_plan(&campaign_id, &expected_plan_hash)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
pub(crate) fn start_security_remediation_campaign(
    campaign_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<SecurityRemediationCampaignRecord, String> {
    with_database(&state, |database| {
        SecurityRemediationCampaignService::new(database)
            .start(&campaign_id)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
pub(crate) fn pause_security_remediation_campaign(
    campaign_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<SecurityRemediationCampaignRecord, String> {
    with_database(&state, |database| {
        SecurityRemediationCampaignService::new(database)
            .pause(&campaign_id)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
pub(crate) fn resume_security_remediation_campaign(
    campaign_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<SecurityRemediationCampaignRecord, String> {
    with_database(&state, |database| {
        SecurityRemediationCampaignService::new(database)
            .resume(&campaign_id)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
pub(crate) fn cancel_security_remediation_campaign(
    campaign_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<SecurityRemediationCampaignRecord, String> {
    with_database(&state, |database| {
        SecurityRemediationCampaignService::new(database)
            .cancel(&campaign_id)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
pub(crate) fn sync_security_remediation_campaign(
    campaign_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<SecurityRemediationCampaignRecord, String> {
    with_database(&state, |database| {
        SecurityRemediationCampaignService::new(database)
            .sync(&campaign_id)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
pub(crate) fn complete_security_remediation_campaign(
    campaign_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<SecurityRemediationCampaignRecord, String> {
    with_database(&state, |database| {
        SecurityRemediationCampaignService::new(database)
            .complete(&campaign_id)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
pub(crate) fn skip_security_remediation_campaign_finding(
    campaign_id: String,
    finding_id: String,
    reason: String,
    state: tauri::State<'_, AppState>,
) -> Result<SecurityRemediationCampaignFindingRecord, String> {
    with_database(&state, |database| {
        SecurityRemediationCampaignService::new(database)
            .skip_finding(&campaign_id, &finding_id, &reason)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
pub(crate) fn get_security_remediation_campaign(
    campaign_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<Option<SecurityRemediationCampaignRecord>, String> {
    with_database(&state, |database| {
        SecurityRemediationCampaignService::new(database)
            .get(&campaign_id)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
pub(crate) fn list_security_remediation_campaigns(
    project_id: Option<String>,
    limit: usize,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<SecurityRemediationCampaignRecord>, String> {
    with_database(&state, |database| {
        SecurityRemediationCampaignService::new(database)
            .list(project_id.as_deref(), limit)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
pub(crate) fn list_security_remediation_campaign_findings(
    campaign_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<SecurityRemediationCampaignFindingRecord>, String> {
    with_database(&state, |database| {
        SecurityRemediationCampaignService::new(database)
            .findings(&campaign_id)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
pub(crate) fn list_security_remediation_campaign_relationships(
    campaign_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<SecurityRemediationRelationshipRecord>, String> {
    with_database(&state, |database| {
        SecurityRemediationCampaignService::new(database)
            .relationships(&campaign_id)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
pub(crate) fn list_security_remediation_campaign_events(
    campaign_id: String,
    limit: usize,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<SecurityRemediationCampaignEventRecord>, String> {
    with_database(&state, |database| {
        SecurityRemediationCampaignService::new(database)
            .events(&campaign_id, limit)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
pub(crate) fn security_remediation_campaign_summary(
    campaign_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<SecurityRemediationCampaignSummary, String> {
    with_database(&state, |database| {
        SecurityRemediationCampaignService::new(database)
            .summary(&campaign_id)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
pub(crate) fn security_remediation_campaign_before_after(
    campaign_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<SecurityRemediationBeforeAfterItem>, String> {
    with_database(&state, |database| {
        SecurityRemediationCampaignService::new(database)
            .before_after(&campaign_id)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
pub(crate) fn security_remediation_campaign_regression_tracking(
    campaign_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<SecurityRemediationRegressionTracking>, String> {
    with_database(&state, |database| {
        SecurityRemediationCampaignService::new(database)
            .regression_tracking(&campaign_id)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
pub(crate) fn assess_security_remediation_campaign_rollback(
    campaign_id: String,
    finding_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<SecurityRemediationRollbackAssessment, String> {
    with_database(&state, |database| {
        SecurityRemediationCampaignService::new(database)
            .rollback_assessment(&campaign_id, &finding_id)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
pub(crate) fn security_remediation_campaign_debt(
    campaign_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<SecurityRemediationDebtView, String> {
    with_database(&state, |database| {
        SecurityRemediationCampaignService::new(database)
            .security_debt(&campaign_id)
            .map_err(|error| error.to_string())
    })
}
