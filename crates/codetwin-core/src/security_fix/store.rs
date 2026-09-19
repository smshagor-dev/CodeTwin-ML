use super::*;

impl<'a> SecurityFixService<'a> {
    pub fn record_application(
        &self,
        attempt_id: &str,
        application_run_id: &str,
    ) -> Result<SecurityFixAttemptRecord, SecurityFixError> {
        let attempt = self
            .get_attempt(attempt_id)?
            .ok_or_else(|| SecurityFixError::AttemptNotFound(attempt_id.to_string()))?;
        let run: Option<(String, String)> = self
            .database
            .connection()
            .query_row(
                "SELECT repair_id,status FROM repair_application_runs WHERE id=?1",
                [application_run_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((repair_id, status)) = run else {
            return Err(SecurityFixError::State(
                "repair application run not found".into(),
            ));
        };
        if attempt.repair_id.as_deref() != Some(repair_id.as_str()) {
            return Err(SecurityFixError::State(
                "repair application does not belong to this fix attempt".into(),
            ));
        }
        if status != "applied" {
            return Err(SecurityFixError::State(format!(
                "repair application status is {status}"
            )));
        }

        let retest_floor_rowid: i64 = self.database.connection().query_row(
            "SELECT COALESCE(MAX(rowid),0)
             FROM guided_security_retests
             WHERE finding_id=?1",
            [&attempt.finding_id],
            |row| row.get(0),
        )?;
        self.database.connection().execute(
            "UPDATE security_fix_attempts
             SET status='applied',application_run_id=?2,retest_floor_rowid=?3,
                 validation_state='not_executed',retest_state='not_executed',
                 updated_at=CURRENT_TIMESTAMP WHERE id=?1",
            params![attempt_id, application_run_id, retest_floor_rowid],
        )?;
        self.append_event(
            attempt_id,
            "patch_applied",
            "Approved patch was applied by the existing transactional repair subsystem. Repository validation and targeted security retest are pending.",
            &json!({
                "application_run_id": application_run_id,
                "retest_floor_rowid": retest_floor_rowid,
            }).to_string(),
        )?;
        self.get_attempt(attempt_id)?
            .ok_or_else(|| SecurityFixError::AttemptNotFound(attempt_id.to_string()))
    }

    pub fn record_rollback(
        &self,
        attempt_id: &str,
        application_run_id: &str,
    ) -> Result<SecurityFixAttemptRecord, SecurityFixError> {
        let attempt = self
            .get_attempt(attempt_id)?
            .ok_or_else(|| SecurityFixError::AttemptNotFound(attempt_id.to_string()))?;
        if attempt.application_run_id.as_deref() != Some(application_run_id) {
            return Err(SecurityFixError::State(
                "rollback run does not match the applied fix attempt".into(),
            ));
        }
        let run_status: Option<String> = self
            .database
            .connection()
            .query_row(
                "SELECT status FROM repair_application_runs WHERE id=?1",
                [application_run_id],
                |row| row.get(0),
            )
            .optional()?;
        if run_status.as_deref() != Some("rolled_back") {
            return Err(SecurityFixError::State(
                "rollback has not completed successfully".into(),
            ));
        }
        if attempt.status == "rolled_back" {
            return Ok(attempt);
        }

        self.database.connection().execute(
            "UPDATE security_fix_attempts
             SET status='rolled_back',updated_at=CURRENT_TIMESTAMP WHERE id=?1",
            [attempt_id],
        )?;
        self.append_event(
            attempt_id,
            "fix_rolled_back",
            "Rollback restored the pre-fix file state. Historical patch, validation and retest evidence was retained.",
            &json!({"application_run_id": application_run_id}).to_string(),
        )?;
        self.get_attempt(attempt_id)?
            .ok_or_else(|| SecurityFixError::AttemptNotFound(attempt_id.to_string()))
    }

    pub fn record_application_recovery_rollback(
        &self,
        attempt_id: &str,
        application_run_id: &str,
    ) -> Result<SecurityFixAttemptRecord, SecurityFixError> {
        let attempt = self
            .get_attempt(attempt_id)?
            .ok_or_else(|| SecurityFixError::AttemptNotFound(attempt_id.to_string()))?;
        if attempt.status != "approved" || attempt.application_run_id.is_some() {
            return Err(SecurityFixError::State(
                "application recovery rollback requires an approved attempt without an applied-run link"
                    .into(),
            ));
        }

        let run: Option<(String, String)> = self
            .database
            .connection()
            .query_row(
                "SELECT repair_id,status FROM repair_application_runs WHERE id=?1",
                [application_run_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((repair_id, status)) = run else {
            return Err(SecurityFixError::State(
                "repair application run not found".into(),
            ));
        };
        if attempt.repair_id.as_deref() != Some(repair_id.as_str()) {
            return Err(SecurityFixError::State(
                "recovery rollback run does not belong to this fix attempt".into(),
            ));
        }
        if status != "rolled_back" {
            return Err(SecurityFixError::State(format!(
                "recovery rollback requires rolled_back application status; current status is {status}"
            )));
        }

        let retest_floor_rowid: i64 = self.database.connection().query_row(
            "SELECT COALESCE(MAX(rowid),0)
             FROM guided_security_retests
             WHERE finding_id=?1",
            [&attempt.finding_id],
            |row| row.get(0),
        )?;
        self.database.connection().execute(
            "UPDATE security_fix_attempts
             SET status='rolled_back',application_run_id=?2,retest_floor_rowid=?3,
                 updated_at=CURRENT_TIMESTAMP WHERE id=?1",
            params![attempt_id, application_run_id, retest_floor_rowid],
        )?;
        self.append_event(
            attempt_id,
            "application_bookkeeping_rollback",
            "The patch application completed, but security bookkeeping did not. CodeTwin automatically restored the pre-fix file state and retained the repair application audit record.",
            &json!({
                "application_run_id": application_run_id,
                "retest_floor_rowid": retest_floor_rowid,
            })
            .to_string(),
        )?;
        self.get_attempt(attempt_id)?
            .ok_or_else(|| SecurityFixError::AttemptNotFound(attempt_id.to_string()))
    }

    pub fn add_validation_result(
        &self,
        attempt_id: &str,
        input: ValidationResultInput<'_>,
    ) -> Result<SecurityFixValidationRecord, SecurityFixError> {
        if self.get_attempt(attempt_id)?.is_none() {
            return Err(SecurityFixError::AttemptNotFound(attempt_id.to_string()));
        }
        if !matches!(input.status, "PASS" | "FAIL" | "NOT_EXECUTED") {
            return Err(SecurityFixError::State(
                "invalid validation status".into(),
            ));
        }
        if !matches!(
            input.classification,
            "NONE"
                | "PRE_EXISTING_FAILURE"
                | "PATCH_INTRODUCED_FAILURE"
                | "INFRASTRUCTURE_FAILURE"
                | "UNKNOWN"
        ) {
            return Err(SecurityFixError::State(
                "invalid validation classification".into(),
            ));
        }
        let sequence: i64 = self.database.connection().query_row(
            "SELECT COALESCE(MAX(sequence),0)+1
             FROM security_fix_validation_results WHERE attempt_id=?1",
            [attempt_id],
            |row| row.get(0),
        )?;
        let id = self.random_id("secfixval")?;
        self.database.connection().execute(
            "INSERT INTO security_fix_validation_results(
                id,attempt_id,sequence,command_label,runner_kind,target_json,status,
                exit_code,duration_ms,classification,stdout_summary,stderr_summary
             ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
            params![
                id,
                attempt_id,
                sequence,
                bounded_text(input.command_label, 512),
                bounded_text(input.runner_kind, 128),
                serde_json::to_string(input.targets)?,
                input.status,
                input.exit_code,
                input.duration_ms.and_then(|value| i64::try_from(value).ok()),
                input.classification,
                redact_sensitive_summary(input.stdout_summary, 4_096),
                redact_sensitive_summary(input.stderr_summary, 4_096),
            ],
        )?;
        self.validation_by_id(&id)?
            .ok_or_else(|| SecurityFixError::State(
                "validation result disappeared after persistence".into(),
            ))
    }

    pub fn complete_validation(
        &self,
        attempt_id: &str,
    ) -> Result<SecurityFixAttemptRecord, SecurityFixError> {
        let attempt = self
            .get_attempt(attempt_id)?
            .ok_or_else(|| SecurityFixError::AttemptNotFound(attempt_id.to_string()))?;
        if !matches!(
            attempt.status.as_str(),
            "applied" | "validation_failed" | "verification_pending" | "unable_to_verify"
        ) {
            return Err(SecurityFixError::State(format!(
                "validation cannot complete in status {}",
                attempt.status
            )));
        }

        let results = self.validation_results(attempt_id, MAX_VALIDATIONS)?;
        let patch_failure = results.iter().any(|item| {
            item.status == "FAIL" && item.classification == "PATCH_INTRODUCED_FAILURE"
        });
        let any_failure = results.iter().any(|item| item.status == "FAIL");
        let any_not_executed = results.iter().any(|item| item.status == "NOT_EXECUTED");
        let any_pass = results.iter().any(|item| item.status == "PASS");

        let validation_state = if any_failure {
            "failed"
        } else if !any_pass {
            "not_executed"
        } else if any_not_executed {
            "partial"
        } else {
            "passed"
        };
        let status = if patch_failure {
            "validation_failed"
        } else {
            "verification_pending"
        };
        self.database.connection().execute(
            "UPDATE security_fix_attempts
             SET validation_state=?2,status=?3,updated_at=CURRENT_TIMESTAMP WHERE id=?1",
            params![attempt_id, validation_state, status],
        )?;
        self.append_event(
            attempt_id,
            "validation_completed",
            "Post-patch validation completed. Runtime security retest remains mandatory for Fix Verified.",
            &json!({
                "validation_state": validation_state,
                "patch_introduced_failure": patch_failure,
                "not_executed": any_not_executed,
            })
            .to_string(),
        )?;
        self.get_attempt(attempt_id)?
            .ok_or_else(|| SecurityFixError::AttemptNotFound(attempt_id.to_string()))
    }

    pub fn record_static_after_snapshot(
        &self,
        attempt_id: &str,
    ) -> Result<SecurityFixAttemptRecord, SecurityFixError> {
        let attempt = self
            .get_attempt(attempt_id)?
            .ok_or_else(|| SecurityFixError::AttemptNotFound(attempt_id.to_string()))?;
        let snapshot = self.static_security_snapshot(&attempt.project_id)?;
        self.database.connection().execute(
            "UPDATE security_fix_attempts
             SET static_after_json=?2,updated_at=CURRENT_TIMESTAMP WHERE id=?1",
            params![attempt_id, snapshot],
        )?;
        self.append_event(
            attempt_id,
            "static_security_compared",
            "Post-patch static security analysis snapshot recorded. This is an additional signal and does not replace runtime retesting.",
            &json!({
                "before": attempt.static_before_json,
                "after": snapshot,
            })
            .to_string(),
        )?;
        self.get_attempt(attempt_id)?
            .ok_or_else(|| SecurityFixError::AttemptNotFound(attempt_id.to_string()))
    }

    pub fn sync_retest_result(
        &self,
        finding_id: &str,
        guided_status: &str,
    ) -> Result<Option<SecurityFixAttemptRecord>, SecurityFixError> {
        let Some(attempt) = self.latest_attempt_for_finding(finding_id)? else {
            return Ok(None);
        };
        if !matches!(
            attempt.status.as_str(),
            "applied" | "verification_pending" | "validation_failed" | "unable_to_verify"
        ) {
            return Ok(Some(attempt));
        }

        let validations = self.validation_results(&attempt.id, MAX_VALIDATIONS)?;
        let regression_failure = validations.iter().any(|item| {
            item.status == "FAIL"
                && matches!(
                    item.classification.as_str(),
                    "PATCH_INTRODUCED_FAILURE" | "UNKNOWN"
                )
        });
        let (retest_state, status) = match guided_status {
            "retest_passed" if regression_failure => {
                ("REGRESSION_DETECTED", "validation_failed")
            }
            "retest_passed" => ("FIX_VERIFIED", "fix_verified"),
            "still_vulnerable" => ("STILL_VULNERABLE", "still_vulnerable"),
            "unable_to_verify" => ("UNABLE_TO_VERIFY", "unable_to_verify"),
            _ => {
                return Err(SecurityFixError::State(
                    "invalid guided retest status".into(),
                ))
            }
        };

        self.database.connection().execute(
            "UPDATE security_fix_attempts
             SET retest_state=?2,status=?3,updated_at=CURRENT_TIMESTAMP WHERE id=?1",
            params![attempt.id, retest_state, status],
        )?;
        self.append_event(
            &attempt.id,
            "security_retest_completed",
            match retest_state {
                "FIX_VERIFIED" => {
                    "Original vulnerable runtime behavior was no longer reproducible. Fix Verified."
                }
                "STILL_VULNERABLE" => {
                    "Targeted retest still reproduced the original vulnerability. Revise Fix must analyze the new evidence before another proposal."
                }
                "UNABLE_TO_VERIFY" => {
                    "Runtime verification could not complete safely. Applied — Verification Pending."
                }
                "REGRESSION_DETECTED" => {
                    "Security behavior no longer reproduced, but repository validation indicates a possible patch regression; Fix Verified is withheld."
                }
                _ => "Targeted security retest completed.",
            },
            &json!({
                "guided_status": guided_status,
                "retest_state": retest_state,
            })
            .to_string(),
        )?;
        self.get_attempt(&attempt.id)
    }

    pub fn get_attempt(
        &self,
        attempt_id: &str,
    ) -> Result<Option<SecurityFixAttemptRecord>, SecurityFixError> {
        self.database
            .connection()
            .query_row(
                "SELECT id,finding_id,session_id,project_id,repair_id,attempt_number,eligibility,
                        category,status,root_cause_json,strategy_json,test_plan_json,patch_hash,
                        safety_class,safety_json,approved_patch_hash,approved_files_json,
                        approved_safety_class,caution_acknowledged,approved_at,
                        application_run_id,validation_state,retest_state,static_before_json,
                        static_after_json,created_at,updated_at,retest_floor_rowid
                 FROM security_fix_attempts WHERE id=?1",
                [attempt_id],
                map_attempt,
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn attempt_for_repair(
        &self,
        repair_id: &str,
    ) -> Result<Option<SecurityFixAttemptRecord>, SecurityFixError> {
        self.database
            .connection()
            .query_row(
                "SELECT id,finding_id,session_id,project_id,repair_id,attempt_number,eligibility,
                        category,status,root_cause_json,strategy_json,test_plan_json,patch_hash,
                        safety_class,safety_json,approved_patch_hash,approved_files_json,
                        approved_safety_class,caution_acknowledged,approved_at,
                        application_run_id,validation_state,retest_state,static_before_json,
                        static_after_json,created_at,updated_at,retest_floor_rowid
                 FROM security_fix_attempts WHERE repair_id=?1 LIMIT 1",
                [repair_id],
                map_attempt,
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn attempt_for_application_run(
        &self,
        application_run_id: &str,
    ) -> Result<Option<SecurityFixAttemptRecord>, SecurityFixError> {
        self.database
            .connection()
            .query_row(
                "SELECT id,finding_id,session_id,project_id,repair_id,attempt_number,eligibility,
                        category,status,root_cause_json,strategy_json,test_plan_json,patch_hash,
                        safety_class,safety_json,approved_patch_hash,approved_files_json,
                        approved_safety_class,caution_acknowledged,approved_at,
                        application_run_id,validation_state,retest_state,static_before_json,
                        static_after_json,created_at,updated_at,retest_floor_rowid
                 FROM security_fix_attempts WHERE application_run_id=?1 LIMIT 1",
                [application_run_id],
                map_attempt,
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn list_attempts(
        &self,
        finding_id: &str,
        limit: usize,
    ) -> Result<Vec<SecurityFixAttemptRecord>, SecurityFixError> {
        let mut statement = self.database.connection().prepare(
            "SELECT id,finding_id,session_id,project_id,repair_id,attempt_number,eligibility,
                    category,status,root_cause_json,strategy_json,test_plan_json,patch_hash,
                    safety_class,safety_json,approved_patch_hash,approved_files_json,
                    approved_safety_class,caution_acknowledged,approved_at,
                    application_run_id,validation_state,retest_state,static_before_json,
                    static_after_json,created_at,updated_at,retest_floor_rowid
             FROM security_fix_attempts WHERE finding_id=?1
             ORDER BY attempt_number DESC LIMIT ?2",
        )?;
        let rows = statement.query_map(
            params![finding_id, bounded_limit(limit, 50)],
            map_attempt,
        )?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn validation_results(
        &self,
        attempt_id: &str,
        limit: usize,
    ) -> Result<Vec<SecurityFixValidationRecord>, SecurityFixError> {
        let mut statement = self.database.connection().prepare(
            "SELECT id,attempt_id,sequence,command_label,runner_kind,target_json,status,
                    exit_code,duration_ms,classification,stdout_summary,stderr_summary,created_at
             FROM security_fix_validation_results WHERE attempt_id=?1
             ORDER BY sequence LIMIT ?2",
        )?;
        let rows = statement.query_map(
            params![attempt_id, bounded_limit(limit, MAX_VALIDATIONS)],
            map_validation,
        )?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn events(
        &self,
        attempt_id: &str,
        limit: usize,
    ) -> Result<Vec<SecurityFixEventRecord>, SecurityFixError> {
        let mut statement = self.database.connection().prepare(
            "SELECT id,attempt_id,sequence,event_type,message,detail_json,created_at
             FROM security_fix_events WHERE attempt_id=?1 ORDER BY sequence LIMIT ?2",
        )?;
        let rows = statement.query_map(
            params![attempt_id, bounded_limit(limit, MAX_EVENTS)],
            |row| {
                Ok(SecurityFixEventRecord {
                    id: row.get(0)?,
                    attempt_id: row.get(1)?,
                    sequence: to_usize(row.get(2)?),
                    event_type: row.get(3)?,
                    message: row.get(4)?,
                    detail_json: row.get(5)?,
                    created_at: row.get(6)?,
                })
            },
        )?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub(crate) fn latest_attempt_for_finding(
        &self,
        finding_id: &str,
    ) -> Result<Option<SecurityFixAttemptRecord>, SecurityFixError> {
        self.database
            .connection()
            .query_row(
                "SELECT id,finding_id,session_id,project_id,repair_id,attempt_number,eligibility,
                        category,status,root_cause_json,strategy_json,test_plan_json,patch_hash,
                        safety_class,safety_json,approved_patch_hash,approved_files_json,
                        approved_safety_class,caution_acknowledged,approved_at,
                        application_run_id,validation_state,retest_state,static_before_json,
                        static_after_json,created_at,updated_at,retest_floor_rowid
                 FROM security_fix_attempts WHERE finding_id=?1
                 ORDER BY attempt_number DESC LIMIT 1",
                [finding_id],
                map_attempt,
            )
            .optional()
            .map_err(Into::into)
    }

    pub(crate) fn append_event(
        &self,
        attempt_id: &str,
        event_type: &str,
        message: &str,
        detail_json: &str,
    ) -> Result<(), SecurityFixError> {
        let detail: serde_json::Value = serde_json::from_str(detail_json)?;
        reject_sensitive_json(&detail)?;
        if contains_sensitive_text(message) {
            return Err(SecurityFixError::State(
                "security fix history message must not persist authentication or secret material"
                    .into(),
            ));
        }
        let exists: bool = self.database.connection().query_row(
            "SELECT EXISTS(SELECT 1 FROM security_fix_attempts WHERE id=?1)",
            [attempt_id],
            |row| row.get(0),
        )?;
        if !exists {
            return Err(SecurityFixError::AttemptNotFound(attempt_id.to_string()));
        }

        let sequence: i64 = self.database.connection().query_row(
            "SELECT COALESCE(MAX(sequence),0)+1
             FROM security_fix_events WHERE attempt_id=?1",
            [attempt_id],
            |row| row.get(0),
        )?;
        let id = self.random_id("secfixevt")?;
        self.database.connection().execute(
            "INSERT INTO security_fix_events(
                id,attempt_id,sequence,event_type,message,detail_json
             ) VALUES (?1,?2,?3,?4,?5,?6)",
            params![
                id,
                attempt_id,
                sequence,
                bounded_text(event_type, 128),
                bounded_text(message, 2_048),
                detail_json,
            ],
        )?;
        Ok(())
    }

    pub(crate) fn random_id(&self, prefix: &str) -> Result<String, SecurityFixError> {
        let random: String = self.database.connection().query_row(
            "SELECT lower(hex(randomblob(16)))",
            [],
            |row| row.get(0),
        )?;
        Ok(format!("{prefix}_{random}"))
    }

    fn validation_by_id(
        &self,
        id: &str,
    ) -> Result<Option<SecurityFixValidationRecord>, SecurityFixError> {
        self.database
            .connection()
            .query_row(
                "SELECT id,attempt_id,sequence,command_label,runner_kind,target_json,status,
                        exit_code,duration_ms,classification,stdout_summary,stderr_summary,created_at
                 FROM security_fix_validation_results WHERE id=?1",
                [id],
                map_validation,
            )
            .optional()
            .map_err(Into::into)
    }
}

fn map_attempt(row: &rusqlite::Row<'_>) -> rusqlite::Result<SecurityFixAttemptRecord> {
    let eligibility_text: String = row.get(6)?;
    let root_cause_json: String = row.get(9)?;
    let strategy_json: String = row.get(10)?;
    let test_plan_json: String = row.get(11)?;
    let safety_class_text: Option<String> = row.get(13)?;
    let safety_json: String = row.get(14)?;
    Ok(SecurityFixAttemptRecord {
        id: row.get(0)?,
        finding_id: row.get(1)?,
        session_id: row.get(2)?,
        project_id: row.get(3)?,
        repair_id: row.get(4)?,
        attempt_number: to_usize(row.get(5)?),
        eligibility: FixEligibility::parse(&eligibility_text)
            .map_err(|error| sqlite_conversion_error(6, error.to_string()))?,
        category: row.get(7)?,
        status: row.get(8)?,
        root_causes: serde_json::from_str(&root_cause_json)
            .map_err(|error| sqlite_conversion_error(9, error.to_string()))?,
        strategy: serde_json::from_str(&strategy_json)
            .map_err(|error| sqlite_conversion_error(10, error.to_string()))?,
        test_plan: serde_json::from_str(&test_plan_json)
            .map_err(|error| sqlite_conversion_error(11, error.to_string()))?,
        patch_hash: row.get(12)?,
        safety_class: safety_class_text
            .as_deref()
            .map(PatchSafetyClass::parse)
            .transpose()
            .map_err(|error| sqlite_conversion_error(13, error.to_string()))?,
        safety: if safety_json == "{}" {
            None
        } else {
            Some(
                serde_json::from_str(&safety_json)
                    .map_err(|error| sqlite_conversion_error(14, error.to_string()))?,
            )
        },
        approved_patch_hash: row.get(15)?,
        approved_files_json: row.get(16)?,
        approved_safety_class: row
            .get::<_, Option<String>>(17)?
            .as_deref()
            .map(PatchSafetyClass::parse)
            .transpose()
            .map_err(|error| sqlite_conversion_error(17, error.to_string()))?,
        caution_acknowledged: row.get::<_, i64>(18)? != 0,
        approved_at: row.get(19)?,
        application_run_id: row.get(20)?,
        validation_state: row.get(21)?,
        retest_state: row.get(22)?,
        static_before_json: row.get(23)?,
        static_after_json: row.get(24)?,
        created_at: row.get(25)?,
        updated_at: row.get(26)?,
        retest_floor_rowid: row.get(27)?,
    })
}

fn map_validation(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<SecurityFixValidationRecord> {
    let target_json: String = row.get(5)?;
    let duration: Option<i64> = row.get(8)?;
    Ok(SecurityFixValidationRecord {
        id: row.get(0)?,
        attempt_id: row.get(1)?,
        sequence: to_usize(row.get(2)?),
        command_label: row.get(3)?,
        runner_kind: row.get(4)?,
        targets: serde_json::from_str(&target_json)
            .map_err(|error| sqlite_conversion_error(5, error.to_string()))?,
        status: row.get(6)?,
        exit_code: row.get(7)?,
        duration_ms: duration.and_then(|value| u64::try_from(value).ok()),
        classification: row.get(9)?,
        stdout_summary: row.get(10)?,
        stderr_summary: row.get(11)?,
        created_at: row.get(12)?,
    })
}

fn sqlite_conversion_error(index: usize, message: String) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        index,
        rusqlite::types::Type::Text,
        message.into(),
    )
}

#[cfg(test)]
mod tests {
    use super::super::{PatchSafetyClass, SecurityFixError};

    #[test]
    fn product_status_names_are_stable() {
        assert_eq!(PatchSafetyClass::SafeToReview.as_db(), "SAFE_TO_REVIEW");
        assert!(matches!(
            SecurityFixError::StaleApproval.to_string().as_str(),
            "Source changed since approval. Regenerate/review the fix."
        ));
    }
}
