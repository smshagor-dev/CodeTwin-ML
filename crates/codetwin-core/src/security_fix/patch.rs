use super::*;

impl<'a> SecurityFixService<'a> {
    pub fn generate_patch(
        &self,
        attempt_id: &str,
    ) -> Result<PatchReview, SecurityFixError> {
        let attempt = self
            .get_attempt(attempt_id)?
            .ok_or_else(|| SecurityFixError::AttemptNotFound(attempt_id.to_string()))?;
        if attempt.status != "prepared" {
            return Err(SecurityFixError::AttemptNotEditable(attempt.status));
        }
        let root = attempt
            .root_causes
            .first()
            .ok_or(SecurityFixError::PatchGenerationUnavailable)?;
        if root.confidence < 0.82 {
            return Err(SecurityFixError::PatchGenerationUnavailable);
        }
        let snapshot = RepairWorkspaceQueryService::new(self.database)
            .read_source_snapshot(&root.file_id)
            .map_err(|error| SecurityFixError::Source(error.to_string()))?;
        let finding = self.finding_context(&attempt.finding_id)?;
        let proposed = propose_bounded_patch(&finding, &snapshot.content)
            .ok_or(SecurityFixError::PatchGenerationUnavailable)?;
        self.propose_replacement(attempt_id, &root.file_id, &proposed)
    }

    pub fn propose_replacement(
        &self,
        attempt_id: &str,
        file_id: &str,
        proposed_content: &str,
    ) -> Result<PatchReview, SecurityFixError> {
        let attempt = self
            .get_attempt(attempt_id)?
            .ok_or_else(|| SecurityFixError::AttemptNotFound(attempt_id.to_string()))?;
        if !matches!(
            attempt.status.as_str(),
            "prepared" | "patch_proposed" | "rejected"
        ) {
            return Err(SecurityFixError::AttemptNotEditable(attempt.status));
        }
        let repair_id = attempt
            .repair_id
            .as_deref()
            .ok_or(SecurityFixError::PatchGenerationUnavailable)?;
        VerifiedRepairService::new(self.database)
            .add_file_replacement(repair_id, file_id, proposed_content)
            .map_err(|error| SecurityFixError::Repair(error.to_string()))?;

        let review = self.review_attempt(attempt_id)?;
        let next_status = if review.safety.classification == PatchSafetyClass::Rejected {
            "rejected"
        } else {
            "patch_proposed"
        };
        self.database.connection().execute(
            "UPDATE security_fix_attempts
             SET status=?2,patch_hash=?3,safety_class=?4,safety_json=?5,
                 approved_patch_hash=NULL,approved_files_json=NULL,approved_at=NULL,
                 updated_at=CURRENT_TIMESTAMP
             WHERE id=?1",
            params![
                attempt_id,
                next_status,
                review.safety.patch_hash,
                review.safety.classification.as_db(),
                serde_json::to_string(&review.safety)?,
            ],
        )?;
        self.append_event(
            attempt_id,
            "patch_reviewed",
            if next_status == "rejected" {
                "Patch proposal was rejected by the safety analyzer and cannot be approved."
            } else {
                "Patch proposal is ready for explicit developer review."
            },
            &serde_json::to_string(&review.safety)?,
        )?;
        self.review_attempt(attempt_id)
    }

    pub fn review_attempt(
        &self,
        attempt_id: &str,
    ) -> Result<PatchReview, SecurityFixError> {
        let attempt = self
            .get_attempt(attempt_id)?
            .ok_or_else(|| SecurityFixError::AttemptNotFound(attempt_id.to_string()))?;
        let repair_id = attempt
            .repair_id
            .as_deref()
            .ok_or(SecurityFixError::PatchGenerationUnavailable)?;
        let changes = VerifiedRepairService::new(self.database)
            .list_changes(repair_id, MAX_PATCH_FILES + 1)
            .map_err(|error| SecurityFixError::Repair(error.to_string()))?;
        if changes.is_empty() {
            return Err(SecurityFixError::PatchGenerationUnavailable);
        }
        let safety = self.analyze_patch_safety(&attempt, &changes)?;
        let unified_diff = self.unified_diff(&changes)?;
        Ok(PatchReview {
            attempt_id: attempt_id.to_string(),
            repair_id: repair_id.to_string(),
            unified_diff,
            safety,
            affected_files: changes
                .iter()
                .map(|change| change.relative_path.clone())
                .collect(),
            expected_behavior: attempt.strategy.expected_behavior.clone(),
            tests_to_run: attempt
                .test_plan
                .targeted
                .iter()
                .map(|item| item.label.clone())
                .collect(),
            security_retest: attempt.test_plan.security_retest.clone(),
        })
    }

    pub fn approve_attempt(
        &self,
        attempt_id: &str,
        expected_patch_hash: &str,
        accept_caution: bool,
    ) -> Result<SecurityFixAttemptRecord, SecurityFixError> {
        if expected_patch_hash.len() != 64
            || !expected_patch_hash
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(SecurityFixError::StaleApproval);
        }

        let connection = self.database.connection();
        connection.execute_batch("SAVEPOINT security_fix_approval")?;
        let result = (|| -> Result<SecurityFixAttemptRecord, SecurityFixError> {
            let attempt = self
                .get_attempt(attempt_id)?
                .ok_or_else(|| SecurityFixError::AttemptNotFound(attempt_id.to_string()))?;
            if attempt.status != "patch_proposed" {
                return Err(SecurityFixError::AttemptNotApprovable(attempt.status));
            }

            let repair_id = attempt
                .repair_id
                .as_deref()
                .ok_or(SecurityFixError::PatchGenerationUnavailable)?;
            self.assert_attempt_relationships(&attempt, repair_id)?;

            let review = self.review_attempt(attempt_id)?;
            if review.safety.patch_hash != expected_patch_hash
                || attempt.patch_hash.as_deref() != Some(expected_patch_hash)
            {
                return Err(SecurityFixError::StaleApproval);
            }
            match review.safety.classification {
                PatchSafetyClass::Rejected => return Err(SecurityFixError::PatchRejected),
                PatchSafetyClass::Caution if !accept_caution => {
                    return Err(SecurityFixError::CautionAcknowledgementRequired)
                }
                PatchSafetyClass::SafeToReview | PatchSafetyClass::Caution => {}
            }

            let changes = VerifiedRepairService::new(self.database)
                .list_changes(repair_id, MAX_PATCH_FILES + 1)
                .map_err(|error| SecurityFixError::Repair(error.to_string()))?;
            if changes.is_empty() || changes.len() > MAX_PATCH_FILES {
                return Err(SecurityFixError::PatchRejected);
            }
            if patch_hash(&changes) != expected_patch_hash {
                return Err(SecurityFixError::StaleApproval);
            }
            let approved_files = approved_file_identity(&changes);

            VerifiedRepairService::new(self.database)
                .approve_plan(repair_id)
                .map_err(|error| SecurityFixError::Repair(error.to_string()))?;

            let updated = connection.execute(
                "UPDATE security_fix_attempts
                 SET status='approved',approved_patch_hash=?2,approved_files_json=?3,
                     approved_safety_class=?4,caution_acknowledged=?5,
                     approved_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP
                 WHERE id=?1 AND status='patch_proposed' AND patch_hash=?2",
                params![
                    attempt_id,
                    review.safety.patch_hash,
                    serde_json::to_string(&approved_files)?,
                    review.safety.classification.as_db(),
                    if accept_caution { 1i64 } else { 0i64 },
                ],
            )?;
            if updated != 1 {
                return Err(SecurityFixError::StaleApproval);
            }

            self.append_event(
                attempt_id,
                "fix_approved",
                "Developer approved the exact displayed patch identity, affected files and base hashes.",
                &json!({
                    "patch_hash": review.safety.patch_hash,
                    "files": approved_files,
                    "safety_class": review.safety.classification,
                })
                .to_string(),
            )?;

            self.get_attempt(attempt_id)?
                .ok_or_else(|| SecurityFixError::AttemptNotFound(attempt_id.to_string()))
        })();

        match result {
            Ok(record) => {
                connection.execute_batch("RELEASE SAVEPOINT security_fix_approval")?;
                Ok(record)
            }
            Err(error) => {
                let _ = connection.execute_batch(
                    "ROLLBACK TO SAVEPOINT security_fix_approval;
                     RELEASE SAVEPOINT security_fix_approval;",
                );
                Err(error)
            }
        }
    }

    pub fn assert_application_allowed(
        &self,
        attempt_id: &str,
    ) -> Result<String, SecurityFixError> {
        let attempt = self
            .get_attempt(attempt_id)?
            .ok_or_else(|| SecurityFixError::AttemptNotFound(attempt_id.to_string()))?;
        if attempt.status != "approved" {
            return Err(SecurityFixError::AttemptNotApproved);
        }
        let approved_patch = attempt
            .approved_patch_hash
            .as_deref()
            .ok_or(SecurityFixError::AttemptNotApproved)?;
        let approved_files_json = attempt
            .approved_files_json
            .as_deref()
            .ok_or(SecurityFixError::AttemptNotApproved)?;
        let approved_safety = attempt
            .approved_safety_class
            .ok_or(SecurityFixError::AttemptNotApproved)?;
        if approved_safety == PatchSafetyClass::Caution && !attempt.caution_acknowledged {
            return Err(SecurityFixError::AttemptNotApproved);
        }
        let repair_id = attempt
            .repair_id
            .as_deref()
            .ok_or(SecurityFixError::AttemptNotApproved)?;

        let repair = VerifiedRepairService::new(self.database);
        let plan = self.assert_attempt_relationships(&attempt, repair_id)?;
        if plan.status != "approved" {
            return Err(SecurityFixError::AttemptNotApproved);
        }

        let changes = repair
            .list_changes(repair_id, MAX_PATCH_FILES + 1)
            .map_err(|error| SecurityFixError::Repair(error.to_string()))?;
        if changes.is_empty() || changes.len() > MAX_PATCH_FILES {
            return Err(SecurityFixError::StaleApproval);
        }
        let current_hash = patch_hash(&changes);
        let current_files = approved_file_identity(&changes);
        let current_safety = self.analyze_patch_safety(&attempt, &changes)?;
        if current_safety.classification != approved_safety
            || current_safety.classification == PatchSafetyClass::Rejected
        {
            return Err(SecurityFixError::StaleApproval);
        }
        let approved_files: Vec<BTreeMap<String, String>> =
            serde_json::from_str(approved_files_json)?;
        if current_hash != approved_patch || current_files != approved_files {
            return Err(SecurityFixError::StaleApproval);
        }

        for change in &changes {
            let file_id = change
                .file_id
                .as_deref()
                .ok_or(SecurityFixError::StaleApproval)?;
            let snapshot = RepairWorkspaceQueryService::new(self.database)
                .read_source_snapshot(file_id)
                .map_err(|_| SecurityFixError::StaleApproval)?;
            if snapshot.content_hash != change.base_content_hash {
                return Err(SecurityFixError::StaleApproval);
            }
        }
        Ok(repair_id.to_string())
    }

    fn assert_attempt_relationships(
        &self,
        attempt: &SecurityFixAttemptRecord,
        repair_id: &str,
    ) -> Result<RepairPlanRecord, SecurityFixError> {
        let finding = self.finding_context(&attempt.finding_id)?;
        if finding.project_id.as_deref() != Some(attempt.project_id.as_str()) {
            return Err(SecurityFixError::StaleApproval);
        }

        let plan = VerifiedRepairService::new(self.database)
            .get_plan(repair_id)
            .map_err(|error| SecurityFixError::Repair(error.to_string()))?
            .ok_or(SecurityFixError::StaleApproval)?;
        if plan.project_id != attempt.project_id {
            return Err(SecurityFixError::StaleApproval);
        }

        let linked: bool = self.database.connection().query_row(
            "SELECT EXISTS(
                SELECT 1 FROM guided_security_fix_links
                WHERE finding_id=?1 AND repair_id=?2
             )",
            params![attempt.finding_id, repair_id],
            |row| row.get(0),
        )?;
        if !linked {
            return Err(SecurityFixError::StaleApproval);
        }
        Ok(plan)
    }

    fn analyze_patch_safety(
        &self,
        attempt: &SecurityFixAttemptRecord,
        changes: &[RepairChangeRecord],
    ) -> Result<PatchSafetyReport, SecurityFixError> {
        let finding = self.finding_context(&attempt.finding_id)?;
        let mut risk_notes = Vec::new();
        let mut rejected_reasons = Vec::new();
        if changes.len() > MAX_PATCH_FILES {
            rejected_reasons.push(format!(
                "Patch changes {} files; guided fixes are bounded to {MAX_PATCH_FILES}.",
                changes.len()
            ));
        }

        let allowed = attempt
            .root_causes
            .iter()
            .map(|candidate| candidate.file_id.as_str())
            .collect::<BTreeSet<_>>();
        let mut changed_lines = 0usize;

        for change in changes {
            if unsafe_patch_path(&change.relative_path) {
                rejected_reasons.push(format!(
                    "{} escapes or ambiguously addresses the imported project root.",
                    change.relative_path
                ));
                continue;
            }
            let Some(file_id) = change.file_id.as_deref() else {
                rejected_reasons.push(format!(
                    "{} is not bound to an indexed text source file.",
                    change.relative_path
                ));
                continue;
            };
            let source = RepairWorkspaceQueryService::new(self.database)
                .read_source_snapshot(file_id)
                .map_err(|error| SecurityFixError::Source(error.to_string()))?;
            changed_lines = changed_lines
                .saturating_add(line_change_count(&source.content, &change.proposed_content));

            let old_lower = source.content.to_ascii_lowercase();
            let new_lower = change.proposed_content.to_ascii_lowercase();
            let additions = added_lines(&source.content, &change.proposed_content)
                .to_ascii_lowercase();
            let removals = removed_lines(&source.content, &change.proposed_content)
                .to_ascii_lowercase();

            for (needle, message) in [
                (
                    "rejectunauthorized: false",
                    "TLS certificate verification is disabled.",
                ),
                (
                    "node_tls_reject_unauthorized",
                    "Global TLS certificate verification override was introduced.",
                ),
                (
                    "dangerouslysetinnerhtml",
                    "Unsafe React HTML rendering was introduced.",
                ),
                ("child_process", "Shell or process execution surface was introduced."),
                ("eval(", "Dynamic code evaluation was introduced."),
                ("shell=true", "Shell execution was introduced."),
            ] {
                if additions.contains(needle) {
                    rejected_reasons.push(message.into());
                }
            }
            if additions.contains("access-control-allow-origin") && additions.contains('*') {
                rejected_reasons
                    .push("Patch introduces an unrestricted CORS wildcard.".into());
            }
            if looks_like_secret(&additions) {
                rejected_reasons
                    .push("Patch appears to introduce a hardcoded secret or credential.".into());
            }
            let removed_control = [
                "csrf",
                "authorize",
                "authorization",
                "permission",
                "validate",
                "validator",
            ]
            .iter()
            .any(|needle| removals.contains(needle));
            let replacement_control = [
                "csrf",
                "authorize",
                "authorization",
                "permission",
                "validate",
                "validator",
            ]
            .iter()
            .any(|needle| additions.contains(needle));
            if removed_control && !replacement_control {
                rejected_reasons.push(
                    "Patch removes a recognizable security control without a replacement.".into(),
                );
            }
            if additions.contains("catch") && additions.contains("{}") {
                risk_notes.push(
                    "Patch may introduce empty exception handling; review error semantics.".into(),
                );
            }
            if !allowed.contains(file_id)
                && !is_test_path(&change.relative_path)
                && !is_configuration_path(&change.relative_path)
            {
                risk_notes.push(format!(
                    "{} is outside the ranked root-cause set; confirm the change is necessary.",
                    change.relative_path
                ));
            }
            if is_test_path(&change.relative_path)
                && change.proposed_content.lines().count().saturating_mul(2)
                    < source.content.lines().count()
            {
                rejected_reasons.push(format!(
                    "{} removes more than half of an existing test file.",
                    change.relative_path
                ));
            }

            if attempt.category == "sql_injection" {
                if contains_interpolated_sql(&new_lower, finding.parameter_name.as_deref())
                    || introduced_sql_concatenation(&additions)
                    || additions.contains("replace(\"'\"")
                    || additions.contains("replace('\\''")
                {
                    rejected_reasons.push(
                        "SQL injection remediation still uses interpolation, concatenation, or manual quote escaping instead of parameter binding."
                            .into(),
                    );
                }
            }
            if attempt.category == "xss"
                && (additions.contains(".innerhtml")
                    || additions.contains("dangerouslysetinnerhtml"))
            {
                rejected_reasons.push(
                    "XSS remediation introduces or preserves an unsafe rendering sink in changed lines."
                        .into(),
                );
            }
            if old_lower == new_lower {
                rejected_reasons.push(format!(
                    "{} has no effective content change.",
                    change.relative_path
                ));
            }
        }

        if attempt.category == "access_control"
            && changes
                .iter()
                .all(|change| is_frontend_only_path(&change.relative_path))
        {
            rejected_reasons.push(
                "Authorization remediation changes only frontend/UI code and cannot enforce server-side access control."
                    .into(),
            );
        }
        if changed_lines > MAX_CHANGED_LINES_REJECT {
            rejected_reasons.push(format!(
                "Patch changes {changed_lines} lines; maximum bounded guided fix is {MAX_CHANGED_LINES_REJECT}."
            ));
        } else if changed_lines > MAX_CHANGED_LINES_REVIEW {
            risk_notes.push(format!(
                "Patch changes {changed_lines} lines and exceeds the focused-review threshold of {MAX_CHANGED_LINES_REVIEW}."
            ));
        }

        let classification = if !rejected_reasons.is_empty() {
            PatchSafetyClass::Rejected
        } else if risk_notes.is_empty() {
            PatchSafetyClass::SafeToReview
        } else {
            PatchSafetyClass::Caution
        };
        Ok(PatchSafetyReport {
            classification,
            patch_hash: patch_hash(changes),
            files_changed: changes.len(),
            changed_lines,
            risk_notes,
            rejected_reasons,
        })
    }

    fn unified_diff(
        &self,
        changes: &[RepairChangeRecord],
    ) -> Result<String, SecurityFixError> {
        let mut output = String::new();
        for change in changes {
            let file_id = change
                .file_id
                .as_deref()
                .ok_or_else(|| SecurityFixError::State(
                    "repair change is not bound to an indexed file".into(),
                ))?;
            let source = RepairWorkspaceQueryService::new(self.database)
                .read_source_snapshot(file_id)
                .map_err(|error| SecurityFixError::Source(error.to_string()))?;
            output.push_str(&format!(
                "--- a/{}\n+++ b/{}\n",
                change.relative_path, change.relative_path
            ));
            output.push_str(&simple_unified_diff(
                &source.content,
                &change.proposed_content,
            ));
            output.push('\n');
        }
        Ok(output)
    }
}

pub(super) fn propose_bounded_patch(
    finding: &FindingContext,
    content: &str,
) -> Option<String> {
    match finding.category.as_str() {
        "sql_injection" => {
            rewrite_js_sql_parameter_binding(content, finding.parameter_name.as_deref()?)
        }
        "xss" => rewrite_dom_text_sink(content, finding.parameter_name.as_deref()?),
        _ => None,
    }
}

fn rewrite_js_sql_parameter_binding(content: &str, parameter: &str) -> Option<String> {
    let marker = format!("{}{{{parameter}}}", char::from(36));
    let tick = char::from(96);
    let mut changed = false;
    let mut lines = Vec::new();

    for original in content.lines() {
        let lower = original.to_ascii_lowercase();
        let sql_like = ["select ", "update ", "insert ", "delete "]
            .iter()
            .any(|needle| lower.contains(needle));
        let query_call = original.contains(".query(") || original.contains(".execute(");
        if !changed
            && sql_like
            && query_call
            && original.contains(tick)
            && original.matches(&marker).count() == 1
        {
            let quoted_single = format!("'{marker}'");
            let quoted_double = format!("\"{marker}\"");
            let mut line = original
                .replace(&quoted_single, "?")
                .replace(&quoted_double, "?")
                .replace(&marker, "?");
            let last_tick = line.rfind(tick)?;
            let close = line[last_tick + tick.len_utf8()..].find(')')?
                + last_tick
                + tick.len_utf8();
            line.insert_str(close, &format!(", [{parameter}]"));
            if !line.contains(&marker) {
                lines.push(line);
                changed = true;
                continue;
            }
        }
        lines.push(original.to_string());
    }
    changed.then(|| preserve_trailing_newline(content, lines.join("\n")))
}

fn rewrite_dom_text_sink(content: &str, parameter: &str) -> Option<String> {
    let mut changed = false;
    let mut lines = Vec::new();
    for original in content.lines() {
        let trimmed = original.trim();
        let rhs_matches = trimmed.contains(&format!("= {parameter};"))
            || trimmed.contains(&format!("= String({parameter});"));
        if !changed
            && original.contains(".innerHTML")
            && rhs_matches
            && !original.contains("dangerouslySetInnerHTML")
        {
            lines.push(original.replacen(".innerHTML", ".textContent", 1));
            changed = true;
        } else {
            lines.push(original.to_string());
        }
    }
    changed.then(|| preserve_trailing_newline(content, lines.join("\n")))
}

fn preserve_trailing_newline(original: &str, mut value: String) -> String {
    if original.ends_with('\n') && !value.ends_with('\n') {
        value.push('\n');
    }
    value
}

pub(super) fn is_configuration_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.ends_with(".conf")
        || lower.ends_with(".config.js")
        || lower.ends_with(".config.ts")
        || lower.ends_with(".json")
        || lower.ends_with(".toml")
        || lower.ends_with(".yaml")
        || lower.ends_with(".yml")
        || lower.contains("middleware")
        || lower.contains("nginx")
        || lower.contains("server")
        || lower.contains("config")
}

fn unsafe_patch_path(value: &str) -> bool {
    let normalized = value.replace('\\', "/");
    normalized.is_empty()
        || normalized.starts_with('/')
        || normalized.starts_with("//")
        || normalized.as_bytes().get(1).is_some_and(|byte| *byte == b':')
        || normalized
            .split('/')
            .any(|segment| matches!(segment, ".." | "."))
}

fn is_test_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.contains("/test")
        || lower.contains("/tests/")
        || lower.contains("__tests__")
        || lower.ends_with(".test.ts")
        || lower.ends_with(".test.tsx")
        || lower.ends_with(".spec.ts")
        || lower.ends_with(".spec.tsx")
        || lower.ends_with("_test.py")
        || lower.ends_with("_test.rs")
}

fn is_frontend_only_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.ends_with(".tsx")
        || lower.ends_with(".jsx")
        || lower.ends_with(".css")
        || lower.ends_with(".scss")
        || lower.ends_with(".html")
}

fn looks_like_secret(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    ["api_key", "apikey", "secret", "password", "private_key", "bearer "]
        .iter()
        .any(|needle| lower.contains(needle))
        && (lower.contains("=\"")
            || lower.contains("='")
            || lower.contains(": \"")
            || lower.contains(": '"))
}

fn contains_interpolated_sql(text: &str, parameter: Option<&str>) -> bool {
    let sql = ["select ", "update ", "insert ", "delete "]
        .iter()
        .any(|needle| text.contains(needle));
    if !sql {
        return false;
    }
    let marker_prefix = format!("{}{{", char::from(36));
    if let Some(parameter) = parameter {
        let marker = format!("{}{{{parameter}}}", char::from(36));
        text.contains(&marker)
            || text.contains(&format!("+ {parameter}"))
            || text.contains(&format!("{parameter} +"))
    } else {
        text.contains(&marker_prefix)
    }
}

fn introduced_sql_concatenation(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    ["select ", "update ", "insert ", "delete "]
        .iter()
        .any(|needle| lower.contains(needle))
        && lower.contains('+')
}

fn line_change_count(before: &str, after: &str) -> usize {
    let before_lines = before.lines().collect::<Vec<_>>();
    let after_lines = after.lines().collect::<Vec<_>>();
    let max = before_lines.len().max(after_lines.len());
    (0..max)
        .filter(|index| before_lines.get(*index) != after_lines.get(*index))
        .count()
}

fn added_lines(before: &str, after: &str) -> String {
    let before_set = before.lines().collect::<BTreeSet<_>>();
    after
        .lines()
        .filter(|line| !before_set.contains(line))
        .collect::<Vec<_>>()
        .join("\n")
}

fn removed_lines(before: &str, after: &str) -> String {
    let after_set = after.lines().collect::<BTreeSet<_>>();
    before
        .lines()
        .filter(|line| !after_set.contains(line))
        .collect::<Vec<_>>()
        .join("\n")
}

fn simple_unified_diff(before: &str, after: &str) -> String {
    let before_lines = before.lines().collect::<Vec<_>>();
    let after_lines = after.lines().collect::<Vec<_>>();
    let max = before_lines.len().max(after_lines.len());
    let mut output = String::new();
    let mut unchanged_run = false;
    for index in 0..max {
        match (before_lines.get(index), after_lines.get(index)) {
            (Some(left), Some(right)) if left == right => {
                if !unchanged_run {
                    output.push_str(" ... unchanged lines omitted ...\n");
                    unchanged_run = true;
                }
            }
            (left, right) => {
                unchanged_run = false;
                if let Some(left) = left {
                    output.push_str("- ");
                    output.push_str(left);
                    output.push('\n');
                }
                if let Some(right) = right {
                    output.push_str("+ ");
                    output.push_str(right);
                    output.push('\n');
                }
            }
        }
    }
    output
}

fn patch_hash(changes: &[RepairChangeRecord]) -> String {
    let mut identities = changes
        .iter()
        .map(|change| {
            format!(
                "{}\0{}\0{}",
                change.relative_path, change.base_content_hash, change.proposed_content_hash
            )
        })
        .collect::<Vec<_>>();
    identities.sort();
    let mut hasher = Sha256::new();
    for identity in identities {
        hasher.update(identity.as_bytes());
        hasher.update(b"\n");
    }
    format!("{:x}", hasher.finalize())
}

fn approved_file_identity(
    changes: &[RepairChangeRecord],
) -> Vec<BTreeMap<String, String>> {
    let mut values = changes
        .iter()
        .map(|change| {
            BTreeMap::from([
                ("path".to_string(), change.relative_path.clone()),
                ("base_hash".to_string(), change.base_content_hash.clone()),
                (
                    "proposed_hash".to_string(),
                    change.proposed_content_hash.clone(),
                ),
            ])
        })
        .collect::<Vec<_>>();
    values.sort_by(|left, right| left.get("path").cmp(&right.get("path")));
    values
}

#[cfg(test)]
mod tests {
    use super::{
        contains_interpolated_sql, rewrite_dom_text_sink, rewrite_js_sql_parameter_binding,
    };

    #[test]
    fn sql_binding_transform_is_bounded_and_parameterized() {
        let tick = char::from(96);
        let source = format!(
            "async function search(q) {{\n  return db.query({tick}SELECT * FROM products WHERE name = '\\x24{{q}}'{tick});\n}}\n"
        )
        .replace("\\x24", "$");
        let patched = rewrite_js_sql_parameter_binding(&source, "q").expect("patch");
        assert!(patched.contains("WHERE name = ?"));
        assert!(patched.contains("[q]"));
        assert!(!patched.contains(&format!("{}{{q}}", char::from(36))));
        assert!(contains_interpolated_sql(
            &source.to_ascii_lowercase(),
            Some("q")
        ));
        assert!(!contains_interpolated_sql(
            &patched.to_ascii_lowercase(),
            Some("q")
        ));
    }

    #[test]
    fn xss_plain_text_transform_uses_text_content() {
        let source = "function render(q) {\n  output.innerHTML = q;\n}\n";
        let patched = rewrite_dom_text_sink(source, "q").expect("patch");
        assert!(patched.contains("output.textContent = q"));
        assert!(!patched.contains(".innerHTML"));
    }
}
