use super::*;

impl<'a> SecurityFixService<'a> {
    pub fn evaluate_eligibility(
        &self,
        finding_id: &str,
    ) -> Result<FixEligibilityAssessment, SecurityFixError> {
        let finding = self.finding_context(finding_id)?;
        let mut reasons = Vec::new();
        let mut candidates = GuidedSecurityStore::new(self.database)
            .correlate_source_candidates(finding_id, MAX_ROOT_CAUSES)
            .map_err(|error| SecurityFixError::Guided(error.to_string()))?;
        let initial_count = candidates.len();

        if finding.confidence == "Potential"
            && !(finding.category == "access_control" && finding.evidence_count >= 2)
        {
            reasons.push(
                "Potential runtime evidence is not strong enough for generated patching.".into(),
            );
            return Ok(FixEligibilityAssessment {
                finding_id: finding_id.to_string(),
                result: FixEligibility::InsufficientEvidence,
                reasons,
                evidence_count: finding.evidence_count,
                source_candidate_count: initial_count,
                best_source_confidence: candidates.first().map(|value| value.confidence),
                supported_language: None,
                bounded_patch_available: false,
            });
        }
        if finding.confidence == "Potential" && finding.category == "access_control" {
            reasons.push(
                "Two-identity authorization evidence remains conservative Potential evidence; CodeTwin may prepare a guided server-side remediation, but never an automatic authorization rewrite."
                    .into(),
            );
        }
        if finding.evidence_count == 0 {
            reasons.push("No persisted runtime evidence is available for the finding.".into());
            return Ok(FixEligibilityAssessment {
                finding_id: finding_id.to_string(),
                result: FixEligibility::InsufficientEvidence,
                reasons,
                evidence_count: 0,
                source_candidate_count: initial_count,
                best_source_confidence: candidates.first().map(|value| value.confidence),
                supported_language: None,
                bounded_patch_available: false,
            });
        }

        let Some(project_id) = finding.project_id.as_deref() else {
            reasons.push(
                "The finding is not associated with an imported CodeTwin project.".into(),
            );
            return Ok(FixEligibilityAssessment {
                finding_id: finding_id.to_string(),
                result: FixEligibility::ManualRemediation,
                reasons,
                evidence_count: finding.evidence_count,
                source_candidate_count: initial_count,
                best_source_confidence: candidates.first().map(|value| value.confidence),
                supported_language: None,
                bounded_patch_available: false,
            });
        };

        if candidates.is_empty() && is_configuration_category(&finding.category) {
            if let Some(candidate) = self.configuration_candidate(project_id, &finding.category)? {
                candidates.push(candidate);
            }
        }

        let Some(best) = candidates.first() else {
            reasons.push("No bounded source or configuration target could be correlated.".into());
            return Ok(FixEligibilityAssessment {
                finding_id: finding_id.to_string(),
                result: FixEligibility::ManualRemediation,
                reasons,
                evidence_count: finding.evidence_count,
                source_candidate_count: 0,
                best_source_confidence: None,
                supported_language: None,
                bounded_patch_available: false,
            });
        };

        let snapshot = match RepairWorkspaceQueryService::new(self.database)
            .read_source_snapshot(&best.file_id)
        {
            Ok(value) => value,
            Err(error) => {
                reasons.push(format!("Source candidate cannot be safely read: {error}"));
                return Ok(FixEligibilityAssessment {
                    finding_id: finding_id.to_string(),
                    result: FixEligibility::ManualRemediation,
                    reasons,
                    evidence_count: finding.evidence_count,
                    source_candidate_count: candidates.len(),
                    best_source_confidence: Some(best.confidence),
                    supported_language: None,
                    bounded_patch_available: false,
                });
            }
        };
        let language = snapshot
            .language
            .clone()
            .unwrap_or_else(|| "unknown".to_string());
        let bounded_patch = super::patch::propose_bounded_patch(&finding, &snapshot.content).is_some();

        let result = if is_configuration_category(&finding.category) {
            if best.confidence >= 0.55 {
                reasons.push(
                    "An in-project configuration candidate exists, but configuration semantics require developer review."
                        .into(),
                );
                FixEligibility::GuidedFixCandidate
            } else {
                reasons.push("Configuration correlation is too weak for generated editing.".into());
                FixEligibility::ManualRemediation
            }
        } else if bounded_patch && best.confidence >= 0.82 {
            reasons.push(
                "Runtime evidence, strong source correlation and a conservative bounded transformation are available."
                    .into(),
            );
            FixEligibility::AutoFixCandidate
        } else if best.confidence >= 0.58 && is_supported_fix_category(&finding.category) {
            reasons.push(
                "A plausible bounded source target exists, but the edit requires guided developer review."
                    .into(),
            );
            FixEligibility::GuidedFixCandidate
        } else {
            reasons.push(
                "Source correlation or category support is insufficient for a generated edit.".into(),
            );
            FixEligibility::ManualRemediation
        };

        Ok(FixEligibilityAssessment {
            finding_id: finding_id.to_string(),
            result,
            reasons,
            evidence_count: finding.evidence_count,
            source_candidate_count: candidates.len(),
            best_source_confidence: Some(best.confidence),
            supported_language: Some(language),
            bounded_patch_available: bounded_patch,
        })
    }

    pub fn analyze_root_causes(
        &self,
        finding_id: &str,
    ) -> Result<Vec<RootCauseCandidate>, SecurityFixError> {
        let finding = self.finding_context(finding_id)?;
        let mut candidates = GuidedSecurityStore::new(self.database)
            .correlate_source_candidates(finding_id, MAX_ROOT_CAUSES)
            .map_err(|error| SecurityFixError::Guided(error.to_string()))?;
        if candidates.is_empty() && is_configuration_category(&finding.category) {
            if let Some(project_id) = finding.project_id.as_deref() {
                if let Some(candidate) =
                    self.configuration_candidate(project_id, &finding.category)?
                {
                    candidates.push(candidate);
                }
            }
        }

        let mut output = Vec::new();
        for candidate in candidates.into_iter().take(MAX_ROOT_CAUSES) {
            let range = candidate
                .symbol_id
                .as_deref()
                .and_then(|symbol_id| self.symbol_range(symbol_id).ok().flatten());
            let mut reasoning = vec![
                candidate.rationale.clone(),
                format!("Runtime endpoint: {} {}", finding.method, finding.endpoint_url),
            ];
            if let Some(parameter) = finding.parameter_name.as_deref() {
                reasoning.push(format!("Affected runtime parameter: {parameter}"));
                if candidate
                    .symbol_name
                    .as_deref()
                    .is_some_and(|name| name.eq_ignore_ascii_case(parameter))
                {
                    reasoning.push(
                        "The correlated symbol name matches the affected runtime parameter.".into(),
                    );
                }
            }
            reasoning.push(format!(
                "{} persisted runtime evidence record(s) support the finding.",
                finding.evidence_count
            ));
            if candidate.confidence < 0.75 {
                reasoning.push(
                    "Correlation remains heuristic; alternative candidates must be reviewed."
                        .into(),
                );
            }
            output.push(RootCauseCandidate {
                file_id: candidate.file_id,
                relative_path: candidate.relative_path,
                symbol_id: candidate.symbol_id,
                symbol_name: candidate.symbol_name,
                source_start_line: range.map(|value| value.0),
                source_end_line: range.map(|value| value.1),
                confidence: candidate.confidence,
                reasoning,
            });
        }
        Ok(output)
    }

    pub fn prepare_fix(
        &self,
        finding_id: &str,
        allow_additional_attempt: bool,
    ) -> Result<SecurityFixPreparation, SecurityFixError> {
        let finding = self.finding_context(finding_id)?;
        let project_id = finding.project_id.clone().ok_or_else(|| {
            SecurityFixError::State(
                "Prepare Fix requires an associated imported CodeTwin project".into(),
            )
        })?;
        let next_attempt = self.next_attempt_number(finding_id)?;
        if next_attempt > MAX_FIX_ATTEMPTS && !allow_additional_attempt {
            return Err(SecurityFixError::AttemptLimitReached);
        }

        let eligibility = self.evaluate_eligibility(finding_id)?;
        let root_causes = self.analyze_root_causes(finding_id)?;
        let mut strategy = build_strategy(&finding, &root_causes);
        if let Some(previous) = self.latest_attempt_for_finding(finding_id)? {
            if previous.status == "still_vulnerable" {
                strategy.rationale.push_str(
                    " A previous guided fix attempt remained vulnerable. The next proposal must address the residual runtime behavior rather than repeat the same patch.",
                );
                if let Some(hash) = previous.patch_hash.as_deref() {
                    strategy
                        .compatibility_risks
                        .push(format!("Previous insufficient patch identity: {hash}."));
                }
            }
        }
        let test_plan = self.build_test_plan_for_context(&finding, &root_causes)?;
        let static_before_json = self.static_security_snapshot(&project_id)?;

        let repair = if matches!(
            eligibility.result,
            FixEligibility::AutoFixCandidate | FixEligibility::GuidedFixCandidate
        ) {
            Some(
                VerifiedRepairService::new(self.database)
                    .create_plan(
                        &project_id,
                        None,
                        &format!("Security fix: {}", bounded_text(&finding.title, 180)),
                        &format!(
                            "Runtime finding {} {} ({}, {}). Root-cause candidates and the remediation strategy are stored in the guided security-fix attempt. This repair plan cannot become applicable until patch safety review and explicit developer approval.",
                            finding.method,
                            finding.endpoint_url,
                            finding.category,
                            finding.confidence
                        ),
                    )
                    .map_err(|error| SecurityFixError::Repair(error.to_string()))?,
            )
        } else {
            None
        };

        if let Some(repair) = repair.as_ref() {
            self.database.connection().execute(
                "INSERT INTO guided_security_fix_links(finding_id, repair_id, state)
                 VALUES (?1,?2,'fix_proposed')
                 ON CONFLICT(finding_id) DO UPDATE SET
                    repair_id=excluded.repair_id,
                    state='fix_proposed',
                    updated_at=CURRENT_TIMESTAMP",
                params![finding.finding_id, repair.id],
            )?;
            GuidedSecurityStore::new(self.database)
                .set_finding_lifecycle(
                    &finding.finding_id,
                    finding.session_id.as_deref(),
                    "fix_proposed",
                )
                .map_err(|error| SecurityFixError::Guided(error.to_string()))?;
        }

        let id = self.random_id("secfix")?;
        self.database.connection().execute(
            "INSERT INTO security_fix_attempts(
                id,finding_id,session_id,project_id,repair_id,attempt_number,eligibility,
                category,status,root_cause_json,strategy_json,test_plan_json,static_before_json
             ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,'prepared',?9,?10,?11,?12)",
            params![
                id,
                finding.finding_id,
                finding.session_id,
                project_id,
                repair.as_ref().map(|record| record.id.as_str()),
                to_i64(next_attempt),
                eligibility.result.as_db(),
                finding.category,
                serde_json::to_string(&root_causes)?,
                serde_json::to_string(&strategy)?,
                serde_json::to_string(&test_plan)?,
                static_before_json,
            ],
        )?;
        self.append_event(
            &id,
            "fix_prepared",
            "Fix eligibility, root-cause candidates, remediation strategy and validation plan prepared. No source was modified.",
            &json!({
                "eligibility": eligibility.result,
                "attempt_number": next_attempt,
                "repair_id": repair.as_ref().map(|record| record.id.as_str()),
            })
            .to_string(),
        )?;

        let attempt = self
            .get_attempt(&id)?
            .ok_or_else(|| SecurityFixError::AttemptNotFound(id.clone()))?;
        Ok(SecurityFixPreparation {
            attempt,
            eligibility,
            root_causes,
            strategy,
            test_plan,
            repair,
        })
    }

    pub fn analyze_multi_finding_overlap(
        &self,
        finding_ids: &[String],
    ) -> Result<MultiFindingOverlap, SecurityFixError> {
        let mut file_to_findings = BTreeMap::<String, BTreeSet<String>>::new();
        for finding_id in finding_ids.iter().take(50) {
            for candidate in self.analyze_root_causes(finding_id)?.into_iter().take(3) {
                file_to_findings
                    .entry(candidate.relative_path)
                    .or_default()
                    .insert(finding_id.clone());
            }
        }
        let overlapping_files = file_to_findings
            .into_iter()
            .filter_map(|(file, findings)| (findings.len() > 1).then_some(file))
            .collect::<Vec<_>>();
        let requires_combined_review = !overlapping_files.is_empty();
        Ok(MultiFindingOverlap {
            finding_ids: finding_ids.iter().take(50).cloned().collect(),
            overlapping_files: overlapping_files.clone(),
            requires_combined_review,
            message: if requires_combined_review {
                "Selected findings overlap the same source files. CodeTwin will not silently merge independent patch proposals; regenerate a combined review."
                    .into()
            } else {
                "No overlapping top source candidates were detected; findings should still be reviewed and applied independently by default."
                    .into()
            },
        })
    }

    pub(crate) fn finding_context(
        &self,
        finding_id: &str,
    ) -> Result<FindingContext, SecurityFixError> {
        self.database
            .connection()
            .query_row(
                "SELECT wf.id,gs.id,ws.project_id,wf.category,wf.confidence,wf.endpoint_url,wf.method,
                        wf.parameter_name,wf.title,wf.description,wf.remediation,
                        (SELECT COUNT(*) FROM web_security_evidence e WHERE e.finding_id=wf.id)
                 FROM web_security_findings wf
                 JOIN web_security_scans ws ON ws.id=wf.scan_id
                 LEFT JOIN guided_security_sessions gs ON gs.scan_id=wf.scan_id
                 WHERE wf.id=?1",
                [finding_id],
                |row| {
                    Ok(FindingContext {
                        finding_id: row.get(0)?,
                        session_id: row.get(1)?,
                        project_id: row.get(2)?,
                        category: row.get(3)?,
                        confidence: row.get(4)?,
                        endpoint_url: row.get(5)?,
                        method: row.get(6)?,
                        parameter_name: row.get(7)?,
                        title: row.get(8)?,
                        description: row.get(9)?,
                        remediation: row.get(10)?,
                        evidence_count: to_usize(row.get(11)?),
                    })
                },
            )
            .optional()?
            .ok_or_else(|| SecurityFixError::FindingNotFound(finding_id.to_string()))
    }

    pub(crate) fn next_attempt_number(
        &self,
        finding_id: &str,
    ) -> Result<usize, SecurityFixError> {
        let value: i64 = self.database.connection().query_row(
            "SELECT COALESCE(MAX(attempt_number),0)+1 FROM security_fix_attempts WHERE finding_id=?1",
            [finding_id],
            |row| row.get(0),
        )?;
        Ok(to_usize(value))
    }

    pub(crate) fn configuration_candidate(
        &self,
        project_id: &str,
        category: &str,
    ) -> Result<Option<crate::GuidedSourceCandidate>, SecurityFixError> {
        let patterns = match category {
            "csp" | "hsts" | "security_headers" => {
                vec!["nginx", "server", "middleware", "config"]
            }
            "cors" => vec!["cors", "server", "middleware", "config"],
            "session_cookie" | "sensitive_cache_control" => {
                vec!["session", "cookie", "server", "middleware", "config"]
            }
            _ => vec!["config"],
        };
        let mut statement = self.database.connection().prepare(
            "SELECT id,relative_path FROM files
             WHERE project_id=?1 AND is_active=1
             ORDER BY relative_path LIMIT 1000",
        )?;
        let rows = statement.query_map([project_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        for row in rows {
            let (file_id, path) = row?;
            let lower = path.to_ascii_lowercase();
            if patterns.iter().any(|needle| lower.contains(needle))
                && super::patch::is_configuration_path(&path)
            {
                return Ok(Some(crate::GuidedSourceCandidate {
                    id: format!("config:{file_id}"),
                    finding_id: String::new(),
                    rank: 1,
                    file_id,
                    relative_path: path,
                    symbol_id: None,
                    symbol_name: None,
                    confidence: 0.60,
                    rationale: "Configuration-oriented finding matched an in-project configuration or middleware file. This is heuristic and requires developer review.".into(),
                    created_at: String::new(),
                }));
            }
        }
        Ok(None)
    }

    pub(crate) fn symbol_range(
        &self,
        symbol_id: &str,
    ) -> Result<Option<(usize, usize)>, SecurityFixError> {
        self.database
            .connection()
            .query_row(
                "SELECT start_line,end_line FROM symbols WHERE id=?1 AND is_active=1",
                [symbol_id],
                |row| {
                    Ok((
                        to_usize(row.get::<_, i64>(0)?),
                        to_usize(row.get::<_, i64>(1)?),
                    ))
                },
            )
            .optional()
            .map_err(Into::into)
    }

    pub(crate) fn static_security_snapshot(
        &self,
        project_id: &str,
    ) -> Result<String, SecurityFixError> {
        let open: i64 = self.database.connection().query_row(
            "SELECT COUNT(*) FROM findings
             WHERE project_id=?1 AND analyzer_key='appsec' AND status='open'",
            [project_id],
            |row| row.get(0),
        )?;
        let by_severity = {
            let mut map = BTreeMap::<String, usize>::new();
            let mut statement = self.database.connection().prepare(
                "SELECT severity,COUNT(*) FROM findings
                 WHERE project_id=?1 AND analyzer_key='appsec' AND status='open'
                 GROUP BY severity",
            )?;
            let rows = statement.query_map([project_id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })?;
            for row in rows {
                let (severity, count) = row?;
                map.insert(severity, to_usize(count));
            }
            map
        };
        Ok(json!({"open_findings": to_usize(open), "by_severity": by_severity}).to_string())
    }

    fn build_test_plan_for_context(
        &self,
        finding: &FindingContext,
        root_causes: &[RootCauseCandidate],
    ) -> Result<SecurityFixTestPlan, SecurityFixError> {
        let project_id = finding
            .project_id
            .as_deref()
            .ok_or_else(|| SecurityFixError::State("test planning requires a project".into()))?;
        let artifacts = QaDiscoveryService::new(self.database)
            .list_artifacts(project_id, true, None, 1_000)
            .map_err(|error| SecurityFixError::QaDiscovery(error.to_string()))?;
        let changed_paths = root_causes
            .iter()
            .take(3)
            .map(|candidate| candidate.relative_path.to_ascii_lowercase())
            .collect::<Vec<_>>();
        let mut targeted = vec![
            SelectedValidation {
                label: "CodeTwin source re-index".into(),
                runner_kind: "codetwin_index".into(),
                targets: root_causes
                    .iter()
                    .take(3)
                    .map(|item| item.relative_path.clone())
                    .collect(),
                reason: "Refresh indexed hashes and symbols after patch application.".into(),
                repository_command_execution_required: false,
            },
            SelectedValidation {
                label: "CodeTwin static security analysis".into(),
                runner_kind: "codetwin_security".into(),
                targets: root_causes
                    .iter()
                    .take(3)
                    .map(|item| item.relative_path.clone())
                    .collect(),
                reason: "Compare source-security signals after the patch; runtime retest remains mandatory.".into(),
                repository_command_execution_required: false,
            },
        ];

        let mut relevant_test_selected = false;
        for artifact in artifacts {
            if artifact.artifact_kind != "test_file" {
                continue;
            }
            let lower = artifact.relative_path.to_ascii_lowercase();
            let relevant = changed_paths.iter().any(|changed| {
                let stem = changed
                    .rsplit('/')
                    .next()
                    .unwrap_or(changed)
                    .split('.')
                    .next()
                    .unwrap_or("");
                !stem.is_empty() && lower.contains(stem)
            }) || lower.contains("security")
                || lower.contains("auth")
                || lower.contains("integration");
            if relevant {
                relevant_test_selected = true;
                targeted.push(SelectedValidation {
                    label: format!("{}: {}", artifact.framework, artifact.relative_path),
                    runner_kind: artifact.framework,
                    targets: vec![artifact.relative_path],
                    reason: "Existing discovered test artifact is related to the changed module or security boundary.".into(),
                    repository_command_execution_required: true,
                });
            }
            if targeted.len() >= 8 {
                break;
            }
        }

        let availability = QaExecutionService::new(self.database).availability();
        Ok(SecurityFixTestPlan {
            targeted,
            full_suite_optional: true,
            qa_execution_available: availability.execution_enabled,
            qa_execution_reason: availability.reason,
            security_retest: format!(
                "Targeted {} retest for {} {}{} using only the original authorized detector family, endpoint and authentication context.",
                finding.category,
                finding.method,
                finding.endpoint_url,
                finding
                    .parameter_name
                    .as_deref()
                    .map(|value| format!(" parameter {value}"))
                    .unwrap_or_default()
            ),
            regression_test_proposal: regression_test_suggestion(&finding.category),
            regression_generation_status: if relevant_test_selected {
                "EXISTING_TEST_SELECTED".into()
            } else {
                "RECOMMENDATION_ONLY".into()
            },
            regression_generation_reason: if relevant_test_selected {
                "CodeTwin selected existing discovered tests related to the changed module/security boundary instead of inventing a new test location.".into()
            } else {
                "No existing test file/framework location could be inferred safely enough for source modification. CodeTwin provides the minimal defensive regression recommendation and records repository execution as unsupported/NOT EXECUTED when the trusted QA backend is unavailable.".into()
            },
        })
    }
}

pub(crate) fn is_supported_fix_category(category: &str) -> bool {
    matches!(
        category,
        "sql_injection"
            | "xss"
            | "csrf"
            | "open_redirect"
            | "access_control"
            | "api_input_validation"
            | "cors"
            | "csp"
            | "hsts"
            | "security_headers"
            | "session_cookie"
            | "sensitive_cache_control"
    )
}

pub(crate) fn is_configuration_category(category: &str) -> bool {
    matches!(
        category,
        "cors"
            | "csp"
            | "hsts"
            | "security_headers"
            | "session_cookie"
            | "sensitive_cache_control"
    )
}

pub(crate) fn regression_test_suggestion(category: &str) -> String {
    match category {
        "sql_injection" => {
            "Add a defensive test proving SQL-looking input is passed as data and cannot alter query structure.".into()
        }
        "xss" => {
            "Add a test proving the original marker remains encoded or non-executable in the same output context.".into()
        }
        "access_control" => {
            "Add a two-identity test proving user B cannot access user A's protected object while user A still can.".into()
        }
        "open_redirect" => {
            "Add a test proving an external redirect target is rejected while approved local redirects still work.".into()
        }
        "csrf" => {
            "Add a test proving a state-changing request without valid CSRF proof is rejected.".into()
        }
        "api_input_validation" => {
            "Add a test proving malformed input returns a deterministic 4xx validation response rather than a 5xx.".into()
        }
        _ => {
            "Add a focused regression test for the original defensive expectation without destructive exploit behavior.".into()
        }
    }
}

pub(crate) fn build_strategy(
    finding: &FindingContext,
    root_causes: &[RootCauseCandidate],
) -> FixStrategy {
    let likely_files = root_causes
        .iter()
        .take(3)
        .map(|candidate| candidate.relative_path.clone())
        .collect::<Vec<_>>();
    let (summary, rationale, expected, risks, prohibited) = match finding.category.as_str() {
        "sql_injection" => (
            "Replace attacker-controlled SQL interpolation or concatenation with prepared statements, parameter binding, or a safe ORM query API.",
            "The vulnerable input must remain data rather than becoming SQL syntax.",
            "Malicious-looking input is handled as a value and cannot change query structure.",
            vec!["Driver placeholder syntax and result typing must remain compatible.".into()],
            vec![
                "Do not rely on manual quote escaping.".into(),
                "Do not blacklist SQL keywords.".into(),
                "Do not hide database errors instead of fixing query construction.".into(),
                "Do not move validation only to the client.".into(),
            ],
        ),
        "xss" => (
            "Use context-appropriate framework-native safe rendering or encoding at the vulnerable sink.",
            "The defense depends on whether the value enters HTML text, an attribute, a URL, or script/JSON context.",
            "The original marker remains non-executable in the same output context while legitimate output still renders.",
            vec!["Encoding semantics can affect intentionally rendered markup.".into()],
            vec![
                "Do not remove the output feature merely to suppress the finding.".into(),
                "Do not blindly HTML-escape script or URL contexts.".into(),
                "Do not introduce unsafe innerHTML-style sinks.".into(),
            ],
        ),
        "csrf" => (
            "Enable the framework-native anti-CSRF middleware or token validation on state-changing requests.",
            "Server-side CSRF validation should protect authenticated state changes.",
            "Cross-site state-changing requests without valid CSRF proof are rejected.",
            vec!["API clients may need explicit token or same-site configuration.".into()],
            vec!["Do not disable CSRF middleware globally.".into()],
        ),
        "open_redirect" => (
            "Validate redirect destinations against local paths or an explicit allow-list.",
            "Untrusted destinations must not control an arbitrary external Location header.",
            "External redirect markers are rejected or normalized to an approved local destination.",
            vec!["Federated-login callbacks may require an explicit allow-list.".into()],
            vec!["Do not use substring or unsafe domain-suffix checks.".into()],
        ),
        "access_control" => (
            "Add a server-side ownership, role, or policy check at the route/controller/service boundary.",
            "Authorization must be enforced on the server for the exact object/action, not by hiding UI controls.",
            "Test identity B cannot access identity A's protected resource while legitimate access still works.",
            vec!["Policy changes can affect legitimate cross-account or admin workflows.".into()],
            vec![
                "Do not implement the fix only in frontend code.".into(),
                "Do not rely on client-provided owner or role fields.".into(),
            ],
        ),
        "api_input_validation" => (
            "Validate the request with the framework/schema layer before business logic and return deterministic 4xx errors.",
            "Malformed input should be rejected before unsafe parser or application paths.",
            "The original malformed input produces a bounded validation error instead of a server failure.",
            vec!["Stricter schemas can reject previously tolerated invalid clients.".into()],
            vec!["Do not only catch and suppress the resulting exception.".into()],
        ),
        "cors" => (
            "Restrict CORS to exact trusted origins and methods required by the application.",
            "Credentialed endpoints must not reflect arbitrary origins.",
            "Untrusted origins do not receive readable credentialed responses.",
            vec!["Legitimate cross-origin clients must be represented in the allow-list.".into()],
            vec!["Do not replace origin validation with an unrestricted wildcard.".into()],
        ),
        "csp" | "hsts" | "security_headers" => (
            "Update framework, server, or reverse-proxy configuration with the missing security header using project-native configuration.",
            "Browser security headers belong at the correct server/configuration boundary.",
            "The target response includes the intended policy without weakening existing headers.",
            vec!["CSP or HSTS can break incompatible resources or subdomains if enabled too broadly.".into()],
            vec!["Do not modify external production infrastructure automatically.".into()],
        ),
        "session_cookie" | "sensitive_cache_control" => (
            "Apply framework-native cookie or cache-control settings centrally on the server.",
            "Cookie and cache policies should not be hardcoded per response with secret material.",
            "The response exposes the intended flags without leaking session material.",
            vec!["Cross-site authentication flows may require SameSite=None with Secure.".into()],
            vec!["Do not hardcode session secrets or cookie values.".into()],
        ),
        _ => (
            "Apply the finding-specific remediation at the strongest correlated server-side source or configuration boundary.",
            "The change must address observed runtime behavior while preserving unrelated behavior.",
            "The original vulnerable behavior is no longer reproducible in a targeted retest.",
            vec!["Source correlation may be incomplete.".into()],
            vec!["Do not disable security checks to make validation pass.".into()],
        ),
    };

    FixStrategy {
        category: finding.category.clone(),
        change_summary: summary.into(),
        rationale: format!(
            "{rationale} Observed runtime detail: {} Existing remediation guidance: {}",
            bounded_text(&finding.description, 600),
            bounded_text(&finding.remediation, 600),
        ),
        likely_files,
        expected_behavior: expected.into(),
        compatibility_risks: risks,
        prohibited_shortcuts: prohibited,
        regression_test_suggestion: regression_test_suggestion(&finding.category),
    }
}
