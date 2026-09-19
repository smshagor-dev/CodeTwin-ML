CREATE TABLE security_fix_attempts (
  id TEXT PRIMARY KEY,
  finding_id TEXT NOT NULL REFERENCES web_security_findings(id) ON DELETE CASCADE,
  session_id TEXT REFERENCES guided_security_sessions(id) ON DELETE SET NULL,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  repair_id TEXT UNIQUE REFERENCES repair_plans(id) ON DELETE SET NULL,
  attempt_number INTEGER NOT NULL CHECK(attempt_number >= 1),
  eligibility TEXT NOT NULL CHECK(eligibility IN (
    'AUTO_FIX_CANDIDATE','GUIDED_FIX_CANDIDATE','MANUAL_REMEDIATION','INSUFFICIENT_EVIDENCE'
  )),
  category TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN (
    'prepared','patch_proposed','rejected','approved','applied',
    'validation_failed','verification_pending','fix_verified',
    'still_vulnerable','unable_to_verify','rolled_back'
  )),
  root_cause_json TEXT NOT NULL DEFAULT '[]',
  strategy_json TEXT NOT NULL DEFAULT '{}',
  test_plan_json TEXT NOT NULL DEFAULT '{}',
  patch_hash TEXT,
  safety_class TEXT CHECK(safety_class IS NULL OR safety_class IN ('SAFE_TO_REVIEW','CAUTION','REJECTED')),
  safety_json TEXT NOT NULL DEFAULT '{}',
  approved_patch_hash TEXT,
  approved_files_json TEXT,
  approved_safety_class TEXT
    CHECK(approved_safety_class IS NULL OR approved_safety_class IN ('SAFE_TO_REVIEW','CAUTION')),
  caution_acknowledged INTEGER NOT NULL DEFAULT 0 CHECK(caution_acknowledged IN (0,1)),
  approved_at TEXT,
  application_run_id TEXT REFERENCES repair_application_runs(id) ON DELETE SET NULL,
  validation_state TEXT NOT NULL DEFAULT 'not_executed'
    CHECK(validation_state IN ('not_executed','passed','failed','partial')),
  static_before_json TEXT NOT NULL DEFAULT '{}',
  static_after_json TEXT NOT NULL DEFAULT '{}',
  retest_state TEXT NOT NULL DEFAULT 'not_executed'
    CHECK(retest_state IN ('not_executed','FIX_VERIFIED','STILL_VULNERABLE','UNABLE_TO_VERIFY','REGRESSION_DETECTED')),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(finding_id, attempt_number)
);
CREATE INDEX idx_security_fix_attempts_finding
  ON security_fix_attempts(finding_id, attempt_number DESC);
CREATE INDEX idx_security_fix_attempts_project_status
  ON security_fix_attempts(project_id, status, updated_at DESC);

CREATE TABLE security_fix_validation_results (
  id TEXT PRIMARY KEY,
  attempt_id TEXT NOT NULL REFERENCES security_fix_attempts(id) ON DELETE CASCADE,
  sequence INTEGER NOT NULL CHECK(sequence >= 1),
  command_label TEXT NOT NULL,
  runner_kind TEXT NOT NULL,
  target_json TEXT NOT NULL DEFAULT '[]',
  status TEXT NOT NULL CHECK(status IN ('PASS','FAIL','NOT_EXECUTED')),
  exit_code INTEGER,
  duration_ms INTEGER CHECK(duration_ms IS NULL OR duration_ms >= 0),
  classification TEXT NOT NULL CHECK(classification IN (
    'NONE','PRE_EXISTING_FAILURE','PATCH_INTRODUCED_FAILURE','INFRASTRUCTURE_FAILURE','UNKNOWN'
  )),
  stdout_summary TEXT NOT NULL DEFAULT '',
  stderr_summary TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(attempt_id, sequence)
);
CREATE INDEX idx_security_fix_validation_attempt
  ON security_fix_validation_results(attempt_id, sequence);

CREATE TABLE security_fix_events (
  id TEXT PRIMARY KEY,
  attempt_id TEXT NOT NULL REFERENCES security_fix_attempts(id) ON DELETE CASCADE,
  sequence INTEGER NOT NULL CHECK(sequence >= 1),
  event_type TEXT NOT NULL,
  message TEXT NOT NULL,
  detail_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(attempt_id, sequence)
);
CREATE INDEX idx_security_fix_events_attempt
  ON security_fix_events(attempt_id, sequence);


-- Approval identity becomes immutable once approval has been recorded. Lifecycle
-- fields may continue to advance, but a different finding, patch, file set,
-- safety result, or base/proposed identity can never reuse the approval.
CREATE TRIGGER security_fix_attempt_approval_identity_immutable
BEFORE UPDATE ON security_fix_attempts
WHEN OLD.approved_at IS NOT NULL AND (
  NEW.finding_id IS NOT OLD.finding_id OR
  NEW.session_id IS NOT OLD.session_id OR
  NEW.project_id IS NOT OLD.project_id OR
  NEW.repair_id IS NOT OLD.repair_id OR
  NEW.attempt_number IS NOT OLD.attempt_number OR
  NEW.eligibility IS NOT OLD.eligibility OR
  NEW.category IS NOT OLD.category OR
  NEW.root_cause_json IS NOT OLD.root_cause_json OR
  NEW.strategy_json IS NOT OLD.strategy_json OR
  NEW.test_plan_json IS NOT OLD.test_plan_json OR
  NEW.patch_hash IS NOT OLD.patch_hash OR
  NEW.safety_class IS NOT OLD.safety_class OR
  NEW.safety_json IS NOT OLD.safety_json OR
  NEW.approved_patch_hash IS NOT OLD.approved_patch_hash OR
  NEW.approved_files_json IS NOT OLD.approved_files_json OR
  NEW.approved_safety_class IS NOT OLD.approved_safety_class OR
  NEW.caution_acknowledged IS NOT OLD.caution_acknowledged OR
  NEW.approved_at IS NOT OLD.approved_at OR
  NEW.static_before_json IS NOT OLD.static_before_json OR
  NEW.created_at IS NOT OLD.created_at
)
BEGIN
  SELECT RAISE(ABORT, 'approved security fix identity is immutable');
END;

-- FIX_VERIFIED is a persistence invariant, not a UI convention. It requires a
-- successful targeted runtime retest after the applied repair plus no blocking
-- patch-introduced/unknown validation regression.
CREATE TRIGGER security_fix_verified_requires_retest
BEFORE UPDATE OF status, retest_state ON security_fix_attempts
WHEN NEW.status = 'fix_verified' AND (
  NEW.retest_state <> 'FIX_VERIFIED' OR
  NEW.application_run_id IS NULL OR
  NOT EXISTS (
    SELECT 1
    FROM guided_security_retests gr
    JOIN repair_application_runs rar ON rar.id = NEW.application_run_id
    WHERE gr.finding_id = NEW.finding_id
      AND gr.status = 'retest_passed'
      AND gr.created_at >= COALESCE(rar.completed_at, rar.created_at)
  ) OR
  EXISTS (
    SELECT 1
    FROM security_fix_validation_results vr
    WHERE vr.attempt_id = NEW.id
      AND vr.status = 'FAIL'
      AND vr.classification IN ('PATCH_INTRODUCED_FAILURE','UNKNOWN')
  )
)
BEGIN
  SELECT RAISE(ABORT, 'FIX_VERIFIED requires a successful post-apply targeted retest and no blocking regression');
END;

CREATE TRIGGER security_fix_verified_insert_guard
BEFORE INSERT ON security_fix_attempts
WHEN NEW.status = 'fix_verified' OR NEW.retest_state = 'FIX_VERIFIED'
BEGIN
  SELECT RAISE(ABORT, 'FIX_VERIFIED cannot be inserted directly');
END;

CREATE TRIGGER security_fix_validation_results_immutable
BEFORE UPDATE ON security_fix_validation_results
BEGIN
  SELECT RAISE(ABORT, 'security fix validation history is immutable');
END;

CREATE TRIGGER security_fix_events_immutable
BEFORE UPDATE ON security_fix_events
BEGIN
  SELECT RAISE(ABORT, 'security fix event history is immutable');
END;
