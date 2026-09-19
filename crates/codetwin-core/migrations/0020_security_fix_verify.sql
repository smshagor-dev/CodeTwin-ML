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
  approved_at TEXT,
  application_run_id TEXT REFERENCES repair_application_runs(id) ON DELETE SET NULL,
  validation_state TEXT NOT NULL DEFAULT 'not_executed'
    CHECK(validation_state IN ('not_executed','passed','failed','partial')),
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
