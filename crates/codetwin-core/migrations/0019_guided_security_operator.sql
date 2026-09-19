CREATE TABLE guided_security_sessions (
  id TEXT PRIMARY KEY,
  website_id TEXT REFERENCES websites(id) ON DELETE SET NULL,
  project_id TEXT REFERENCES projects(id) ON DELETE SET NULL,
  target_url TEXT NOT NULL,
  environment TEXT NOT NULL CHECK(environment IN ('local','development','staging','authorized_production')),
  testing_depth TEXT NOT NULL CHECK(testing_depth IN ('quick','standard','deep','custom')),
  auth_mode TEXT NOT NULL CHECK(auth_mode IN ('none','existing_session','test_account_a','test_accounts_a_b')),
  status TEXT NOT NULL CHECK(status IN ('preparing','awaiting_approval','approved','running','completed','failed','cancelled')),
  authorization_confirmed INTEGER NOT NULL CHECK(authorization_confirmed = 1),
  config_json TEXT NOT NULL,
  preflight_json TEXT NOT NULL DEFAULT '{}',
  application_map_json TEXT NOT NULL DEFAULT '{}',
  plan_json TEXT NOT NULL DEFAULT '{}',
  mapping_requests INTEGER NOT NULL DEFAULT 0 CHECK(mapping_requests >= 0),
  scan_id TEXT UNIQUE REFERENCES web_security_scans(id) ON DELETE SET NULL,
  last_error TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  prepared_at TEXT,
  approved_at TEXT,
  started_at TEXT,
  finished_at TEXT,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_guided_security_sessions_project_created
  ON guided_security_sessions(project_id, created_at DESC);
CREATE INDEX idx_guided_security_sessions_status_created
  ON guided_security_sessions(status, created_at DESC);

CREATE TABLE guided_security_plan_items (
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES guided_security_sessions(id) ON DELETE CASCADE,
  operation_key TEXT NOT NULL,
  endpoint_url TEXT NOT NULL,
  method TEXT NOT NULL,
  parameter_name TEXT,
  category TEXT NOT NULL,
  risk TEXT NOT NULL CHECK(risk IN ('SAFE','CAUTION','RESTRICTED')),
  selected INTEGER NOT NULL CHECK(selected IN (0,1)),
  reason TEXT NOT NULL,
  skip_reason TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(session_id, operation_key)
);
CREATE INDEX idx_guided_security_plan_session
  ON guided_security_plan_items(session_id, risk, selected, category);

CREATE TABLE guided_security_activity (
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES guided_security_sessions(id) ON DELETE CASCADE,
  sequence INTEGER NOT NULL CHECK(sequence >= 1),
  event_type TEXT NOT NULL,
  phase TEXT NOT NULL,
  message TEXT NOT NULL,
  detail_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(session_id, sequence)
);
CREATE INDEX idx_guided_security_activity_session
  ON guided_security_activity(session_id, sequence);

CREATE TABLE guided_security_source_candidates (
  id TEXT PRIMARY KEY,
  finding_id TEXT NOT NULL REFERENCES web_security_findings(id) ON DELETE CASCADE,
  rank INTEGER NOT NULL CHECK(rank >= 1),
  file_id TEXT NOT NULL REFERENCES files(id) ON DELETE CASCADE,
  symbol_id TEXT REFERENCES symbols(id) ON DELETE SET NULL,
  confidence REAL NOT NULL CHECK(confidence >= 0.0 AND confidence <= 1.0),
  rationale TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(finding_id, rank)
);
CREATE INDEX idx_guided_security_source_finding
  ON guided_security_source_candidates(finding_id, rank);

CREATE TABLE guided_security_finding_lifecycle (
  finding_id TEXT PRIMARY KEY REFERENCES web_security_findings(id) ON DELETE CASCADE,
  session_id TEXT REFERENCES guided_security_sessions(id) ON DELETE SET NULL,
  state TEXT NOT NULL CHECK(state IN ('open','fix_proposed','fix_applied','retest_passed','still_vulnerable','unable_to_verify')),
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE guided_security_retests (
  id TEXT PRIMARY KEY,
  finding_id TEXT NOT NULL REFERENCES web_security_findings(id) ON DELETE CASCADE,
  session_id TEXT REFERENCES guided_security_sessions(id) ON DELETE SET NULL,
  status TEXT NOT NULL CHECK(status IN ('retest_passed','still_vulnerable','unable_to_verify')),
  original_confidence TEXT NOT NULL
    CHECK(original_confidence IN ('Potential','Likely','Confirmed')),
  observed_confidence TEXT
    CHECK(observed_confidence IS NULL OR observed_confidence IN ('Potential','Likely','Confirmed')),
  requests_performed INTEGER NOT NULL DEFAULT 0 CHECK(requests_performed >= 0),
  detail_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_guided_security_retests_finding
  ON guided_security_retests(finding_id, created_at DESC);

CREATE TABLE guided_security_comparisons (
  id TEXT PRIMARY KEY,
  session_id TEXT REFERENCES guided_security_sessions(id) ON DELETE SET NULL,
  previous_scan_id TEXT NOT NULL REFERENCES web_security_scans(id) ON DELETE CASCADE,
  current_scan_id TEXT NOT NULL REFERENCES web_security_scans(id) ON DELETE CASCADE,
  comparison_json TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(previous_scan_id, current_scan_id)
);

CREATE TABLE guided_security_fix_links (
  finding_id TEXT PRIMARY KEY REFERENCES web_security_findings(id) ON DELETE CASCADE,
  repair_id TEXT NOT NULL REFERENCES repair_plans(id) ON DELETE CASCADE,
  state TEXT NOT NULL CHECK(state IN ('fix_proposed','fix_applied')),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
