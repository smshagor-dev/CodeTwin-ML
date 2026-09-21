CREATE TABLE security_remediation_campaigns (
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES guided_security_sessions(id) ON DELETE CASCADE,
  scan_id TEXT NOT NULL REFERENCES web_security_scans(id) ON DELETE CASCADE,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  target_url TEXT NOT NULL,
  environment TEXT NOT NULL
    CHECK(environment IN ('local','development','staging','authorized_production')),
  scope_json TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN (
    'DRAFT','ANALYZING','READY_FOR_REVIEW','APPROVED','IN_PROGRESS',
    'PAUSED','BLOCKED','COMPLETED','COMPLETED_WITH_UNRESOLVED_FINDINGS','CANCELLED'
  )),
  selected_count INTEGER NOT NULL CHECK(selected_count BETWEEN 1 AND 500),
  plan_revision INTEGER NOT NULL DEFAULT 0 CHECK(plan_revision >= 0),
  plan_json TEXT NOT NULL DEFAULT '{}',
  plan_hash TEXT,
  approved_plan_hash TEXT,
  baseline_json TEXT NOT NULL,
  completion_json TEXT NOT NULL DEFAULT '{}',
  completion_retest_floor_rowid INTEGER NOT NULL DEFAULT 0 CHECK(completion_retest_floor_rowid >= 0),
  completion_verification_started_at TEXT,
  completion_verification_completed_at TEXT,
  completion_source_hashes_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  analyzed_at TEXT,
  approved_at TEXT,
  started_at TEXT,
  paused_at TEXT,
  finished_at TEXT,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(session_id, id)
);

CREATE INDEX idx_security_remediation_campaigns_project_created
  ON security_remediation_campaigns(project_id, created_at DESC);
CREATE INDEX idx_security_remediation_campaigns_scan_status
  ON security_remediation_campaigns(scan_id, status, updated_at DESC);

CREATE TABLE security_remediation_campaign_findings (
  campaign_id TEXT NOT NULL REFERENCES security_remediation_campaigns(id) ON DELETE CASCADE,
  finding_id TEXT NOT NULL REFERENCES web_security_findings(id) ON DELETE CASCADE,
  ordinal INTEGER NOT NULL CHECK(ordinal >= 1),
  status TEXT NOT NULL CHECK(status IN (
    'QUEUED','PREPARING_FIX','AWAITING_REVIEW','APPLYING','VALIDATING','RETESTING',
    'VERIFIED','STILL_VULNERABLE','MANUAL_ACTION_REQUIRED','UNABLE_TO_VERIFY',
    'REGRESSION_DETECTED','BLOCKED','SKIPPED'
  )),
  eligibility TEXT NOT NULL CHECK(eligibility IN (
    'AUTO_FIX_CANDIDATE','GUIDED_FIX_CANDIDATE','MANUAL_REMEDIATION','INSUFFICIENT_EVIDENCE'
  )),
  severity TEXT NOT NULL CHECK(severity IN ('critical','high','medium','low','informational')),
  confidence TEXT NOT NULL CHECK(confidence IN ('Potential','Likely','Confirmed')),
  category TEXT NOT NULL,
  endpoint_url TEXT NOT NULL,
  source_file_id TEXT REFERENCES files(id) ON DELETE SET NULL,
  source_symbol_id TEXT REFERENCES symbols(id) ON DELETE SET NULL,
  root_file_id TEXT REFERENCES files(id) ON DELETE SET NULL,
  root_symbol_id TEXT REFERENCES symbols(id) ON DELETE SET NULL,
  shared_root_primary_finding_id TEXT REFERENCES web_security_findings(id) ON DELETE SET NULL,
  order_reason TEXT NOT NULL DEFAULT '',
  depends_on_json TEXT NOT NULL DEFAULT '[]',
  expected_affected_json TEXT NOT NULL DEFAULT '[]',
  retest_floor_rowid INTEGER NOT NULL DEFAULT 0 CHECK(retest_floor_rowid >= 0),
  active_attempt_id TEXT REFERENCES security_fix_attempts(id) ON DELETE SET NULL,
  skip_reason TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY(campaign_id, finding_id),
  UNIQUE(campaign_id, ordinal)
);

CREATE INDEX idx_security_remediation_campaign_findings_state
  ON security_remediation_campaign_findings(campaign_id, status, ordinal);
CREATE INDEX idx_security_remediation_campaign_findings_attempt
  ON security_remediation_campaign_findings(active_attempt_id);

CREATE TABLE security_remediation_campaign_relationships (
  id TEXT PRIMARY KEY,
  campaign_id TEXT NOT NULL REFERENCES security_remediation_campaigns(id) ON DELETE CASCADE,
  from_finding_id TEXT NOT NULL,
  to_finding_id TEXT NOT NULL,
  relationship TEXT NOT NULL CHECK(relationship IN (
    'INDEPENDENT','SHARED_ROOT_CAUSE','SOURCE_OVERLAP','VALIDATION_DEPENDENCY',
    'RETEST_DEPENDENCY','POTENTIAL_CONFLICT'
  )),
  confidence REAL NOT NULL CHECK(confidence >= 0.0 AND confidence <= 1.0),
  reason TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(campaign_id, from_finding_id, to_finding_id, relationship),
  FOREIGN KEY(campaign_id, from_finding_id)
    REFERENCES security_remediation_campaign_findings(campaign_id, finding_id) ON DELETE CASCADE,
  FOREIGN KEY(campaign_id, to_finding_id)
    REFERENCES security_remediation_campaign_findings(campaign_id, finding_id) ON DELETE CASCADE
);

CREATE INDEX idx_security_remediation_relationships_campaign
  ON security_remediation_campaign_relationships(campaign_id, relationship, confidence DESC);

CREATE TABLE security_remediation_campaign_events (
  id TEXT PRIMARY KEY,
  campaign_id TEXT NOT NULL REFERENCES security_remediation_campaigns(id) ON DELETE CASCADE,
  sequence INTEGER NOT NULL CHECK(sequence >= 1),
  event_type TEXT NOT NULL,
  message TEXT NOT NULL,
  detail_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(campaign_id, sequence)
);

CREATE INDEX idx_security_remediation_campaign_events_campaign
  ON security_remediation_campaign_events(campaign_id, sequence);

CREATE TRIGGER security_remediation_campaign_finding_scope_guard
BEFORE INSERT ON security_remediation_campaign_findings
WHEN NOT EXISTS (
  SELECT 1
  FROM security_remediation_campaigns c
  JOIN web_security_findings f ON f.id = NEW.finding_id
  WHERE c.id = NEW.campaign_id
    AND f.scan_id = c.scan_id
)
BEGIN
  SELECT RAISE(ABORT, 'campaign finding must belong to the campaign scan');
END;

CREATE TRIGGER security_remediation_campaign_approved_plan_immutable
BEFORE UPDATE OF session_id, scan_id, project_id, target_url, environment, scope_json,
                 selected_count, plan_revision, plan_json, plan_hash,
                 approved_plan_hash, approved_at, baseline_json
ON security_remediation_campaigns
WHEN OLD.approved_plan_hash IS NOT NULL AND (
  NEW.session_id IS NOT OLD.session_id OR
  NEW.scan_id IS NOT OLD.scan_id OR
  NEW.project_id IS NOT OLD.project_id OR
  NEW.target_url IS NOT OLD.target_url OR
  NEW.environment IS NOT OLD.environment OR
  NEW.scope_json IS NOT OLD.scope_json OR
  NEW.selected_count IS NOT OLD.selected_count OR
  NEW.plan_revision IS NOT OLD.plan_revision OR
  NEW.plan_json IS NOT OLD.plan_json OR
  NEW.plan_hash IS NOT OLD.plan_hash OR
  NEW.approved_plan_hash IS NOT OLD.approved_plan_hash OR
  NEW.approved_at IS NOT OLD.approved_at OR
  NEW.baseline_json IS NOT OLD.baseline_json
)
BEGIN
  SELECT RAISE(ABORT, 'approved remediation campaign plan identity is immutable');
END;

CREATE TRIGGER security_remediation_campaign_finding_plan_immutable
BEFORE UPDATE OF campaign_id, finding_id, ordinal, eligibility, severity, confidence, category,
                 endpoint_url, source_file_id, source_symbol_id, root_file_id, root_symbol_id,
                 shared_root_primary_finding_id, order_reason, depends_on_json,
                 expected_affected_json, retest_floor_rowid
ON security_remediation_campaign_findings
WHEN EXISTS (
  SELECT 1 FROM security_remediation_campaigns c
  WHERE c.id = OLD.campaign_id AND c.approved_plan_hash IS NOT NULL
) AND (
  NEW.campaign_id IS NOT OLD.campaign_id OR
  NEW.finding_id IS NOT OLD.finding_id OR
  NEW.ordinal IS NOT OLD.ordinal OR
  NEW.eligibility IS NOT OLD.eligibility OR
  NEW.severity IS NOT OLD.severity OR
  NEW.confidence IS NOT OLD.confidence OR
  NEW.category IS NOT OLD.category OR
  NEW.endpoint_url IS NOT OLD.endpoint_url OR
  NEW.source_file_id IS NOT OLD.source_file_id OR
  NEW.source_symbol_id IS NOT OLD.source_symbol_id OR
  NEW.root_file_id IS NOT OLD.root_file_id OR
  NEW.root_symbol_id IS NOT OLD.root_symbol_id OR
  NEW.shared_root_primary_finding_id IS NOT OLD.shared_root_primary_finding_id OR
  NEW.order_reason IS NOT OLD.order_reason OR
  NEW.depends_on_json IS NOT OLD.depends_on_json OR
  NEW.expected_affected_json IS NOT OLD.expected_affected_json OR
  NEW.retest_floor_rowid IS NOT OLD.retest_floor_rowid
)
BEGIN
  SELECT RAISE(ABORT, 'approved remediation campaign finding plan is immutable');
END;

CREATE TRIGGER security_remediation_campaign_status_transition_guard
BEFORE UPDATE OF status ON security_remediation_campaigns
WHEN OLD.status <> NEW.status AND NOT (
  (OLD.status = 'DRAFT' AND NEW.status IN ('ANALYZING','CANCELLED')) OR
  (OLD.status = 'ANALYZING' AND NEW.status IN ('READY_FOR_REVIEW','BLOCKED','CANCELLED')) OR
  (OLD.status = 'READY_FOR_REVIEW' AND NEW.status IN ('ANALYZING','APPROVED','CANCELLED')) OR
  (OLD.status = 'APPROVED' AND NEW.status IN ('IN_PROGRESS','PAUSED','BLOCKED','CANCELLED')) OR
  (OLD.status = 'IN_PROGRESS' AND NEW.status IN (
    'PAUSED','BLOCKED','COMPLETED','COMPLETED_WITH_UNRESOLVED_FINDINGS','CANCELLED'
  )) OR
  (OLD.status = 'PAUSED' AND NEW.status IN ('IN_PROGRESS','BLOCKED','CANCELLED')) OR
  (OLD.status = 'BLOCKED' AND NEW.status IN (
    'IN_PROGRESS','PAUSED','COMPLETED','COMPLETED_WITH_UNRESOLVED_FINDINGS','CANCELLED'
  ))
)
BEGIN
  SELECT RAISE(ABORT, 'invalid remediation campaign lifecycle transition');
END;

CREATE TRIGGER security_remediation_campaign_finding_transition_guard
BEFORE UPDATE OF status ON security_remediation_campaign_findings
WHEN OLD.status <> NEW.status AND NOT (
  (OLD.status = 'QUEUED' AND NEW.status IN (
    'PREPARING_FIX','AWAITING_REVIEW','APPLYING','VALIDATING','RETESTING',
    'VERIFIED','STILL_VULNERABLE','MANUAL_ACTION_REQUIRED','UNABLE_TO_VERIFY','BLOCKED','SKIPPED'
  )) OR
  (OLD.status = 'PREPARING_FIX' AND NEW.status IN (
    'AWAITING_REVIEW','APPLYING','VALIDATING','RETESTING','VERIFIED',
    'STILL_VULNERABLE','MANUAL_ACTION_REQUIRED','UNABLE_TO_VERIFY',
    'REGRESSION_DETECTED','BLOCKED','SKIPPED','QUEUED'
  )) OR
  (OLD.status = 'AWAITING_REVIEW' AND NEW.status IN (
    'APPLYING','VALIDATING','RETESTING','VERIFIED','STILL_VULNERABLE',
    'UNABLE_TO_VERIFY','REGRESSION_DETECTED','BLOCKED','SKIPPED','QUEUED'
  )) OR
  (OLD.status = 'APPLYING' AND NEW.status IN (
    'VALIDATING','RETESTING','VERIFIED','STILL_VULNERABLE','UNABLE_TO_VERIFY',
    'REGRESSION_DETECTED','BLOCKED','QUEUED'
  )) OR
  (OLD.status = 'VALIDATING' AND NEW.status IN (
    'RETESTING','VERIFIED','STILL_VULNERABLE','UNABLE_TO_VERIFY',
    'REGRESSION_DETECTED','BLOCKED','QUEUED'
  )) OR
  (OLD.status = 'RETESTING' AND NEW.status IN (
    'VERIFIED','STILL_VULNERABLE','UNABLE_TO_VERIFY','REGRESSION_DETECTED',
    'BLOCKED','QUEUED'
  )) OR
  (OLD.status = 'STILL_VULNERABLE' AND NEW.status IN (
    'PREPARING_FIX','AWAITING_REVIEW','RETESTING','VERIFIED',
    'UNABLE_TO_VERIFY','BLOCKED','SKIPPED','QUEUED'
  )) OR
  (OLD.status = 'UNABLE_TO_VERIFY' AND NEW.status IN (
    'PREPARING_FIX','AWAITING_REVIEW','RETESTING','VERIFIED',
    'STILL_VULNERABLE','BLOCKED','SKIPPED','QUEUED'
  )) OR
  (OLD.status = 'REGRESSION_DETECTED' AND NEW.status IN (
    'BLOCKED','QUEUED','PREPARING_FIX','AWAITING_REVIEW','SKIPPED'
  )) OR
  (OLD.status = 'BLOCKED' AND NEW.status IN (
    'QUEUED','PREPARING_FIX','AWAITING_REVIEW','APPLYING','VALIDATING',
    'RETESTING','VERIFIED','STILL_VULNERABLE','UNABLE_TO_VERIFY',
    'MANUAL_ACTION_REQUIRED','SKIPPED'
  )) OR
  (OLD.status = 'MANUAL_ACTION_REQUIRED' AND NEW.status IN (
    'QUEUED','RETESTING','VERIFIED','STILL_VULNERABLE','UNABLE_TO_VERIFY',
    'BLOCKED','SKIPPED'
  )) OR
  (OLD.status = 'VERIFIED' AND NEW.status = 'QUEUED') OR
  (OLD.status = 'SKIPPED' AND NEW.status = 'QUEUED')
)
BEGIN
  SELECT RAISE(ABORT, 'invalid remediation campaign finding transition');
END;

CREATE TRIGGER security_remediation_campaign_verified_requires_evidence
BEFORE UPDATE OF status ON security_remediation_campaign_findings
WHEN NEW.status = 'VERIFIED' AND OLD.status <> 'VERIFIED' AND NOT (
  (
    NEW.active_attempt_id IS NOT NULL AND EXISTS (
      SELECT 1 FROM security_fix_attempts sfa
      WHERE sfa.id = NEW.active_attempt_id
        AND sfa.finding_id = NEW.finding_id
        AND sfa.status = 'fix_verified'
        AND sfa.retest_state = 'FIX_VERIFIED'
    )
  ) OR EXISTS (
    SELECT 1
    FROM guided_security_retests gr
    JOIN security_remediation_campaigns c ON c.id = NEW.campaign_id
    WHERE gr.finding_id = NEW.finding_id
      AND gr.status = 'retest_passed'
      AND gr.rowid > NEW.retest_floor_rowid
  )
)
BEGIN
  SELECT RAISE(ABORT, 'campaign VERIFIED requires persisted Fix & Verify or targeted retest evidence');
END;

CREATE TRIGGER security_remediation_campaign_completion_verification_guard
BEFORE UPDATE OF status ON security_remediation_campaigns
WHEN NEW.status IN ('COMPLETED','COMPLETED_WITH_UNRESOLVED_FINDINGS') AND (
  NEW.completion_verification_completed_at IS NULL OR
  EXISTS (
    SELECT 1
    FROM security_remediation_campaign_findings cf
    WHERE cf.campaign_id = NEW.id
      AND NOT EXISTS (
        SELECT 1
        FROM guided_security_retests gr
        WHERE gr.finding_id = cf.finding_id
          AND gr.rowid > NEW.completion_retest_floor_rowid
      )
  )
)
BEGIN
  SELECT RAISE(ABORT, 'campaign completion requires fresh targeted retest evidence for every selected finding');
END;

CREATE TRIGGER security_remediation_campaign_events_immutable
BEFORE UPDATE ON security_remediation_campaign_events
BEGIN
  SELECT RAISE(ABORT, 'remediation campaign event history is immutable');
END;

CREATE TRIGGER security_remediation_campaign_events_delete_guard
BEFORE DELETE ON security_remediation_campaign_events
BEGIN
  SELECT RAISE(ABORT, 'remediation campaign event history is append-only');
END;
