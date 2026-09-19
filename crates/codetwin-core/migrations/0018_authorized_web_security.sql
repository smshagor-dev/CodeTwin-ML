CREATE TABLE web_security_scans (
  id TEXT PRIMARY KEY,
  website_id TEXT REFERENCES websites(id) ON DELETE SET NULL,
  project_id TEXT REFERENCES projects(id) ON DELETE SET NULL,
  target_url TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('queued','running','completed','failed','cancelled')),
  phase TEXT NOT NULL CHECK(phase IN ('queued','discovering','crawling','passive_analysis','active_testing','correlating','completed','failed','cancelled')),
  authorization_confirmed INTEGER NOT NULL CHECK(authorization_confirmed = 1),
  scope_json TEXT NOT NULL,
  config_json TEXT NOT NULL,
  auth_metadata_json TEXT NOT NULL,
  endpoints_discovered INTEGER NOT NULL DEFAULT 0 CHECK(endpoints_discovered >= 0),
  requests_performed INTEGER NOT NULL DEFAULT 0 CHECK(requests_performed >= 0),
  findings_count INTEGER NOT NULL DEFAULT 0 CHECK(findings_count >= 0),
  last_error TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  started_at TEXT,
  finished_at TEXT,
  cancelled_at TEXT
);

CREATE INDEX idx_web_security_scans_website_created
  ON web_security_scans(website_id, created_at DESC);
CREATE INDEX idx_web_security_scans_project_created
  ON web_security_scans(project_id, created_at DESC);
CREATE INDEX idx_web_security_scans_status_created
  ON web_security_scans(status, created_at DESC);

CREATE TABLE web_security_endpoints (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL REFERENCES web_security_scans(id) ON DELETE CASCADE,
  url TEXT NOT NULL,
  method TEXT NOT NULL,
  depth INTEGER NOT NULL CHECK(depth >= 0),
  source TEXT NOT NULL,
  parameter_names_json TEXT NOT NULL,
  parameter_locations_json TEXT NOT NULL DEFAULT '{}',
  response_header_names_json TEXT NOT NULL DEFAULT '[]',
  cookie_names_json TEXT NOT NULL DEFAULT '[]',
  content_type TEXT,
  status_code INTEGER,
  redirect_to TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(scan_id, method, url)
);
CREATE INDEX idx_web_security_endpoints_scan_method
  ON web_security_endpoints(scan_id, method, url);

CREATE TABLE web_security_findings (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL REFERENCES web_security_scans(id) ON DELETE CASCADE,
  fingerprint TEXT NOT NULL,
  category TEXT NOT NULL,
  severity TEXT NOT NULL CHECK(severity IN ('critical','high','medium','low','informational')),
  confidence TEXT NOT NULL CHECK(confidence IN ('Potential','Likely','Confirmed')),
  target TEXT NOT NULL,
  endpoint_url TEXT NOT NULL,
  method TEXT NOT NULL,
  parameter_name TEXT,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  reproduction_summary TEXT NOT NULL,
  impact TEXT NOT NULL,
  remediation TEXT NOT NULL,
  references_json TEXT NOT NULL,
  source_file_id TEXT REFERENCES files(id) ON DELETE SET NULL,
  source_symbol_id TEXT REFERENCES symbols(id) ON DELETE SET NULL,
  source_confidence REAL,
  status TEXT NOT NULL DEFAULT 'open'
    CHECK(status IN ('open','resolved','accepted_risk','false_positive')),
  first_detected TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_detected TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(scan_id, fingerprint)
);
CREATE INDEX idx_web_security_findings_scan_severity
  ON web_security_findings(scan_id, severity, confidence, status);
CREATE INDEX idx_web_security_findings_endpoint
  ON web_security_findings(scan_id, endpoint_url, category);

CREATE TABLE web_security_evidence (
  id TEXT PRIMARY KEY,
  finding_id TEXT NOT NULL REFERENCES web_security_findings(id) ON DELETE CASCADE,
  summary TEXT NOT NULL,
  request_metadata_json TEXT NOT NULL,
  response_metadata_json TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_web_security_evidence_finding
  ON web_security_evidence(finding_id, created_at);
