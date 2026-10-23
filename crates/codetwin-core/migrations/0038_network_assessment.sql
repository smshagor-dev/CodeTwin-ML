-- Reviewed single-target network assessment. Explicit ports only: no CIDR sweeps.
CREATE TABLE network_assessment_runs (
  id TEXT PRIMARY KEY,
  target TEXT NOT NULL,
  ports_json TEXT NOT NULL,
  addresses_json TEXT NOT NULL,
  allow_private_networks INTEGER NOT NULL CHECK(allow_private_networks IN (0,1)),
  authorization_confirmed INTEGER NOT NULL CHECK(authorization_confirmed=1),
  budget_seconds INTEGER NOT NULL CHECK(budget_seconds BETWEEN 1 AND 60),
  status TEXT NOT NULL CHECK(status IN ('planned','approved','running','completed','partial','failed','interrupted','cancelled')),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  started_at TEXT,
  finished_at TEXT,
  message TEXT
);
CREATE INDEX network_assessment_status ON network_assessment_runs(created_at DESC);
CREATE TABLE network_assessment_probes (
  run_id TEXT NOT NULL REFERENCES network_assessment_runs(id) ON DELETE CASCADE,
  port INTEGER NOT NULL CHECK(port BETWEEN 1 AND 65535),
  address TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('open','closed','timeout','unreachable')),
  elapsed_ms INTEGER NOT NULL,
  tls_status TEXT CHECK(tls_status IN ('verified','not_verified')),
  PRIMARY KEY(run_id,port)
);
