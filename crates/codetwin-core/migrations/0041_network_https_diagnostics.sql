-- Bounded HTTPS request diagnostic categories, never raw transport errors or certificates.
-- Null for historic scans, unselected HTTPS ports, and verified HTTPS responses.
ALTER TABLE network_assessment_probes
ADD COLUMN https_failure_kind TEXT CHECK (
  https_failure_kind IS NULL OR https_failure_kind IN (
    'budget_exhausted', 'setup_failed', 'timeout',
    'connection_or_tls_failure', 'request_failed'
  )
);
