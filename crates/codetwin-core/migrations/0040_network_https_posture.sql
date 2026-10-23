-- Add bounded, privacy-reduced HTTPS response-header observations to approved TCP scans.
-- Null for previous results, non-HTTPS ports, or failed TLS verification.
ALTER TABLE network_assessment_probes ADD COLUMN https_posture_json TEXT;
