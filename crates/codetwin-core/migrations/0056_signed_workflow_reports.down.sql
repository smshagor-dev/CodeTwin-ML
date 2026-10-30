-- Reverts 0056.
DROP TABLE workflow_report_signatures;
DROP TABLE trusted_report_signers;
DROP TRIGGER workflow_reports_append_only;
DROP TABLE workflow_reports;
