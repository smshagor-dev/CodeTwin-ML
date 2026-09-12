ALTER TABLE qa_execution_plans ADD COLUMN approved_project_manifest_sha256 TEXT;
ALTER TABLE qa_execution_plans ADD COLUMN approved_project_manifest_json TEXT;
ALTER TABLE qa_execution_runs ADD COLUMN project_manifest_sha256 TEXT;

CREATE TRIGGER qa_execution_approval_requires_manifest
BEFORE UPDATE OF status ON qa_execution_plans
WHEN NEW.status = 'approved'
  AND (
    NEW.approved_project_manifest_sha256 IS NULL
    OR NEW.approved_project_manifest_json IS NULL
    OR length(NEW.approved_project_manifest_sha256) != 64
    OR lower(NEW.approved_project_manifest_sha256) GLOB '*[^0-9a-f]*'
  )
BEGIN
  SELECT RAISE(ABORT, 'approved QA execution plan requires a valid bound project manifest');
END;

CREATE TRIGGER qa_execution_approved_insert_requires_manifest
BEFORE INSERT ON qa_execution_plans
WHEN NEW.status = 'approved'
  AND (
    NEW.approved_project_manifest_sha256 IS NULL
    OR NEW.approved_project_manifest_json IS NULL
    OR length(NEW.approved_project_manifest_sha256) != 64
    OR lower(NEW.approved_project_manifest_sha256) GLOB '*[^0-9a-f]*'
  )
BEGIN
  SELECT RAISE(ABORT, 'approved QA execution plan requires a valid bound project manifest');
END;

CREATE TRIGGER qa_execution_nonapproved_insert_rejects_manifest
BEFORE INSERT ON qa_execution_plans
WHEN NEW.status != 'approved'
  AND (
    NEW.approved_project_manifest_sha256 IS NOT NULL
    OR NEW.approved_project_manifest_json IS NOT NULL
  )
BEGIN
  SELECT RAISE(ABORT, 'non-approved QA execution plan cannot carry approval manifest evidence');
END;

CREATE TRIGGER qa_execution_manifest_only_on_approval
BEFORE UPDATE OF approved_project_manifest_sha256, approved_project_manifest_json ON qa_execution_plans
WHEN OLD.approved_project_manifest_sha256 IS NULL
  AND OLD.approved_project_manifest_json IS NULL
  AND (
    NEW.approved_project_manifest_sha256 IS NOT NULL
    OR NEW.approved_project_manifest_json IS NOT NULL
  )
  AND NEW.status != 'approved'
BEGIN
  SELECT RAISE(ABORT, 'QA execution project manifest can only be bound during approval');
END;

CREATE TRIGGER qa_execution_approved_manifest_immutable
BEFORE UPDATE OF approved_project_manifest_sha256, approved_project_manifest_json ON qa_execution_plans
WHEN (OLD.approved_project_manifest_sha256 IS NOT NULL OR OLD.approved_project_manifest_json IS NOT NULL)
  AND (
    NEW.approved_project_manifest_sha256 IS NOT OLD.approved_project_manifest_sha256
    OR NEW.approved_project_manifest_json IS NOT OLD.approved_project_manifest_json
  )
BEGIN
  SELECT RAISE(ABORT, 'approved QA execution project manifest binding is immutable');
END;

CREATE TRIGGER qa_execution_approved_status_immutable
BEFORE UPDATE OF status ON qa_execution_plans
WHEN OLD.status = 'approved' AND NEW.status != 'approved'
BEGIN
  SELECT RAISE(ABORT, 'approved QA execution plan status is immutable');
END;

CREATE TRIGGER qa_execution_run_manifest_matches_plan
BEFORE INSERT ON qa_execution_runs
WHEN NEW.project_manifest_sha256 IS NULL
  OR NOT EXISTS (
    SELECT 1
    FROM qa_execution_plans
    WHERE id = NEW.plan_id
      AND status = 'approved'
      AND approved_project_manifest_sha256 IS NEW.project_manifest_sha256
  )
BEGIN
  SELECT RAISE(ABORT, 'QA execution run manifest must match an approved plan manifest');
END;
