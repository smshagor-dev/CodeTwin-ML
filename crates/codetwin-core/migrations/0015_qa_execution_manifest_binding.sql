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
  )
BEGIN
  SELECT RAISE(ABORT, 'approved QA execution plan requires a bound project manifest');
END;

CREATE TRIGGER qa_execution_approved_insert_requires_manifest
BEFORE INSERT ON qa_execution_plans
WHEN NEW.status = 'approved'
  AND (
    NEW.approved_project_manifest_sha256 IS NULL
    OR NEW.approved_project_manifest_json IS NULL
    OR length(NEW.approved_project_manifest_sha256) != 64
  )
BEGIN
  SELECT RAISE(ABORT, 'approved QA execution plan requires a bound project manifest');
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

CREATE TRIGGER qa_execution_run_manifest_matches_plan
BEFORE INSERT ON qa_execution_runs
WHEN NEW.project_manifest_sha256 IS NULL
  OR NEW.project_manifest_sha256 IS NOT (
    SELECT approved_project_manifest_sha256
    FROM qa_execution_plans
    WHERE id = NEW.plan_id
  )
BEGIN
  SELECT RAISE(ABORT, 'QA execution run manifest must match the approved plan manifest');
END;
