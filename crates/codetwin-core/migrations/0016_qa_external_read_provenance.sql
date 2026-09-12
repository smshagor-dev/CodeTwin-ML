ALTER TABLE qa_execution_plans ADD COLUMN approved_external_read_surface_sha256 TEXT;
ALTER TABLE qa_execution_plans ADD COLUMN approved_external_read_surface_json TEXT;
ALTER TABLE qa_execution_runs ADD COLUMN external_read_surface_sha256 TEXT;

CREATE TRIGGER qa_execution_approval_requires_external_surface
BEFORE UPDATE OF status ON qa_execution_plans
WHEN NEW.status = 'approved'
  AND (
    NEW.approved_external_read_surface_sha256 IS NULL
    OR NEW.approved_external_read_surface_json IS NULL
    OR length(NEW.approved_external_read_surface_sha256) != 64
    OR lower(NEW.approved_external_read_surface_sha256) GLOB '*[^0-9a-f]*'
  )
BEGIN
  SELECT RAISE(ABORT, 'approved QA execution plan requires a valid bound external read surface');
END;

CREATE TRIGGER qa_execution_approved_insert_requires_external_surface
BEFORE INSERT ON qa_execution_plans
WHEN NEW.status = 'approved'
  AND (
    NEW.approved_external_read_surface_sha256 IS NULL
    OR NEW.approved_external_read_surface_json IS NULL
    OR length(NEW.approved_external_read_surface_sha256) != 64
    OR lower(NEW.approved_external_read_surface_sha256) GLOB '*[^0-9a-f]*'
  )
BEGIN
  SELECT RAISE(ABORT, 'approved QA execution plan requires a valid bound external read surface');
END;

CREATE TRIGGER qa_execution_nonapproved_insert_rejects_external_surface
BEFORE INSERT ON qa_execution_plans
WHEN NEW.status != 'approved'
  AND (
    NEW.approved_external_read_surface_sha256 IS NOT NULL
    OR NEW.approved_external_read_surface_json IS NOT NULL
  )
BEGIN
  SELECT RAISE(ABORT, 'non-approved QA execution plan cannot carry external read-surface evidence');
END;

CREATE TRIGGER qa_execution_external_surface_only_on_approval
BEFORE UPDATE OF approved_external_read_surface_sha256, approved_external_read_surface_json ON qa_execution_plans
WHEN OLD.approved_external_read_surface_sha256 IS NULL
  AND OLD.approved_external_read_surface_json IS NULL
  AND (
    NEW.approved_external_read_surface_sha256 IS NOT NULL
    OR NEW.approved_external_read_surface_json IS NOT NULL
  )
  AND NEW.status != 'approved'
BEGIN
  SELECT RAISE(ABORT, 'QA execution external read surface can only be bound during approval');
END;

CREATE TRIGGER qa_execution_approved_external_surface_immutable
BEFORE UPDATE OF approved_external_read_surface_sha256, approved_external_read_surface_json ON qa_execution_plans
WHEN (
    OLD.approved_external_read_surface_sha256 IS NOT NULL
    OR OLD.approved_external_read_surface_json IS NOT NULL
  )
  AND (
    NEW.approved_external_read_surface_sha256 IS NOT OLD.approved_external_read_surface_sha256
    OR NEW.approved_external_read_surface_json IS NOT OLD.approved_external_read_surface_json
  )
BEGIN
  SELECT RAISE(ABORT, 'approved QA execution external read-surface binding is immutable');
END;

CREATE TRIGGER qa_execution_approved_spec_immutable
BEFORE UPDATE OF project_id, discovery_run_id, runner_kind, request_json, toolchain_json, policy_json, capabilities_json, command_json, provenance_json, blocking_reasons_json ON qa_execution_plans
WHEN OLD.status = 'approved'
  AND (
    NEW.project_id IS NOT OLD.project_id
    OR NEW.discovery_run_id IS NOT OLD.discovery_run_id
    OR NEW.runner_kind IS NOT OLD.runner_kind
    OR NEW.request_json IS NOT OLD.request_json
    OR NEW.toolchain_json IS NOT OLD.toolchain_json
    OR NEW.policy_json IS NOT OLD.policy_json
    OR NEW.capabilities_json IS NOT OLD.capabilities_json
    OR NEW.command_json IS NOT OLD.command_json
    OR NEW.provenance_json IS NOT OLD.provenance_json
    OR NEW.blocking_reasons_json IS NOT OLD.blocking_reasons_json
  )
BEGIN
  SELECT RAISE(ABORT, 'approved QA execution plan specification and provenance are immutable');
END;

CREATE TRIGGER qa_execution_run_external_surface_matches_plan
BEFORE INSERT ON qa_execution_runs
WHEN NEW.external_read_surface_sha256 IS NULL
  OR NOT EXISTS (
    SELECT 1
    FROM qa_execution_plans
    WHERE id = NEW.plan_id
      AND status = 'approved'
      AND approved_external_read_surface_sha256 IS NEW.external_read_surface_sha256
  )
BEGIN
  SELECT RAISE(ABORT, 'QA execution run external read surface must match an approved plan surface');
END;
