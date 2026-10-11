CREATE TABLE assessment_scopes (
 project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
 revision INTEGER NOT NULL CHECK(revision > 0),
 root_path TEXT NOT NULL,
 input_hash TEXT NOT NULL CHECK(length(input_hash)=64),
 file_count INTEGER NOT NULL CHECK(file_count BETWEEN 1 AND 2000),
 max_files INTEGER NOT NULL CHECK(max_files BETWEEN 1 AND 2000),
 budget_seconds INTEGER NOT NULL CHECK(budget_seconds BETWEEN 1 AND 3600),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 PRIMARY KEY(project_id,revision)
);
CREATE TABLE assessment_jobs (
 id TEXT PRIMARY KEY,
 project_id TEXT NOT NULL,
 scope_revision INTEGER NOT NULL,
 definition_version INTEGER NOT NULL DEFAULT 1 CHECK(definition_version=1),
 status TEXT NOT NULL DEFAULT 'planned' CHECK(status IN ('planned','running','completed','failed','cancelled','interrupted')),
 cancel_requested INTEGER NOT NULL DEFAULT 0 CHECK(cancel_requested IN (0,1)),
 message TEXT,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 started_at TEXT,
 finished_at TEXT,
 FOREIGN KEY(project_id,scope_revision) REFERENCES assessment_scopes(project_id,revision) ON DELETE CASCADE
);
CREATE UNIQUE INDEX assessment_single_active_project ON assessment_jobs(project_id) WHERE status='running';
CREATE TABLE assessment_steps (
 job_id TEXT NOT NULL REFERENCES assessment_jobs(id) ON DELETE CASCADE,
 position INTEGER NOT NULL CHECK(position BETWEEN 0 AND 1),
 tool_id TEXT NOT NULL CHECK(tool_id IN ('code.sast','code.quality')),
 status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','running','completed','failed','cancelled','interrupted')),
 run_id TEXT REFERENCES analysis_runs(id) ON DELETE SET NULL,
 coverage_complete INTEGER CHECK(coverage_complete IN (0,1)),
 started_at TEXT,
 finished_at TEXT,
 PRIMARY KEY(job_id,position),
 UNIQUE(job_id,tool_id)
);
CREATE TRIGGER assessment_scope_immutable BEFORE UPDATE ON assessment_scopes BEGIN SELECT RAISE(ABORT,'assessment scopes are immutable'); END;
CREATE TRIGGER assessment_plan_binding_immutable BEFORE UPDATE OF project_id,scope_revision,definition_version ON assessment_jobs BEGIN SELECT RAISE(ABORT,'assessment plan binding is immutable'); END;
CREATE TRIGGER assessment_step_binding_immutable BEFORE UPDATE OF job_id,position,tool_id ON assessment_steps BEGIN SELECT RAISE(ABORT,'assessment tool selection is immutable'); END;
