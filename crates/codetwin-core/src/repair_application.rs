use std::{
    fs::{self, File, OpenOptions, Permissions},
    io::Write,
    path::{Component, Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{Database, RepairChangeRecord, RepairPlanRecord, VerifiedRepairService};

const MAX_APPLICATION_FILES: usize = 500;
const MAX_APPLICATION_FILE_BYTES: u64 = 5 * 1024 * 1024;
const MAX_HISTORY: usize = 200;
const MAX_ERROR_BYTES: usize = 4096;

#[derive(Debug, Error)]
pub enum RepairApplicationError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("repair plan not found: {0}")]
    PlanNotFound(String),
    #[error("repair plan must be approved before application; current status: {0}")]
    PlanNotApproved(String),
    #[error("repair application not found: {0}")]
    ApplicationNotFound(String),
    #[error("repair application is not eligible for rollback; current status: {0}")]
    ApplicationNotApplied(String),
    #[error("repair plan has no proposed changes")]
    NoChanges,
    #[error("repair plan exceeds the application file limit of {MAX_APPLICATION_FILES}")]
    TooManyChanges,
    #[error("unsafe repair path: {0}")]
    UnsafePath(String),
    #[error("repair target is not a regular non-symlink file: {0}")]
    UnsafeTarget(String),
    #[error("repair target exceeds the application byte limit: {0}")]
    OversizedTarget(String),
    #[error("repair base hash no longer matches the repository file: {0}")]
    StaleBase(String),
    #[error("stored proposed content does not match its persisted hash: {0}")]
    CorruptProposal(String),
    #[error("repair backup is missing or corrupt for: {0}")]
    CorruptBackup(String),
    #[error("rollback refused because the current file no longer matches the applied proposal: {0}")]
    RollbackConflict(String),
    #[error("unsafe repair backup root")]
    UnsafeBackupRoot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairApplicationRunRecord {
    pub id: String,
    pub repair_id: String,
    pub project_id: String,
    pub status: String,
    pub changes_total: usize,
    pub changes_applied: usize,
    pub rollback_performed: bool,
    pub backup_dir_name: String,
    pub error_message: Option<String>,
    pub created_at: String,
    pub completed_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairApplicationItemRecord {
    pub run_id: String,
    pub change_id: String,
    pub relative_path: String,
    pub base_content_hash: String,
    pub proposed_content_hash: String,
    pub backup_content_hash: String,
    pub backup_file_name: String,
    pub state: String,
}

pub struct RepairApplicationService<'a> {
    database: &'a Database,
}

impl<'a> RepairApplicationService<'a> {
    pub const fn new(database: &'a Database) -> Self {
        Self { database }
    }

    pub fn apply_plan(
        &self,
        repair_id: &str,
        backup_root: impl AsRef<Path>,
    ) -> Result<RepairApplicationRunRecord, RepairApplicationError> {
        let repair = VerifiedRepairService::new(self.database);
        let plan = repair
            .get_plan(repair_id)
            .map_err(|error| RepairApplicationError::UnsafePath(error.to_string()))?
            .ok_or_else(|| RepairApplicationError::PlanNotFound(repair_id.to_owned()))?;
        if plan.status != "approved" {
            return Err(RepairApplicationError::PlanNotApproved(plan.status));
        }
        let changes = repair
            .list_changes(repair_id, MAX_APPLICATION_FILES + 1)
            .map_err(|error| RepairApplicationError::UnsafePath(error.to_string()))?;
        if changes.is_empty() {
            return Err(RepairApplicationError::NoChanges);
        }
        if changes.len() > MAX_APPLICATION_FILES {
            return Err(RepairApplicationError::TooManyChanges);
        }

        let root = self.project_root(&plan.project_id)?;
        let backup_root = ensure_backup_root(backup_root.as_ref())?;
        let run_id = application_id(repair_id);
        let backup_dir_name = safe_token(&run_id);
        let backup_dir = backup_root.join(&backup_dir_name);
        fs::create_dir(&backup_dir)?;
        self.insert_run(
            &run_id,
            &plan,
            changes.len(),
            &backup_dir_name,
        )?;

        let prepared = match self.prepare_apply(&root, &run_id, &changes, &backup_dir) {
            Ok(prepared) => prepared,
            Err(error) => {
                self.finish_run(&run_id, "failed", 0, false, Some(&error.to_string()))?;
                let _ = fs::remove_dir_all(&backup_dir);
                return self.get_run(&run_id)?.ok_or_else(|| {
                    RepairApplicationError::ApplicationNotFound(run_id.clone())
                });
            }
        };

        self.insert_items(&run_id, &prepared)?;
        if let Err(error) = stage_apply_files(&prepared) {
            cleanup_staged_files(&prepared);
            self.finish_run(&run_id, "failed", 0, false, Some(&error.to_string()))?;
            return self.get_run(&run_id)?.ok_or_else(|| {
                RepairApplicationError::ApplicationNotFound(run_id.clone())
            });
        }

        let mut applied_indices = Vec::new();
        let mut failure: Option<String> = None;
        for (index, item) in prepared.iter().enumerate() {
            if let Err(error) = revalidate_hash(&item.target_path, &item.change.base_content_hash) {
                failure = Some(error.to_string());
                break;
            }
            if let Err(error) = swap_in_staged(item) {
                failure = Some(error.to_string());
                break;
            }
            applied_indices.push(index);
        }

        if let Some(message) = failure {
            let rollback_ok = rollback_applied_swaps(&prepared, &applied_indices);
            cleanup_staged_files(&prepared);
            let status = if rollback_ok { "failed" } else { "rollback_failed" };
            for index in &applied_indices {
                self.set_item_state(
                    &run_id,
                    &prepared[*index].change.id,
                    if rollback_ok { "rolled_back" } else { "applied" },
                )?;
            }
            self.finish_run(
                &run_id,
                status,
                if rollback_ok { 0 } else { applied_indices.len() },
                !applied_indices.is_empty(),
                Some(&message),
            )?;
            return self.get_run(&run_id)?.ok_or_else(|| {
                RepairApplicationError::ApplicationNotFound(run_id.clone())
            });
        }

        let mut cleanup_warnings = Vec::new();
        for item in &prepared {
            if let Err(error) = fs::remove_file(&item.sidecar_path) {
                cleanup_warnings.push(format!("{}: {error}", item.change.relative_path));
            }
            self.set_item_state(&run_id, &item.change.id, "applied")?;
        }
        self.database.connection().execute(
            "UPDATE repair_plans SET status='applied', updated_at=CURRENT_TIMESTAMP WHERE id=?1",
            [repair_id],
        )?;
        let warning = if cleanup_warnings.is_empty() {
            None
        } else {
            Some(format!(
                "application succeeded but sidecar cleanup reported: {}",
                cleanup_warnings.join("; ")
            ))
        };
        self.finish_run(
            &run_id,
            "applied",
            prepared.len(),
            false,
            warning.as_deref(),
        )?;
        self.get_run(&run_id)?
            .ok_or_else(|| RepairApplicationError::ApplicationNotFound(run_id))
    }

    pub fn rollback_application(
        &self,
        run_id: &str,
        backup_root: impl AsRef<Path>,
    ) -> Result<RepairApplicationRunRecord, RepairApplicationError> {
        let run = self
            .get_run(run_id)?
            .ok_or_else(|| RepairApplicationError::ApplicationNotFound(run_id.to_owned()))?;
        if run.status != "applied" {
            return Err(RepairApplicationError::ApplicationNotApplied(run.status));
        }
        let plan_status: String = self.database.connection().query_row(
            "SELECT status FROM repair_plans WHERE id=?1",
            [&run.repair_id],
            |row| row.get(0),
        )?;
        if plan_status != "applied" {
            return Err(RepairApplicationError::ApplicationNotApplied(plan_status));
        }
        let root = self.project_root(&run.project_id)?;
        let backup_root = ensure_backup_root(backup_root.as_ref())?;
        let backup_dir = backup_root.join(&run.backup_dir_name);
        let backup_meta = fs::symlink_metadata(&backup_dir)
            .map_err(|_| RepairApplicationError::CorruptBackup(run.id.clone()))?;
        if backup_meta.file_type().is_symlink() || !backup_meta.is_dir() {
            return Err(RepairApplicationError::CorruptBackup(run.id));
        }
        let items = self.application_items(run_id, MAX_APPLICATION_FILES + 1)?;
        if items.is_empty() || items.len() > MAX_APPLICATION_FILES {
            return Err(RepairApplicationError::CorruptBackup(run_id.to_owned()));
        }
        let prepared = self.prepare_rollback(&root, run_id, &items, &backup_dir)?;
        stage_rollback_files(&prepared)?;

        let mut restored_indices = Vec::new();
        let mut failure: Option<String> = None;
        for (index, item) in prepared.iter().enumerate() {
            if let Err(error) = revalidate_hash(&item.target_path, &item.item.proposed_content_hash) {
                failure = Some(error.to_string());
                break;
            }
            if let Err(error) = swap_in_rollback(item) {
                failure = Some(error.to_string());
                break;
            }
            restored_indices.push(index);
        }

        if let Some(message) = failure {
            let recovered = restore_applied_state(&prepared, &restored_indices);
            cleanup_rollback_staged_files(&prepared);
            if !recovered {
                self.finish_run(
                    run_id,
                    "rollback_failed",
                    run.changes_applied,
                    true,
                    Some(&message),
                )?;
                return self.get_run(run_id)?.ok_or_else(|| {
                    RepairApplicationError::ApplicationNotFound(run_id.to_owned())
                });
            }
            return Err(RepairApplicationError::RollbackConflict(message));
        }

        let mut cleanup_warnings = Vec::new();
        for item in &prepared {
            if let Err(error) = fs::remove_file(&item.sidecar_path) {
                cleanup_warnings.push(format!("{}: {error}", item.item.relative_path));
            }
            self.set_item_state(run_id, &item.item.change_id, "rolled_back")?;
        }
        self.database.connection().execute(
            "UPDATE repair_plans SET status='approved', updated_at=CURRENT_TIMESTAMP WHERE id=?1",
            [&run.repair_id],
        )?;
        let warning = if cleanup_warnings.is_empty() {
            None
        } else {
            Some(format!(
                "rollback succeeded but sidecar cleanup reported: {}",
                cleanup_warnings.join("; ")
            ))
        };
        self.finish_run(
            run_id,
            "rolled_back",
            0,
            true,
            warning.as_deref(),
        )?;
        self.get_run(run_id)?
            .ok_or_else(|| RepairApplicationError::ApplicationNotFound(run_id.to_owned()))
    }

    pub fn history(
        &self,
        repair_id: &str,
        limit: usize,
    ) -> Result<Vec<RepairApplicationRunRecord>, RepairApplicationError> {
        let mut statement = self.database.connection().prepare(
            "SELECT id, repair_id, project_id, status, changes_total, changes_applied, rollback_performed, backup_dir_name, error_message, created_at, completed_at\
             FROM repair_application_runs WHERE repair_id=?1 ORDER BY created_at DESC, id DESC LIMIT ?2",
        )?;
        let rows = statement.query_map(
            params![repair_id, bounded(limit, MAX_HISTORY)],
            map_application_run,
        )?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn application_items(
        &self,
        run_id: &str,
        limit: usize,
    ) -> Result<Vec<RepairApplicationItemRecord>, RepairApplicationError> {
        let mut statement = self.database.connection().prepare(
            "SELECT run_id, change_id, relative_path, base_content_hash, proposed_content_hash, backup_content_hash, backup_file_name, state\
             FROM repair_application_items WHERE run_id=?1 ORDER BY relative_path, change_id LIMIT ?2",
        )?;
        let rows = statement.query_map(
            params![run_id, bounded(limit, MAX_APPLICATION_FILES)],
            map_application_item,
        )?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn get_run(
        &self,
        run_id: &str,
    ) -> Result<Option<RepairApplicationRunRecord>, RepairApplicationError> {
        self.database
            .connection()
            .query_row(
                "SELECT id, repair_id, project_id, status, changes_total, changes_applied, rollback_performed, backup_dir_name, error_message, created_at, completed_at\
                 FROM repair_application_runs WHERE id=?1",
                [run_id],
                map_application_run,
            )
            .optional()
            .map_err(Into::into)
    }

    fn project_root(&self, project_id: &str) -> Result<PathBuf, RepairApplicationError> {
        let root: String = self.database.connection().query_row(
            "SELECT root_path FROM projects WHERE id=?1",
            [project_id],
            |row| row.get(0),
        )?;
        let root = PathBuf::from(root);
        let metadata = fs::symlink_metadata(&root)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(RepairApplicationError::UnsafePath(root.display().to_string()));
        }
        Ok(fs::canonicalize(root)?)
    }

    fn insert_run(
        &self,
        run_id: &str,
        plan: &RepairPlanRecord,
        total: usize,
        backup_dir_name: &str,
    ) -> Result<(), RepairApplicationError> {
        self.database.connection().execute(
            "INSERT INTO repair_application_runs(id, repair_id, project_id, status, changes_total, backup_dir_name)\
             VALUES (?1, ?2, ?3, 'running', ?4, ?5)",
            params![run_id, plan.id, plan.project_id, to_i64(total), backup_dir_name],
        )?;
        Ok(())
    }

    fn insert_items(
        &self,
        run_id: &str,
        prepared: &[PreparedApply],
    ) -> Result<(), RepairApplicationError> {
        let tx = self.database.connection().unchecked_transaction()?;
        for item in prepared {
            tx.execute(
                "INSERT INTO repair_application_items(\
                   run_id, change_id, relative_path, base_content_hash, proposed_content_hash, backup_content_hash, backup_file_name\
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    run_id,
                    item.change.id,
                    item.change.relative_path,
                    item.change.base_content_hash,
                    item.change.proposed_content_hash,
                    item.original_hash,
                    item.backup_file_name,
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    fn set_item_state(
        &self,
        run_id: &str,
        change_id: &str,
        state: &str,
    ) -> Result<(), RepairApplicationError> {
        self.database.connection().execute(
            "UPDATE repair_application_items SET state=?3 WHERE run_id=?1 AND change_id=?2",
            params![run_id, change_id, state],
        )?;
        Ok(())
    }

    fn finish_run(
        &self,
        run_id: &str,
        status: &str,
        applied: usize,
        rollback_performed: bool,
        error_message: Option<&str>,
    ) -> Result<(), RepairApplicationError> {
        let error_message = error_message.map(|value| truncate_utf8(value, MAX_ERROR_BYTES));
        self.database.connection().execute(
            "UPDATE repair_application_runs SET status=?2, changes_applied=?3, rollback_performed=?4, error_message=?5, completed_at=CURRENT_TIMESTAMP WHERE id=?1",
            params![
                run_id,
                status,
                to_i64(applied),
                i64::from(rollback_performed),
                error_message,
            ],
        )?;
        Ok(())
    }

    fn prepare_apply(
        &self,
        root: &Path,
        run_id: &str,
        changes: &[RepairChangeRecord],
        backup_dir: &Path,
    ) -> Result<Vec<PreparedApply>, RepairApplicationError> {
        let mut prepared = Vec::with_capacity(changes.len());
        for change in changes {
            let relative = safe_relative_path(&change.relative_path)?;
            let target = root.join(&relative);
            let metadata = fs::symlink_metadata(&target)
                .map_err(|_| RepairApplicationError::UnsafeTarget(change.relative_path.clone()))?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(RepairApplicationError::UnsafeTarget(change.relative_path.clone()));
            }
            if metadata.len() > MAX_APPLICATION_FILE_BYTES {
                return Err(RepairApplicationError::OversizedTarget(change.relative_path.clone()));
            }
            let canonical_target = fs::canonicalize(&target)?;
            if !canonical_target.starts_with(root) {
                return Err(RepairApplicationError::UnsafePath(change.relative_path.clone()));
            }
            let parent = canonical_target
                .parent()
                .ok_or_else(|| RepairApplicationError::UnsafePath(change.relative_path.clone()))?;
            if !parent.starts_with(root) {
                return Err(RepairApplicationError::UnsafePath(change.relative_path.clone()));
            }
            let original = fs::read(&canonical_target)?;
            let original_hash = sha256_hex(&original);
            if original_hash != change.base_content_hash {
                return Err(RepairApplicationError::StaleBase(change.relative_path.clone()));
            }
            let proposed = change.proposed_content.as_bytes();
            if proposed.len() != change.proposed_byte_size
                || sha256_hex(proposed) != change.proposed_content_hash
            {
                return Err(RepairApplicationError::CorruptProposal(
                    change.relative_path.clone(),
                ));
            }
            let token = safe_token(&format!("{run_id}:{}", change.id));
            let stage_path = parent.join(format!(".codetwin-{token}.new"));
            let sidecar_path = parent.join(format!(".codetwin-{token}.old"));
            if stage_path.exists() || sidecar_path.exists() {
                return Err(RepairApplicationError::UnsafePath(change.relative_path.clone()));
            }
            let backup_file_name = format!("{}.bak", safe_token(&change.id));
            let backup_path = backup_dir.join(&backup_file_name);
            if backup_path.exists() {
                return Err(RepairApplicationError::CorruptBackup(
                    change.relative_path.clone(),
                ));
            }
            prepared.push(PreparedApply {
                change: change.clone(),
                target_path: canonical_target,
                stage_path,
                sidecar_path,
                backup_path,
                backup_file_name,
                original,
                original_hash,
                permissions: metadata.permissions(),
            });
        }
        Ok(prepared)
    }

    fn prepare_rollback(
        &self,
        root: &Path,
        run_id: &str,
        items: &[RepairApplicationItemRecord],
        backup_dir: &Path,
    ) -> Result<Vec<PreparedRollback>, RepairApplicationError> {
        let mut prepared = Vec::with_capacity(items.len());
        for item in items {
            let relative = safe_relative_path(&item.relative_path)?;
            let target = root.join(&relative);
            let metadata = fs::symlink_metadata(&target)
                .map_err(|_| RepairApplicationError::UnsafeTarget(item.relative_path.clone()))?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(RepairApplicationError::UnsafeTarget(item.relative_path.clone()));
            }
            if metadata.len() > MAX_APPLICATION_FILE_BYTES {
                return Err(RepairApplicationError::OversizedTarget(item.relative_path.clone()));
            }
            let canonical_target = fs::canonicalize(&target)?;
            if !canonical_target.starts_with(root) {
                return Err(RepairApplicationError::UnsafePath(item.relative_path.clone()));
            }
            let current = fs::read(&canonical_target)?;
            if sha256_hex(&current) != item.proposed_content_hash {
                return Err(RepairApplicationError::RollbackConflict(
                    item.relative_path.clone(),
                ));
            }
            let backup_path = backup_dir.join(&item.backup_file_name);
            let backup_meta = fs::symlink_metadata(&backup_path)
                .map_err(|_| RepairApplicationError::CorruptBackup(item.relative_path.clone()))?;
            if backup_meta.file_type().is_symlink() || !backup_meta.is_file() {
                return Err(RepairApplicationError::CorruptBackup(item.relative_path.clone()));
            }
            let backup = fs::read(&backup_path)?;
            if sha256_hex(&backup) != item.backup_content_hash
                || item.backup_content_hash != item.base_content_hash
            {
                return Err(RepairApplicationError::CorruptBackup(item.relative_path.clone()));
            }
            let parent = canonical_target
                .parent()
                .ok_or_else(|| RepairApplicationError::UnsafePath(item.relative_path.clone()))?;
            let token = safe_token(&format!("rollback:{run_id}:{}", item.change_id));
            let stage_path = parent.join(format!(".codetwin-{token}.restore"));
            let sidecar_path = parent.join(format!(".codetwin-{token}.applied"));
            if stage_path.exists() || sidecar_path.exists() {
                return Err(RepairApplicationError::UnsafePath(item.relative_path.clone()));
            }
            prepared.push(PreparedRollback {
                item: item.clone(),
                target_path: canonical_target,
                stage_path,
                sidecar_path,
                backup,
                permissions: backup_meta.permissions(),
            });
        }
        Ok(prepared)
    }
}

struct PreparedApply {
    change: RepairChangeRecord,
    target_path: PathBuf,
    stage_path: PathBuf,
    sidecar_path: PathBuf,
    backup_path: PathBuf,
    backup_file_name: String,
    original: Vec<u8>,
    original_hash: String,
    permissions: Permissions,
}

struct PreparedRollback {
    item: RepairApplicationItemRecord,
    target_path: PathBuf,
    stage_path: PathBuf,
    sidecar_path: PathBuf,
    backup: Vec<u8>,
    permissions: Permissions,
}

fn stage_apply_files(items: &[PreparedApply]) -> Result<(), RepairApplicationError> {
    for item in items {
        write_new_file(&item.backup_path, &item.original, item.permissions.clone())?;
        write_new_file(
            &item.stage_path,
            item.change.proposed_content.as_bytes(),
            item.permissions.clone(),
        )?;
    }
    Ok(())
}

fn stage_rollback_files(items: &[PreparedRollback]) -> Result<(), RepairApplicationError> {
    for item in items {
        write_new_file(&item.stage_path, &item.backup, item.permissions.clone())?;
    }
    Ok(())
}

fn swap_in_staged(item: &PreparedApply) -> Result<(), RepairApplicationError> {
    fs::rename(&item.target_path, &item.sidecar_path)?;
    match fs::rename(&item.stage_path, &item.target_path) {
        Ok(()) => Ok(()),
        Err(error) => {
            let _ = fs::rename(&item.sidecar_path, &item.target_path);
            Err(error.into())
        }
    }
}

fn swap_in_rollback(item: &PreparedRollback) -> Result<(), RepairApplicationError> {
    fs::rename(&item.target_path, &item.sidecar_path)?;
    match fs::rename(&item.stage_path, &item.target_path) {
        Ok(()) => Ok(()),
        Err(error) => {
            let _ = fs::rename(&item.sidecar_path, &item.target_path);
            Err(error.into())
        }
    }
}

fn rollback_applied_swaps(items: &[PreparedApply], indices: &[usize]) -> bool {
    let mut ok = true;
    for index in indices.iter().rev() {
        let item = &items[*index];
        if !item.target_path.exists() || !item.sidecar_path.exists() {
            ok = false;
            continue;
        }
        let discard = &item.stage_path;
        if fs::rename(&item.target_path, discard).is_err() {
            ok = false;
            continue;
        }
        if fs::rename(&item.sidecar_path, &item.target_path).is_err() {
            let _ = fs::rename(discard, &item.target_path);
            ok = false;
            continue;
        }
        let _ = fs::remove_file(discard);
    }
    ok
}

fn restore_applied_state(items: &[PreparedRollback], indices: &[usize]) -> bool {
    let mut ok = true;
    for index in indices.iter().rev() {
        let item = &items[*index];
        if !item.target_path.exists() || !item.sidecar_path.exists() {
            ok = false;
            continue;
        }
        let discard = &item.stage_path;
        if fs::rename(&item.target_path, discard).is_err() {
            ok = false;
            continue;
        }
        if fs::rename(&item.sidecar_path, &item.target_path).is_err() {
            let _ = fs::rename(discard, &item.target_path);
            ok = false;
            continue;
        }
        let _ = fs::remove_file(discard);
    }
    ok
}

fn cleanup_staged_files(items: &[PreparedApply]) {
    for item in items {
        let _ = fs::remove_file(&item.stage_path);
        if item.sidecar_path.exists() && !item.target_path.exists() {
            let _ = fs::rename(&item.sidecar_path, &item.target_path);
        }
    }
}

fn cleanup_rollback_staged_files(items: &[PreparedRollback]) {
    for item in items {
        let _ = fs::remove_file(&item.stage_path);
        if item.sidecar_path.exists() && !item.target_path.exists() {
            let _ = fs::rename(&item.sidecar_path, &item.target_path);
        }
    }
}

fn revalidate_hash(path: &Path, expected: &str) -> Result<(), RepairApplicationError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(RepairApplicationError::UnsafeTarget(path.display().to_string()));
    }
    if metadata.len() > MAX_APPLICATION_FILE_BYTES {
        return Err(RepairApplicationError::OversizedTarget(path.display().to_string()));
    }
    if sha256_hex(&fs::read(path)?) != expected {
        return Err(RepairApplicationError::StaleBase(path.display().to_string()));
    }
    Ok(())
}

fn write_new_file(
    path: &Path,
    bytes: &[u8],
    permissions: Permissions,
) -> Result<(), RepairApplicationError> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::set_permissions(path, permissions)?;
    Ok(())
}

fn ensure_backup_root(path: &Path) -> Result<PathBuf, RepairApplicationError> {
    if path.exists() {
        let metadata = fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(RepairApplicationError::UnsafeBackupRoot);
        }
    } else {
        fs::create_dir_all(path)?;
    }
    let canonical = fs::canonicalize(path)?;
    let metadata = fs::symlink_metadata(&canonical)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(RepairApplicationError::UnsafeBackupRoot);
    }
    Ok(canonical)
}

fn safe_relative_path(value: &str) -> Result<PathBuf, RepairApplicationError> {
    let path = Path::new(value);
    if path.as_os_str().is_empty() || path.is_absolute() {
        return Err(RepairApplicationError::UnsafePath(value.to_owned()));
    }
    let mut safe = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => safe.push(part),
            _ => return Err(RepairApplicationError::UnsafePath(value.to_owned())),
        }
    }
    if safe.as_os_str().is_empty() {
        return Err(RepairApplicationError::UnsafePath(value.to_owned()));
    }
    Ok(safe)
}

fn application_id(repair_id: &str) -> String {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos().to_string())
        .unwrap_or_else(|_| "0".to_owned());
    format!("repair-application:{}", sha256_hex(format!("{repair_id}:{nonce}").as_bytes()))
}

fn safe_token(value: &str) -> String {
    sha256_hex(value.as_bytes())[..32].to_owned()
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn bounded(value: usize, max: usize) -> i64 {
    i64::try_from(value.clamp(1, max)).unwrap_or(i64::MAX)
}

fn to_i64(value: usize) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn to_usize(value: i64) -> usize {
    usize::try_from(value).unwrap_or_default()
}

fn truncate_utf8(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_owned();
    }
    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

fn map_application_run(row: &rusqlite::Row<'_>) -> rusqlite::Result<RepairApplicationRunRecord> {
    let total: i64 = row.get(4)?;
    let applied: i64 = row.get(5)?;
    let rollback: i64 = row.get(6)?;
    Ok(RepairApplicationRunRecord {
        id: row.get(0)?,
        repair_id: row.get(1)?,
        project_id: row.get(2)?,
        status: row.get(3)?,
        changes_total: to_usize(total),
        changes_applied: to_usize(applied),
        rollback_performed: rollback != 0,
        backup_dir_name: row.get(7)?,
        error_message: row.get(8)?,
        created_at: row.get(9)?,
        completed_at: row.get(10)?,
    })
}

fn map_application_item(row: &rusqlite::Row<'_>) -> rusqlite::Result<RepairApplicationItemRecord> {
    Ok(RepairApplicationItemRecord {
        run_id: row.get(0)?,
        change_id: row.get(1)?,
        relative_path: row.get(2)?,
        base_content_hash: row.get(3)?,
        proposed_content_hash: row.get(4)?,
        backup_content_hash: row.get(5)?,
        backup_file_name: row.get(6)?,
        state: row.get(7)?,
    })
}
