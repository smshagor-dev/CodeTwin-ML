//! Semantic memory operations (migration 54): durable background indexing,
//! per-project settings, model-change status, secure deletion, retention,
//! neural contradiction detection and cross-session episodes.
use std::sync::atomic::AtomicBool;

use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::temporal::contradicts;
use super::{
    bounded, cosine, from_blob, item_from_row, now_ms, EmbeddingProvider, KnowledgeMemory,
    MemoryInput, MemoryItem, MemoryLayer, RankingConfig, ReconcileOutcome, ITEM_COLUMNS,
};
use crate::collaboration::new_id;

/// Age limits per layer, in days (`None` keeps forever). Approved knowledge
/// is never removed by retention.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RetentionPolicy {
    pub working_days: Option<u32>,
    pub episodic_days: Option<u32>,
    pub project_fact_days: Option<u32>,
    pub evidence_ref_days: Option<u32>,
}

impl RetentionPolicy {
    fn limits(&self) -> [(MemoryLayer, Option<u32>); 4] {
        [
            (MemoryLayer::Working, self.working_days),
            (MemoryLayer::Episodic, self.episodic_days),
            (MemoryLayer::ProjectFact, self.project_fact_days),
            (MemoryLayer::EvidenceRef, self.evidence_ref_days),
        ]
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MemorySettings {
    pub active_model: Option<String>,
    pub ranking: RankingConfig,
    pub retention: RetentionPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IndexJob {
    pub id: String,
    pub project_id: String,
    pub model: String,
    pub state: String,
    pub total: usize,
    pub done: usize,
    pub error: Option<String>,
    pub started_ms: i64,
    pub finished_ms: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexStatus {
    pub model: String,
    pub dims: Option<usize>,
    pub kind: Option<String>,
    pub revision: Option<String>,
    pub live_items: usize,
    /// Items whose vector matches their current content.
    pub current: usize,
    /// Items with a vector of older content (revised since indexing).
    pub stale: usize,
    /// Items never embedded with this model.
    pub missing: usize,
    pub active_model: Option<String>,
    /// Other models with vectors in this project (left over from a switch).
    pub other_models: Vec<String>,
    pub last_job: Option<IndexJob>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticConflict {
    pub left: MemoryItem,
    pub right: MemoryItem,
    pub similarity: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Episode {
    pub run_id: String,
    pub items: Vec<MemoryItem>,
    pub last_ms: i64,
}

fn job_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<IndexJob> {
    Ok(IndexJob {
        id: r.get(0)?,
        project_id: r.get(1)?,
        model: r.get(2)?,
        state: r.get(3)?,
        total: r.get::<_, i64>(4)? as usize,
        done: r.get::<_, i64>(5)? as usize,
        error: r.get(6)?,
        started_ms: r.get(7)?,
        finished_ms: r.get(8)?,
    })
}

const JOB_COLUMNS: &str = "id,project_id,model,state,total,done,error,started_ms,finished_ms";

impl KnowledgeMemory<'_> {
    // ------------------------------------------------------------ settings

    pub fn settings(&self, project_id: &str) -> Result<MemorySettings, String> {
        let row: Option<(Option<String>, Option<String>, Option<String>)> = self
            .db
            .connection()
            .query_row(
                "SELECT active_model, ranking_json, retention_json FROM memory_settings WHERE project_id=?1",
                [project_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(|e| e.to_string())?;
        let Some((active_model, ranking, retention)) = row else {
            return Ok(MemorySettings::default());
        };
        fn parse<T: serde::de::DeserializeOwned>(s: Option<String>) -> Option<T> {
            s.and_then(|s| serde_json::from_str(&s).ok())
        }
        Ok(MemorySettings {
            active_model,
            ranking: parse(ranking).unwrap_or_default(),
            retention: parse(retention).unwrap_or_default(),
        })
    }

    pub fn save_settings(&self, project_id: &str, settings: &MemorySettings) -> Result<(), String> {
        settings.ranking.validate()?;
        if let Some(model) = &settings.active_model {
            let known: bool = self
                .db
                .connection()
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM embedding_models WHERE model=?1)",
                    [model],
                    |r| r.get(0),
                )
                .map_err(|e| e.to_string())?;
            if !known {
                return Err(format!(
                    "{model} has not been registered by an indexing run"
                ));
            }
        }
        let ranking = serde_json::to_string(&settings.ranking).map_err(|e| e.to_string())?;
        let retention = serde_json::to_string(&settings.retention).map_err(|e| e.to_string())?;
        self.db
            .connection()
            .execute(
                "INSERT INTO memory_settings(project_id,active_model,ranking_json,retention_json,updated_ms)
                 VALUES (?1,?2,?3,?4,?5)
                 ON CONFLICT(project_id) DO UPDATE SET active_model=excluded.active_model,
                   ranking_json=excluded.ranking_json, retention_json=excluded.retention_json,
                   updated_ms=excluded.updated_ms",
                params![
                    project_id,
                    settings.active_model,
                    ranking,
                    retention,
                    now_ms()
                ],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    // ------------------------------------------------------------ indexing

    /// Open a durable index job. Only one job per project runs at a time.
    pub fn start_index_job(&self, project_id: &str, model: &str) -> Result<IndexJob, String> {
        let conn = self.db.connection();
        // The job row references the registry; register lazily with a
        // placeholder only if the model is new (dims are confirmed on the
        // first embedded batch, which rejects a mismatch).
        let known: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM embedding_models WHERE model=?1)",
                [model],
                |r| r.get(0),
            )
            .map_err(|e| e.to_string())?;
        if !known {
            return Err(format!(
                "{model} is not registered yet; call index_project with the embedder"
            ));
        }
        let id = new_id("mjob");
        conn.execute(
            "INSERT INTO memory_index_jobs(id,project_id,model,state,started_ms) VALUES (?1,?2,?3,'running',?4)",
            params![id, project_id, model, now_ms()],
        )
        .map_err(|e| {
            if e.to_string().contains("UNIQUE") {
                "an index job is already running for this project".to_owned()
            } else {
                e.to_string()
            }
        })?;
        self.index_job(&id)?
            .ok_or_else(|| "index job vanished".into())
    }

    pub fn index_job(&self, job_id: &str) -> Result<Option<IndexJob>, String> {
        self.db
            .connection()
            .query_row(
                &format!("SELECT {JOB_COLUMNS} FROM memory_index_jobs WHERE id=?1"),
                [job_id],
                job_from_row,
            )
            .optional()
            .map_err(|e| e.to_string())
    }

    pub fn index_jobs(&self, project_id: &str, limit: usize) -> Result<Vec<IndexJob>, String> {
        let mut stmt = self
            .db
            .connection()
            .prepare(&format!(
                "SELECT {JOB_COLUMNS} FROM memory_index_jobs WHERE project_id=?1
                 ORDER BY started_ms DESC, id DESC LIMIT ?2"
            ))
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(
                params![project_id, limit.clamp(1, 100) as i64],
                job_from_row,
            )
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<_, _>>().map_err(|e| e.to_string())
    }

    /// Embed everything pending for `embedder` in the background-job model:
    /// registers the model, records a durable job, reports progress after
    /// every batch and stops between batches when `cancel` is set.
    pub fn index_project(
        &self,
        project_id: &str,
        embedder: &dyn EmbeddingProvider,
        cancel: &AtomicBool,
        progress: &mut dyn FnMut(&IndexJob),
    ) -> Result<IndexJob, String> {
        let model = embedder.model_id();
        // A one-text probe registers the model with its real dimensionality
        // before any job row references it.
        let probe = embedder.embed(project_id, &["dimension probe".to_owned()])?;
        let dims = probe.first().map_or(0, Vec::len);
        self.register_model(
            &model,
            dims,
            embedder.kind(),
            embedder.revision().as_deref(),
            embedder.weights_sha256().as_deref(),
        )?;
        let job = self.start_index_job(project_id, &model)?;
        let conn = self.db.connection();
        let mut report = |done: usize, total: usize| {
            let _ = conn.execute(
                "UPDATE memory_index_jobs SET done=?2, total=?3 WHERE id=?1",
                params![job.id, done as i64, total as i64],
            );
            if let Ok(Some(j)) = self.index_job(&job.id) {
                progress(&j);
            }
        };
        let outcome = self.embed_pending(project_id, embedder, 5_000, cancel, &mut report);
        let cancelled = cancel.load(std::sync::atomic::Ordering::Relaxed);
        let (state, error) = match &outcome {
            Ok(_) if cancelled => ("cancelled", None),
            Ok(_) => ("completed", None),
            Err(e) => ("failed", Some(bounded(e, 500))),
        };
        conn.execute(
            "UPDATE memory_index_jobs SET state=?2, error=?3, finished_ms=?4 WHERE id=?1",
            params![job.id, state, error, now_ms()],
        )
        .map_err(|e| e.to_string())?;
        let finished = self.index_job(&job.id)?.ok_or("index job vanished")?;
        progress(&finished);
        outcome.map(|_| finished)
    }

    /// Mark jobs left `running` by a crash or shutdown as `interrupted`.
    /// Call once at startup, before any new job begins.
    pub fn recover_interrupted_jobs(&self) -> Result<usize, String> {
        self.db
            .connection()
            .execute(
                "UPDATE memory_index_jobs SET state='interrupted', finished_ms=?1,
                   error='the application stopped while indexing; re-run to resume'
                 WHERE state='running'",
                [now_ms()],
            )
            .map_err(|e| e.to_string())
    }

    /// How complete `model`'s index is for this project.
    pub fn index_status(&self, project_id: &str, model: &str) -> Result<IndexStatus, String> {
        let conn = self.db.connection();
        let now = now_ms();
        let (live, current, stale): (i64, i64, i64) = conn
            .query_row(
                "SELECT COUNT(*),
                   COALESCE(SUM(EXISTS(SELECT 1 FROM memory_neural_vectors v WHERE v.item_id=m.id
                       AND v.model=?3 AND v.content_sha256=m.content_sha256)),0),
                   COALESCE(SUM(EXISTS(SELECT 1 FROM memory_neural_vectors v WHERE v.item_id=m.id
                       AND v.model=?3 AND v.content_sha256<>m.content_sha256)),0)
                 FROM memory_items m WHERE m.project_id=?1 AND (m.expires_ms IS NULL OR m.expires_ms > ?2)",
                params![project_id, now, model],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .map_err(|e| e.to_string())?;
        let registry: Option<(i64, String, Option<String>)> = conn
            .query_row(
                "SELECT dims, kind, revision FROM embedding_models WHERE model=?1",
                [model],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(|e| e.to_string())?;
        let other_models = {
            let mut stmt = conn
                .prepare(
                    "SELECT DISTINCT model FROM memory_neural_vectors WHERE project_id=?1 AND model<>?2
                     ORDER BY model LIMIT 20",
                )
                .map_err(|e| e.to_string())?;
            let rows = stmt
                .query_map(params![project_id, model], |r| r.get(0))
                .map_err(|e| e.to_string())?;
            rows.collect::<Result<Vec<String>, _>>()
                .map_err(|e| e.to_string())?
        };
        let last_job = conn
            .query_row(
                &format!(
                    "SELECT {JOB_COLUMNS} FROM memory_index_jobs WHERE project_id=?1 AND model=?2
                     ORDER BY started_ms DESC, id DESC LIMIT 1"
                ),
                params![project_id, model],
                job_from_row,
            )
            .optional()
            .map_err(|e| e.to_string())?;
        Ok(IndexStatus {
            model: model.to_owned(),
            dims: registry.as_ref().map(|r| r.0 as usize),
            kind: registry.as_ref().map(|r| r.1.clone()),
            revision: registry.and_then(|r| r.2),
            live_items: live as usize,
            current: current as usize,
            stale: stale as usize,
            missing: (live - current - stale).max(0) as usize,
            active_model: self.settings(project_id)?.active_model,
            other_models,
            last_job,
        })
    }

    /// Drop this project's vectors of a model it no longer uses.
    pub fn purge_model_vectors(&self, project_id: &str, model: &str) -> Result<usize, String> {
        if self.settings(project_id)?.active_model.as_deref() == Some(model) {
            return Err("switch the active model before purging its vectors".into());
        }
        self.db
            .connection()
            .execute(
                "DELETE FROM memory_neural_vectors WHERE project_id=?1 AND model=?2",
                params![project_id, model],
            )
            .map_err(|e| e.to_string())
    }

    // ------------------------------------------------------------ deletion

    /// Delete items matching `filter` (an SQL condition on `memory_items`
    /// with `?1` = project) and leave a content-free tombstone for each.
    /// Vectors, history and graph nodes go with them; `secure_delete` and
    /// the FTS5 secure-delete option zero the freed content.
    pub(super) fn secure_delete_where(
        &self,
        project_id: &str,
        filter: &str,
        extra: &[&dyn rusqlite::ToSql],
        reason: &str,
        actor: &str,
    ) -> Result<usize, String> {
        let conn = self.db.connection();
        let tx = conn.unchecked_transaction().map_err(|e| e.to_string())?;
        let victims: Vec<(String, String)> = {
            let mut stmt = tx
                .prepare(&format!(
                    "SELECT id, content_sha256 FROM memory_items WHERE project_id=?1 AND ({filter})"
                ))
                .map_err(|e| e.to_string())?;
            let mut args: Vec<&dyn rusqlite::ToSql> = vec![&project_id];
            args.extend_from_slice(extra);
            let rows = stmt
                .query_map(args.as_slice(), |r| Ok((r.get(0)?, r.get(1)?)))
                .map_err(|e| e.to_string())?;
            rows.collect::<Result<_, _>>().map_err(|e| e.to_string())?
        };
        let now = now_ms();
        for (id, sha) in &victims {
            tx.execute(
                "DELETE FROM kg_nodes WHERE project_id=?1 AND kind='memory' AND ref_id=?2",
                params![project_id, id],
            )
            .map_err(|e| e.to_string())?;
            tx.execute("DELETE FROM memory_items WHERE id=?1", [id])
                .map_err(|e| e.to_string())?;
            tx.execute(
                "INSERT INTO memory_deletions(project_id,item_id,content_sha256,reason,actor,deleted_ms)
                 VALUES (?1,?2,?3,?4,?5,?6)",
                params![project_id, id, sha, reason, bounded(actor, 120), now],
            )
            .map_err(|e| e.to_string())?;
        }
        tx.commit().map_err(|e| e.to_string())?;
        if !victims.is_empty() {
            // Best effort: move freed WAL pages back into the (zeroed) file.
            let _ = conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()));
        }
        Ok(victims.len())
    }

    pub fn secure_delete(
        &self,
        project_id: &str,
        item_id: &str,
        actor: &str,
    ) -> Result<bool, String> {
        self.secure_delete_where(project_id, "id=?2", &[&item_id], "operator", actor)
            .map(|n| n == 1)
    }

    /// Content-free record of what was deleted, newest first.
    pub fn deletions(&self, project_id: &str, limit: usize) -> Result<Vec<Value>, String> {
        let mut stmt = self
            .db
            .connection()
            .prepare(
                "SELECT item_id, content_sha256, reason, actor, deleted_ms FROM memory_deletions
                 WHERE project_id=?1 ORDER BY deleted_ms DESC, id DESC LIMIT ?2",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(params![project_id, limit.clamp(1, 500) as i64], |r| {
                Ok(serde_json::json!({
                    "item_id": r.get::<_, String>(0)?,
                    "content_sha256": r.get::<_, String>(1)?,
                    "reason": r.get::<_, String>(2)?,
                    "actor": r.get::<_, String>(3)?,
                    "deleted_ms": r.get::<_, i64>(4)?,
                }))
            })
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<_, _>>().map_err(|e| e.to_string())
    }

    /// Apply the project's retention policy. Returns items removed.
    pub fn apply_retention(&self, project_id: &str, actor: &str) -> Result<usize, String> {
        let policy = self.settings(project_id)?.retention;
        let now = now_ms();
        let mut removed = 0;
        for (layer, days) in policy.limits() {
            let Some(days) = days else { continue };
            let cutoff = now - i64::from(days) * 86_400_000;
            removed += self.secure_delete_where(
                project_id,
                "layer=?2 AND updated_ms < ?3",
                &[&layer.as_str(), &cutoff],
                "retention",
                actor,
            )?;
        }
        Ok(removed)
    }

    // ------------------------------------------------------- contradictions

    fn current_vectors(
        &self,
        project_id: &str,
        model: &str,
        layer: Option<MemoryLayer>,
        limit: usize,
    ) -> Result<Vec<(MemoryItem, Vec<f32>)>, String> {
        let mut stmt = self
            .db
            .connection()
            .prepare(&format!(
                "SELECT {}, v.vector, v.dims FROM memory_items m JOIN memory_neural_vectors v
                   ON v.item_id=m.id AND v.model=?2 AND v.content_sha256=m.content_sha256
                 WHERE m.project_id=?1 AND (?3 IS NULL OR m.layer=?3)
                   AND (m.expires_ms IS NULL OR m.expires_ms > ?4)
                 ORDER BY m.updated_ms DESC LIMIT ?5",
                ITEM_COLUMNS
                    .split(',')
                    .map(|c| format!("m.{}", c.trim()))
                    .collect::<Vec<_>>()
                    .join(",")
            ))
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(
                params![
                    project_id,
                    model,
                    layer.map(MemoryLayer::as_str),
                    now_ms(),
                    limit as i64
                ],
                |r| {
                    let item = item_from_row(r)?;
                    let blob: Vec<u8> = r.get(18)?;
                    let dims: i64 = r.get(19)?;
                    Ok((item, blob, dims))
                },
            )
            .map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for row in rows {
            let (item, blob, dims) = row.map_err(|e| e.to_string())?;
            if let Some(v) = from_blob(&blob, usize::try_from(dims).unwrap_or(0)) {
                out.push((item, v));
            }
        }
        Ok(out)
    }

    /// Pairs of memories that a neural model places close together (same
    /// topic) but whose statements contradict each other — e.g. differently
    /// titled notes that disagree. Checks the newest 400 embedded items.
    pub fn semantic_conflicts(
        &self,
        project_id: &str,
        model: &str,
        min_similarity: f64,
    ) -> Result<Vec<SemanticConflict>, String> {
        if !(0.5..=1.0).contains(&min_similarity) {
            return Err("similarity threshold must be within 0.5..1".into());
        }
        let items = self.current_vectors(project_id, model, None, 400)?;
        let mut found = Vec::new();
        for (i, (a, va)) in items.iter().enumerate() {
            for (b, vb) in &items[i + 1..] {
                if va.len() != vb.len() {
                    continue;
                }
                let similarity = cosine(va, vb);
                if similarity >= min_similarity && contradicts(&a.body, &b.body) {
                    found.push(SemanticConflict {
                        left: a.clone(),
                        right: b.clone(),
                        similarity,
                    });
                }
            }
        }
        found.sort_by(|x, y| y.similarity.total_cmp(&x.similarity));
        found.truncate(100);
        Ok(found)
    }

    /// Like [`Self::reconcile`], but when no item has the same title, an
    /// item the neural model finds near-identical in meaning (cosine at or
    /// above `min_similarity`, same layer) is treated as the same fact, so a
    /// reworded contradiction is caught instead of stored alongside.
    pub fn reconcile_semantic(
        &self,
        input: &MemoryInput,
        actor: &str,
        embedder: &dyn EmbeddingProvider,
        min_similarity: f64,
    ) -> Result<ReconcileOutcome, String> {
        let by_title = self.reconcile_preview_title(input)?;
        if by_title {
            return self.reconcile(input, actor);
        }
        let model = embedder.model_id();
        let query = embedder
            .embed(
                &input.project_id,
                &[format!("{} {}", input.title, input.body)],
            )?
            .pop()
            .ok_or("embedder returned no vector")?;
        let best = self
            .current_vectors(&input.project_id, &model, Some(input.layer), 2_000)?
            .into_iter()
            .filter(|(_, v)| v.len() == query.len())
            .map(|(item, v)| (cosine(&query, &v), item))
            .max_by(|a, b| a.0.total_cmp(&b.0));
        match best {
            Some((similarity, existing)) if similarity >= min_similarity => {
                self.reconcile_against(existing, input, actor)
            }
            _ => self.reconcile(input, actor),
        }
    }

    fn reconcile_preview_title(&self, input: &MemoryInput) -> Result<bool, String> {
        let wanted = input.title.trim().to_lowercase();
        let mut stmt = self
            .db
            .connection()
            .prepare(
                "SELECT title FROM memory_items WHERE project_id=?1 AND layer=?2
                   AND (expires_ms IS NULL OR expires_ms > ?3) ORDER BY updated_ms DESC LIMIT 500",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(
                params![input.project_id, input.layer.as_str(), now_ms()],
                |r| r.get::<_, String>(0),
            )
            .map_err(|e| e.to_string())?;
        for title in rows {
            if title.map_err(|e| e.to_string())?.trim().to_lowercase() == wanted {
                return Ok(true);
            }
        }
        Ok(false)
    }

    // ------------------------------------------------------------ episodes

    /// Episodic memory grouped by workflow run, newest session first, so a
    /// new session can see what earlier sessions did and concluded.
    pub fn episodes(&self, project_id: &str, max_runs: usize) -> Result<Vec<Episode>, String> {
        let mut stmt = self
            .db
            .connection()
            .prepare(&format!(
                "SELECT {ITEM_COLUMNS} FROM memory_items WHERE project_id=?1 AND layer='episodic'
                   AND run_id IS NOT NULL AND run_id IN (
                     SELECT run_id FROM memory_items WHERE project_id=?1 AND layer='episodic'
                       AND run_id IS NOT NULL GROUP BY run_id ORDER BY MAX(updated_ms) DESC LIMIT ?2)
                 ORDER BY updated_ms DESC"
            ))
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(
                params![project_id, max_runs.clamp(1, 50) as i64],
                item_from_row,
            )
            .map_err(|e| e.to_string())?;
        let mut episodes: Vec<Episode> = Vec::new();
        for row in rows {
            let item = row.map_err(|e| e.to_string())?;
            let run_id = item.run_id.clone().unwrap_or_default();
            match episodes.iter_mut().find(|e| e.run_id == run_id) {
                Some(e) => e.items.push(item),
                None => episodes.push(Episode {
                    run_id,
                    last_ms: item.updated_ms,
                    items: vec![item],
                }),
            }
        }
        Ok(episodes)
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::sync::atomic::Ordering;

    use super::*;
    use crate::knowledge_memory::{Fusion, RetrievalBudget, RetrievalContext, RetrievalResult};
    use crate::Database;

    /// Test double: topic-indicator vectors. It exercises indexing and
    /// ranking logic only; real semantics are tested against the pinned
    /// model in `tests/local_neural_embeddings.rs`.
    struct TopicEmbedder {
        dims: usize,
        fail: bool,
        calls: Cell<usize>,
    }

    const TOPICS: [&[&str]; 4] = [
        &["deploy", "release", "rollout", "ship"],
        &["database", "sql", "migration", "schema"],
        &["login", "auth", "password", "token"],
        &["fruit", "banana", "apple", "strawberr"],
    ];

    impl EmbeddingProvider for TopicEmbedder {
        fn model_id(&self) -> String {
            "neural:test-topics@127.0.0.1".into()
        }
        fn embed(&self, _: &str, texts: &[String]) -> Result<Vec<Vec<f32>>, String> {
            self.calls.set(self.calls.get() + 1);
            if self.fail {
                return Err("connection refused".into());
            }
            Ok(texts
                .iter()
                .map(|t| {
                    let t = t.to_lowercase();
                    let mut v = vec![0.01f32; self.dims];
                    for (i, words) in TOPICS.iter().enumerate() {
                        v[i] += words.iter().filter(|w| t.contains(*w)).count() as f32;
                    }
                    let n = v.iter().map(|x| x * x).sum::<f32>().sqrt();
                    v.iter().map(|x| x / n).collect()
                })
                .collect())
        }
    }

    fn embedder() -> TopicEmbedder {
        TopicEmbedder {
            dims: 16,
            fail: false,
            calls: Cell::new(0),
        }
    }

    fn setup() -> Database {
        let db = Database::open_in_memory().unwrap();
        for p in ["p1", "p2"] {
            db.connection()
                .execute(
                    "INSERT INTO projects(id,root_path,display_name) VALUES (?1,?2,?1)",
                    params![p, format!("/{p}")],
                )
                .unwrap();
        }
        db
    }

    fn fact(project: &str, title: &str, body: &str) -> MemoryInput {
        MemoryInput {
            project_id: project.into(),
            layer: MemoryLayer::ProjectFact,
            title: title.into(),
            body: body.into(),
            source_kind: "test".into(),
            source_ref: "fixture".into(),
            source_sha256: None,
            run_id: None,
            task_id: None,
            confidence: 0.6,
            verified: false,
            ttl_ms: None,
        }
    }

    fn no_cancel() -> AtomicBool {
        AtomicBool::new(false)
    }

    #[test]
    fn indexing_is_incremental_cancellable_and_durable() {
        let db = setup();
        let m = KnowledgeMemory::new(&db);
        for i in 0..40 {
            m.remember(&fact(
                "p1",
                &format!("note {i}"),
                &format!("database migration {i}"),
            ))
            .unwrap();
        }
        let e = embedder();
        // Cancel after the first batch: committed batches survive.
        let cancel = no_cancel();
        let mut seen = Vec::new();
        let job = m
            .index_project("p1", &e, &cancel, &mut |j| {
                seen.push(j.done);
                if j.done >= 16 {
                    cancel.store(true, Ordering::Relaxed);
                }
            })
            .unwrap();
        assert_eq!(job.state, "cancelled");
        assert_eq!((job.done, job.total), (16, 40));
        assert!(seen.windows(2).all(|w| w[0] <= w[1]), "monotonic progress");
        let status = m.index_status("p1", &e.model_id()).unwrap();
        assert_eq!(
            (status.current, status.missing, status.dims),
            (16, 24, Some(16))
        );
        // Resume embeds only what is missing.
        cancel.store(false, Ordering::Relaxed);
        let job = m.index_project("p1", &e, &cancel, &mut |_| {}).unwrap();
        assert_eq!((job.state.as_str(), job.total), ("completed", 24));
        // Revising an item makes exactly that vector stale.
        let item = m.list("p1", None, 1).unwrap().remove(0);
        m.revise(
            "p1",
            &item.id,
            "note x",
            "schema change",
            "fixture",
            0.6,
            false,
            "op",
        )
        .unwrap();
        let status = m.index_status("p1", &e.model_id()).unwrap();
        assert_eq!((status.current, status.stale), (39, 1));
        // A crash leaves a running job; startup recovery marks it.
        let j = m.start_index_job("p1", &e.model_id()).unwrap();
        assert!(
            m.start_index_job("p1", &e.model_id()).is_err(),
            "one job at a time"
        );
        assert_eq!(m.recover_interrupted_jobs().unwrap(), 1);
        assert_eq!(m.index_job(&j.id).unwrap().unwrap().state, "interrupted");
    }

    #[test]
    fn model_dimension_changes_are_refused_and_switches_reported() {
        let db = setup();
        let m = KnowledgeMemory::new(&db);
        m.remember(&fact("p1", "a", "deploy the release")).unwrap();
        let e = embedder();
        m.index_project("p1", &e, &no_cancel(), &mut |_| {})
            .unwrap();
        let resized = TopicEmbedder {
            dims: 32,
            ..embedder()
        };
        let err = m
            .index_project("p1", &resized, &no_cancel(), &mut |_| {})
            .unwrap_err();
        assert!(err.contains("dimensions"), "{err}");
        let mut settings = m.settings("p1").unwrap();
        settings.active_model = Some("neural:never-indexed".into());
        assert!(m.save_settings("p1", &settings).is_err());
        settings.active_model = Some(e.model_id());
        m.save_settings("p1", &settings).unwrap();
        assert!(m.purge_model_vectors("p1", &e.model_id()).is_err());
        let status = m.index_status("p1", "neural:other@x").unwrap();
        assert_eq!(status.other_models, vec![e.model_id()]);
        assert_eq!(status.missing, 1);
    }

    #[test]
    fn neural_retrieval_reports_fallbacks_and_explains_scores() {
        let db = setup();
        let m = KnowledgeMemory::new(&db);
        m.remember(&fact(
            "p1",
            "Rollout",
            "We ship on Fridays after the release train",
        ))
        .unwrap();
        m.remember(&fact(
            "p1",
            "Credentials",
            "Password reset tokens expire in an hour",
        ))
        .unwrap();
        m.remember(&fact("p2", "Rollout", "Project two deploys continuously"))
            .unwrap();
        let e = embedder();
        let budget = RetrievalBudget::default();
        // Not indexed yet: lexical, with the reason.
        let r = m.retrieve_with("p1", "deploy", budget, Some(&e)).unwrap();
        assert!(!r.neural);
        assert!(r.fallback_reason.unwrap().contains("not been indexed"));
        m.index_project("p1", &e, &no_cancel(), &mut |_| {})
            .unwrap();
        // "deploy" shares no word with the rollout note; only vectors match it.
        let r = m.retrieve_with("p1", "deploy", budget, Some(&e)).unwrap();
        assert!(r.neural && r.fallback_reason.is_none());
        assert_eq!(r.items[0].item.title, "Rollout");
        assert!(r.items.iter().all(|i| i.item.project_id == "p1"));
        let x = &r.items[0].explanation;
        assert_eq!((x.keyword_rank, x.vector_rank), (None, Some(1)));
        // An unreachable provider degrades to lexical instead of failing.
        let down = TopicEmbedder {
            fail: true,
            ..embedder()
        };
        let r = m
            .retrieve_with("p1", "password", budget, Some(&down))
            .unwrap();
        assert!(!r.neural);
        assert!(r.fallback_reason.unwrap().contains("unavailable"));
        assert_eq!(r.items[0].item.title, "Credentials");
        // New content is keyword-searchable before it is embedded.
        m.remember(&fact("p1", "Bananas", "fruit bowl")).unwrap();
        let r = m.retrieve_with("p1", "deploy", budget, Some(&e)).unwrap();
        assert_eq!(r.unembedded, 1);
    }

    #[test]
    fn ranking_modes_context_and_diversity() {
        let db = setup();
        let m = KnowledgeMemory::new(&db);
        for (t, b) in [
            ("Login A", "auth token login flow"),
            ("Login B", "auth token login flow, second copy"),
            ("Login security", "auth token vulnerability finding"),
            ("Schema", "database migration for auth tables"),
        ] {
            m.remember(&fact("p1", t, b)).unwrap();
        }
        let e = embedder();
        m.index_project("p1", &e, &no_cancel(), &mut |_| {})
            .unwrap();
        let budget = RetrievalBudget::default();
        let none = RetrievalContext::default();
        let base = RankingConfig::default();
        let rrf = RankingConfig {
            fusion: Fusion::ReciprocalRank,
            ..base.clone()
        };
        let r = m
            .retrieve_ranked("p1", "auth login", budget, Some(&e), &rrf, &none)
            .unwrap();
        assert_eq!(r.fusion, Fusion::ReciprocalRank);
        assert!(r.items[0].explanation.fused <= rrf.keyword_weight + rrf.vector_weight + 1e-9);
        // The security specialist sees the security note first.
        let ctx = RetrievalContext {
            specialist: Some("security-reviewer".into()),
            ..RetrievalContext::default()
        };
        let r = m
            .retrieve_ranked("p1", "auth login", budget, Some(&e), &base, &ctx)
            .unwrap();
        assert_eq!(r.items[0].item.title, "Login security");
        assert!(r.items[0].explanation.context_boost > 0.0);
        // MMR pushes the near-duplicate below a different result.
        let titles = |r: &RetrievalResult| {
            r.items
                .iter()
                .map(|i| i.item.title.clone())
                .collect::<Vec<_>>()
        };
        let plain = m
            .retrieve_ranked("p1", "auth login", budget, Some(&e), &base, &none)
            .unwrap();
        let diverse = RankingConfig {
            mmr_lambda: Some(0.3),
            ..base.clone()
        };
        let mmr = m
            .retrieve_ranked("p1", "auth login", budget, Some(&e), &diverse, &none)
            .unwrap();
        assert_ne!(titles(&plain), titles(&mmr));
        assert!(mmr.items[1].explanation.diversity_penalty > 0.0);
        // Layer filters and invalid configs.
        let only_episodic = RankingConfig {
            layers: vec![MemoryLayer::Episodic],
            ..base.clone()
        };
        assert!(m
            .retrieve_ranked("p1", "auth", budget, Some(&e), &only_episodic, &none)
            .unwrap()
            .items
            .is_empty());
        let bad = RankingConfig {
            keyword_weight: 2.0,
            ..base
        };
        assert!(m
            .retrieve_ranked("p1", "auth", budget, None, &bad, &none)
            .is_err());
    }

    #[test]
    fn secure_deletion_removes_content_from_the_database_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mem.sqlite3");
        let marker = "QUOKKA-PRIVATE-7781";
        {
            let db = Database::open(&path).unwrap();
            db.connection()
                .execute(
                    "INSERT INTO projects(id,root_path,display_name) VALUES ('p1','/p','p')",
                    [],
                )
                .unwrap();
            let m = KnowledgeMemory::new(&db);
            let keep = m.remember(&fact("p1", "keep", "unrelated text")).unwrap();
            let gone = m
                .remember(&fact(
                    "p1",
                    "secret note",
                    &format!("the token is {marker}"),
                ))
                .unwrap();
            m.index_project("p1", &embedder(), &no_cancel(), &mut |_| {})
                .unwrap();
            let body = format!("rotated {marker}");
            m.revise("p1", &gone.id, "secret note", &body, "x", 0.5, false, "op")
                .unwrap();
            let gone = m.get(&gone.id).unwrap().unwrap();
            assert!(
                !m.delete("p2", &keep.id).unwrap(),
                "no cross-project deletion"
            );
            assert!(m.delete("p1", &gone.id).unwrap());
            let log = m.deletions("p1", 10).unwrap();
            assert_eq!(log.len(), 1);
            assert_eq!(log[0]["content_sha256"], gone.content_sha256.as_str());
            assert!(
                !log[0].to_string().contains(marker),
                "tombstones hold no content"
            );
            let left: i64 = db
                .connection()
                .query_row(
                    "SELECT (SELECT COUNT(*) FROM memory_neural_vectors WHERE item_id=?1)
                          + (SELECT COUNT(*) FROM memory_item_versions WHERE item_id=?1)
                          + (SELECT COUNT(*) FROM memory_vectors WHERE item_id=?1)",
                    [&gone.id],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(left, 0);
            assert!(m
                .retrieve("p1", "QUOKKA", RetrievalBudget::default())
                .unwrap()
                .items
                .is_empty());
        }
        let mut bytes = std::fs::read(&path).unwrap();
        if let Ok(wal) = std::fs::read(dir.path().join("mem.sqlite3-wal")) {
            bytes.extend(wal);
        }
        let lower = marker.to_lowercase();
        assert!(
            !bytes
                .windows(marker.len())
                .any(|w| w == marker.as_bytes() || w == lower.as_bytes()),
            "deleted text must not remain in the database file"
        );
    }

    #[test]
    fn retention_expires_old_layers_but_never_approved_knowledge() {
        let db = setup();
        let m = KnowledgeMemory::new(&db);
        let old = m
            .remember(&MemoryInput {
                layer: MemoryLayer::Episodic,
                ..fact("p1", "old run", "what happened")
            })
            .unwrap();
        let fresh = m.remember(&fact("p1", "fresh", "still true")).unwrap();
        let approved = m.approve(&fresh.id, "alice").unwrap();
        db.connection()
            .execute(
                "UPDATE memory_items SET updated_ms = 0 WHERE id IN (?1, ?2)",
                params![old.id, approved.id],
            )
            .unwrap();
        let mut s = m.settings("p1").unwrap();
        s.retention = RetentionPolicy {
            episodic_days: Some(30),
            project_fact_days: Some(30),
            ..RetentionPolicy::default()
        };
        m.save_settings("p1", &s).unwrap();
        assert_eq!(m.settings("p1").unwrap().retention, s.retention);
        assert_eq!(m.apply_retention("p1", "system").unwrap(), 1);
        assert!(m.get(&old.id).unwrap().is_none());
        assert!(m.get(&approved.id).unwrap().is_some());
        assert!(m.get(&fresh.id).unwrap().is_some());
        assert_eq!(m.deletions("p1", 5).unwrap()[0]["reason"], "retention");
    }

    #[test]
    fn reworded_contradictions_are_caught_by_similarity() {
        let db = setup();
        let m = KnowledgeMemory::new(&db);
        let e = embedder();
        m.remember(&MemoryInput {
            verified: true,
            ..fact("p1", "Deploy policy", "Releases are deployed on Fridays.")
        })
        .unwrap();
        m.index_project("p1", &e, &no_cancel(), &mut |_| {})
            .unwrap();
        // Different title, same topic, contradicting statement.
        let proposed = fact(
            "p1",
            "When we ship",
            "Releases are not deployed on Fridays.",
        );
        let outcome = m
            .reconcile_semantic(&proposed, "model:planner", &e, 0.9)
            .unwrap();
        assert!(
            matches!(outcome, ReconcileOutcome::Conflict { .. }),
            "{outcome:?}"
        );
        // Plain title reconciliation would have stored it alongside.
        let separate = m.reconcile(&proposed, "model:planner").unwrap();
        assert!(matches!(separate, ReconcileOutcome::Added { .. }));
        m.index_project("p1", &e, &no_cancel(), &mut |_| {})
            .unwrap();
        let pairs = m.semantic_conflicts("p1", &e.model_id(), 0.9).unwrap();
        assert_eq!(pairs.len(), 1);
        assert!(pairs[0].similarity > 0.99);
    }

    #[test]
    fn episodes_group_memory_by_session() {
        let db = setup();
        let m = KnowledgeMemory::new(&db);
        for (run, title) in [("r1", "plan"), ("r1", "test"), ("r2", "fix")] {
            m.remember(&MemoryInput {
                layer: MemoryLayer::Episodic,
                run_id: Some(run.into()),
                ..fact("p1", title, &format!("{run} {title}"))
            })
            .unwrap();
        }
        let episodes = m.episodes("p1", 10).unwrap();
        assert_eq!(episodes.len(), 2);
        assert_eq!(episodes.iter().map(|e| e.items.len()).sum::<usize>(), 3);
        assert!(m.episodes("p2", 10).unwrap().is_empty(), "project isolated");
        // Cross-session recall can exclude the current session.
        let r = m
            .retrieve_ranked(
                "p1",
                "plan test fix",
                RetrievalBudget::default(),
                None,
                &RankingConfig::default(),
                &RetrievalContext {
                    exclude_run_id: Some("r1".into()),
                    ..RetrievalContext::default()
                },
            )
            .unwrap();
        assert!(!r.items.is_empty());
        assert!(r
            .items
            .iter()
            .all(|i| i.item.run_id.as_deref() == Some("r2")));
    }
}
