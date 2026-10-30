//! Versioned, contradiction-aware memory and a temporal fact graph.
//!
//! * [`KnowledgeMemory::revise`] keeps the previous content in an
//!   append-only history before changing an item.
//! * [`KnowledgeMemory::reconcile`] decides add / unchanged / revise for a
//!   new observation about an existing item (matched by layer and title).
//!   An unverified observation never overwrites verified memory: it becomes
//!   a [`KnowledgeConflict`] for a human to resolve.
//! * [`KnowledgeMemory::assert_fact`] treats `(from, relation)` as
//!   single-valued: a new target invalidates the old edge (kept for
//!   "as of" queries) unless that would let an inferred fact displace a
//!   verified one, which again becomes a conflict.
use rusqlite::params;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::{
    bounded, hashed_vector, item_from_row, now_ms, sha, to_blob, KnowledgeMemory, MemoryInput,
    MemoryItem, MemoryLayer, DIMS, ITEM_COLUMNS, LOCAL_VECTOR_MODEL,
};
use crate::collaboration::{new_id, Action, Collaboration};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MemoryVersion {
    pub version: i64,
    pub title: String,
    pub body: String,
    pub confidence: f64,
    pub verified: bool,
    pub source_ref: String,
    pub change_kind: String,
    pub changed_by: String,
    pub created_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct KnowledgeConflict {
    pub id: String,
    pub project_id: String,
    pub kind: String,
    pub existing_ref: String,
    pub proposed: Value,
    pub reason: String,
    pub created_ms: i64,
    pub resolved_ms: Option<i64>,
    pub resolved_by: Option<String>,
    pub resolution: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ReconcileOutcome {
    Added {
        item: MemoryItem,
    },
    Unchanged {
        item: MemoryItem,
    },
    Revised {
        item: MemoryItem,
        contradicted: bool,
    },
    Conflict {
        existing: MemoryItem,
        conflict_id: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FactOutcome {
    /// The current edge for `(from, relation)` after the call.
    pub edge_id: String,
    /// Edges this assertion invalidated.
    pub superseded: Vec<String>,
    /// Set when the assertion was held back for human review.
    pub conflict_id: Option<String>,
}

fn normalize_title(t: &str) -> String {
    t.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

pub(super) fn contradicts(a: &str, b: &str) -> bool {
    let claims = [
        research_retrieval::Claim {
            source_id: "existing".into(),
            text: a.into(),
        },
        research_retrieval::Claim {
            source_id: "proposed".into(),
            text: b.into(),
        },
    ];
    !research_retrieval::contradiction_candidates(&claims).is_empty()
}

impl KnowledgeMemory<'_> {
    fn record_conflict(
        &self,
        project_id: &str,
        kind: &str,
        existing_ref: &str,
        proposed: &Value,
        reason: &str,
    ) -> Result<String, String> {
        let id = new_id("kconf");
        let mut proposed = proposed.to_string();
        if proposed.len() > 12_000 {
            return Err("proposed change is too large to hold for review".into());
        }
        if proposed.is_empty() {
            proposed = "{}".into();
        }
        self.db
            .connection()
            .execute(
                "INSERT INTO knowledge_conflicts(id,project_id,kind,existing_ref,proposed_json,reason,created_ms)
                 VALUES (?1,?2,?3,?4,?5,?6,?7)",
                params![id, project_id, kind, existing_ref, proposed, bounded(reason, 500), now_ms()],
            )
            .map_err(|e| e.to_string())?;
        Ok(id)
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_revision(
        &self,
        item: &MemoryItem,
        title: &str,
        body: &str,
        source_ref: &str,
        confidence: f64,
        verified: bool,
        actor: &str,
        change_kind: &str,
    ) -> Result<MemoryItem, String> {
        if item.layer == MemoryLayer::ApprovedKnowledge {
            return Err("approved knowledge changes only through a new operator approval".into());
        }
        if !confidence.is_finite() || !(0.0..=1.0).contains(&confidence) {
            return Err("confidence must be within 0..1".into());
        }
        let title = bounded(title.trim(), 200);
        let body = bounded(body, 8_000);
        if title.is_empty() || source_ref.trim().is_empty() {
            return Err("title and source reference are required".into());
        }
        let content_sha = sha(&format!("{title}\n{body}"));
        let now = now_ms();
        let conn = self.db.connection();
        let tx = conn.unchecked_transaction().map_err(|e| e.to_string())?;
        tx.execute(
            "INSERT INTO memory_item_versions(item_id,project_id,version,title,body,confidence,verified,source_ref,change_kind,changed_by,created_ms)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            params![
                item.id, item.project_id, item.version, item.title, item.body, item.confidence,
                i64::from(item.verified), item.source_ref, change_kind, bounded(actor, 160), now
            ],
        )
        .map_err(|e| {
            // UNIQUE(item_id, version): someone already archived this version.
            if e.to_string().contains("UNIQUE") {
                "memory item changed concurrently; reload and retry".to_owned()
            } else {
                e.to_string()
            }
        })?;
        // Optimistic concurrency: the update applies only to the version read.
        let changed = tx
            .execute(
                "UPDATE memory_items SET title=?2, body=?3, content_sha256=?4, source_ref=?5, confidence=?6,
                    verified=?7, updated_ms=?8, version=version+1 WHERE id=?1 AND version=?9",
                params![
                    item.id, title, body, content_sha, bounded(source_ref, 512), confidence,
                    i64::from(verified), now, item.version
                ],
            )
            .map_err(|e| {
                if e.to_string().contains("UNIQUE") {
                    "an identical memory already exists in this layer".to_owned()
                } else {
                    e.to_string()
                }
            })?;
        if changed != 1 {
            return Err("memory item changed concurrently; reload and retry".into());
        }
        tx.execute(
            "INSERT OR REPLACE INTO memory_vectors(item_id,project_id,model,dims,vector,created_ms)
             VALUES (?1,?2,?3,?4,?5,?6)",
            params![
                item.id,
                item.project_id,
                LOCAL_VECTOR_MODEL,
                DIMS as i64,
                to_blob(&hashed_vector(&format!("{title} {body}"))),
                now
            ],
        )
        .map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        self.get(&item.id)?
            .ok_or_else(|| "memory item vanished".into())
    }

    /// Change an item's content, keeping the previous version in history.
    #[allow(clippy::too_many_arguments)]
    pub fn revise(
        &self,
        project_id: &str,
        item_id: &str,
        title: &str,
        body: &str,
        source_ref: &str,
        confidence: f64,
        verified: bool,
        actor: &str,
    ) -> Result<MemoryItem, String> {
        let item = self
            .get(item_id)?
            .filter(|i| i.project_id == project_id)
            .ok_or("memory item not found in this project")?;
        self.apply_revision(
            &item, title, body, source_ref, confidence, verified, actor, "revised",
        )
    }

    /// Prior versions, newest first.
    pub fn history(&self, project_id: &str, item_id: &str) -> Result<Vec<MemoryVersion>, String> {
        let mut stmt = self
            .db
            .connection()
            .prepare(
                "SELECT version,title,body,confidence,verified,source_ref,change_kind,changed_by,created_ms
                 FROM memory_item_versions WHERE item_id=?1 AND project_id=?2 ORDER BY version DESC LIMIT 200",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(params![item_id, project_id], |r| {
                Ok(MemoryVersion {
                    version: r.get(0)?,
                    title: r.get(1)?,
                    body: r.get(2)?,
                    confidence: r.get(3)?,
                    verified: r.get::<_, i64>(4)? != 0,
                    source_ref: r.get(5)?,
                    change_kind: r.get(6)?,
                    changed_by: r.get(7)?,
                    created_ms: r.get(8)?,
                })
            })
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<_, _>>().map_err(|e| e.to_string())
    }

    /// Fold a new observation into memory (see module docs).
    pub fn reconcile(&self, input: &MemoryInput, actor: &str) -> Result<ReconcileOutcome, String> {
        if input.layer == MemoryLayer::ApprovedKnowledge {
            return Err("approved knowledge is created only by an operator approval".into());
        }
        let wanted = normalize_title(&input.title);
        let existing = {
            let mut stmt = self
                .db
                .connection()
                .prepare(&format!(
                    "SELECT {ITEM_COLUMNS} FROM memory_items WHERE project_id=?1 AND layer=?2
                       AND (expires_ms IS NULL OR expires_ms > ?3) ORDER BY updated_ms DESC LIMIT 500"
                ))
                .map_err(|e| e.to_string())?;
            let rows = stmt
                .query_map(
                    params![input.project_id, input.layer.as_str(), now_ms()],
                    item_from_row,
                )
                .map_err(|e| e.to_string())?;
            let mut found = None;
            for row in rows {
                let item = row.map_err(|e| e.to_string())?;
                if normalize_title(&item.title) == wanted {
                    found = Some(item);
                    break;
                }
            }
            found
        };
        let Some(existing) = existing else {
            return Ok(ReconcileOutcome::Added {
                item: self.remember(input)?,
            });
        };
        self.reconcile_against(existing, input, actor)
    }

    /// Fold `input` into `existing`, an item already judged to describe the
    /// same fact (by title, or by neural similarity).
    pub(super) fn reconcile_against(
        &self,
        existing: MemoryItem,
        input: &MemoryInput,
        actor: &str,
    ) -> Result<ReconcileOutcome, String> {
        if existing.body.trim() == input.body.trim() {
            // Same fact restated: refresh it in place (titles may differ in case).
            self.db
                .connection()
                .execute(
                    "UPDATE memory_items SET updated_ms=?2, confidence=MAX(confidence, ?3),
                        verified=MAX(verified, ?4) WHERE id=?1",
                    params![
                        existing.id,
                        now_ms(),
                        input.confidence,
                        i64::from(input.verified)
                    ],
                )
                .map_err(|e| e.to_string())?;
            let item = self.get(&existing.id)?.ok_or("memory item vanished")?;
            return Ok(ReconcileOutcome::Unchanged { item });
        }
        let contradicted = contradicts(&existing.body, &input.body);
        if existing.verified && !input.verified {
            let conflict_id = self.record_conflict(
                &input.project_id,
                "memory",
                &existing.id,
                &serde_json::to_value(input).map_err(|e| e.to_string())?,
                if contradicted {
                    "unverified observation contradicts verified memory"
                } else {
                    "unverified observation would overwrite verified memory"
                },
            )?;
            return Ok(ReconcileOutcome::Conflict {
                existing,
                conflict_id,
            });
        }
        let item = self.apply_revision(
            &existing,
            &input.title,
            &input.body,
            &input.source_ref,
            input.confidence,
            input.verified,
            actor,
            if contradicted {
                "superseded"
            } else {
                "revised"
            },
        )?;
        Ok(ReconcileOutcome::Revised { item, contradicted })
    }

    /// Assert that `(from, relation)` now points at `to` (single-valued).
    #[allow(clippy::too_many_arguments)]
    pub fn assert_fact(
        &self,
        project_id: &str,
        from: &str,
        relation: &str,
        to: &str,
        source_ref: &str,
        confidence: f64,
        verified: bool,
    ) -> Result<FactOutcome, String> {
        let current: Vec<(String, String, String)> = {
            let mut stmt = self
                .db
                .connection()
                .prepare(
                    "SELECT id, to_node, provenance FROM kg_edges
                     WHERE project_id=?1 AND from_node=?2 AND relation=?3 AND invalidated_ms IS NULL AND to_node<>?4",
                )
                .map_err(|e| e.to_string())?;
            let rows = stmt
                .query_map(params![project_id, from, relation, to], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?))
                })
                .map_err(|e| e.to_string())?;
            rows.collect::<Result<_, _>>().map_err(|e| e.to_string())?
        };
        if !verified {
            if let Some((edge, _, _)) = current.iter().find(|(_, _, p)| p == "verified") {
                let conflict_id = self.record_conflict(
                    project_id,
                    "edge",
                    edge,
                    &json!({"from": from, "relation": relation, "to": to,
                            "source_ref": source_ref, "confidence": confidence, "verified": verified}),
                    "inferred fact would replace a verified fact",
                )?;
                return Ok(FactOutcome {
                    edge_id: edge.clone(),
                    superseded: Vec::new(),
                    conflict_id: Some(conflict_id),
                });
            }
        }
        let edge_id = self.link(
            project_id, from, to, relation, source_ref, confidence, verified,
        )?;
        let now = now_ms();
        let mut superseded = Vec::new();
        for (old, _, _) in current {
            self.db
                .connection()
                .execute(
                    "UPDATE kg_edges SET invalidated_ms=?2, superseded_by=?3 WHERE id=?1 AND invalidated_ms IS NULL",
                    params![old, now, edge_id],
                )
                .map_err(|e| e.to_string())?;
            superseded.push(old);
        }
        Ok(FactOutcome {
            edge_id,
            superseded,
            conflict_id: None,
        })
    }

    pub fn conflicts(
        &self,
        project_id: &str,
        open_only: bool,
    ) -> Result<Vec<KnowledgeConflict>, String> {
        let mut stmt = self
            .db
            .connection()
            .prepare(
                "SELECT id,project_id,kind,existing_ref,proposed_json,reason,created_ms,resolved_ms,resolved_by,resolution
                 FROM knowledge_conflicts WHERE project_id=?1 AND (?2 = 0 OR resolved_ms IS NULL)
                 ORDER BY created_ms DESC LIMIT 500",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(params![project_id, i64::from(open_only)], |r| {
                let proposed: String = r.get(4)?;
                Ok(KnowledgeConflict {
                    id: r.get(0)?,
                    project_id: r.get(1)?,
                    kind: r.get(2)?,
                    existing_ref: r.get(3)?,
                    proposed: serde_json::from_str(&proposed).unwrap_or(Value::Null),
                    reason: r.get(5)?,
                    created_ms: r.get(6)?,
                    resolved_ms: r.get(7)?,
                    resolved_by: r.get(8)?,
                    resolution: r.get(9)?,
                })
            })
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<_, _>>().map_err(|e| e.to_string())
    }

    /// Accept or reject a held-back change. Requires human approval
    /// authority; an accepted change is applied with the reviewer recorded.
    pub fn resolve_conflict(
        &self,
        project_id: &str,
        conflict_id: &str,
        actor: &str,
        accept: bool,
    ) -> Result<(), String> {
        Collaboration::new(self.db).authorize(project_id, actor, Action::Approve)?;
        let conflict = self
            .conflicts(project_id, true)?
            .into_iter()
            .find(|c| c.id == conflict_id)
            .ok_or("conflict not found or already resolved")?;
        if accept {
            match conflict.kind.as_str() {
                "memory" => {
                    let input: MemoryInput = serde_json::from_value(conflict.proposed.clone())
                        .map_err(|_| "stored proposal is unreadable".to_string())?;
                    let existing = self
                        .get(&conflict.existing_ref)?
                        .ok_or("the conflicting memory no longer exists")?;
                    self.apply_revision(
                        &existing,
                        &input.title,
                        &input.body,
                        &input.source_ref,
                        input.confidence,
                        input.verified,
                        actor,
                        "superseded",
                    )?;
                }
                "edge" => {
                    let p = &conflict.proposed;
                    let field = |k: &str| {
                        p.get(k)
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_owned()
                    };
                    let (from, relation, to) = (field("from"), field("relation"), field("to"));
                    let edge_id = self.link(
                        project_id,
                        &from,
                        &to,
                        &relation,
                        &field("source_ref"),
                        p.get("confidence").and_then(Value::as_f64).unwrap_or(0.5),
                        false,
                    )?;
                    self.db
                        .connection()
                        .execute(
                            "UPDATE kg_edges SET invalidated_ms=?2, superseded_by=?3 WHERE id=?1 AND invalidated_ms IS NULL",
                            params![conflict.existing_ref, now_ms(), edge_id],
                        )
                        .map_err(|e| e.to_string())?;
                }
                other => return Err(format!("unknown conflict kind `{other}`")),
            }
        }
        let changed = self
            .db
            .connection()
            .execute(
                "UPDATE knowledge_conflicts SET resolved_ms=?2, resolved_by=?3, resolution=?4
                 WHERE id=?1 AND resolved_ms IS NULL",
                params![
                    conflict_id,
                    now_ms(),
                    actor,
                    if accept { "accepted" } else { "rejected" }
                ],
            )
            .map_err(|e| e.to_string())?;
        if changed != 1 {
            return Err("conflict was resolved concurrently".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::{EmbeddingProvider, RetrievalBudget};
    use super::*;
    use crate::collaboration::PrincipalKind;
    use crate::Database;

    fn db() -> Database {
        let db = Database::open_in_memory().unwrap();
        db.connection()
            .execute(
                "INSERT INTO projects(id, root_path, display_name, path_identity) VALUES ('p1','/tmp/p1','p1','/tmp/p1')",
                [],
            )
            .unwrap();
        db
    }

    fn fact(title: &str, body: &str, verified: bool) -> MemoryInput {
        MemoryInput {
            project_id: "p1".into(),
            layer: MemoryLayer::ProjectFact,
            title: title.into(),
            body: body.into(),
            source_kind: "test".into(),
            source_ref: "test:1".into(),
            source_sha256: None,
            run_id: None,
            task_id: None,
            confidence: 0.7,
            verified,
            ttl_ms: None,
        }
    }

    #[test]
    fn revisions_keep_append_only_history_and_detect_lost_updates() {
        let db = db();
        let m = KnowledgeMemory::new(&db);
        let item = m
            .remember(&fact("Auth", "Sessions use JWT", false))
            .unwrap();
        assert_eq!(item.version, 1);
        let v2 = m
            .revise(
                "p1",
                &item.id,
                "Auth",
                "Sessions use opaque tokens",
                "pr:42",
                0.9,
                false,
                "alice",
            )
            .unwrap();
        assert_eq!(v2.version, 2);
        let history = m.history("p1", &item.id).unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].body, "Sessions use JWT");
        assert_eq!(history[0].changed_by, "alice");
        assert!(db
            .connection()
            .execute("UPDATE memory_item_versions SET body='x'", [])
            .is_err());
        // A writer holding the stale version 1 cannot clobber version 2.
        let err = m
            .apply_revision(
                &item,
                "Auth",
                "stale write",
                "x",
                0.5,
                false,
                "bob",
                "revised",
            )
            .unwrap_err();
        assert!(err.contains("concurrently"), "{err}");
        assert!(
            m.revise("p2", &item.id, "Auth", "x", "x", 0.5, false, "a")
                .is_err(),
            "project isolated"
        );
    }

    #[test]
    fn reconcile_adds_revises_and_never_lets_unverified_overwrite_verified() {
        let db = db();
        let m = KnowledgeMemory::new(&db);
        let ReconcileOutcome::Added { item } = m
            .reconcile(&fact("Streaming", "Streaming is supported", true), "worker")
            .unwrap()
        else {
            panic!("expected add")
        };
        assert!(matches!(
            m.reconcile(
                &fact("streaming ", "Streaming is supported", true),
                "worker"
            )
            .unwrap(),
            ReconcileOutcome::Unchanged { .. }
        ));
        assert_eq!(
            m.list("p1", None, 50).unwrap().len(),
            1,
            "a restated fact is not duplicated"
        );
        let ReconcileOutcome::Conflict {
            existing,
            conflict_id,
        } = m
            .reconcile(
                &fact("Streaming", "Streaming is not supported", false),
                "worker",
            )
            .unwrap()
        else {
            panic!("expected conflict")
        };
        assert_eq!(existing.id, item.id);
        assert_eq!(
            m.get(&item.id).unwrap().unwrap().body,
            "Streaming is supported",
            "not overwritten"
        );
        let open = m.conflicts("p1", true).unwrap();
        assert_eq!(open.len(), 1);
        assert_eq!(
            open[0].reason,
            "unverified observation contradicts verified memory"
        );

        // Automation cannot resolve; a human approver can.
        Collaboration::new(&db)
            .ensure_principal("bot:x", "bot", PrincipalKind::Automation)
            .unwrap();
        assert!(m
            .resolve_conflict("p1", &conflict_id, "bot:x", true)
            .is_err());
        m.resolve_conflict("p1", &conflict_id, "alice", true)
            .unwrap();
        let now = m.get(&item.id).unwrap().unwrap();
        assert_eq!(now.body, "Streaming is not supported");
        assert_eq!(
            m.history("p1", &item.id).unwrap()[0].change_kind,
            "superseded"
        );
        assert!(m.conflicts("p1", true).unwrap().is_empty());
        assert!(m
            .resolve_conflict("p1", &conflict_id, "alice", true)
            .is_err());

        // Verified observations revise directly and report contradiction.
        let ReconcileOutcome::Revised {
            contradicted,
            item: revised,
        } = m
            .reconcile(&fact("Streaming", "Streaming is supported", true), "worker")
            .unwrap()
        else {
            panic!("expected revise")
        };
        assert!(contradicted);
        assert_eq!(revised.version, 3);
    }

    #[test]
    fn exclusive_facts_supersede_and_remain_queryable_as_of_a_time() {
        let db = db();
        let m = KnowledgeMemory::new(&db);
        let svc = m.upsert_node("p1", "file", "src/auth.rs", "auth").unwrap();
        let old = m
            .upsert_node("p1", "decision", "use-jwt", "Use JWT")
            .unwrap();
        let new = m
            .upsert_node("p1", "decision", "use-opaque", "Use opaque tokens")
            .unwrap();
        let first = m
            .assert_fact("p1", &svc, "decided", &old, "adr:1", 0.9, true)
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(5));
        let before_change = now_ms();
        std::thread::sleep(std::time::Duration::from_millis(5));

        // An inferred fact cannot displace a verified one.
        let held = m
            .assert_fact("p1", &svc, "decided", &new, "model:guess", 0.6, false)
            .unwrap();
        assert!(held.conflict_id.is_some());
        assert_eq!(held.edge_id, first.edge_id);
        assert_eq!(m.neighborhood("p1", &svc, 1).unwrap().edges.len(), 1);

        let second = m
            .assert_fact("p1", &svc, "decided", &new, "adr:2", 0.95, true)
            .unwrap();
        assert_eq!(second.superseded, vec![first.edge_id.clone()]);
        let current = m.neighborhood("p1", &svc, 1).unwrap();
        assert_eq!(current.edges.len(), 1);
        assert_eq!(current.edges[0].to_node, new);
        let past = m
            .neighborhood_at("p1", &svc, 1, Some(before_change))
            .unwrap();
        assert_eq!(past.edges.len(), 1);
        assert_eq!(past.edges[0].to_node, old, "history is preserved");
        assert!(past.edges[0].invalidated_ms.is_some());

        // Re-asserting the old fact revalidates it and supersedes the new one.
        let back = m
            .assert_fact("p1", &svc, "decided", &old, "adr:3", 0.9, true)
            .unwrap();
        assert_eq!(back.superseded, vec![second.edge_id]);
        assert_eq!(m.neighborhood("p1", &svc, 1).unwrap().edges[0].to_node, old);
    }

    /// Deterministic stand-in with a tiny concept space, so the test can
    /// check that retrieval really ranks by the provider's vectors.
    struct ConceptEmbedder;
    impl EmbeddingProvider for ConceptEmbedder {
        fn model_id(&self) -> String {
            "neural:test-concepts@127.0.0.1".into()
        }
        fn embed(&self, _project: &str, texts: &[String]) -> Result<Vec<Vec<f32>>, String> {
            Ok(texts
                .iter()
                .map(|t| {
                    let t = t.to_lowercase();
                    let mut v = [0.01f32; 8];
                    if ["login", "credential", "authentication", "sign-in"]
                        .iter()
                        .any(|w| t.contains(w))
                    {
                        v[0] = 1.0;
                    }
                    if ["invoice", "billing", "payment"]
                        .iter()
                        .any(|w| t.contains(w))
                    {
                        v[1] = 1.0;
                    }
                    let n = v.iter().map(|x| x * x).sum::<f32>().sqrt();
                    v.iter().map(|x| x / n).collect()
                })
                .collect())
        }
    }

    #[test]
    fn neural_vectors_rank_synonyms_and_go_stale_on_revision() {
        let db = db();
        let m = KnowledgeMemory::new(&db);
        let auth = m
            .remember(&fact(
                "Sign-in flow",
                "Credential checks happen in the gateway",
                false,
            ))
            .unwrap();
        m.remember(&fact("Billing", "Invoices are generated nightly", false))
            .unwrap();
        let lexical = m
            .retrieve("p1", "authentication", RetrievalBudget::default())
            .unwrap();
        assert_eq!(lexical.vector_model, LOCAL_VECTOR_MODEL);
        assert!(
            lexical.items.is_empty(),
            "no shared tokens, so lexical recall finds nothing"
        );

        // Without stored vectors the embedder is not used and lexical is reported.
        let unindexed = m
            .retrieve_with(
                "p1",
                "authentication",
                RetrievalBudget::default(),
                Some(&ConceptEmbedder),
            )
            .unwrap();
        assert_eq!(unindexed.vector_model, LOCAL_VECTOR_MODEL);

        assert_eq!(m.embed_project("p1", &ConceptEmbedder, 100).unwrap(), 2);
        assert_eq!(
            m.embed_project("p1", &ConceptEmbedder, 100).unwrap(),
            0,
            "already current"
        );
        let neural = m
            .retrieve_with(
                "p1",
                "authentication",
                RetrievalBudget::default(),
                Some(&ConceptEmbedder),
            )
            .unwrap();
        assert_eq!(neural.vector_model, "neural:test-concepts@127.0.0.1");
        assert_eq!(neural.items[0].item.id, auth.id);

        m.revise(
            "p1",
            &auth.id,
            "Sign-in flow",
            "Moved to a separate service",
            "pr:1",
            0.8,
            false,
            "a",
        )
        .unwrap();
        let stale = m
            .retrieve_with(
                "p1",
                "authentication",
                RetrievalBudget::default(),
                Some(&ConceptEmbedder),
            )
            .unwrap();
        assert!(
            stale
                .items
                .iter()
                .all(|s| s.item.id != auth.id || s.vector_score == 0.0),
            "stale vector ignored"
        );
        assert_eq!(
            m.embed_project("p1", &ConceptEmbedder, 100).unwrap(),
            1,
            "only the revised item is re-embedded"
        );
    }
}
