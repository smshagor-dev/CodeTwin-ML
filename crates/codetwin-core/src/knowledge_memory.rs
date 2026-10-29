//! Layered project memory with hybrid (FTS5 + local vector) retrieval and an
//! evidence-grounded knowledge graph (migration 49).
//!
//! * Memory is retrieval context, never authorization.
//! * Everything is scoped by `project_id`; no query crosses projects.
//! * The default vectors are deterministic hashed-token vectors — lexical
//!   recall, not neural semantics. Neural vectors can be stored under another
//!   `model` name by an explicitly consented embedding provider.
//! * Graph edges always carry a source reference, a confidence and whether
//!   they are `verified` (backed by persisted evidence) or `inferred`.
//! * Edges have a validity interval (migration 53); superseded facts are
//!   invalidated, not deleted, so the graph can be read "as of" a time.
//! * [`EmbeddingProvider`] vectors are stored per model next to the lexical
//!   ones; retrieval reports which model actually ranked the results.
use std::collections::{BTreeMap, BTreeSet};

use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::Database;

mod embeddings;
mod temporal;
pub use embeddings::{EmbeddingDestination, EmbeddingProvider, HttpEmbedder};
pub use temporal::{FactOutcome, KnowledgeConflict, MemoryVersion, ReconcileOutcome};

pub const LOCAL_VECTOR_MODEL: &str = "hashed-lexical-v1";
const DIMS: usize = 128;
const MAX_ITEMS_PER_PROJECT: i64 = 5_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryLayer {
    Working,
    Episodic,
    ProjectFact,
    ApprovedKnowledge,
    EvidenceRef,
}

impl MemoryLayer {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Working => "working",
            Self::Episodic => "episodic",
            Self::ProjectFact => "project_fact",
            Self::ApprovedKnowledge => "approved_knowledge",
            Self::EvidenceRef => "evidence_ref",
        }
    }
    fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "working" => Self::Working,
            "episodic" => Self::Episodic,
            "project_fact" => Self::ProjectFact,
            "approved_knowledge" => Self::ApprovedKnowledge,
            "evidence_ref" => Self::EvidenceRef,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryInput {
    pub project_id: String,
    pub layer: MemoryLayer,
    pub title: String,
    pub body: String,
    pub source_kind: String,
    pub source_ref: String,
    pub source_sha256: Option<String>,
    pub run_id: Option<String>,
    pub task_id: Option<String>,
    pub confidence: f64,
    pub verified: bool,
    pub ttl_ms: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryItem {
    pub id: String,
    pub project_id: String,
    pub layer: MemoryLayer,
    pub title: String,
    pub body: String,
    pub source_kind: String,
    pub source_ref: String,
    pub source_sha256: Option<String>,
    pub content_sha256: String,
    pub run_id: Option<String>,
    pub task_id: Option<String>,
    pub confidence: f64,
    pub verified: bool,
    pub approved_by: Option<String>,
    pub created_ms: i64,
    pub updated_ms: i64,
    pub expires_ms: Option<i64>,
    #[serde(default = "first_version")]
    pub version: i64,
}

const fn first_version() -> i64 {
    1
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct RetrievalBudget {
    pub max_items: usize,
    pub max_chars: usize,
}

impl Default for RetrievalBudget {
    fn default() -> Self {
        Self {
            max_items: 12,
            max_chars: 6_000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoredMemory {
    pub item: MemoryItem,
    pub keyword_score: f64,
    pub vector_score: f64,
    pub score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetrievalResult {
    pub items: Vec<ScoredMemory>,
    pub candidates: usize,
    /// Relevant items left out by the item/character budget.
    pub omitted: usize,
    pub omitted_chars: usize,
    pub vector_model: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GraphNode {
    pub id: String,
    pub kind: String,
    pub ref_id: String,
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GraphEdge {
    pub id: String,
    pub from_node: String,
    pub to_node: String,
    pub relation: String,
    pub source_ref: String,
    pub confidence: f64,
    pub provenance: String,
    pub valid_from_ms: Option<i64>,
    /// Set once a newer fact superseded this edge.
    pub invalidated_ms: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceGraph {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
    pub truncated: bool,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn sha(text: &str) -> String {
    hex(&Sha256::digest(text.as_bytes()))
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64)
}

fn tokens(text: &str) -> Vec<String> {
    text.split(|c: char| !c.is_alphanumeric() && c != '_')
        .filter(|t| t.chars().count() >= 2)
        .map(str::to_lowercase)
        .take(4_000)
        .collect()
}

/// Deterministic, normalized hashed-token vector (signed feature hashing).
pub fn hashed_vector(text: &str) -> Vec<f32> {
    let mut v = vec![0f32; DIMS];
    for token in tokens(text) {
        let d = Sha256::digest(token.as_bytes());
        let index = (u16::from_le_bytes([d[0], d[1]]) as usize) % DIMS;
        let sign = if d[2] & 1 == 0 { 1.0 } else { -1.0 };
        v[index] += sign;
    }
    let norm = v.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm > 0.0 {
        v.iter_mut().for_each(|x| *x /= norm);
    }
    v
}

fn to_blob(v: &[f32]) -> Vec<u8> {
    v.iter().flat_map(|x| x.to_le_bytes()).collect()
}

fn from_blob(b: &[u8], dims: usize) -> Option<Vec<f32>> {
    if dims == 0 || b.len() != dims * 4 {
        return None;
    }
    let v: Vec<f32> = b
        .chunks_exact(4)
        .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect();
    v.iter().all(|x| x.is_finite()).then_some(v)
}

fn cosine(a: &[f32], b: &[f32]) -> f64 {
    if a.len() != b.len() {
        return 0.0;
    }
    a.iter()
        .zip(b)
        .map(|(x, y)| f64::from(*x) * f64::from(*y))
        .sum()
}

const ITEM_COLUMNS: &str =
    "id,project_id,layer,title,body,source_kind,source_ref,source_sha256,content_sha256,
    run_id,task_id,confidence,verified,approved_by,created_ms,updated_ms,expires_ms,version";

fn item_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<MemoryItem> {
    let layer: String = row.get(2)?;
    Ok(MemoryItem {
        id: row.get(0)?,
        project_id: row.get(1)?,
        layer: MemoryLayer::parse(&layer).ok_or_else(|| {
            rusqlite::Error::FromSqlConversionFailure(
                2,
                rusqlite::types::Type::Text,
                "layer".into(),
            )
        })?,
        title: row.get(3)?,
        body: row.get(4)?,
        source_kind: row.get(5)?,
        source_ref: row.get(6)?,
        source_sha256: row.get(7)?,
        content_sha256: row.get(8)?,
        run_id: row.get(9)?,
        task_id: row.get(10)?,
        confidence: row.get(11)?,
        verified: row.get::<_, i64>(12)? != 0,
        approved_by: row.get(13)?,
        created_ms: row.get(14)?,
        updated_ms: row.get(15)?,
        expires_ms: row.get(16)?,
        version: row.get(17)?,
    })
}

fn bounded(text: &str, max: usize) -> String {
    text.chars().take(max).collect()
}

pub struct KnowledgeMemory<'a> {
    db: &'a Database,
}

impl<'a> KnowledgeMemory<'a> {
    pub const fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Store (or refresh) a memory item. Identical content in the same layer
    /// is deduplicated. Approved knowledge can only be created via `approve`.
    pub fn remember(&self, input: &MemoryInput) -> Result<MemoryItem, String> {
        if input.layer == MemoryLayer::ApprovedKnowledge {
            return Err("approved knowledge is created only by an operator approval".into());
        }
        if !input.confidence.is_finite() || !(0.0..=1.0).contains(&input.confidence) {
            return Err("confidence must be within 0..1".into());
        }
        let title = bounded(input.title.trim(), 200);
        let body = bounded(&input.body, 8_000);
        if title.is_empty() || input.source_ref.trim().is_empty() {
            return Err("title and source reference are required".into());
        }
        let content_sha = sha(&format!("{title}\n{body}"));
        let now = now_ms();
        let conn = self.db.connection();
        let tx = conn.unchecked_transaction().map_err(|e| e.to_string())?;
        let existing: Option<String> = tx
            .query_row(
                "SELECT id FROM memory_items WHERE project_id=?1 AND layer=?2 AND content_sha256=?3",
                params![input.project_id, input.layer.as_str(), content_sha],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| e.to_string())?;
        let id = match existing {
            Some(id) => {
                tx.execute(
                    "UPDATE memory_items SET updated_ms=?2, confidence=MAX(confidence, ?3),
                        verified=MAX(verified, ?4), expires_ms=?5 WHERE id=?1",
                    params![
                        id,
                        now,
                        input.confidence,
                        i64::from(input.verified),
                        input.ttl_ms.map(|t| now + t)
                    ],
                )
                .map_err(|e| e.to_string())?;
                id
            }
            None => {
                let id = format!(
                    "mem_{}",
                    &sha(&format!(
                        "{}:{content_sha}:{}",
                        input.project_id,
                        input.layer.as_str()
                    ))[..24]
                );
                tx.execute(
                    "INSERT INTO memory_items(id,project_id,layer,title,body,source_kind,source_ref,source_sha256,
                        content_sha256,run_id,task_id,confidence,verified,created_ms,updated_ms,expires_ms)
                     VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?14,?15)",
                    params![
                        id,
                        input.project_id,
                        input.layer.as_str(),
                        title,
                        body,
                        bounded(&input.source_kind, 64),
                        bounded(&input.source_ref, 512),
                        input.source_sha256,
                        content_sha,
                        input.run_id,
                        input.task_id,
                        input.confidence,
                        i64::from(input.verified),
                        now,
                        input.ttl_ms.map(|t| now + t)
                    ],
                )
                .map_err(|e| e.to_string())?;
                tx.execute(
                    "INSERT OR REPLACE INTO memory_vectors(item_id,project_id,model,dims,vector,created_ms)
                     VALUES (?1,?2,?3,?4,?5,?6)",
                    params![id, input.project_id, LOCAL_VECTOR_MODEL, DIMS as i64, to_blob(&hashed_vector(&format!("{title} {body}"))), now],
                )
                .map_err(|e| e.to_string())?;
                id
            }
        };
        // Bound storage: drop the oldest unapproved items beyond the cap.
        tx.execute(
            "DELETE FROM memory_items WHERE id IN (
                SELECT id FROM memory_items WHERE project_id=?1 AND layer <> 'approved_knowledge'
                ORDER BY updated_ms DESC LIMIT -1 OFFSET ?2)",
            params![input.project_id, MAX_ITEMS_PER_PROJECT],
        )
        .map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        self.get(&id)?.ok_or_else(|| "memory item vanished".into())
    }

    pub fn get(&self, id: &str) -> Result<Option<MemoryItem>, String> {
        self.db
            .connection()
            .query_row(
                &format!("SELECT {ITEM_COLUMNS} FROM memory_items WHERE id=?1"),
                [id],
                item_from_row,
            )
            .optional()
            .map_err(|e| e.to_string())
    }

    pub fn list(
        &self,
        project_id: &str,
        layer: Option<MemoryLayer>,
        limit: usize,
    ) -> Result<Vec<MemoryItem>, String> {
        let mut stmt = self
            .db
            .connection()
            .prepare(&format!(
                "SELECT {ITEM_COLUMNS} FROM memory_items WHERE project_id=?1 AND (?2 IS NULL OR layer=?2)
                 ORDER BY updated_ms DESC LIMIT ?3"
            ))
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(
                params![
                    project_id,
                    layer.map(MemoryLayer::as_str),
                    limit.clamp(1, 500) as i64
                ],
                item_from_row,
            )
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<_, _>>().map_err(|e| e.to_string())
    }

    /// Operator promotion of an item into user-approved reusable knowledge.
    pub fn approve(&self, item_id: &str, operator: &str) -> Result<MemoryItem, String> {
        let operator = operator.trim();
        if operator.is_empty()
            || ["worker:", "model:", "agent:"]
                .iter()
                .any(|p| operator.to_lowercase().starts_with(p))
        {
            return Err("only an operator can approve knowledge".into());
        }
        let item = self.get(item_id)?.ok_or("memory item not found")?;
        let now = now_ms();
        let id = format!(
            "mem_{}",
            &sha(&format!(
                "{}:{}:approved",
                item.project_id, item.content_sha256
            ))[..24]
        );
        let conn = self.db.connection();
        conn.execute(
            "INSERT OR IGNORE INTO memory_items(id,project_id,layer,title,body,source_kind,source_ref,source_sha256,
                content_sha256,run_id,task_id,confidence,verified,approved_by,created_ms,updated_ms)
             SELECT ?2,project_id,'approved_knowledge',title,body,source_kind,source_ref,source_sha256,
                content_sha256,run_id,task_id,confidence,verified,?3,?4,?4 FROM memory_items WHERE id=?1",
            params![item_id, id, bounded(operator, 120), now],
        )
        .map_err(|e| e.to_string())?;
        conn.execute(
            "INSERT OR IGNORE INTO memory_vectors(item_id,project_id,model,dims,vector,created_ms)
             SELECT ?2,project_id,model,dims,vector,?3 FROM memory_vectors WHERE item_id=?1",
            params![item_id, id, now],
        )
        .map_err(|e| e.to_string())?;
        self.get(&id)?.ok_or_else(|| "approval failed".into())
    }

    pub fn delete(&self, project_id: &str, item_id: &str) -> Result<bool, String> {
        self.db
            .connection()
            .execute(
                "DELETE FROM memory_items WHERE id=?1 AND project_id=?2",
                params![item_id, project_id],
            )
            .map(|n| n == 1)
            .map_err(|e| e.to_string())
    }

    pub fn clear(&self, project_id: &str, layer: Option<MemoryLayer>) -> Result<usize, String> {
        self.db
            .connection()
            .execute(
                "DELETE FROM memory_items WHERE project_id=?1 AND (?2 IS NULL OR layer=?2)",
                params![project_id, layer.map(MemoryLayer::as_str)],
            )
            .map_err(|e| e.to_string())
    }

    pub fn expire(&self) -> Result<usize, String> {
        self.db
            .connection()
            .execute(
                "DELETE FROM memory_items WHERE expires_ms IS NOT NULL AND expires_ms <= ?1",
                [now_ms()],
            )
            .map_err(|e| e.to_string())
    }

    /// Rebuild the keyword index and the local vectors for one project.
    pub fn reindex(&self, project_id: &str) -> Result<usize, String> {
        let conn = self.db.connection();
        conn.execute("INSERT INTO memory_fts(memory_fts) VALUES ('rebuild')", [])
            .map_err(|e| e.to_string())?;
        let items = self.list(project_id, None, 500)?;
        let now = now_ms();
        for item in &items {
            conn.execute(
                "INSERT OR REPLACE INTO memory_vectors(item_id,project_id,model,dims,vector,created_ms)
                 VALUES (?1,?2,?3,?4,?5,?6)",
                params![item.id, project_id, LOCAL_VECTOR_MODEL, DIMS as i64, to_blob(&hashed_vector(&format!("{} {}", item.title, item.body))), now],
            )
            .map_err(|e| e.to_string())?;
        }
        Ok(items.len())
    }

    /// Hybrid keyword + vector retrieval within one project, bounded by
    /// `budget`, with transparent omission accounting.
    pub fn retrieve(
        &self,
        project_id: &str,
        query: &str,
        budget: RetrievalBudget,
    ) -> Result<RetrievalResult, String> {
        self.retrieve_with(project_id, query, budget, None)
    }

    /// Like [`Self::retrieve`], ranking the vector half with `embedder`'s
    /// stored vectors when the project has been embedded with that model.
    /// Falls back to the lexical vectors otherwise; `vector_model` in the
    /// result always names the model that was actually used.
    pub fn retrieve_with(
        &self,
        project_id: &str,
        query: &str,
        budget: RetrievalBudget,
        embedder: Option<&dyn EmbeddingProvider>,
    ) -> Result<RetrievalResult, String> {
        let terms: Vec<String> = tokens(query).into_iter().take(16).collect();
        let now = now_ms();
        let conn = self.db.connection();
        let mut keyword: BTreeMap<String, f64> = BTreeMap::new();
        if !terms.is_empty() {
            let fts_query = terms
                .iter()
                .map(|t| format!("\"{}\"", t.replace('"', "")))
                .collect::<Vec<_>>()
                .join(" OR ");
            let mut stmt = conn
                .prepare(
                    "SELECT m.id, bm25(memory_fts) FROM memory_fts JOIN memory_items m ON m.rowid = memory_fts.rowid
                     WHERE memory_fts MATCH ?1 AND m.project_id = ?2 ORDER BY bm25(memory_fts) LIMIT 100",
                )
                .map_err(|e| e.to_string())?;
            let rows = stmt
                .query_map(params![fts_query, project_id], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, f64>(1)?))
                })
                .map_err(|e| e.to_string())?;
            for row in rows {
                let (id, rank) = row.map_err(|e| e.to_string())?;
                // bm25 is negative-is-better; map to 0..1.
                keyword.insert(id, 1.0 - 1.0 / (1.0 + (-rank).max(0.0)));
            }
        }
        let embeddings::QueryVector {
            model: vector_model,
            vector: query_vector,
            neural,
        } = self.query_vector(project_id, query, embedder)?;
        let mut vector: BTreeMap<String, f64> = BTreeMap::new();
        {
            let mut stmt = conn
                .prepare(if neural {
                    // Vectors of since-revised content are stale and skipped.
                    "SELECT v.item_id, v.vector, v.dims FROM memory_neural_vectors v
                     JOIN memory_items m ON m.id = v.item_id AND m.content_sha256 = v.content_sha256
                     WHERE v.project_id=?1 AND v.model=?2 ORDER BY v.created_ms DESC LIMIT 2000"
                } else {
                    "SELECT item_id, vector, dims FROM memory_vectors WHERE project_id=?1 AND model=?2
                     ORDER BY created_ms DESC LIMIT 2000"
                })
                .map_err(|e| e.to_string())?;
            let rows = stmt
                .query_map(params![project_id, vector_model], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, Vec<u8>>(1)?,
                        r.get::<_, i64>(2)?,
                    ))
                })
                .map_err(|e| e.to_string())?;
            for row in rows {
                let (id, blob, dims) = row.map_err(|e| e.to_string())?;
                // Invalid/corrupt vectors are skipped, never trusted.
                if let Some(v) = from_blob(&blob, usize::try_from(dims).unwrap_or(0)) {
                    let s = cosine(&query_vector, &v);
                    if s > 0.05 {
                        vector.insert(id, s);
                    }
                }
            }
        }
        let ids: BTreeSet<String> = keyword.keys().chain(vector.keys()).cloned().collect();
        let mut scored = Vec::new();
        for id in ids {
            let Some(item) = self.get(&id)? else { continue };
            if item.project_id != project_id || item.expires_ms.is_some_and(|e| e <= now) {
                continue;
            }
            let k = keyword.get(&id).copied().unwrap_or(0.0);
            let v = vector.get(&id).copied().unwrap_or(0.0);
            let trust = match item.layer {
                MemoryLayer::ApprovedKnowledge => 0.15,
                _ if item.verified => 0.1,
                _ => 0.0,
            };
            scored.push(ScoredMemory {
                score: 0.55 * k + 0.45 * v + trust,
                keyword_score: k,
                vector_score: v,
                item,
            });
        }
        scored.sort_by(|a, b| b.score.total_cmp(&a.score).then(a.item.id.cmp(&b.item.id)));
        let candidates = scored.len();
        let mut used = 0;
        let mut items = Vec::new();
        let mut omitted_chars = 0;
        for entry in scored {
            let size = entry.item.title.len() + entry.item.body.len();
            if items.len() < budget.max_items && used + size <= budget.max_chars {
                used += size;
                items.push(entry);
            } else {
                omitted_chars += size;
            }
        }
        Ok(RetrievalResult {
            omitted: candidates - items.len(),
            omitted_chars,
            candidates,
            items,
            vector_model,
        })
    }

    // ------------------------------------------------------------ graph

    pub fn upsert_node(
        &self,
        project_id: &str,
        kind: &str,
        ref_id: &str,
        label: &str,
    ) -> Result<String, String> {
        let id = format!(
            "kgn_{}",
            &sha(&format!("{project_id}:{kind}:{ref_id}"))[..24]
        );
        self.db
            .connection()
            .execute(
                "INSERT INTO kg_nodes(id,project_id,kind,ref_id,label,created_ms) VALUES (?1,?2,?3,?4,?5,?6)
                 ON CONFLICT(project_id,kind,ref_id) DO UPDATE SET label=excluded.label",
                params![id, project_id, kind, bounded(ref_id, 512), bounded(label, 200), now_ms()],
            )
            .map_err(|e| e.to_string())?;
        Ok(id)
    }

    /// Link two nodes of the same project. `verified` edges must cite a
    /// persisted evidence reference; anything else is `inferred`.
    #[allow(clippy::too_many_arguments)]
    pub fn link(
        &self,
        project_id: &str,
        from: &str,
        to: &str,
        relation: &str,
        source_ref: &str,
        confidence: f64,
        verified: bool,
    ) -> Result<String, String> {
        if !(0.0..=1.0).contains(&confidence) {
            return Err("confidence must be within 0..1".into());
        }
        if source_ref.trim().is_empty() {
            return Err("every edge needs a source reference".into());
        }
        let conn = self.db.connection();
        let same_project: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM kg_nodes WHERE id IN (?1,?2) AND project_id=?3",
                params![from, to, project_id],
                |r| r.get(0),
            )
            .map_err(|e| e.to_string())?;
        if same_project != 2 {
            return Err("both nodes must belong to the project".into());
        }
        let id = format!("kge_{}", &sha(&format!("{from}:{to}:{relation}"))[..24]);
        conn.execute(
            "INSERT INTO kg_edges(id,project_id,from_node,to_node,relation,source_ref,confidence,provenance,created_ms,valid_from_ms)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?9)
             ON CONFLICT(from_node,to_node,relation) DO UPDATE SET confidence=MAX(confidence, excluded.confidence),
               provenance=CASE WHEN excluded.provenance='verified' THEN 'verified' ELSE provenance END,
               valid_from_ms=CASE WHEN invalidated_ms IS NULL THEN valid_from_ms ELSE excluded.valid_from_ms END,
               invalidated_ms=NULL, superseded_by=NULL",
            params![id, project_id, from, to, relation, bounded(source_ref, 512), confidence,
                if verified { "verified" } else { "inferred" }, now_ms()],
        )
        .map_err(|e| e.to_string())?;
        Ok(id)
    }

    /// Bounded neighbourhood of currently valid edges (breadth-first,
    /// depth ≤ 3, ≤ 200 nodes).
    pub fn neighborhood(
        &self,
        project_id: &str,
        start: &str,
        depth: usize,
    ) -> Result<EvidenceGraph, String> {
        self.neighborhood_at(project_id, start, depth, None)
    }

    /// Neighbourhood as it was believed at `at_ms` (`None` = now).
    pub fn neighborhood_at(
        &self,
        project_id: &str,
        start: &str,
        depth: usize,
        at_ms: Option<i64>,
    ) -> Result<EvidenceGraph, String> {
        let conn = self.db.connection();
        let mut seen: BTreeSet<String> = [start.to_owned()].into();
        let mut frontier = vec![start.to_owned()];
        let mut edges: BTreeMap<String, GraphEdge> = BTreeMap::new();
        let mut truncated = false;
        for _ in 0..depth.min(3) {
            let mut next = Vec::new();
            for node in &frontier {
                let mut stmt = conn
                    .prepare(
                        "SELECT id,from_node,to_node,relation,source_ref,confidence,provenance,valid_from_ms,invalidated_ms
                         FROM kg_edges
                         WHERE project_id=?1 AND (from_node=?2 OR to_node=?2)
                           AND CASE WHEN ?3 IS NULL THEN invalidated_ms IS NULL
                                    ELSE COALESCE(valid_from_ms, created_ms) <= ?3
                                         AND (invalidated_ms IS NULL OR invalidated_ms > ?3) END
                         LIMIT 100",
                    )
                    .map_err(|e| e.to_string())?;
                let rows = stmt
                    .query_map(params![project_id, node, at_ms], |r| {
                        Ok(GraphEdge {
                            id: r.get(0)?,
                            from_node: r.get(1)?,
                            to_node: r.get(2)?,
                            relation: r.get(3)?,
                            source_ref: r.get(4)?,
                            confidence: r.get(5)?,
                            provenance: r.get(6)?,
                            valid_from_ms: r.get(7)?,
                            invalidated_ms: r.get(8)?,
                        })
                    })
                    .map_err(|e| e.to_string())?;
                for edge in rows {
                    let edge = edge.map_err(|e| e.to_string())?;
                    for n in [&edge.from_node, &edge.to_node] {
                        if seen.len() >= 200 {
                            truncated = true;
                        } else if seen.insert(n.clone()) {
                            next.push(n.clone());
                        }
                    }
                    edges.insert(edge.id.clone(), edge);
                }
            }
            frontier = next;
        }
        let mut nodes = Vec::new();
        for id in &seen {
            if let Some(node) = conn
                .query_row(
                    "SELECT id,kind,ref_id,label FROM kg_nodes WHERE id=?1 AND project_id=?2",
                    params![id, project_id],
                    |r| {
                        Ok(GraphNode {
                            id: r.get(0)?,
                            kind: r.get(1)?,
                            ref_id: r.get(2)?,
                            label: r.get(3)?,
                        })
                    },
                )
                .optional()
                .map_err(|e| e.to_string())?
            {
                nodes.push(node);
            }
        }
        let edges = edges
            .into_values()
            .filter(|e| seen.contains(&e.from_node) && seen.contains(&e.to_node))
            .collect();
        Ok(EvidenceGraph {
            nodes,
            edges,
            truncated,
        })
    }

    pub fn find_node(
        &self,
        project_id: &str,
        kind: &str,
        ref_id: &str,
    ) -> Result<Option<String>, String> {
        self.db
            .connection()
            .query_row(
                "SELECT id FROM kg_nodes WHERE project_id=?1 AND kind=?2 AND ref_id=?3",
                params![project_id, kind, ref_id],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| e.to_string())
    }

    /// Index a settled workflow run: an episodic summary per task plus graph
    /// nodes/edges. Evidence references with a content hash become verified
    /// `references` edges; model hypotheses only ever produce inferred edges.
    pub fn ingest_workflow_run(&self, run_id: &str) -> Result<usize, String> {
        let conn = self.db.connection();
        let store = task_orchestrator::Store::new(conn);
        let run = store.get_run(run_id).map_err(|e| e.to_string())?;
        if !run.state.is_terminal() && run.state != task_orchestrator::RunState::Blocked {
            return Err("only settled runs are indexed".into());
        }
        let tasks = store.list_tasks(run_id).map_err(|e| e.to_string())?;
        let run_node =
            self.upsert_node(&run.project_id, "run", &run.id, &bounded(&run.goal, 200))?;
        let mut written = 0;
        for task in tasks.iter().filter(|t| !t.is_superseded()) {
            let class = task.evidence_class.map_or("none", |c| c.as_str());
            let kind = if class == "hypothesis" || class == "recommendation" {
                "hypothesis"
            } else {
                "task"
            };
            let node = self.upsert_node(&run.project_id, kind, &task.id, &task.title)?;
            self.link(
                &run.project_id,
                &run_node,
                &node,
                "produced",
                &format!("workflow_tasks:{}", task.id),
                1.0,
                true,
            )?;
            if let Some(summary) = &task.summary {
                let evidence = task.evidence_class.is_some_and(|c| c.is_evidence());
                self.remember(&MemoryInput {
                    project_id: run.project_id.clone(),
                    layer: MemoryLayer::Episodic,
                    title: format!("{} ({}, {})", task.title, task.role, task.state),
                    body: format!("Goal: {}\nEvidence class: {class}\n{summary}", run.goal),
                    source_kind: "workflow_task".into(),
                    source_ref: format!("workflow_tasks:{}", task.id),
                    source_sha256: task.output_sha256.clone(),
                    run_id: Some(run.id.clone()),
                    task_id: Some(task.id.clone()),
                    confidence: if evidence { 0.8 } else { 0.3 },
                    verified: evidence && task.state == task_orchestrator::TaskState::Completed,
                    ttl_ms: None,
                })?;
                written += 1;
            }
            let refs = task
                .output
                .as_ref()
                .and_then(|o| o.get("evidence_refs"))
                .and_then(|r| r.as_array())
                .cloned()
                .unwrap_or_default();
            for r in refs.iter().take(50) {
                let (Some(kind), Some(id)) = (
                    r.get("kind").and_then(|v| v.as_str()),
                    r.get("id").and_then(|v| v.as_str()),
                ) else {
                    continue;
                };
                let graph_kind = match kind {
                    "file" => "file",
                    "symbol" => "symbol",
                    "finding" | "security_finding" | "dependency_finding" | "secret_finding" => {
                        "finding"
                    }
                    "test" | "qa_artifact" => "test",
                    "research_source" => "source",
                    _ => continue,
                };
                let target = self.upsert_node(&run.project_id, graph_kind, id, id)?;
                let hashed = r
                    .get("sha256")
                    .and_then(|v| v.as_str())
                    .is_some_and(|h| h.len() == 64);
                let verified = hashed && task.evidence_class.is_some_and(|c| c.is_evidence());
                self.link(
                    &run.project_id,
                    &node,
                    &target,
                    "references",
                    &format!("workflow_tasks:{}", task.id),
                    if verified { 0.9 } else { 0.4 },
                    verified,
                )?;
            }
        }
        Ok(written)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> Database {
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

    fn input(project: &str, title: &str, body: &str) -> MemoryInput {
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
            confidence: 0.7,
            verified: false,
            ttl_ms: None,
        }
    }

    #[test]
    fn hybrid_retrieval_is_project_isolated_and_budgeted() {
        let db = db();
        let m = KnowledgeMemory::new(&db);
        m.remember(&input(
            "p1",
            "Auth uses JWT",
            "The login handler validates JWT tokens with RS256",
        ))
        .unwrap();
        m.remember(&input(
            "p1",
            "Database",
            "Postgres connection pooling is configured in db.rs",
        ))
        .unwrap();
        m.remember(&input(
            "p2",
            "Auth secret",
            "Project two stores JWT keys in vault",
        ))
        .unwrap();
        let r = m
            .retrieve("p1", "jwt login", RetrievalBudget::default())
            .unwrap();
        assert_eq!(r.items[0].item.title, "Auth uses JWT");
        assert!(
            r.items.iter().all(|i| i.item.project_id == "p1"),
            "no cross-project leakage"
        );
        let tight = m
            .retrieve(
                "p1",
                "jwt login database postgres",
                RetrievalBudget {
                    max_items: 1,
                    max_chars: 10_000,
                },
            )
            .unwrap();
        assert_eq!(tight.items.len(), 1);
        assert!(tight.omitted >= 1, "omissions are reported");
    }

    #[test]
    fn dedup_expiry_deletion_and_approval() {
        let db = db();
        let m = KnowledgeMemory::new(&db);
        let a = m.remember(&input("p1", "Fact", "same body")).unwrap();
        let b = m.remember(&input("p1", "Fact", "same body")).unwrap();
        assert_eq!(a.id, b.id);
        assert!(m
            .remember(&MemoryInput {
                layer: MemoryLayer::ApprovedKnowledge,
                ..input("p1", "x", "y")
            })
            .is_err());
        assert!(m.approve(&a.id, "model:planner").is_err());
        let approved = m.approve(&a.id, "operator").unwrap();
        assert_eq!(approved.layer, MemoryLayer::ApprovedKnowledge);
        let short = m
            .remember(&MemoryInput {
                ttl_ms: Some(-1),
                ..input("p1", "Temp", "expires")
            })
            .unwrap();
        assert!(m
            .retrieve("p1", "expires", RetrievalBudget::default())
            .unwrap()
            .items
            .iter()
            .all(|i| i.item.id != short.id));
        assert_eq!(m.expire().unwrap(), 1);
        assert!(m.delete("p1", &a.id).unwrap());
        assert!(
            !m.delete("p2", &approved.id).unwrap(),
            "cannot delete across projects"
        );
        assert!(m.reindex("p1").unwrap() >= 1);
    }

    #[test]
    fn corrupt_vectors_are_ignored() {
        let db = db();
        let m = KnowledgeMemory::new(&db);
        let item = m
            .remember(&input("p1", "Vector", "hashed vector text"))
            .unwrap();
        db.connection()
            .execute(
                "UPDATE memory_vectors SET vector=X'0102' WHERE item_id=?1",
                [&item.id],
            )
            .unwrap();
        let r = m
            .retrieve("p1", "zzz-unrelated", RetrievalBudget::default())
            .unwrap();
        assert!(r.items.is_empty());
        let nan: Vec<u8> = f32::NAN.to_le_bytes().repeat(DIMS);
        db.connection()
            .execute(
                "UPDATE memory_vectors SET vector=?2 WHERE item_id=?1",
                params![item.id, nan],
            )
            .unwrap();
        assert!(m
            .retrieve("p1", "unrelated words", RetrievalBudget::default())
            .is_ok());
    }

    #[test]
    fn graph_edges_carry_provenance_and_stay_in_project() {
        let db = db();
        let m = KnowledgeMemory::new(&db);
        let f = m
            .upsert_node("p1", "finding", "f1", "SQL injection")
            .unwrap();
        let t = m.upsert_node("p1", "test", "t1", "test_login").unwrap();
        let other = m.upsert_node("p2", "patch", "x", "patch").unwrap();
        assert!(
            m.link("p1", &t, &f, "tests", "", 0.5, false).is_err(),
            "source ref required"
        );
        assert!(
            m.link("p1", &t, &other, "tests", "src", 0.5, false)
                .is_err(),
            "no cross-project edges"
        );
        m.link("p1", &t, &f, "tests", "qa_artifact:t1", 0.6, false)
            .unwrap();
        let g = m.neighborhood("p1", &f, 2).unwrap();
        assert_eq!(g.nodes.len(), 2);
        assert_eq!(g.edges[0].provenance, "inferred");
        m.link("p1", &t, &f, "tests", "qa_run:42", 0.9, true)
            .unwrap();
        let g = m.neighborhood("p1", &f, 2).unwrap();
        assert_eq!(g.edges[0].provenance, "verified");
    }
}
