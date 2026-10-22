//! Local project-scoped vector recall and verified knowledge graph.
//! Vectors use deterministic token hashing; they are lexical, not neural embeddings.
//! Only role/tool/status provenance is stored; scanner output and source never leave the run.
use crate::{native_agents::NativeAgents, Database};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const VECTOR_SIZE: usize = 64;
const MAX_NODES: usize = 500;
const MAX_QUERY: usize = 120;
const MAX_RESULTS: usize = 25;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgeNode {
    pub run_id: String,
    pub position: usize,
    pub role: String,
    pub tool: String,
    pub status: String,
    pub score: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgeEdge {
    pub run_id: String,
    pub from_position: usize,
    pub to_position: usize,
    pub relation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgeGraph {
    pub project_id: String,
    pub nodes: Vec<KnowledgeNode>,
    pub edges: Vec<KnowledgeEdge>,
}

pub struct AgentKnowledge<'a> {
    db: &'a Database,
}

impl<'a> AgentKnowledge<'a> {
    pub const fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Idempotently index a completed/failed run's trusted role provenance.
    pub fn ingest(&self, run_id: &str) -> Result<usize, String> {
        let run = NativeAgents::new(self.db).get(run_id)?;
        if !matches!(
            run.status.as_str(),
            "completed" | "failed" | "cancelled" | "interrupted"
        ) {
            return Err("Only terminal runs can enter the knowledge index".into());
        }
        let tx = self.db.connection().unchecked_transaction().map_err(err)?;
        let mut written = 0;
        for step in &run.steps {
            if !matches!(step.status.as_str(), "completed" | "failed") {
                continue;
            }
            let vector = encode(&format!("{} {} {}", step.role, step.tool, step.status));
            let payload = serde_json::to_string(&vector).map_err(err)?;
            written += tx
                .execute(
                    "INSERT OR IGNORE INTO native_knowledge_nodes
                 (project_id,run_id,position,role,tool,status,vector_json)
                 VALUES (?1,?2,?3,?4,?5,?6,?7)",
                    params![
                        run.project_id,
                        run.id,
                        step.position,
                        step.role,
                        step.tool,
                        step.status,
                        payload
                    ],
                )
                .map_err(err)?;
        }
        tx.execute(
            "INSERT OR IGNORE INTO native_knowledge_edges
             (project_id,run_id,from_position,to_position,relation)
             SELECT n.project_id,h.run_id,h.from_position,h.to_position,'verified_handoff'
             FROM native_agent_handoffs h
             JOIN native_knowledge_nodes n ON n.run_id=h.run_id AND n.position=h.from_position
             JOIN native_knowledge_nodes d ON d.run_id=h.run_id AND d.position=h.to_position
             WHERE h.run_id=?1 AND n.project_id=?2 AND d.project_id=?2",
            params![run.id, run.project_id],
        )
        .map_err(err)?;
        // Bound local storage. Edge rows cascade through explicit removal below.
        let mut remove = tx
            .prepare(
                "SELECT run_id,position FROM native_knowledge_nodes
             WHERE project_id=?1 ORDER BY created_at DESC,rowid DESC
             LIMIT -1 OFFSET ?2",
            )
            .map_err(err)?;
        let expired = remove
            .query_map(params![run.project_id, MAX_NODES as i64], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, usize>(1)?))
            })
            .map_err(err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(err)?;
        drop(remove);
        for (run_id, position) in expired {
            tx.execute(
                "DELETE FROM native_knowledge_edges WHERE run_id=?1 AND
                 (from_position=?2 OR to_position=?2)",
                params![run_id, position],
            )
            .map_err(err)?;
            tx.execute(
                "DELETE FROM native_knowledge_nodes WHERE run_id=?1 AND position=?2",
                params![run_id, position],
            )
            .map_err(err)?;
        }
        tx.commit().map_err(err)?;
        Ok(written)
    }

    pub fn search(
        &self,
        project_id: &str,
        query: &str,
        limit: usize,
    ) -> Result<Vec<KnowledgeNode>, String> {
        validate(project_id, query)?;
        let vector = encode(query);
        if vector.iter().all(|value| *value == 0.0) {
            return Ok(Vec::new());
        }
        let mut stmt = self
            .db
            .connection()
            .prepare(
                "SELECT run_id,position,role,tool,status,vector_json
             FROM native_knowledge_nodes WHERE project_id=?1 LIMIT 500",
            )
            .map_err(err)?;
        let mut rows = stmt
            .query_map([project_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, usize>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                ))
            })
            .map_err(err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(err)?
            .into_iter()
            .filter_map(|(run_id, position, role, tool, status, encoded)| {
                let stored: Vec<f32> = serde_json::from_str(&encoded).ok()?;
                if stored.len() != VECTOR_SIZE || stored.iter().any(|v| !v.is_finite()) {
                    return None;
                }
                let score = vector
                    .iter()
                    .zip(stored.iter())
                    .map(|(a, b)| a * b)
                    .sum::<f32>();
                (score > 0.0).then_some(KnowledgeNode {
                    run_id,
                    position,
                    role,
                    tool,
                    status,
                    score,
                })
            })
            .collect::<Vec<_>>();
        rows.sort_by(|a, b| {
            b.score
                .total_cmp(&a.score)
                .then_with(|| a.run_id.cmp(&b.run_id))
        });
        rows.truncate(limit.clamp(1, MAX_RESULTS));
        Ok(rows)
    }

    pub fn graph(&self, project_id: &str, run_id: &str) -> Result<KnowledgeGraph, String> {
        if project_id.is_empty()
            || project_id.len() > 256
            || run_id.is_empty()
            || run_id.len() > 256
        {
            return Err("Project and run must be selected".into());
        }
        let owned: bool = self
            .db
            .connection()
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM native_agent_runs WHERE id=?1 AND project_id=?2)",
                params![run_id, project_id],
                |row| row.get(0),
            )
            .map_err(err)?;
        if !owned {
            return Err("Review does not belong to this project".into());
        }
        let mut stmt = self
            .db
            .connection()
            .prepare(
                "SELECT run_id,position,role,tool,status
             FROM native_knowledge_nodes WHERE project_id=?1 AND run_id=?2 ORDER BY position",
            )
            .map_err(err)?;
        let nodes = stmt
            .query_map(params![project_id, run_id], |row| {
                Ok(KnowledgeNode {
                    run_id: row.get(0)?,
                    position: row.get(1)?,
                    role: row.get(2)?,
                    tool: row.get(3)?,
                    status: row.get(4)?,
                    score: 1.0,
                })
            })
            .map_err(err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(err)?;
        let mut edges_query = self
            .db
            .connection()
            .prepare(
                "SELECT run_id,from_position,to_position,relation FROM native_knowledge_edges
             WHERE project_id=?1 AND run_id=?2 ORDER BY from_position",
            )
            .map_err(err)?;
        let edges = edges_query
            .query_map(params![project_id, run_id], |row| {
                Ok(KnowledgeEdge {
                    run_id: row.get(0)?,
                    from_position: row.get(1)?,
                    to_position: row.get(2)?,
                    relation: row.get(3)?,
                })
            })
            .map_err(err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(err)?;
        Ok(KnowledgeGraph {
            project_id: project_id.to_owned(),
            nodes,
            edges,
        })
    }

    pub fn clear(&self, project_id: &str) -> Result<usize, String> {
        if project_id.trim().is_empty() || project_id.len() > 256 {
            return Err("Select a valid project".into());
        }
        let tx = self.db.connection().unchecked_transaction().map_err(err)?;
        tx.execute(
            "DELETE FROM native_knowledge_edges WHERE project_id=?1",
            [project_id],
        )
        .map_err(err)?;
        let count = tx
            .execute(
                "DELETE FROM native_knowledge_nodes WHERE project_id=?1",
                [project_id],
            )
            .map_err(err)?;
        tx.commit().map_err(err)?;
        Ok(count)
    }
}

fn validate(project: &str, query: &str) -> Result<(), String> {
    if project.is_empty() || project.len() > 256 || query.len() > MAX_QUERY {
        return Err("Invalid project identifier or overlong query".into());
    }
    Ok(())
}

/// Deterministic, no-provider hashed word-vector. Not a neural semantic embedding.
fn encode(text: &str) -> Vec<f32> {
    let mut output = vec![0.0f32; VECTOR_SIZE];
    for token in text
        .split(|c: char| !c.is_alphanumeric())
        .filter(|s| !s.is_empty())
        .take(48)
    {
        let digest = Sha256::digest(token.to_lowercase().as_bytes());
        let index = (u16::from_be_bytes([digest[0], digest[1]]) as usize) % VECTOR_SIZE;
        output[index] += 1.0;
    }
    let magnitude = output.iter().map(|v| v * v).sum::<f32>().sqrt();
    if magnitude > 0.0 {
        for v in &mut output {
            *v /= magnitude;
        }
    }
    output
}

fn err(error: impl std::fmt::Display) -> String {
    error.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hashed_vectors_are_stable_normalized_and_separate_terms() {
        assert_eq!(encode("Source Audit"), encode("source audit"));
        assert_eq!(encode(""), vec![0.0; VECTOR_SIZE]);
        let v = encode("source");
        assert!((v.iter().map(|x| x * x).sum::<f32>() - 1.0).abs() < 0.0001);
    }
    #[test]
    fn indexed_review_produces_searchable_nodes_and_verified_edges() {
        let db = Database::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("sample.ts"), "export const value = true;").unwrap();
        let project = crate::ProjectIndexService::new(&db)
            .index_project(root.path())
            .unwrap()
            .project_id;
        let roles = vec!["scout".to_owned(), "source".to_owned()];
        let agents = NativeAgents::new(&db);
        let run = agents
            .create_with_roles(&project, "Review", 10, 300, &roles)
            .unwrap();
        agents.approve(&run.id).unwrap();
        let result = agents.execute(&run.id).unwrap();
        assert_eq!(result.status, "completed", "{:?}", result.message);
        let knowledge = AgentKnowledge::new(&db);
        assert_eq!(knowledge.ingest(&run.id).unwrap(), 0);
        let hits = knowledge.search(&project, "source", 12).unwrap();
        assert!(!hits.is_empty());
        let graph = knowledge.graph(&project, &run.id).unwrap();
        assert_eq!(graph.nodes.len(), 2);
        assert_eq!(graph.edges.len(), 1);
        assert_eq!(knowledge.clear(&project).unwrap(), 2);
        assert!(knowledge.graph(&project, &run.id).unwrap().nodes.is_empty());
    }

    #[test]
    fn project_memory_is_not_cross_readable() {
        let db = Database::open_in_memory().unwrap();
        let k = AgentKnowledge::new(&db);
        assert!(k.search("absent", "", 10).unwrap().is_empty());
        assert!(k.graph("absent", "other").is_err());
        assert_eq!(k.clear("absent").unwrap(), 0);
    }
}
