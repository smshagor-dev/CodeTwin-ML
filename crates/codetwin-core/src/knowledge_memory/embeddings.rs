//! Neural embeddings for project memory.
//!
//! Vectors come from an OpenAI-compatible `/embeddings` endpoint: either a
//! loopback model on this machine (nothing leaves it) or a remote provider
//! the project has explicitly consented to, with text redacted and bounded
//! before egress. Vectors are stored in `memory_neural_vectors` under the
//! provider's model label, so a hashed vector is never reported as neural.
use std::io::Read;
use std::time::Duration;

use model_gateway::redact::redact;
use model_gateway::CloudConsent;
use reqwest::{blocking::Client, redirect::Policy, Url};
use rusqlite::{params, OptionalExtension};
use serde_json::{json, Value};

use super::{hashed_vector, now_ms, to_blob, KnowledgeMemory, LOCAL_VECTOR_MODEL};
use crate::native_neural_embeddings::parse_embedding_response;

const MAX_BATCH: usize = 32;
const MAX_TEXT_CHARS: usize = 2_000;
const MAX_RESPONSE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_DIMS: usize = 4096;

pub trait EmbeddingProvider {
    /// Label stored with every vector, e.g. `neural:nomic-embed-text@127.0.0.1`.
    fn model_id(&self) -> String;
    /// Embed `texts` on behalf of `project_id` (used for consent checks).
    fn embed(&self, project_id: &str, texts: &[String]) -> Result<Vec<Vec<f32>>, String>;
    /// Where inference runs: `local` (in process), `loopback` or `remote`.
    fn kind(&self) -> &'static str {
        "loopback"
    }
    /// Pinned model revision, when the provider knows it.
    fn revision(&self) -> Option<String> {
        None
    }
    /// SHA-256 of the model weights, when the provider verified them.
    fn weights_sha256(&self) -> Option<String> {
        None
    }
}

#[derive(Debug, Clone)]
pub enum EmbeddingDestination {
    /// A model served on this machine; no project data leaves it.
    Loopback,
    /// A remote provider, allowed only under this project consent.
    Consented(CloudConsent),
}

pub struct HttpEmbedder {
    endpoint: Url,
    model: String,
    token: Option<String>,
    destination: EmbeddingDestination,
}

fn is_loopback(host: &str) -> bool {
    matches!(host, "127.0.0.1" | "localhost" | "[::1]" | "::1")
}

impl HttpEmbedder {
    pub fn new(
        endpoint: &str,
        model: &str,
        token: Option<String>,
        destination: EmbeddingDestination,
    ) -> Result<Self, String> {
        let url = Url::parse(endpoint).map_err(|_| "invalid embedding endpoint".to_string())?;
        let host = url.host_str().ok_or("embedding endpoint has no host")?;
        if !url.path().ends_with("/embeddings")
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(
                "embedding endpoint must end in /embeddings, without credentials or query".into(),
            );
        }
        match &destination {
            EmbeddingDestination::Loopback if !is_loopback(host) => {
                return Err("a loopback embedder must point at 127.0.0.1, ::1 or localhost".into());
            }
            EmbeddingDestination::Consented(_) if url.scheme() != "https" || is_loopback(host) => {
                return Err("a remote embedder must use HTTPS to a non-loopback host".into());
            }
            _ => {}
        }
        if model.trim().is_empty() || model.len() > 150 {
            return Err("embedding model identifier is invalid".into());
        }
        Ok(Self {
            endpoint: url,
            model: model.trim().to_owned(),
            token: token.filter(|t| !t.is_empty()),
            destination,
        })
    }
}

impl EmbeddingProvider for HttpEmbedder {
    fn model_id(&self) -> String {
        format!(
            "neural:{}@{}",
            self.model,
            self.endpoint.host_str().unwrap_or("unknown")
        )
    }

    fn kind(&self) -> &'static str {
        match self.destination {
            EmbeddingDestination::Loopback => "loopback",
            EmbeddingDestination::Consented(_) => "remote",
        }
    }

    fn embed(&self, project_id: &str, texts: &[String]) -> Result<Vec<Vec<f32>>, String> {
        if texts.is_empty() || texts.len() > MAX_BATCH {
            return Err(format!("embed 1–{MAX_BATCH} texts per call"));
        }
        let mut inputs: Vec<String> = texts
            .iter()
            .map(|t| t.chars().take(MAX_TEXT_CHARS).collect())
            .collect();
        if let EmbeddingDestination::Consented(consent) = &self.destination {
            // Memory can quote source, so remote egress needs both switches.
            if consent.project_id != project_id
                || !consent.allow_cloud
                || !consent.allow_source_excerpts
            {
                return Err(
                    "project consent does not allow sending memory text to a remote embedder"
                        .into(),
                );
            }
            inputs = inputs.into_iter().map(|t| redact(&t).0).collect();
            let bytes: usize = inputs.iter().map(String::len).sum();
            if bytes > consent.max_payload_bytes {
                return Err("embedding payload exceeds the consented size".into());
            }
        }
        let body = serde_json::to_vec(&json!({"model": self.model, "input": inputs}))
            .map_err(|e| e.to_string())?;
        let client = Client::builder()
            .timeout(Duration::from_secs(60))
            .redirect(Policy::none())
            .build()
            .map_err(|e| e.to_string())?;
        let mut request = client
            .post(self.endpoint.clone())
            .header("Content-Type", "application/json")
            .body(body);
        if let Some(token) = &self.token {
            request = request.bearer_auth(token);
        }
        let response = request
            .send()
            .map_err(|e| format!("embedding provider unreachable: {}", e.without_url()))?;
        if !response.status().is_success() {
            return Err(format!(
                "embedding provider returned HTTP {}",
                response.status().as_u16()
            ));
        }
        let mut bytes = Vec::new();
        response
            .take(MAX_RESPONSE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        if bytes.len() as u64 > MAX_RESPONSE_BYTES {
            return Err("embedding response too large".into());
        }
        let value: Value =
            serde_json::from_slice(&bytes).map_err(|_| "invalid embedding JSON".to_string())?;
        let vectors = parse_embedding_response(&value, inputs.len())?;
        if vectors.first().is_some_and(|v| v.len() > MAX_DIMS) {
            return Err("embedding dimensions exceed the supported maximum".into());
        }
        Ok(vectors)
    }
}

/// Which stored vectors a query is compared against.
pub(super) struct QueryVector {
    pub model: String,
    pub vector: Vec<f32>,
    pub neural: bool,
    /// Set when a neural ranking was requested but lexical was used.
    pub fallback_reason: Option<String>,
}

/// Progress of an embedding pass: items embedded so far and in total.
pub type ProgressFn<'a> = &'a mut dyn FnMut(usize, usize);

impl KnowledgeMemory<'_> {
    /// Embed up to `limit` live items whose current content has no vector
    /// for this model yet. Returns how many were embedded.
    pub fn embed_project(
        &self,
        project_id: &str,
        embedder: &dyn EmbeddingProvider,
        limit: usize,
    ) -> Result<usize, String> {
        self.embed_pending(
            project_id,
            embedder,
            limit,
            &std::sync::atomic::AtomicBool::new(false),
            &mut |_, _| {},
        )
    }

    /// Record `model`'s dimensionality and version, or confirm a previous
    /// registration agrees. A label that changes size is refused: its old
    /// vectors live in a different space and must be reindexed under a new
    /// label instead.
    pub fn register_model(
        &self,
        model: &str,
        dims: usize,
        kind: &str,
        revision: Option<&str>,
        weights_sha256: Option<&str>,
    ) -> Result<(), String> {
        if model == LOCAL_VECTOR_MODEL {
            return Err("the lexical model label is reserved".into());
        }
        let conn = self.db.connection();
        conn.execute(
            "INSERT OR IGNORE INTO embedding_models(model,dims,kind,revision,weights_sha256,registered_ms)
             VALUES (?1,?2,?3,?4,?5,?6)",
            params![model, dims as i64, kind, revision, weights_sha256, now_ms()],
        )
        .map_err(|e| e.to_string())?;
        let (known_dims, known_rev): (i64, Option<String>) = conn
            .query_row(
                "SELECT dims, revision FROM embedding_models WHERE model=?1",
                [model],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(|e| e.to_string())?;
        if known_dims != dims as i64 {
            return Err(format!(
                "{model} was registered with {known_dims} dimensions but now returns {dims}; \
                 reindex under a new model label"
            ));
        }
        if let (Some(known), Some(now)) = (known_rev.as_deref(), revision) {
            if known != now {
                return Err(format!(
                    "{model} was registered at revision {known}, not {now}"
                ));
            }
        }
        Ok(())
    }

    /// Incremental, cancellable embedding of items whose current content
    /// has no vector for `embedder`'s model. Cancellation is checked between
    /// batches; finished batches stay committed, so a later pass resumes.
    pub fn embed_pending(
        &self,
        project_id: &str,
        embedder: &dyn EmbeddingProvider,
        limit: usize,
        cancel: &std::sync::atomic::AtomicBool,
        progress: ProgressFn<'_>,
    ) -> Result<usize, String> {
        let model = embedder.model_id();
        if model == LOCAL_VECTOR_MODEL {
            return Err("the lexical model label is reserved".into());
        }
        let conn = self.db.connection();
        let pending: Vec<(String, String)> = {
            let mut stmt = conn
                .prepare(
                    "SELECT m.id, m.title || ' ' || m.body FROM memory_items m
                     WHERE m.project_id=?1 AND (m.expires_ms IS NULL OR m.expires_ms > ?2)
                       AND NOT EXISTS (SELECT 1 FROM memory_neural_vectors v
                                       WHERE v.item_id=m.id AND v.model=?3 AND v.content_sha256=m.content_sha256)
                     ORDER BY m.updated_ms DESC LIMIT ?4",
                )
                .map_err(|e| e.to_string())?;
            let rows = stmt
                .query_map(
                    params![project_id, now_ms(), model, limit.min(2000) as i64],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .map_err(|e| e.to_string())?;
            rows.collect::<Result<_, _>>().map_err(|e| e.to_string())?
        };
        let mut done = 0;
        let total = pending.len();
        progress(0, total);
        let mut registered = false;
        // Small batches keep cancellation responsive for in-process models.
        for chunk in pending.chunks(16.min(MAX_BATCH)) {
            if cancel.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }
            let texts: Vec<String> = chunk.iter().map(|(_, t)| t.clone()).collect();
            let vectors = embedder.embed(project_id, &texts)?;
            if vectors.len() != chunk.len() {
                return Err("embedding count mismatch".into());
            }
            let dims = vectors.first().map_or(0, Vec::len);
            if vectors.iter().any(|v| {
                v.len() != dims
                    || v.len() < 8
                    || v.len() > MAX_DIMS
                    || v.iter().any(|x| !x.is_finite())
            }) {
                return Err("provider returned an invalid vector".into());
            }
            if !registered {
                self.register_model(
                    &model,
                    dims,
                    embedder.kind(),
                    embedder.revision().as_deref(),
                    embedder.weights_sha256().as_deref(),
                )?;
                registered = true;
            }
            let tx = conn.unchecked_transaction().map_err(|e| e.to_string())?;
            for ((id, _), v) in chunk.iter().zip(&vectors) {
                tx.execute(
                    "INSERT OR REPLACE INTO memory_neural_vectors(item_id,project_id,model,dims,vector,content_sha256,created_ms)
                     SELECT ?1, ?2, ?3, ?4, ?5, content_sha256, ?6 FROM memory_items WHERE id=?1 AND project_id=?2",
                    params![id, project_id, model, v.len() as i64, to_blob(v), now_ms()],
                )
                .map_err(|e| e.to_string())?;
            }
            tx.commit().map_err(|e| e.to_string())?;
            done += chunk.len();
            progress(done, total);
        }
        Ok(done)
    }

    /// The query vector and the stored vectors it is compared with. The
    /// embedder is used only when the project already has its vectors. Any
    /// neural failure (offline provider, model mismatch) falls back to the
    /// lexical vectors with the reason reported, never silently.
    pub(super) fn query_vector(
        &self,
        project_id: &str,
        query: &str,
        embedder: Option<&dyn EmbeddingProvider>,
    ) -> Result<QueryVector, String> {
        let mut fallback_reason = None;
        if let Some(embedder) = embedder {
            let model = embedder.model_id();
            let registered: Option<i64> = self
                .db
                .connection()
                .query_row(
                    "SELECT e.dims FROM embedding_models e WHERE e.model=?2 AND EXISTS(
                       SELECT 1 FROM memory_neural_vectors v WHERE v.project_id=?1 AND v.model=?2)",
                    params![project_id, model],
                    |r| r.get(0),
                )
                .optional()
                .map_err(|e| e.to_string())?;
            match registered {
                None => {
                    fallback_reason =
                        Some(format!("project memory has not been indexed with {model}"));
                }
                Some(dims) => match embedder.embed(project_id, &[query.to_owned()]) {
                    Ok(mut vectors) if vectors.len() == 1 && vectors[0].len() as i64 == dims => {
                        return Ok(QueryVector {
                            model,
                            vector: vectors.remove(0),
                            neural: true,
                            fallback_reason: None,
                        });
                    }
                    Ok(_) => {
                        fallback_reason = Some(format!(
                            "{model} returned vectors incompatible with its stored {dims}-dimension index"
                        ));
                    }
                    Err(e) => {
                        fallback_reason = Some(format!("neural embedder unavailable: {e}"));
                    }
                },
            }
        }
        Ok(QueryVector {
            model: LOCAL_VECTOR_MODEL.to_owned(),
            vector: hashed_vector(query),
            neural: false,
            fallback_reason,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::TcpListener;
    use std::sync::mpsc;

    fn consent(project: &str, cloud: bool, excerpts: bool) -> CloudConsent {
        CloudConsent {
            project_id: project.into(),
            allow_cloud: cloud,
            allow_source_excerpts: excerpts,
            allow_local_fallback: false,
            max_payload_bytes: 64 * 1024,
            granted_by: "alice".into(),
            granted_ms: 1,
        }
    }

    #[test]
    fn endpoints_and_destinations_are_validated() {
        let lb = EmbeddingDestination::Loopback;
        assert!(HttpEmbedder::new(
            "http://127.0.0.1:11434/v1/embeddings",
            "m",
            None,
            lb.clone()
        )
        .is_ok());
        assert!(HttpEmbedder::new(
            "https://api.example.com/v1/embeddings",
            "m",
            None,
            lb.clone()
        )
        .is_err());
        assert!(HttpEmbedder::new("http://127.0.0.1/v1/chat", "m", None, lb.clone()).is_err());
        assert!(HttpEmbedder::new("http://u:p@127.0.0.1/v1/embeddings", "m", None, lb).is_err());
        let remote = EmbeddingDestination::Consented(consent("p1", true, true));
        assert!(HttpEmbedder::new(
            "http://api.example.com/v1/embeddings",
            "m",
            None,
            remote.clone()
        )
        .is_err());
        assert!(
            HttpEmbedder::new("https://127.0.0.1/v1/embeddings", "m", None, remote.clone())
                .is_err()
        );
        assert!(
            HttpEmbedder::new("https://api.example.com/v1/embeddings", "m", None, remote).is_ok()
        );
    }

    #[test]
    fn remote_embedding_requires_matching_consent_before_any_network() {
        // Unroutable TEST-NET host: reaching the network would error differently.
        for c in [
            consent("other", true, true),
            consent("p1", false, true),
            consent("p1", true, false),
        ] {
            let e = HttpEmbedder::new(
                "https://192.0.2.1/v1/embeddings",
                "m",
                None,
                EmbeddingDestination::Consented(c),
            )
            .unwrap();
            let err = e.embed("p1", &["text".into()]).unwrap_err();
            assert!(err.contains("consent"), "{err}");
        }
    }

    #[test]
    fn loopback_embedder_speaks_the_openai_wire_format() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut buf = vec![0u8; 16 * 1024];
            let mut got = Vec::new();
            // Read headers and the declared body.
            loop {
                let n = std::io::Read::read(&mut s, &mut buf).unwrap();
                got.extend_from_slice(&buf[..n]);
                let text = String::from_utf8_lossy(&got).to_string();
                if let Some(idx) = text.find("\r\n\r\n") {
                    let len: usize = text
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|v| v.trim().parse().unwrap())
                        })
                        .unwrap_or(0);
                    if got.len() >= idx + 4 + len {
                        break;
                    }
                }
            }
            tx.send(String::from_utf8_lossy(&got).to_string()).unwrap();
            let v: Vec<f32> = (0..16).map(|i| i as f32).collect();
            let body = json!({"data": [
                {"index": 1, "embedding": v.iter().rev().collect::<Vec<_>>()},
                {"index": 0, "embedding": v}
            ]})
            .to_string();
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            s.write_all(resp.as_bytes()).unwrap();
        });
        let e = HttpEmbedder::new(
            &format!("http://127.0.0.1:{port}/v1/embeddings"),
            "nomic-embed-text",
            Some("local-token".into()),
            EmbeddingDestination::Loopback,
        )
        .unwrap();
        assert_eq!(e.model_id(), "neural:nomic-embed-text@127.0.0.1");
        let vectors = e.embed("p1", &["alpha".into(), "beta".into()]).unwrap();
        let request = rx.recv().unwrap();
        assert!(request.starts_with("POST /v1/embeddings"));
        assert!(request.contains("Bearer local-token"));
        assert!(
            request.contains(r#""input":["alpha","beta"]"#)
                && request.contains(r#""model":"nomic-embed-text""#)
        );
        assert_eq!(vectors.len(), 2);
        assert_eq!(vectors[0].len(), 16);
        // Re-ordered by `index` and L2-normalised by the shared parser.
        assert!(vectors[0][15] > vectors[0][0]);
        let norm: f32 = vectors[1].iter().map(|x| x * x).sum::<f32>().sqrt();
        assert!((norm - 1.0).abs() < 1e-4);
    }
}
