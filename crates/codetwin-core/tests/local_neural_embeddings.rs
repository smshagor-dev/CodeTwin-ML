//! Real local neural embeddings against the pinned all-MiniLM-L6-v2 model.
//!
//! Needs the pinned model files in `CODETWIN_LOCAL_EMBEDDING_DIR` (CI
//! downloads and hash-checks them). Without them the tests report SKIPPED,
//! unless `CODETWIN_REQUIRE_LOCAL_EMBEDDINGS=1`, which turns that into a
//! failure so CI cannot pass silently without the model.
//!
//! The parity fixture was produced independently of this crate by
//! `scripts/minilm_reference_embed.py` (Hugging Face `tokenizers` plus a
//! NumPy float64 BERT forward pass).
use std::path::PathBuf;

use codetwin_core::knowledge_memory::{
    model_status, EmbeddingProvider, LocalModelStatus, LocalNeuralEmbedder, MINILM_L6_V2,
};
use serde_json::Value;

pub fn local_model_dir() -> Option<PathBuf> {
    let required = std::env::var("CODETWIN_REQUIRE_LOCAL_EMBEDDINGS").as_deref() == Ok("1");
    let dir = std::env::var_os("CODETWIN_LOCAL_EMBEDDING_DIR").map(PathBuf::from);
    match dir.as_deref().map(|d| model_status(d, &MINILM_L6_V2)) {
        Some(LocalModelStatus::Ready { .. }) => dir,
        other => {
            assert!(
                !required,
                "pinned local model required but not ready: {other:?}"
            );
            eprintln!("SKIPPED: set CODETWIN_LOCAL_EMBEDDING_DIR to the pinned model ({other:?})");
            None
        }
    }
}

fn cosine(a: &[f32], b: &[f32]) -> f64 {
    a.iter()
        .zip(b)
        .map(|(x, y)| f64::from(*x) * f64::from(*y))
        .sum()
}

#[test]
fn local_model_matches_independent_reference() {
    let Some(dir) = local_model_dir() else { return };
    let embedder = LocalNeuralEmbedder::load(&dir, &MINILM_L6_V2).expect("load pinned model");
    assert_eq!(embedder.dims(), 384);
    assert_eq!(
        embedder.model_id(),
        "neural:local/all-MiniLM-L6-v2@1110a243"
    );
    let fixture: Value = serde_json::from_str(include_str!("fixtures/minilm_l6_v2_reference.json"))
        .expect("fixture");
    assert_eq!(fixture["revision"], MINILM_L6_V2.revision);
    let cases = fixture["cases"].as_array().unwrap();
    let texts: Vec<String> = cases
        .iter()
        .map(|c| c["text"].as_str().unwrap().to_owned())
        .collect();
    // Embedded as one padded batch: masking must make padding irrelevant.
    let vectors = embedder.embed("p", &texts).expect("embed");
    let mut worst = 0f32;
    for (case, v) in cases.iter().zip(&vectors) {
        let reference: Vec<f32> = case["embedding"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_f64().unwrap() as f32)
            .collect();
        let diff = v
            .iter()
            .zip(&reference)
            .map(|(a, b)| (a - b).abs())
            .fold(0f32, f32::max);
        worst = worst.max(diff);
        let cos = cosine(v, &reference);
        assert!(
            cos > 0.9999 && diff < 1e-3,
            "{:?}: cosine {cos}, max diff {diff}",
            case["text"]
        );
    }
    // Real semantics: a paraphrase with no shared content words scores far
    // above an unrelated sentence.
    let paraphrase = cosine(&vectors[0], &vectors[1]);
    let unrelated = cosine(&vectors[0], &vectors[2]);
    println!(
        "parity: {} cases, worst |diff| {worst:.2e}; paraphrase {paraphrase:.3}, unrelated {unrelated:.3}",
        cases.len()
    );
    assert!(paraphrase > 0.5 && unrelated < 0.2);
    // Deterministic across calls and batch composition.
    let single = embedder.embed("p", &texts[..1]).unwrap();
    assert!(cosine(&single[0], &vectors[0]) > 0.99999);
}

/// (title, body) memories; queries below reference them by index.
const CORPUS: &[(&str, &str)] = &[
    (
        "Release cadence",
        "We ship to production every Thursday afternoon after QA sign-off.",
    ),
    (
        "Primary datastore",
        "Customer records live in PostgreSQL 16 with logical replication to a standby.",
    ),
    (
        "Session handling",
        "Users stay signed in through a refresh token rotated every fifteen minutes.",
    ),
    (
        "Flaky CI",
        "The payments suite intermittently times out on the Windows runner.",
    ),
    (
        "Cache layer",
        "Redis sits in front of the catalog service with a five minute TTL.",
    ),
    (
        "Secrets",
        "API keys are read from the OS keychain and never written to disk.",
    ),
    (
        "Error budget",
        "The checkout service may fail 0.1 percent of requests per month.",
    ),
    (
        "Frontend stack",
        "The dashboard is written in React with Vite and TypeScript.",
    ),
    (
        "Rate limiting",
        "The public API allows forty requests per minute per client.",
    ),
    (
        "Backups",
        "Nightly snapshots are copied to cold storage and kept for ninety days.",
    ),
    (
        "On-call",
        "Pages go to the platform rotation; escalation after twenty minutes.",
    ),
    (
        "Logging",
        "Structured JSON logs are shipped to the central aggregator with PII redacted.",
    ),
    (
        "Mobile app",
        "The iOS client is built with SwiftUI and talks GraphQL.",
    ),
    (
        "Search",
        "Product search uses an inverted index rebuilt hourly.",
    ),
    (
        "Feature flags",
        "New behaviour is gated by flags that product managers toggle.",
    ),
    (
        "Dependency policy",
        "Third-party packages need a license review before adoption.",
    ),
];

/// (query, index of the relevant memory). Phrased to share as few words
/// with the target as possible: lexical search mostly cannot answer these.
const QUERIES: &[(&str, usize)] = &[
    ("how often do we deploy", 0),
    ("which relational database holds customer data", 1),
    ("how long until a login expires", 2),
    ("unreliable tests on microsoft runners", 3),
    ("in-memory key value store expiry", 4),
    ("where are credentials kept", 5),
    ("allowed downtime for the purchase flow", 6),
    ("what UI framework does the web console use", 7),
    ("throttling limits for external callers", 8),
    ("disaster recovery copies retention", 9),
    ("who gets woken up for incidents", 10),
    ("personal data in telemetry", 11),
    ("apple phone application technology", 12),
    ("toggling unreleased functionality", 14),
];

struct Quality {
    r1: f64,
    r3: f64,
    mrr: f64,
}

fn evaluate(
    memory: &codetwin_core::knowledge_memory::KnowledgeMemory<'_>,
    ids: &[String],
    embedder: Option<&dyn EmbeddingProvider>,
    ranking: &codetwin_core::knowledge_memory::RankingConfig,
) -> Quality {
    use codetwin_core::knowledge_memory::{RetrievalBudget, RetrievalContext};
    let (mut r1, mut r3, mut mrr) = (0.0, 0.0, 0.0);
    for (query, target) in QUERIES {
        let result = memory
            .retrieve_ranked(
                "p1",
                query,
                RetrievalBudget {
                    max_items: 10,
                    max_chars: 100_000,
                },
                embedder,
                ranking,
                &RetrievalContext::default(),
            )
            .unwrap();
        if embedder.is_some() {
            assert!(result.neural, "{:?}", result.fallback_reason);
        }
        let rank = result
            .items
            .iter()
            .position(|s| s.item.id == ids[*target])
            .map(|p| p + 1);
        if let Some(rank) = rank {
            r1 += f64::from(rank == 1);
            r3 += f64::from(rank <= 3);
            mrr += 1.0 / rank as f64;
        }
    }
    let n = QUERIES.len() as f64;
    Quality {
        r1: r1 / n,
        r3: r3 / n,
        mrr: mrr / n,
    }
}

#[test]
fn neural_hybrid_retrieval_beats_lexical_on_paraphrased_queries() {
    use codetwin_core::knowledge_memory::{
        Fusion, KnowledgeMemory, MemoryInput, MemoryLayer, RankingConfig,
    };
    let Some(dir) = local_model_dir() else { return };
    let embedder = LocalNeuralEmbedder::load(&dir, &MINILM_L6_V2).unwrap();
    let db = codetwin_core::Database::open_in_memory().unwrap();
    for p in ["p1", "p2"] {
        db.connection()
            .execute(
                "INSERT INTO projects(id,root_path,display_name) VALUES (?1,?1,?1)",
                [p],
            )
            .unwrap();
    }
    let memory = KnowledgeMemory::new(&db);
    let input = |project: &str, title: &str, body: &str| MemoryInput {
        project_id: project.into(),
        layer: MemoryLayer::ProjectFact,
        title: title.into(),
        body: body.into(),
        source_kind: "fixture".into(),
        source_ref: "retrieval-quality".into(),
        source_sha256: None,
        run_id: None,
        task_id: None,
        confidence: 0.7,
        verified: false,
        ttl_ms: None,
    };
    let ids: Vec<String> = CORPUS
        .iter()
        .map(|(t, b)| memory.remember(&input("p1", t, b)).unwrap().id)
        .collect();
    // A decoy in another project that matches the first query best.
    memory
        .remember(&input(
            "p2",
            "Deploy frequency",
            "We deploy several times per day.",
        ))
        .unwrap();
    let cancel = std::sync::atomic::AtomicBool::new(false);
    let started = std::time::Instant::now();
    let job = memory
        .index_project("p1", &embedder, &cancel, &mut |_| {})
        .unwrap();
    let indexing_ms = started.elapsed().as_millis();
    assert_eq!((job.state.as_str(), job.done), ("completed", CORPUS.len()));
    let status = memory.index_status("p1", &embedder.model_id()).unwrap();
    assert_eq!((status.dims, status.current), (Some(384), CORPUS.len()));
    assert_eq!(status.kind.as_deref(), Some("local"));
    assert_eq!(status.revision.as_deref(), Some(MINILM_L6_V2.revision));

    let weighted = RankingConfig::default();
    let rrf = RankingConfig {
        fusion: Fusion::ReciprocalRank,
        ..RankingConfig::default()
    };
    let lexical = evaluate(&memory, &ids, None, &weighted);
    let hybrid = evaluate(&memory, &ids, Some(&embedder), &weighted);
    let fused = evaluate(&memory, &ids, Some(&embedder), &rrf);
    println!(
        "retrieval quality over {} paraphrased queries / {} memories (index {} items in {indexing_ms} ms):",
        QUERIES.len(),
        CORPUS.len(),
        job.done
    );
    for (name, q) in [
        ("lexical (FTS5 + hashed)", &lexical),
        ("neural hybrid (weighted)", &hybrid),
        ("neural hybrid (RRF)", &fused),
    ] {
        println!(
            "  {name:<26} R@1 {:.2}  R@3 {:.2}  MRR {:.3}",
            q.r1, q.r3, q.mrr
        );
    }
    assert!(hybrid.mrr >= lexical.mrr + 0.25, "neural must clearly help");
    assert!(hybrid.r3 >= 0.85 && hybrid.mrr >= 0.75);
    assert!(fused.r3 >= 0.75);

    // Isolation: the other project's better-matching decoy never appears.
    let r = memory
        .retrieve_with(
            "p1",
            "how often do we deploy",
            codetwin_core::knowledge_memory::RetrievalBudget::default(),
            Some(&embedder),
        )
        .unwrap();
    assert!(r.items.iter().all(|s| s.item.project_id == "p1"));
}
