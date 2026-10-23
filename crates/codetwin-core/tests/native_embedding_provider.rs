//! Optional actual provider check. Requires an explicitly configured embeddings API.
//! Does not transmit source code or scan findings; sends a fixed public test phrase.
use codetwin_core::native_neural_embeddings::NeuralMemory;

#[test]
fn configured_embedding_provider_returns_real_normalized_vector() {
    if std::env::var("CODETWIN_TEST_REAL_EMBEDDINGS").ok().as_deref() != Some("1") {
        eprintln!("SKIPPED: set CODETWIN_TEST_REAL_EMBEDDINGS=1 and configure the embeddings provider");
        return;
    }
    let probe = NeuralMemory::probe()
        .expect("A reachable, compatible embedding provider must return a real vector");
    assert!((16..=3072).contains(&probe.dimensions));
    assert!(probe.normalized);
    assert!(!probe.model.trim().is_empty());
    println!(
        "Validated embedding model with {} dimensions and {} ms response",
        probe.dimensions, probe.latency_ms
    );
}
