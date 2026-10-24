//! Detached Ed25519 attestations for already verified, completed security reviews.
//! Private key custody is deliberately OUTSIDE CodeTwin's SQLite database.
//! The host supplies an Ed25519 signature from a separately trusted signer;
//! public-key trust must be pinned independently of this self-described bundle.
use crate::{
    native_action_log::NativeActionLog, native_agent_delegation::NativeDelegation,
    native_agent_handoffs::AgentHandoffs, native_agents::NativeAgents, Database,
};
use ring::signature::{UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const FORMAT: &str = "codetwin-review-evidence-v1";
const DOMAIN: &[u8] = b"CodeTwin-ML/review-evidence/ed25519/v1\0";

/// Self-contained metadata fingerprints, without raw scanned file contents,
/// source snippets, model text or secrets from specialist results.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReviewEvidenceManifest {
    pub format: String,
    pub run_id: String,
    pub project_id: String,
    pub created_at: String,
    pub finished_at: String,
    pub objective_sha256: String,
    pub specialists: Vec<Value>,
    pub receipts: Vec<Value>,
    pub handoffs: Vec<Value>,
    pub delegation: Vec<Value>,
}

/// This bundle is not trusted just because it contains a public key.
/// Pass a separately pinned public key to all verification functions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedReviewEvidence {
    pub manifest: ReviewEvidenceManifest,
    pub signer_public_key_hex: String,
    pub signature_hex: String,
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push_str(&format!("{byte:02x}"));
    }
    result
}

fn hex_decode(text: &str, expected_bytes: usize) -> Result<Vec<u8>, String> {
    if text.len() != expected_bytes * 2 || !text.is_ascii() {
        return Err("Invalid Ed25519 key or signature length".into());
    }
    (0..text.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&text[index..index + 2], 16)
                .map_err(|_| "Invalid hex encoding".into())
        })
        .collect()
}

fn fingerprint(text: &str) -> String {
    hex_encode(&Sha256::digest(text.as_bytes()))
}

/// Read and validate a completed review before preparing its external
/// attestation. No keys or signatures are written to SQLite, and no tools run.
pub fn build_verified_manifest(
    db: &Database,
    run_id: &str,
) -> Result<ReviewEvidenceManifest, String> {
    let supervisor = NativeAgents::new(db);
    let run = supervisor.get(run_id)?;
    if run.status != "completed" {
        return Err("Only a completed review can be attested".into());
    }
    let verdict = supervisor.verify_evidence(run_id)?;
    if !verdict.verified {
        return Err(format!(
            "Review has unverified evidence: {}",
            verdict.issues.join("; ")
        ));
    }
    let receipts = NativeActionLog::new(db).list(run_id)?;
    let handoffs = AgentHandoffs::new(db).list(run_id)?;
    let delegation = NativeDelegation::new(db).graph(run_id)?;
    let finished_at = run
        .finished_at
        .ok_or("Completed review lacks finish time")?;
    Ok(ReviewEvidenceManifest {
        format: FORMAT.into(),
        run_id: run.id,
        project_id: run.project_id,
        created_at: run.created_at,
        finished_at,
        objective_sha256: fingerprint(&run.objective),
        specialists: run
            .steps
            .iter()
            .map(|step| {
                json!({
                    "position": step.position,
                    "role": step.role,
                    "tool": step.tool,
                    "status": step.status,
                    "result_sha256": fingerprint(step.result.as_deref().unwrap_or_default())
                })
            })
            .collect(),
        receipts: receipts
            .iter()
            .map(|receipt| {
                json!({
                    "position": receipt.position,
                    "role": receipt.role,
                    "status": receipt.status,
                    "result_sha256": receipt.result_sha256,
                    "started_at": receipt.started_at,
                    "finished_at": receipt.finished_at
                })
            })
            .collect(),
        handoffs: handoffs
            .iter()
            .map(|handoff| {
                json!({
                    "from_position": handoff.from_position,
                    "to_position": handoff.to_position,
                    "from_role": handoff.from_role,
                    "to_role": handoff.to_role,
                    "evidence_sha256": handoff.evidence_sha256,
                    "created_at": handoff.created_at
                })
            })
            .collect(),
        delegation: delegation
            .tasks
            .iter()
            .map(|task| {
                json!({
                    "position": task.position,
                    "role": task.role,
                    "tool": task.tool,
                    "status": task.status,
                    "requires": task.requires,
                    "objective_sha256": task.objective.as_deref().map(fingerprint)
                })
            })
            .collect(),
    })
}

/// Portable, public signing request. The hex payload MUST be decoded to
/// bytes before passing it to an independent Ed25519 signer. It is not a
/// private key, and its SHA-256 is for comparing exported requests only.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreparedReviewEvidence {
    pub manifest: ReviewEvidenceManifest,
    pub payload_hex: String,
    pub payload_sha256_hex: String,
}

pub fn prepare_external_attestation(
    db: &Database,
    run_id: &str,
) -> Result<PreparedReviewEvidence, String> {
    let manifest = build_verified_manifest(db, run_id)?;
    let payload = external_signing_payload(&manifest)?;
    Ok(PreparedReviewEvidence {
        manifest,
        payload_hex: hex_encode(&payload),
        payload_sha256_hex: hex_encode(&Sha256::digest(&payload)),
    })
}

/// Bytes to sign with an OS keyring, hardware token, or external key service.
/// This module never generates, loads, stores or exports a private key.
pub fn external_signing_payload(manifest: &ReviewEvidenceManifest) -> Result<Vec<u8>, String> {
    if manifest.format != FORMAT {
        return Err("Unsupported evidence manifest format".into());
    }
    let mut payload = DOMAIN.to_vec();
    payload.extend(serde_json::to_vec(manifest).map_err(|e| e.to_string())?);
    Ok(payload)
}

/// Verify an externally produced signature and attach it to the manifest.
/// This alone does NOT establish trust in its advertised public key.
pub fn assemble_detached_signature(
    manifest: ReviewEvidenceManifest,
    signer_public_key_hex: &str,
    signature_hex: &str,
) -> Result<SignedReviewEvidence, String> {
    let candidate = SignedReviewEvidence {
        manifest,
        signer_public_key_hex: signer_public_key_hex.to_owned(),
        signature_hex: signature_hex.to_owned(),
    };
    verify_with_trusted_public_key(&candidate, signer_public_key_hex)?;
    Ok(candidate)
}

/// Detached verification requires the caller's separately trusted public key.
/// A key supplied inside the bundle is NOT used as its trust anchor.
pub fn verify_with_trusted_public_key(
    bundle: &SignedReviewEvidence,
    trusted_public_key_hex: &str,
) -> Result<(), String> {
    let public_key = hex_decode(trusted_public_key_hex, 32)?;
    let declared = hex_decode(&bundle.signer_public_key_hex, 32)?;
    if public_key != declared {
        return Err("Bundle signer does not match independently trusted key".into());
    }
    let signature = hex_decode(&bundle.signature_hex, 64)?;
    let payload = external_signing_payload(&bundle.manifest)?;
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(&payload, &signature)
        .map_err(|_| "Ed25519 evidence signature verification failed".into())
}

/// Live SQLite re-validation catches changed receipts, handoffs, and results
/// after the signed snapshot was exported. It never updates historical state.
pub fn verify_bundle_against_sqlite(
    db: &Database,
    bundle: &SignedReviewEvidence,
    trusted_public_key_hex: &str,
) -> Result<(), String> {
    verify_with_trusted_public_key(bundle, trusted_public_key_hex)?;
    let now = build_verified_manifest(db, &bundle.manifest.run_id)?;
    if now != bundle.manifest {
        return Err("Signed review snapshot no longer matches SQLite evidence".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::{
        rand::SystemRandom,
        signature::{Ed25519KeyPair, KeyPair},
    };

    #[test]
    fn detached_signatures_require_external_trust_and_detect_mutations() {
        let temp = tempfile::tempdir().unwrap();
        let db = Database::open(temp.path().join("review.sqlite3")).unwrap();
        let root = temp.path().join("source");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("safe.rs"), "pub fn safe() {}").unwrap();
        let project = crate::ProjectIndexService::new(&db)
            .index_project(&root)
            .unwrap()
            .project_id;
        let reviews = NativeAgents::new(&db);
        let run = reviews
            .create_with_roles(
                &project,
                "Externally attested read-only review",
                10,
                180,
                &["scout".into(), "source".into()],
            )
            .unwrap();
        assert!(build_verified_manifest(&db, &run.id).is_err());
        reviews.approve(&run.id).unwrap();
        let complete = reviews.execute(&run.id).unwrap();
        assert_eq!(complete.status, "completed", "{:?}", complete.message);

        let prepared = prepare_external_attestation(&db, &run.id).unwrap();
        let manifest = build_verified_manifest(&db, &run.id).unwrap();
        assert_eq!(prepared.manifest, manifest);
        assert_eq!(prepared.payload_hex.len() % 2, 0);
        assert_eq!(prepared.payload_sha256_hex.len(), 64);
        assert_eq!(
            prepared.payload_hex,
            hex_encode(&external_signing_payload(&manifest).unwrap())
        );
        let plain_text = serde_json::to_string(&manifest).unwrap();
        assert!(!plain_text.contains("pub fn safe()"));
        assert!(!plain_text.contains("Externally attested read-only review"));

        // Test key exists only in this test's ephemeral memory: production
        // signing must be performed externally, not with SQLite secrets.
        let rng = SystemRandom::new();
        let ephemeral_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let signer = Ed25519KeyPair::from_pkcs8(ephemeral_pkcs8.as_ref()).unwrap();
        let trusted = hex_encode(signer.public_key().as_ref());
        let signature = hex_encode(
            signer
                .sign(&external_signing_payload(&manifest).unwrap())
                .as_ref(),
        );
        let bundle = assemble_detached_signature(manifest.clone(), &trusted, &signature).unwrap();
        verify_bundle_against_sqlite(&db, &bundle, &trusted).unwrap();
        let json = serde_json::to_string(&bundle).unwrap();
        let restored: SignedReviewEvidence = serde_json::from_str(&json).unwrap();
        verify_with_trusted_public_key(&restored, &trusted).unwrap();
        let reopened = Database::open(temp.path().join("review.sqlite3")).unwrap();
        verify_bundle_against_sqlite(&reopened, &restored, &trusted).unwrap();
        assert_eq!(restored.manifest, manifest);

        let another_key = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let different = Ed25519KeyPair::from_pkcs8(another_key.as_ref()).unwrap();
        assert!(verify_with_trusted_public_key(
            &bundle,
            &hex_encode(different.public_key().as_ref())
        )
        .is_err());

        let mut modified = bundle.clone();
        modified.manifest.project_id = "another-project".into();
        assert!(verify_with_trusted_public_key(&modified, &trusted).is_err());
        let mut forged = bundle.clone();
        forged.signature_hex = "00".repeat(64);
        assert!(verify_with_trusted_public_key(&forged, &trusted).is_err());
        let mut malformed = bundle.clone();
        malformed.signer_public_key_hex = "short".into();
        assert!(verify_with_trusted_public_key(&malformed, &trusted).is_err());

        // A valid SQLite-length digest can be substituted by a database
        // writer. The detached signed snapshot still rejects live replay.
        db.connection()
            .execute(
                "UPDATE native_action_log SET result_sha256=?2 WHERE run_id=?1 AND position=1",
                rusqlite::params![&run.id, "0".repeat(64)],
            )
            .unwrap();
        verify_with_trusted_public_key(&bundle, &trusted).unwrap();
        assert!(verify_bundle_against_sqlite(&db, &bundle, &trusted).is_err());
        assert!(build_verified_manifest(&db, &run.id).is_err());
    }
}
