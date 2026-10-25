//! Detached Ed25519 attestations for already verified, completed security reviews.
//! Private key custody is deliberately OUTSIDE CodeTwin's SQLite database.
//! The host supplies an Ed25519 signature from a separately trusted signer;
//! public-key trust must be pinned independently of this self-described bundle.
use crate::{
    native_action_log::NativeActionLog, native_agent_delegation::NativeDelegation,
    native_agent_handoffs::AgentHandoffs, native_agents::NativeAgents, Database,
};
use ring::signature::{UnparsedPublicKey, ED25519};
use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const FORMAT: &str = "codetwin-review-evidence-v1";
const DOMAIN: &[u8] = b"CodeTwin-ML/review-evidence/ed25519/v1\0";

/// Self-contained metadata fingerprints, without raw scanned file contents,
/// source snippets, model text or secrets from specialist results.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ReviewEvidenceManifest {
    pub format: String,
    pub run_id: String,
    pub project_id: String,
    pub created_at: String,
    pub finished_at: String,
    pub objective_sha256: String,
    #[serde(deserialize_with = "deserialize_strict_nested_values")]
    pub specialists: Vec<Value>,
    #[serde(deserialize_with = "deserialize_strict_nested_values")]
    pub receipts: Vec<Value>,
    #[serde(deserialize_with = "deserialize_strict_nested_values")]
    pub handoffs: Vec<Value>,
    #[serde(deserialize_with = "deserialize_strict_nested_values")]
    pub delegation: Vec<Value>,
}

/// This bundle is not trusted just because it contains a public key.
/// Pass a separately pinned public key to all verification functions.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedReviewEvidence {
    pub manifest: ReviewEvidenceManifest,
    pub signer_public_key_hex: String,
    pub signature_hex: String,
}

// serde_json::Value normally accepts duplicate object keys and keeps the last
// value. A raw imported evidence document could therefore contain conflicting
// nested claims while still deserializing to the originally signed manifest.
// Reject duplicates recursively without changing the signed JSON wire format.
struct StrictNestedValue(Value);

impl<'de> Deserialize<'de> for StrictNestedValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct StrictVisitor;

        impl<'de> Visitor<'de> for StrictVisitor {
            type Value = StrictNestedValue;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a JSON value without duplicate object keys")
            }

            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(StrictNestedValue(Value::Null))
            }

            fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<Self::Value, E> {
                Ok(StrictNestedValue(Value::Bool(value)))
            }

            fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Self::Value, E> {
                Ok(StrictNestedValue(Value::Number(value.into())))
            }

            fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Self::Value, E> {
                Ok(StrictNestedValue(Value::Number(value.into())))
            }

            fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Self::Value, E> {
                let number = serde_json::Number::from_f64(value)
                    .ok_or_else(|| E::custom("Non-finite evidence number"))?;
                Ok(StrictNestedValue(Value::Number(number)))
            }

            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(StrictNestedValue(Value::String(value.to_owned())))
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut access: A) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(value) = access.next_element::<StrictNestedValue>()? {
                    values.push(value.0);
                }
                Ok(StrictNestedValue(Value::Array(values)))
            }

            fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<Self::Value, A::Error> {
                let mut values = serde_json::Map::new();
                while let Some((key, value)) = access.next_entry::<String, StrictNestedValue>()? {
                    if values.contains_key(&key) {
                        return Err(serde::de::Error::custom(
                            "Duplicate nested review-evidence JSON field",
                        ));
                    }
                    values.insert(key, value.0);
                }
                Ok(StrictNestedValue(Value::Object(values)))
            }
        }

        deserializer.deserialize_any(StrictVisitor)
    }
}

fn deserialize_strict_nested_values<'de, D>(deserializer: D) -> Result<Vec<Value>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let values = Vec::<StrictNestedValue>::deserialize(deserializer)?;
    Ok(values.into_iter().map(|value| value.0).collect())
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

/// Every table contributing to a signed manifest must be read from one
/// consistent SQLite WAL snapshot. A concurrent cancellation, repair, or
/// evidence update must not splice together values from different commits.
/// Roll back a read-only transaction even on errors; no evidence is written.
fn with_verified_read_snapshot<T>(
    db: &Database,
    read: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    let snapshot = db
        .connection()
        .unchecked_transaction()
        .map_err(|error| format!("Cannot open SQLite evidence snapshot: {error}"))?;
    let result = read();
    snapshot
        .rollback()
        .map_err(|error| format!("Cannot close SQLite evidence snapshot: {error}"))?;
    result
}

/// Read and validate a completed review before preparing its external
/// attestation. No keys or signatures are written to SQLite, and no tools run.
pub fn build_verified_manifest(
    db: &Database,
    run_id: &str,
) -> Result<ReviewEvidenceManifest, String> {
    with_verified_read_snapshot(db, || build_manifest_from_snapshot(db, run_id))
}

fn build_manifest_from_snapshot(
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

/// A policy is supplied and pinned independently of signed evidence.
/// It is never sourced from the bundle or implicitly trusted from SQLite.
const TRUST_POLICY_FORMAT: &str = "codetwin-signer-trust-v1";
const TRUST_POLICY_DOMAIN: &[u8] = b"CodeTwin-ML/signer-policy/ed25519/v1\0";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedSignerPolicy {
    pub format: String,
    pub revision: u64,
    pub signers: Vec<TrustedSignerEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TrustedSignerStatus {
    Trusted,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedSignerEntry {
    pub public_key_hex: String,
    pub status: TrustedSignerStatus,
}

/// Key rotation: multiple independent keys may remain trusted. Revocation:
/// a revoked entry makes that key unacceptable even for previously signed
/// evidence. This verifier does not authenticate the policy itself; callers
/// must obtain and pin an authentic, current policy outside CodeTwin.
pub fn verify_with_trusted_signer_policy(
    bundle: &SignedReviewEvidence,
    policy: &TrustedSignerPolicy,
) -> Result<(), String> {
    if policy.format != TRUST_POLICY_FORMAT {
        return Err("Unsupported signer trust policy format".into());
    }
    if policy.revision == 0 || policy.signers.is_empty() || policy.signers.len() > 64 {
        return Err("Signer trust policy has invalid revision or signer count".into());
    }
    let advertised = hex_decode(&bundle.signer_public_key_hex, 32)?;
    let mut distinct = std::collections::HashSet::with_capacity(policy.signers.len());
    let mut matched = None;
    for signer in &policy.signers {
        let key = hex_decode(&signer.public_key_hex, 32)?;
        if !distinct.insert(key.clone()) {
            return Err("Signer trust policy contains duplicate public keys".into());
        }
        if key == advertised {
            matched = Some(signer);
        }
    }
    match matched {
        Some(entry) if entry.status == TrustedSignerStatus::Trusted => {
            verify_with_trusted_public_key(bundle, &entry.public_key_hex)
        }
        Some(_) => Err("Evidence signing key has been revoked".into()),
        None => Err("Evidence signer is not present in the independently trusted policy".into()),
    }
}

/// Signed policy metadata does not establish trust in its advertised key.
/// The authority public key must be pinned through an independent channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedTrustedSignerPolicy {
    pub policy: TrustedSignerPolicy,
    pub authority_public_key_hex: String,
    pub signature_hex: String,
}

/// Exact domain-separated bytes to send to an external Ed25519 policy signer.
/// No private key is generated, imported, or stored by this module.
pub fn signer_policy_signing_payload(policy: &TrustedSignerPolicy) -> Result<Vec<u8>, String> {
    if policy.format != TRUST_POLICY_FORMAT {
        return Err("Unsupported signer trust policy format".into());
    }
    if policy.revision == 0 || policy.signers.is_empty() || policy.signers.len() > 64 {
        return Err("Signer trust policy has invalid revision or signer count".into());
    }
    let mut distinct = std::collections::HashSet::with_capacity(policy.signers.len());
    for signer in &policy.signers {
        let key = hex_decode(&signer.public_key_hex, 32)?;
        if !distinct.insert(key) {
            return Err("Signer trust policy contains duplicate public keys".into());
        }
    }
    let mut payload = TRUST_POLICY_DOMAIN.to_vec();
    payload.extend(serde_json::to_vec(policy).map_err(|e| e.to_string())?);
    Ok(payload)
}

/// Public bytes for an external policy authority to sign. The authority's
/// private key must stay outside CodeTwin and its SQLite database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreparedSignerPolicySigningRequest {
    pub policy: TrustedSignerPolicy,
    pub payload_hex: String,
    pub payload_sha256_hex: String,
}

pub fn prepare_signer_policy_signing_request(
    policy: TrustedSignerPolicy,
) -> Result<PreparedSignerPolicySigningRequest, String> {
    let payload = signer_policy_signing_payload(&policy)?;
    Ok(PreparedSignerPolicySigningRequest {
        policy,
        payload_hex: hex_encode(&payload),
        payload_sha256_hex: hex_encode(&Sha256::digest(&payload)),
    })
}

/// The revision floor is supplied by the caller, not by the signed policy.
/// It must be protected and updated independently; this is not a built-in
/// anti-rollback store and cannot detect an outdated external floor.
pub fn verify_signed_trusted_signer_policy(
    signed: &SignedTrustedSignerPolicy,
    trusted_authority_public_key_hex: &str,
    minimum_revision: u64,
) -> Result<(), String> {
    if minimum_revision == 0 {
        return Err("An independently pinned positive minimum revision is required".into());
    }
    let payload = signer_policy_signing_payload(&signed.policy)?;
    if signed.policy.revision < minimum_revision {
        return Err("Signer trust policy revision is below the independent minimum".into());
    }
    let authority_key = hex_decode(trusted_authority_public_key_hex, 32)?;
    let declared = hex_decode(&signed.authority_public_key_hex, 32)?;
    if authority_key != declared {
        return Err("Policy authority does not match independently trusted key".into());
    }
    // A policy authority must not also be an evidence signer, even when its
    // signer entry is revoked. Otherwise compromise of a review-signing key
    // can become compromise of policy approval and signer revocation.
    for signer in &signed.policy.signers {
        if hex_decode(&signer.public_key_hex, 32)? == authority_key {
            return Err(
                "Policy authority key must be distinct from every evidence signer key".into(),
            );
        }
    }
    let signature = hex_decode(&signed.signature_hex, 64)?;
    UnparsedPublicKey::new(&ED25519, authority_key)
        .verify(&payload, &signature)
        .map_err(|_| "Ed25519 signer policy authority signature verification failed".into())
}

/// SHA-256 of the typed, deterministically serialized signed policy envelope.
/// Pin this value through an independent channel; a digest copied from the
/// untrusted envelope provides no authenticity or rollback protection.
/// This is distinct from the policy signing payload's SHA-256.
pub fn signed_signer_policy_sha256_hex(
    signed: &SignedTrustedSignerPolicy,
) -> Result<String, String> {
    let envelope = serde_json::to_vec(signed).map_err(|error| error.to_string())?;
    Ok(hex_encode(&Sha256::digest(&envelope)))
}

/// Read-only preflight for an externally administered trust-policy rotation.
/// Both SHA-256 pins and the authority key must arrive from independently
/// authenticated channels. This never persists pins, advances a protected
/// revision floor, or approves an authority-key change.
pub fn verify_external_signer_policy_rotation(
    previous: &SignedTrustedSignerPolicy,
    replacement: &SignedTrustedSignerPolicy,
    trusted_authority_public_key_hex: &str,
    current_minimum_revision: u64,
    independently_pinned_previous_sha256_hex: &str,
    independently_pinned_replacement_sha256_hex: &str,
) -> Result<u64, String> {
    verify_signed_trusted_signer_policy(
        previous,
        trusted_authority_public_key_hex,
        current_minimum_revision,
    )?;
    verify_signed_trusted_signer_policy(
        replacement,
        trusted_authority_public_key_hex,
        current_minimum_revision,
    )?;

    let previous_pin = hex_decode(independently_pinned_previous_sha256_hex, 32)?;
    let previous_digest = hex_decode(&signed_signer_policy_sha256_hex(previous)?, 32)?;
    if previous_pin != previous_digest {
        return Err("Previous policy does not match the independently pinned SHA-256".into());
    }
    let replacement_pin = hex_decode(independently_pinned_replacement_sha256_hex, 32)?;
    let replacement_digest = hex_decode(&signed_signer_policy_sha256_hex(replacement)?, 32)?;
    if replacement_pin != replacement_digest {
        return Err("Replacement policy does not match the independently pinned SHA-256".into());
    }
    if replacement.policy.revision <= previous.policy.revision {
        return Err("Replacement signer policy revision must strictly increase".into());
    }
    Ok(replacement.policy.revision)
}

/// An additional exact-envelope pin, supplied outside CodeTwin/SQLite.
/// A valid but older authority-signed policy with the same acceptable
/// revision floor is rejected when its digest differs from the current pin.
/// This does not fetch or protect the pin; its owner must update it securely.
pub fn verify_bundle_with_pinned_signed_signer_policy_against_sqlite(
    db: &Database,
    bundle: &SignedReviewEvidence,
    signed_policy: &SignedTrustedSignerPolicy,
    trusted_authority_public_key_hex: &str,
    minimum_revision: u64,
    independently_pinned_policy_sha256_hex: &str,
) -> Result<(), String> {
    let expected = hex_decode(independently_pinned_policy_sha256_hex, 32)?;
    let actual = hex_decode(&signed_signer_policy_sha256_hex(signed_policy)?, 32)?;
    if expected != actual {
        return Err("Signed signer policy does not match the independently pinned SHA-256".into());
    }
    verify_bundle_with_signed_signer_policy_against_sqlite(
        db,
        bundle,
        signed_policy,
        trusted_authority_public_key_hex,
        minimum_revision,
    )
}

/// Verify policy authority, signer revocation and live SQLite evidence.
pub fn verify_bundle_with_signed_signer_policy_against_sqlite(
    db: &Database,
    bundle: &SignedReviewEvidence,
    signed_policy: &SignedTrustedSignerPolicy,
    trusted_authority_public_key_hex: &str,
    minimum_revision: u64,
) -> Result<(), String> {
    verify_signed_trusted_signer_policy(
        signed_policy,
        trusted_authority_public_key_hex,
        minimum_revision,
    )?;
    verify_bundle_with_signer_policy_against_sqlite(db, bundle, &signed_policy.policy)
}

/// Keep revocation evaluation and SQLite evidence validation together.
/// A stale or user-modified policy cannot be detected here: it must be
/// authenticated and protected separately by the policy's owner.
pub fn verify_bundle_with_signer_policy_against_sqlite(
    db: &Database,
    bundle: &SignedReviewEvidence,
    policy: &TrustedSignerPolicy,
) -> Result<(), String> {
    verify_with_trusted_signer_policy(bundle, policy)?;
    let current = build_verified_manifest(db, &bundle.manifest.run_id)?;
    if current != bundle.manifest {
        return Err("Signed review snapshot no longer matches SQLite evidence".into());
    }
    Ok(())
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
    fn imported_evidence_rejects_duplicate_nested_json_keys() {
        let manifest = ReviewEvidenceManifest {
            format: FORMAT.into(),
            run_id: "review".into(),
            project_id: "project".into(),
            created_at: "2026-01-01".into(),
            finished_at: "2026-01-02".into(),
            objective_sha256: "00".repeat(32),
            specialists: vec![json!({"position": 1, "details": {"status": "ok"}})],
            receipts: vec![json!({"position": 1})],
            handoffs: vec![json!({"position": 1})],
            delegation: vec![json!({"position": 1})],
        };
        let bundle = SignedReviewEvidence {
            manifest,
            signer_public_key_hex: "11".repeat(32),
            signature_hex: "22".repeat(64),
        };
        let original = serde_json::to_string(&bundle).unwrap();
        let parsed: SignedReviewEvidence = serde_json::from_str(&original).unwrap();
        assert_eq!(
            serde_json::to_value(&parsed).unwrap(),
            serde_json::to_value(&bundle).unwrap()
        );

        for field in ["specialists", "receipts", "handoffs", "delegation"] {
            let marker = format!("\"{field}\":[{{");
            let altered = original.replacen(&marker, &format!("{marker}\"position\":1,"), 1);
            assert_ne!(altered, original);
            // Ordinary Value parsing collapses the duplicate into the same
            // signed content. Strict evidence parsing must reject the raw JSON.
            let ordinary: Value = serde_json::from_str(&altered).unwrap();
            assert_eq!(ordinary, serde_json::to_value(&bundle).unwrap());
            assert!(
                serde_json::from_str::<SignedReviewEvidence>(&altered).is_err(),
                "duplicate nested field in {field} must fail closed"
            );
        }

        let deeply_nested = original.replacen(
            "\"status\":\"ok\"",
            "\"status\":\"ok\",\"status\":\"ok\"",
            1,
        );
        assert_ne!(deeply_nested, original);
        assert_eq!(
            serde_json::from_str::<Value>(&deeply_nested).unwrap(),
            serde_json::to_value(&bundle).unwrap()
        );
        assert!(
            serde_json::from_str::<SignedReviewEvidence>(&deeply_nested).is_err(),
            "duplicate keys must be rejected at every nesting depth"
        );
    }

    #[test]
    fn signed_trust_policy_rejects_authority_used_as_an_evidence_signer() {
        let random = SystemRandom::new();
        let reused_pkcs8 = Ed25519KeyPair::generate_pkcs8(&random).unwrap();
        let reused = Ed25519KeyPair::from_pkcs8(reused_pkcs8.as_ref()).unwrap();
        let separate_pkcs8 = Ed25519KeyPair::generate_pkcs8(&random).unwrap();
        let separate = Ed25519KeyPair::from_pkcs8(separate_pkcs8.as_ref()).unwrap();
        let reused_public = hex_encode(reused.public_key().as_ref());
        let separate_public = hex_encode(separate.public_key().as_ref());

        let mut policy = TrustedSignerPolicy {
            format: TRUST_POLICY_FORMAT.into(),
            revision: 1,
            signers: vec![TrustedSignerEntry {
                public_key_hex: reused_public.clone(),
                status: TrustedSignerStatus::Trusted,
            }],
        };
        for status in [TrustedSignerStatus::Trusted, TrustedSignerStatus::Revoked] {
            policy.signers[0].status = status;
            let signed_by_reused_key = SignedTrustedSignerPolicy {
                policy: policy.clone(),
                authority_public_key_hex: reused_public.clone(),
                signature_hex: hex_encode(
                    reused
                        .sign(&signer_policy_signing_payload(&policy).unwrap())
                        .as_ref(),
                ),
            };
            assert!(
                verify_signed_trusted_signer_policy(&signed_by_reused_key, &reused_public, 1,)
                    .unwrap_err()
                    .contains("must be distinct"),
                "even a valid authority signature must not reuse an evidence signer key"
            );
        }

        // A separately pinned authority key still authenticates the same
        // policy, including a revoked evidence signer, without weakening
        // independent authority or policy-revision checks.
        let signed_by_independent_authority = SignedTrustedSignerPolicy {
            policy: policy.clone(),
            authority_public_key_hex: separate_public.clone(),
            signature_hex: hex_encode(
                separate
                    .sign(&signer_policy_signing_payload(&policy).unwrap())
                    .as_ref(),
            ),
        };
        verify_signed_trusted_signer_policy(&signed_by_independent_authority, &separate_public, 1)
            .unwrap();
        assert!(verify_signed_trusted_signer_policy(
            &signed_by_independent_authority,
            &reused_public,
            1,
        )
        .is_err());
        assert!(verify_signed_trusted_signer_policy(
            &signed_by_independent_authority,
            &separate_public,
            2,
        )
        .is_err());
    }

    #[test]
    fn policy_rotation_preflight_rejects_rollback_wrong_pins_and_forgery() {
        let rng = SystemRandom::new();
        let authority_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let authority = Ed25519KeyPair::from_pkcs8(authority_pkcs8.as_ref()).unwrap();
        let signer_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let signer = Ed25519KeyPair::from_pkcs8(signer_pkcs8.as_ref()).unwrap();
        let authority_key = hex_encode(authority.public_key().as_ref());
        let signer_key = hex_encode(signer.public_key().as_ref());
        let sign_policy = |revision| {
            let policy = TrustedSignerPolicy {
                format: TRUST_POLICY_FORMAT.into(),
                revision,
                signers: vec![TrustedSignerEntry {
                    public_key_hex: signer_key.clone(),
                    status: TrustedSignerStatus::Trusted,
                }],
            };
            let signature = authority.sign(&signer_policy_signing_payload(&policy).unwrap());
            SignedTrustedSignerPolicy {
                policy,
                authority_public_key_hex: authority_key.clone(),
                signature_hex: hex_encode(signature.as_ref()),
            }
        };
        let previous = sign_policy(4);
        let replacement = sign_policy(5);
        let old_pin = signed_signer_policy_sha256_hex(&previous).unwrap();
        let new_pin = signed_signer_policy_sha256_hex(&replacement).unwrap();
        let check = |old: &SignedTrustedSignerPolicy,
                     new: &SignedTrustedSignerPolicy,
                     floor,
                     old_digest: &str,
                     new_digest: &str| {
            verify_external_signer_policy_rotation(
                old,
                new,
                &authority_key,
                floor,
                old_digest,
                new_digest,
            )
        };
        assert_eq!(
            check(&previous, &replacement, 4, &old_pin, &new_pin).unwrap(),
            5
        );
        assert!(check(&previous, &previous, 4, &old_pin, &old_pin)
            .unwrap_err()
            .contains("strictly increase"));
        assert!(check(&replacement, &previous, 4, &new_pin, &old_pin)
            .unwrap_err()
            .contains("strictly increase"));
        assert!(
            check(&previous, &replacement, 4, &"00".repeat(32), &new_pin)
                .unwrap_err()
                .contains("Previous policy")
        );
        assert!(
            check(&previous, &replacement, 4, &old_pin, &"00".repeat(32))
                .unwrap_err()
                .contains("Replacement policy")
        );
        assert!(check(&previous, &replacement, 5, &old_pin, &new_pin).is_err());
        assert!(check(&previous, &replacement, 0, &old_pin, &new_pin).is_err());
        assert!(check(&previous, &replacement, 4, "bad", &new_pin).is_err());
        let mut forged = replacement.clone();
        forged.policy.revision = 6;
        let forged_pin = signed_signer_policy_sha256_hex(&forged).unwrap();
        assert!(check(&previous, &forged, 4, &old_pin, &forged_pin).is_err());
        assert!(verify_external_signer_policy_rotation(
            &previous,
            &replacement,
            &signer_key,
            4,
            &old_pin,
            &new_pin,
        )
        .is_err());
    }

    #[test]
    fn evidence_snapshot_is_consistent_across_concurrent_wal_commits() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("snapshot-consistency.sqlite3");
        let reader = Database::open(&path).unwrap();
        reader
            .connection()
            .execute_batch(
                "CREATE TABLE snapshot_probe (value INTEGER NOT NULL);
                            INSERT INTO snapshot_probe(value) VALUES (1);",
            )
            .unwrap();
        let writer = Database::open(&path).unwrap();

        with_verified_read_snapshot(&reader, || {
            let first: i64 = reader
                .connection()
                .query_row("SELECT value FROM snapshot_probe", [], |row| row.get(0))
                .unwrap();
            assert_eq!(first, 1);

            // WAL permits a second connection to commit during the read.
            // The evidence reader must still observe the first snapshot.
            writer
                .connection()
                .execute("UPDATE snapshot_probe SET value=2", [])
                .unwrap();
            let second: i64 = reader
                .connection()
                .query_row("SELECT value FROM snapshot_probe", [], |row| row.get(0))
                .unwrap();
            assert_eq!(second, first);
            Ok(())
        })
        .unwrap();
        assert!(reader.connection().is_autocommit());
        let current: i64 = reader
            .connection()
            .query_row("SELECT value FROM snapshot_probe", [], |row| row.get(0))
            .unwrap();
        assert_eq!(current, 2, "a later verification must see the new commit");

        let rejected: Result<(), String> =
            with_verified_read_snapshot(&reader, || Err("invalid review".into()));
        assert_eq!(rejected.unwrap_err(), "invalid review");
        assert!(reader.connection().is_autocommit());
    }

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

        // A detached signature authenticates only the typed manifest fields.
        // Reject extra JSON claims instead of silently discarding them and
        // reporting the altered bundle as verified.
        let mut unsigned_envelope = serde_json::to_value(&bundle).unwrap();
        unsigned_envelope["operator_approved"] = json!(true);
        assert!(
            serde_json::from_value::<SignedReviewEvidence>(unsigned_envelope).is_err(),
            "unsigned top-level claims must not be accepted"
        );
        let mut unsigned_manifest = serde_json::to_value(&bundle).unwrap();
        unsigned_manifest["manifest"]["risk_accepted"] = json!(true);
        assert!(
            serde_json::from_value::<SignedReviewEvidence>(unsigned_manifest).is_err(),
            "unsigned manifest claims must not be accepted"
        );
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

        let rotated_key = hex_encode(different.public_key().as_ref());
        let mut policy = TrustedSignerPolicy {
            format: TRUST_POLICY_FORMAT.into(),
            revision: 1,
            signers: vec![
                TrustedSignerEntry {
                    public_key_hex: trusted.clone(),
                    status: TrustedSignerStatus::Trusted,
                },
                TrustedSignerEntry {
                    public_key_hex: rotated_key.clone(),
                    status: TrustedSignerStatus::Trusted,
                },
            ],
        };
        verify_bundle_with_signer_policy_against_sqlite(&reopened, &bundle, &policy).unwrap();
        let rotated_signature = hex_encode(
            different
                .sign(&external_signing_payload(&manifest).unwrap())
                .as_ref(),
        );
        let rotated_bundle =
            assemble_detached_signature(manifest.clone(), &rotated_key, &rotated_signature)
                .unwrap();
        verify_with_trusted_signer_policy(&rotated_bundle, &policy).unwrap();

        // Policy authority and review signer are distinct ephemeral test keys.
        let authority_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let authority = Ed25519KeyPair::from_pkcs8(authority_pkcs8.as_ref()).unwrap();
        let authority_key = hex_encode(authority.public_key().as_ref());
        let policy_request = prepare_signer_policy_signing_request(policy.clone()).unwrap();
        assert_eq!(
            policy_request.payload_hex,
            hex_encode(&signer_policy_signing_payload(&policy).unwrap())
        );
        assert_eq!(policy_request.payload_sha256_hex.len(), 64);
        let signed_policy = SignedTrustedSignerPolicy {
            policy: policy.clone(),
            authority_public_key_hex: authority_key.clone(),
            signature_hex: hex_encode(
                authority
                    .sign(&signer_policy_signing_payload(&policy).unwrap())
                    .as_ref(),
            ),
        };
        verify_bundle_with_signed_signer_policy_against_sqlite(
            &reopened,
            &bundle,
            &signed_policy,
            &authority_key,
            1,
        )
        .unwrap();
        let policy_pin = signed_signer_policy_sha256_hex(&signed_policy).unwrap();
        assert_eq!(policy_pin.len(), 64);
        verify_bundle_with_pinned_signed_signer_policy_against_sqlite(
            &reopened,
            &bundle,
            &signed_policy,
            &authority_key,
            1,
            &policy_pin,
        )
        .unwrap();
        assert!(
            verify_bundle_with_pinned_signed_signer_policy_against_sqlite(
                &reopened,
                &bundle,
                &signed_policy,
                &authority_key,
                1,
                &"00".repeat(32),
            )
            .unwrap_err()
            .contains("independently pinned")
        );
        assert!(
            verify_bundle_with_pinned_signed_signer_policy_against_sqlite(
                &reopened,
                &bundle,
                &signed_policy,
                &authority_key,
                1,
                "invalid",
            )
            .is_err()
        );
        let mut altered_envelope = signed_policy.clone();
        altered_envelope.signature_hex = "00".repeat(64);
        assert!(
            verify_bundle_with_pinned_signed_signer_policy_against_sqlite(
                &reopened,
                &bundle,
                &altered_envelope,
                &authority_key,
                1,
                &policy_pin,
            )
            .is_err()
        );

        assert!(verify_signed_trusted_signer_policy(&signed_policy, &authority_key, 0).is_err());
        assert!(
            verify_signed_trusted_signer_policy(&signed_policy, &authority_key, 2)
                .unwrap_err()
                .contains("below")
        );
        assert!(verify_signed_trusted_signer_policy(&signed_policy, &rotated_key, 1).is_err());
        let mut forged_policy = signed_policy.clone();
        forged_policy.policy.signers[0].status = TrustedSignerStatus::Revoked;
        assert!(verify_signed_trusted_signer_policy(&forged_policy, &authority_key, 1).is_err());
        forged_policy = signed_policy.clone();
        forged_policy.signature_hex = "00".repeat(64);
        assert!(verify_signed_trusted_signer_policy(&forged_policy, &authority_key, 1).is_err());
        forged_policy = signed_policy.clone();
        forged_policy.authority_public_key_hex = rotated_key.clone();
        assert!(verify_signed_trusted_signer_policy(&forged_policy, &authority_key, 1).is_err());
        let mut unexpected = serde_json::to_value(&signed_policy).unwrap();
        unexpected["extra"] = json!(true);
        assert!(serde_json::from_value::<SignedTrustedSignerPolicy>(unexpected).is_err());

        // Revoking a former signing key invalidates its older bundles
        // while allowing another independently trusted rotation key.
        policy.revision = 2;
        policy.signers[0].status = TrustedSignerStatus::Revoked;
        let signed_rotated_policy = SignedTrustedSignerPolicy {
            policy: policy.clone(),
            authority_public_key_hex: authority_key.clone(),
            signature_hex: hex_encode(
                authority
                    .sign(&signer_policy_signing_payload(&policy).unwrap())
                    .as_ref(),
            ),
        };
        verify_bundle_with_signed_signer_policy_against_sqlite(
            &reopened,
            &rotated_bundle,
            &signed_rotated_policy,
            &authority_key,
            2,
        )
        .unwrap();
        // Both envelopes are genuinely signed. A stale envelope remains
        // unacceptable when the independent current-envelope pin rotates.
        let rotated_pin = signed_signer_policy_sha256_hex(&signed_rotated_policy).unwrap();
        assert!(
            verify_bundle_with_pinned_signed_signer_policy_against_sqlite(
                &reopened,
                &bundle,
                &signed_policy,
                &authority_key,
                1,
                &rotated_pin,
            )
            .is_err()
        );
        verify_bundle_with_pinned_signed_signer_policy_against_sqlite(
            &reopened,
            &rotated_bundle,
            &signed_rotated_policy,
            &authority_key,
            2,
            &rotated_pin,
        )
        .unwrap();

        assert!(verify_bundle_with_signed_signer_policy_against_sqlite(
            &reopened,
            &bundle,
            &signed_rotated_policy,
            &authority_key,
            2,
        )
        .is_err());
        assert!(verify_signed_trusted_signer_policy(&signed_policy, &authority_key, 2).is_err());
        assert!(verify_with_trusted_signer_policy(&bundle, &policy)
            .unwrap_err()
            .contains("revoked"));
        verify_bundle_with_signer_policy_against_sqlite(&reopened, &rotated_bundle, &policy)
            .unwrap();
        policy.signers.pop();
        assert!(verify_with_trusted_signer_policy(&rotated_bundle, &policy)
            .unwrap_err()
            .contains("not present"));
        policy.signers.push(TrustedSignerEntry {
            public_key_hex: trusted.to_uppercase(),
            status: TrustedSignerStatus::Trusted,
        });
        assert!(verify_with_trusted_signer_policy(&bundle, &policy)
            .unwrap_err()
            .contains("duplicate"));
        policy.signers.pop();
        policy.revision = 0;
        assert!(verify_with_trusted_signer_policy(&bundle, &policy).is_err());
        policy.revision = 3;
        policy.format = "unrecognized-format".into();
        assert!(verify_with_trusted_signer_policy(&bundle, &policy).is_err());
        let mut invalid_json = serde_json::to_value(&policy).unwrap();
        invalid_json["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<TrustedSignerPolicy>(invalid_json).is_err());

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
