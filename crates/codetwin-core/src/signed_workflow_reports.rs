//! Signed, append-only workflow reports.
//!
//! A report is a canonical JSON envelope (keys sorted recursively) stored
//! byte-for-byte, content-addressed by SHA-256 and chained per run: report
//! `n` records the hash of report `n-1`, so a replayed or dropped report is
//! detectable.
//!
//! Signatures are Ed25519 over `DOMAIN || sha256(report bytes)`. Private key
//! custody is deliberately OUTSIDE CodeTwin, as for review evidence: the
//! operator signs the exported payload with their own tooling and attaches
//! the signature. Only public keys are stored, and trust is an explicit,
//! revocable operator decision recorded in `trusted_report_signers`.
//!
//! A valid trusted signature proves who issued a report and that it has not
//! been modified since. It does not prove that the report's findings are
//! correct; verification results say so explicitly.
use ring::signature::{UnparsedPublicKey, ED25519};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::Database;

pub const REPORT_FORMAT: &str = "codetwin.signed-workflow-report.v1";
pub const BUNDLE_FORMAT: &str = "codetwin.signed-workflow-report-bundle.v1";
/// Domain separation: a report signature can never be replayed as any other
/// CodeTwin signature (review evidence, signer policies).
pub const DOMAIN: &[u8] = b"CodeTwin-ML/workflow-report/ed25519/v1\0";
const MAX_REPORT_BYTES: usize = 4_000_000;
pub const TRUTH_DISCLAIMER: &str = "A valid trusted signature shows who issued this report and that it is unmodified since signing. It does not establish that the findings are correct.";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StoredReport {
    pub id: String,
    pub project_id: String,
    pub run_id: String,
    pub sequence: i64,
    pub previous_sha256: Option<String>,
    pub report_sha256: String,
    pub created_ms: i64,
    /// The exact signed bytes. Never re-serialized before hashing.
    pub report_json: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TrustedSigner {
    pub public_key_hex: String,
    pub label: String,
    pub added_by: String,
    pub added_ms: i64,
    pub revoked_ms: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BundleSignature {
    pub public_key_hex: String,
    pub signature_hex: String,
    pub signer_label: Option<String>,
}

/// Self-contained export: everything an independent verifier needs except
/// the decision which public keys to trust, which must come from elsewhere.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ReportBundle {
    pub format: String,
    pub report_sha256: String,
    pub report_json: String,
    pub signatures: Vec<BundleSignature>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SignatureState {
    /// Cryptographically valid and the key is trusted for this signature.
    Trusted,
    /// Cryptographically valid, but the key is not (or no longer) trusted.
    Untrusted,
    /// Signed after the key was revoked.
    Revoked,
    /// Does not verify against the report hash.
    Invalid,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SignatureCheck {
    pub public_key_hex: String,
    pub signer_label: Option<String>,
    pub state: SignatureState,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReportVerdict {
    /// Intact, chain consistent, at least one trusted valid signature.
    Verified,
    /// Intact but carries no signature at all.
    Unsigned,
    /// Intact and validly signed, but by no trusted, unrevoked key.
    UntrustedSigner,
    /// A stored signature does not verify: the report or signature was altered.
    InvalidSignature,
    /// The stored bytes do not hash to the recorded digest, or do not parse.
    Tampered,
    /// The per-run sequence/previous-hash chain is inconsistent.
    ChainBroken,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReportVerification {
    pub report_id: Option<String>,
    pub report_sha256: String,
    pub verdict: ReportVerdict,
    pub integrity_ok: bool,
    pub chain_ok: bool,
    pub signatures: Vec<SignatureCheck>,
    pub problems: Vec<String>,
    pub disclaimer: String,
}

/// Serialize with object keys sorted at every depth, so the same report
/// content always yields the same bytes regardless of map implementation.
pub fn canonical_json(value: &Value) -> String {
    fn sort(value: &Value) -> Value {
        match value {
            Value::Object(map) => {
                let mut keys: Vec<&String> = map.keys().collect();
                keys.sort();
                let mut out = Map::new();
                for key in keys {
                    out.insert(key.clone(), sort(&map[key]));
                }
                Value::Object(out)
            }
            Value::Array(items) => Value::Array(items.iter().map(sort).collect()),
            other => other.clone(),
        }
    }
    sort(value).to_string()
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex_encode(&Sha256::digest(bytes))
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(text: &str, expected_bytes: usize, what: &str) -> Result<Vec<u8>, String> {
    if text.len() != expected_bytes * 2 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("{what} must be {expected_bytes} bytes of hex"));
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).map_err(|_| format!("Invalid {what}")))
        .collect()
}

fn normalize_key(public_key_hex: &str) -> Result<String, String> {
    let key = public_key_hex.trim().to_ascii_lowercase();
    hex_decode(&key, 32, "Ed25519 public key")?;
    Ok(key)
}

/// The exact bytes an external Ed25519 signer must sign for a report.
pub fn signing_payload(report_sha256: &str) -> Result<Vec<u8>, String> {
    let digest = hex_decode(report_sha256, 32, "report SHA-256")?;
    let mut payload = DOMAIN.to_vec();
    payload.extend_from_slice(&digest);
    Ok(payload)
}

fn signature_valid(report_sha256: &str, public_key_hex: &str, signature_hex: &str) -> bool {
    let (Ok(payload), Ok(key), Ok(signature)) = (
        signing_payload(report_sha256),
        hex_decode(public_key_hex, 32, "public key"),
        hex_decode(signature_hex, 64, "signature"),
    ) else {
        return false;
    };
    UnparsedPublicKey::new(&ED25519, key)
        .verify(&payload, &signature)
        .is_ok()
}

fn envelope_ok(report_json: &str, report_sha256: &str) -> Result<Value, String> {
    if sha256_hex(report_json.as_bytes()) != report_sha256 {
        return Err("report bytes do not match the recorded SHA-256".into());
    }
    let value: Value =
        serde_json::from_str(report_json).map_err(|e| format!("report is not JSON: {e}"))?;
    if value.get("format").and_then(Value::as_str) != Some(REPORT_FORMAT) {
        return Err("report envelope has an unexpected format".into());
    }
    if canonical_json(&value) != report_json {
        return Err("report bytes are not in canonical form".into());
    }
    Ok(value)
}

/// Verify an exported bundle without any database: integrity of the bytes
/// and each signature against the caller's own list of trusted keys.
/// Chain position cannot be checked from one bundle and is not claimed.
pub fn verify_bundle(bundle: &ReportBundle, trusted_keys: &[String]) -> ReportVerification {
    let trusted: Vec<String> = trusted_keys
        .iter()
        .filter_map(|k| normalize_key(k).ok())
        .collect();
    let mut problems = Vec::new();
    if bundle.format != BUNDLE_FORMAT {
        problems.push(format!("unsupported bundle format `{}`", bundle.format));
    }
    let integrity_ok = match envelope_ok(&bundle.report_json, &bundle.report_sha256) {
        Ok(_) => bundle.format == BUNDLE_FORMAT,
        Err(problem) => {
            problems.push(problem);
            false
        }
    };
    let signatures: Vec<SignatureCheck> = bundle
        .signatures
        .iter()
        .map(|s| {
            let key = s.public_key_hex.to_ascii_lowercase();
            let state = if !signature_valid(&bundle.report_sha256, &key, &s.signature_hex) {
                SignatureState::Invalid
            } else if trusted.contains(&key) {
                SignatureState::Trusted
            } else {
                SignatureState::Untrusted
            };
            SignatureCheck {
                public_key_hex: key,
                signer_label: s.signer_label.clone(),
                state,
            }
        })
        .collect();
    finish(
        None,
        &bundle.report_sha256,
        integrity_ok,
        true,
        signatures,
        problems,
    )
}

fn finish(
    report_id: Option<String>,
    report_sha256: &str,
    integrity_ok: bool,
    chain_ok: bool,
    signatures: Vec<SignatureCheck>,
    problems: Vec<String>,
) -> ReportVerification {
    let verdict = if !integrity_ok {
        ReportVerdict::Tampered
    } else if !chain_ok {
        ReportVerdict::ChainBroken
    } else if signatures
        .iter()
        .any(|s| s.state == SignatureState::Invalid)
    {
        ReportVerdict::InvalidSignature
    } else if signatures.is_empty() {
        ReportVerdict::Unsigned
    } else if signatures
        .iter()
        .any(|s| s.state == SignatureState::Trusted)
    {
        ReportVerdict::Verified
    } else {
        ReportVerdict::UntrustedSigner
    };
    ReportVerification {
        report_id,
        report_sha256: report_sha256.to_owned(),
        verdict,
        integrity_ok,
        chain_ok,
        signatures,
        problems,
        disclaimer: TRUTH_DISCLAIMER.to_owned(),
    }
}

pub struct WorkflowReportStore<'a> {
    db: &'a Database,
}

impl<'a> WorkflowReportStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Append a report for `run_id`. `body` is the structured report content
    /// (findings, evidence references, citations); the envelope adds the
    /// chain position. Earlier reports are never modified.
    pub fn create(
        &self,
        project_id: &str,
        run_id: &str,
        body: Value,
    ) -> Result<StoredReport, String> {
        let tx = self
            .db
            .connection()
            .unchecked_transaction()
            .map_err(|e| e.to_string())?;
        let previous: Option<(i64, String, String)> = tx
            .query_row(
                "SELECT sequence, report_sha256, project_id FROM workflow_reports
                 WHERE run_id = ?1 ORDER BY sequence DESC LIMIT 1",
                [run_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(|e| e.to_string())?;
        if let Some((_, _, owner)) = &previous {
            if owner != project_id {
                return Err("run belongs to a different project".into());
            }
        }
        let sequence = previous.as_ref().map_or(1, |p| p.0 + 1);
        let previous_sha256 = previous.map(|p| p.1);
        let created_ms = task_orchestrator::store::now_ms();
        let envelope = serde_json::json!({
            "format": REPORT_FORMAT,
            "project_id": project_id,
            "run_id": run_id,
            "sequence": sequence,
            "previous_sha256": previous_sha256,
            "created_ms": created_ms,
            "body": body,
        });
        let report_json = canonical_json(&envelope);
        if report_json.len() > MAX_REPORT_BYTES {
            return Err(format!(
                "report is {} bytes, above the {MAX_REPORT_BYTES}-byte limit",
                report_json.len()
            ));
        }
        let report = StoredReport {
            id: task_orchestrator::store::new_id("wrep"),
            project_id: project_id.to_owned(),
            run_id: run_id.to_owned(),
            sequence,
            previous_sha256,
            report_sha256: sha256_hex(report_json.as_bytes()),
            created_ms,
            report_json,
        };
        tx.execute(
            "INSERT INTO workflow_reports(id,project_id,run_id,sequence,previous_sha256,
               report_json,report_sha256,created_ms) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                report.id,
                report.project_id,
                report.run_id,
                report.sequence,
                report.previous_sha256,
                report.report_json,
                report.report_sha256,
                report.created_ms
            ],
        )
        .map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(report)
    }

    pub fn get(&self, project_id: &str, report_id: &str) -> Result<Option<StoredReport>, String> {
        self.db
            .connection()
            .query_row(
                "SELECT id,project_id,run_id,sequence,previous_sha256,report_sha256,created_ms,
                        report_json
                 FROM workflow_reports WHERE id = ?1 AND project_id = ?2",
                [report_id, project_id],
                row_to_report,
            )
            .optional()
            .map_err(|e| e.to_string())
    }

    pub fn list(
        &self,
        project_id: &str,
        run_id: Option<&str>,
    ) -> Result<Vec<StoredReport>, String> {
        let mut stmt = self
            .db
            .connection()
            .prepare(
                "SELECT id,project_id,run_id,sequence,previous_sha256,report_sha256,created_ms,
                        report_json
                 FROM workflow_reports WHERE project_id = ?1 AND (?2 IS NULL OR run_id = ?2)
                 ORDER BY created_ms DESC, sequence DESC LIMIT 500",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(params![project_id, run_id], row_to_report)
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<_, _>>().map_err(|e| e.to_string())
    }

    /// Pin a public key as a trusted report signer.
    pub fn trust_signer(
        &self,
        public_key_hex: &str,
        label: &str,
        actor: &str,
    ) -> Result<TrustedSigner, String> {
        let key = normalize_key(public_key_hex)?;
        let label = label.trim();
        if label.is_empty() || label.chars().count() > 120 {
            return Err("signer label must be 1-120 characters".into());
        }
        let existing = self.signer(&key)?;
        if existing.as_ref().is_some_and(|s| s.revoked_ms.is_some()) {
            // Re-trusting a revoked key would silently revalidate signatures
            // made while it was revoked; a fresh key is required instead.
            return Err("this key was revoked and cannot be trusted again".into());
        }
        self.db
            .connection()
            .execute(
                "INSERT INTO trusted_report_signers(public_key_hex,label,added_by,added_ms)
                 VALUES (?1,?2,?3,?4)
                 ON CONFLICT(public_key_hex) DO UPDATE SET label = excluded.label",
                params![key, label, actor, task_orchestrator::store::now_ms()],
            )
            .map_err(|e| e.to_string())?;
        self.signer(&key)?
            .ok_or_else(|| "signer was not stored".into())
    }

    pub fn revoke_signer(&self, public_key_hex: &str) -> Result<TrustedSigner, String> {
        let key = normalize_key(public_key_hex)?;
        self.db
            .connection()
            .execute(
                "UPDATE trusted_report_signers SET revoked_ms = ?2
                 WHERE public_key_hex = ?1 AND revoked_ms IS NULL",
                params![key, task_orchestrator::store::now_ms()],
            )
            .map_err(|e| e.to_string())?;
        self.signer(&key)?.ok_or_else(|| "unknown signer".into())
    }

    pub fn signers(&self) -> Result<Vec<TrustedSigner>, String> {
        let mut stmt = self
            .db
            .connection()
            .prepare(
                "SELECT public_key_hex,label,added_by,added_ms,revoked_ms
                 FROM trusted_report_signers ORDER BY added_ms",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], row_to_signer)
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<_, _>>().map_err(|e| e.to_string())
    }

    fn signer(&self, key: &str) -> Result<Option<TrustedSigner>, String> {
        self.db
            .connection()
            .query_row(
                "SELECT public_key_hex,label,added_by,added_ms,revoked_ms
                 FROM trusted_report_signers WHERE public_key_hex = ?1",
                [key],
                row_to_signer,
            )
            .optional()
            .map_err(|e| e.to_string())
    }

    /// Attach a detached signature produced outside CodeTwin. It must verify
    /// against the report's current, intact bytes; trust is decided at
    /// verification time, so an untrusted signer can attach but never
    /// produces a `verified` verdict.
    pub fn attach_signature(
        &self,
        project_id: &str,
        report_id: &str,
        public_key_hex: &str,
        signature_hex: &str,
        signer_label: Option<&str>,
        actor: &str,
    ) -> Result<ReportVerification, String> {
        let report = self.get(project_id, report_id)?.ok_or("unknown report")?;
        envelope_ok(&report.report_json, &report.report_sha256)
            .map_err(|e| format!("refusing to sign a damaged report: {e}"))?;
        let key = normalize_key(public_key_hex)?;
        let signature = signature_hex.trim().to_ascii_lowercase();
        if !signature_valid(&report.report_sha256, &key, &signature) {
            return Err("signature does not verify against this report and key".into());
        }
        let label = signer_label.map(str::trim).filter(|l| !l.is_empty());
        if label.is_some_and(|l| l.chars().count() > 120) {
            return Err("signer label is longer than 120 characters".into());
        }
        self.db
            .connection()
            .execute(
                "INSERT INTO workflow_report_signatures(report_id,public_key_hex,signature_hex,
                   signer_label,attached_by,attached_ms) VALUES (?1,?2,?3,?4,?5,?6)",
                params![
                    report.id,
                    key,
                    signature,
                    label,
                    actor,
                    task_orchestrator::store::now_ms()
                ],
            )
            .map_err(|e| match e {
                rusqlite::Error::SqliteFailure(f, _)
                    if f.code == rusqlite::ErrorCode::ConstraintViolation =>
                {
                    "this key already signed the report".to_owned()
                }
                other => other.to_string(),
            })?;
        self.verify(project_id, report_id)
    }

    /// Full verification: byte integrity, chain consistency against the
    /// stored predecessor, and every signature against the trust store
    /// (a signature attached after its key was revoked does not count).
    pub fn verify(&self, project_id: &str, report_id: &str) -> Result<ReportVerification, String> {
        let report = self.get(project_id, report_id)?.ok_or("unknown report")?;
        let mut problems = Vec::new();
        let integrity_ok = match envelope_ok(&report.report_json, &report.report_sha256) {
            Ok(envelope) => {
                let matches = envelope["run_id"] == report.run_id.as_str()
                    && envelope["project_id"] == report.project_id.as_str()
                    && envelope["sequence"] == report.sequence
                    && envelope["previous_sha256"].as_str() == report.previous_sha256.as_deref();
                if !matches {
                    problems.push("stored columns disagree with the signed envelope".into());
                }
                matches
            }
            Err(problem) => {
                problems.push(problem);
                false
            }
        };
        let chain_ok = self.chain_ok(&report, &mut problems)?;
        let signers = self.signers()?;
        let mut stmt = self
            .db
            .connection()
            .prepare(
                "SELECT public_key_hex,signature_hex,signer_label,attached_ms
                 FROM workflow_report_signatures WHERE report_id = ?1 ORDER BY id",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([&report.id], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, i64>(3)?,
                ))
            })
            .map_err(|e| e.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;
        let signatures = rows
            .into_iter()
            .map(|(key, signature, label, attached_ms)| {
                let signer = signers.iter().find(|s| s.public_key_hex == key);
                let state = if !signature_valid(&report.report_sha256, &key, &signature) {
                    SignatureState::Invalid
                } else {
                    match signer.and_then(|s| s.revoked_ms) {
                        Some(revoked) if attached_ms >= revoked => SignatureState::Revoked,
                        _ if signer.is_some() => SignatureState::Trusted,
                        _ => SignatureState::Untrusted,
                    }
                };
                SignatureCheck {
                    public_key_hex: key,
                    signer_label: label.or_else(|| signer.map(|s| s.label.clone())),
                    state,
                }
            })
            .collect();
        Ok(finish(
            Some(report.id.clone()),
            &report.report_sha256,
            integrity_ok,
            chain_ok,
            signatures,
            problems,
        ))
    }

    fn chain_ok(&self, report: &StoredReport, problems: &mut Vec<String>) -> Result<bool, String> {
        if report.sequence == 1 {
            return Ok(report.previous_sha256.is_none());
        }
        let predecessor: Option<String> = self
            .db
            .connection()
            .query_row(
                "SELECT report_sha256 FROM workflow_reports WHERE run_id = ?1 AND sequence = ?2",
                params![report.run_id, report.sequence - 1],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| e.to_string())?;
        let ok = predecessor.is_some() && predecessor == report.previous_sha256;
        if !ok {
            problems.push(format!(
                "report {} of run {} does not link to its predecessor",
                report.sequence, report.run_id
            ));
        }
        Ok(ok)
    }

    /// Append a signed-report candidate for a durable workflow run: the run
    /// report (tasks with their evidence references, attempts, approvals,
    /// tool invocations, limitations) and every citation recorded for the
    /// run with its current verification state. Unverified citations are
    /// included as such and counted separately, never upgraded.
    pub fn create_run_report(&self, run_id: &str) -> Result<StoredReport, String> {
        let store = task_orchestrator::Store::new(self.db.connection());
        let run_report =
            task_orchestrator::report::build_report(&store, run_id).map_err(|e| e.to_string())?;
        let project_id = run_report.run.project_id.clone();
        let citations = crate::research_citations::ResearchStore::new(self.db)
            .citations(&project_id, Some(run_id))?;
        let verified = citations.iter().filter(|c| c.status == "verified").count();
        let body = serde_json::json!({
            "kind": "workflow_run",
            "outcome": run_report.run.outcome,
            "citation_summary": {"total": citations.len(), "verified": verified},
            "citations": citations,
            "run_report": run_report,
        });
        self.create(&project_id, run_id, body)
    }

    /// Export a portable bundle for independent verification.
    pub fn export(&self, project_id: &str, report_id: &str) -> Result<ReportBundle, String> {
        let report = self.get(project_id, report_id)?.ok_or("unknown report")?;
        let mut stmt = self
            .db
            .connection()
            .prepare(
                "SELECT public_key_hex,signature_hex,signer_label
                 FROM workflow_report_signatures WHERE report_id = ?1 ORDER BY id",
            )
            .map_err(|e| e.to_string())?;
        let signatures = stmt
            .query_map([&report.id], |r| {
                Ok(BundleSignature {
                    public_key_hex: r.get(0)?,
                    signature_hex: r.get(1)?,
                    signer_label: r.get(2)?,
                })
            })
            .map_err(|e| e.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;
        Ok(ReportBundle {
            format: BUNDLE_FORMAT.to_owned(),
            report_sha256: report.report_sha256,
            report_json: report.report_json,
            signatures,
        })
    }
}

fn row_to_report(r: &rusqlite::Row<'_>) -> rusqlite::Result<StoredReport> {
    Ok(StoredReport {
        id: r.get(0)?,
        project_id: r.get(1)?,
        run_id: r.get(2)?,
        sequence: r.get(3)?,
        previous_sha256: r.get(4)?,
        report_sha256: r.get(5)?,
        created_ms: r.get(6)?,
        report_json: r.get(7)?,
    })
}

fn row_to_signer(r: &rusqlite::Row<'_>) -> rusqlite::Result<TrustedSigner> {
    Ok(TrustedSigner {
        public_key_hex: r.get(0)?,
        label: r.get(1)?,
        added_by: r.get(2)?,
        added_ms: r.get(3)?,
        revoked_ms: r.get(4)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use serde_json::json;

    /// Test-only signer standing in for the operator's external tooling.
    fn keypair() -> Ed25519KeyPair {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap()
    }

    fn sign(key: &Ed25519KeyPair, report_sha256: &str) -> (String, String) {
        let signature = key.sign(&signing_payload(report_sha256).unwrap());
        (
            hex_encode(key.public_key().as_ref()),
            hex_encode(signature.as_ref()),
        )
    }

    fn setup() -> Database {
        let db = Database::open_in_memory().unwrap();
        db.connection()
            .execute_batch(
                "INSERT INTO projects(id,root_path,display_name) VALUES ('p','/p','p'),('q','/q','q')",
            )
            .unwrap();
        db
    }

    fn body() -> Value {
        json!({"findings":[{"title":"SQL injection","severity":"high","status":"potential",
               "evidence":[{"kind":"tool","id":"inv_1","sha256":"ab"}]}],"z":1,"a":2})
    }

    #[test]
    fn canonical_json_sorts_nested_keys() {
        let v = json!({"b":{"y":1,"x":[{"d":1,"c":2}]},"a":true});
        assert_eq!(
            canonical_json(&v),
            r#"{"a":true,"b":{"x":[{"c":2,"d":1}],"y":1}}"#
        );
    }

    #[test]
    fn trusted_signature_verifies_and_report_is_chained() {
        let db = setup();
        let store = WorkflowReportStore::new(&db);
        let first = store.create("p", "run1", body()).unwrap();
        let second = store
            .create("p", "run1", json!({"retest":"passed"}))
            .unwrap();
        assert_eq!(second.sequence, 2);
        assert_eq!(
            second.previous_sha256.as_deref(),
            Some(first.report_sha256.as_str())
        );

        let key = keypair();
        let (public, signature) = sign(&key, &second.report_sha256);
        let unsigned = store.verify("p", &second.id).unwrap();
        assert_eq!(unsigned.verdict, ReportVerdict::Unsigned);

        let untrusted = store
            .attach_signature("p", &second.id, &public, &signature, Some("ci"), "op")
            .unwrap();
        assert_eq!(untrusted.verdict, ReportVerdict::UntrustedSigner);

        store.trust_signer(&public, "release key", "op").unwrap();
        let verified = store.verify("p", &second.id).unwrap();
        assert_eq!(verified.verdict, ReportVerdict::Verified);
        assert!(verified.disclaimer.contains("does not establish"));
        assert!(store.verify("q", &second.id).is_err(), "project isolation");
        assert!(
            store.create("q", "run1", body()).is_err(),
            "run bound to project"
        );
    }

    #[test]
    fn wrong_key_and_wrong_report_signatures_are_rejected() {
        let db = setup();
        let store = WorkflowReportStore::new(&db);
        let a = store.create("p", "run1", body()).unwrap();
        let b = store.create("p", "run2", body()).unwrap();
        let key = keypair();
        let other = keypair();
        let (public, sig_a) = sign(&key, &a.report_sha256);
        let (_, sig_for_b) = sign(&key, &b.report_sha256);
        assert!(store
            .attach_signature("p", &a.id, &public, &sig_for_b, None, "op")
            .is_err());
        let (other_public, _) = sign(&other, &a.report_sha256);
        assert!(store
            .attach_signature("p", &a.id, &other_public, &sig_a, None, "op")
            .is_err());
        assert!(store
            .attach_signature("p", &a.id, "zz", &sig_a, None, "op")
            .is_err());
        store
            .attach_signature("p", &a.id, &public, &sig_a, None, "op")
            .unwrap();
        assert!(store
            .attach_signature("p", &a.id, &public, &sig_a, None, "op")
            .is_err());
    }

    #[test]
    fn modified_report_bytes_are_detected_as_tampering() {
        let db = setup();
        let store = WorkflowReportStore::new(&db);
        let report = store.create("p", "run1", body()).unwrap();
        let key = keypair();
        let (public, signature) = sign(&key, &report.report_sha256);
        store.trust_signer(&public, "k", "op").unwrap();
        store
            .attach_signature("p", &report.id, &public, &signature, None, "op")
            .unwrap();
        // An attacker with file access bypasses the append-only trigger.
        let forged = report.report_json.replace("high", "low");
        db.connection()
            .execute_batch("DROP TRIGGER workflow_reports_append_only;")
            .unwrap();
        db.connection()
            .execute(
                "UPDATE workflow_reports SET report_json = ?1 WHERE id = ?2",
                params![forged, report.id],
            )
            .unwrap();
        let result = store.verify("p", &report.id).unwrap();
        assert_eq!(result.verdict, ReportVerdict::Tampered);
        assert!(!result.integrity_ok);

        // Recomputing the stored hash too breaks the signature instead.
        db.connection()
            .execute(
                "UPDATE workflow_reports SET report_sha256 = ?1 WHERE id = ?2",
                params![sha256_hex(forged.as_bytes()), report.id],
            )
            .unwrap();
        let result = store.verify("p", &report.id).unwrap();
        assert_eq!(result.verdict, ReportVerdict::InvalidSignature);
    }

    #[test]
    fn append_only_trigger_blocks_in_app_updates() {
        let db = setup();
        let store = WorkflowReportStore::new(&db);
        let report = store.create("p", "run1", body()).unwrap();
        assert!(db
            .connection()
            .execute(
                "UPDATE workflow_reports SET report_json = '{}' WHERE id = ?1",
                [&report.id]
            )
            .is_err());
    }

    #[test]
    fn corrupted_and_non_canonical_data_is_rejected() {
        let db = setup();
        let store = WorkflowReportStore::new(&db);
        let report = store.create("p", "run1", body()).unwrap();
        let mut bundle = store.export("p", &report.id).unwrap();
        bundle.report_json = "{not json".into();
        bundle.report_sha256 = sha256_hex(bundle.report_json.as_bytes());
        assert_eq!(verify_bundle(&bundle, &[]).verdict, ReportVerdict::Tampered);

        let mut bundle = store.export("p", &report.id).unwrap();
        let pretty = serde_json::to_string_pretty(
            &serde_json::from_str::<Value>(&bundle.report_json).unwrap(),
        )
        .unwrap();
        bundle.report_sha256 = sha256_hex(pretty.as_bytes());
        bundle.report_json = pretty;
        assert_eq!(verify_bundle(&bundle, &[]).verdict, ReportVerdict::Tampered);
        assert!(serde_json::from_str::<ReportBundle>(r#"{"format":"x"}"#).is_err());
    }

    #[test]
    fn revoked_signer_is_not_trusted_for_later_signatures() {
        let db = setup();
        let store = WorkflowReportStore::new(&db);
        let before = store.create("p", "run1", body()).unwrap();
        let key = keypair();
        let (public, sig) = sign(&key, &before.report_sha256);
        store.trust_signer(&public, "k", "op").unwrap();
        store
            .attach_signature("p", &before.id, &public, &sig, None, "op")
            .unwrap();
        // A signature in the same millisecond as the revocation counts as
        // revoked (fail closed); keep this one clearly earlier.
        std::thread::sleep(std::time::Duration::from_millis(5));
        store.revoke_signer(&public).unwrap();
        // Signed before revocation: still attributable to a then-trusted key.
        assert_eq!(
            store.verify("p", &before.id).unwrap().verdict,
            ReportVerdict::Verified
        );
        let after = store.create("p", "run1", body()).unwrap();
        let (_, sig) = sign(&key, &after.report_sha256);
        let result = store
            .attach_signature("p", &after.id, &public, &sig, None, "op")
            .unwrap();
        assert_eq!(result.signatures[0].state, SignatureState::Revoked);
        assert_eq!(result.verdict, ReportVerdict::UntrustedSigner);
        assert!(store.trust_signer(&public, "again", "op").is_err());
    }

    #[test]
    fn run_report_carries_run_evidence_and_citation_states() {
        use crate::research_citations::{Provenance, ResearchStore};
        let db = setup();
        let run = task_orchestrator::Store::new(db.connection())
            .create_run(&task_orchestrator::RunSpec {
                project_id: "p".into(),
                goal: "Assess the login endpoint".into(),
                owner: "op".into(),
                budgets: Default::default(),
                cloud_consented: false,
            })
            .unwrap();
        let research = ResearchStore::new(&db);
        let source = research
            .ingest(
                "p",
                Some(&run.id),
                "advisory.md",
                b"# Advisory\n\nThe login endpoint concatenates user input into SQL queries.\n",
                Provenance::default(),
            )
            .unwrap();
        let cited = research
            .cite(
                "p",
                Some(&run.id),
                None,
                &source.id,
                "The login endpoint builds SQL from user input",
                Some("concatenates user input into SQL queries"),
            )
            .unwrap();
        research
            .cite(
                "p",
                Some(&run.id),
                None,
                &source.id,
                "The endpoint uses MD5",
                Some("uses MD5"),
            )
            .unwrap();

        let store = WorkflowReportStore::new(&db);
        let report = store.create_run_report(&run.id).unwrap();
        assert_eq!(report.project_id, "p");
        let envelope: Value = serde_json::from_str(&report.report_json).unwrap();
        let body = &envelope["body"];
        assert_eq!(
            body["run_report"]["run"]["goal"],
            "Assess the login endpoint"
        );
        assert_eq!(body["citation_summary"]["total"], 2);
        let statuses: Vec<&str> = body["citations"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["status"].as_str().unwrap())
            .collect();
        assert!(statuses.contains(&cited.status.as_str()));
        assert!(
            statuses.iter().any(|s| *s != "verified"),
            "a quote absent from the source is never reported as verified: {statuses:?}"
        );
        assert_eq!(
            store.verify("p", &report.id).unwrap().verdict,
            ReportVerdict::Unsigned
        );
    }

    /// Report bytes produced by this module, signed by the independent
    /// Python tool (`scripts/workflow_report_signature.py`, `cryptography`).
    /// The Python test suite verifies the same file in the other direction.
    #[test]
    fn verifies_bundle_signed_by_independent_python_tool() {
        let fixture: ReportBundle = serde_json::from_str(include_str!(
            "../tests/fixtures/workflow_report_bundle_python_signed.json"
        ))
        .unwrap();
        let key = fixture.signatures[0].public_key_hex.clone();
        let result = verify_bundle(&fixture, std::slice::from_ref(&key));
        assert_eq!(
            result.verdict,
            ReportVerdict::Verified,
            "{:?}",
            result.problems
        );
        let mut altered = fixture.clone();
        altered.report_json = altered.report_json.replace("medium", "low");
        assert_eq!(
            verify_bundle(&altered, &[key]).verdict,
            ReportVerdict::Tampered
        );
    }

    #[test]
    fn broken_chain_is_reported() {
        let db = setup();
        let store = WorkflowReportStore::new(&db);
        store.create("p", "run1", body()).unwrap();
        let second = store.create("p", "run1", body()).unwrap();
        db.connection()
            .execute("DELETE FROM workflow_reports WHERE sequence = 1", [])
            .unwrap();
        let result = store.verify("p", &second.id).unwrap();
        assert_eq!(result.verdict, ReportVerdict::ChainBroken);
    }

    #[test]
    fn exported_bundle_verifies_independently_with_pinned_keys() {
        let db = setup();
        let store = WorkflowReportStore::new(&db);
        let report = store.create("p", "run1", body()).unwrap();
        let key = keypair();
        let (public, sig) = sign(&key, &report.report_sha256);
        store
            .attach_signature("p", &report.id, &public, &sig, Some("ci"), "op")
            .unwrap();
        let bundle = store.export("p", &report.id).unwrap();
        let text = serde_json::to_string(&bundle).unwrap();
        let parsed: ReportBundle = serde_json::from_str(&text).unwrap();
        assert_eq!(
            verify_bundle(&parsed, &[public.to_uppercase()]).verdict,
            ReportVerdict::Verified
        );
        assert_eq!(
            verify_bundle(&parsed, &[]).verdict,
            ReportVerdict::UntrustedSigner,
            "a key inside the bundle is not trusted just for being there"
        );
        let mut swapped = parsed.clone();
        swapped.signatures[0].signature_hex = "00".repeat(64);
        assert_eq!(
            verify_bundle(&swapped, &[public]).verdict,
            ReportVerdict::InvalidSignature
        );
    }
}
