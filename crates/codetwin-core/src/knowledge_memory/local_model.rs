//! In-process neural embeddings from a pinned, hash-verified local model.
//!
//! The model is `sentence-transformers/all-MiniLM-L6-v2` (BERT, 6 layers,
//! 384 dimensions, Apache-2.0) at a fixed Hugging Face revision. Every file is
//! checked against a SHA-256 pinned here before use; the weights are hashed
//! and loaded from the same in-memory buffer, so a file swapped after the
//! check is never executed. Inference runs on the CPU through candle and no
//! project text ever leaves the machine.
//!
//! The model is not bundled: an operator downloads it once (an explicit
//! action, from pinned URLs) or places the files in the model directory by
//! hand. Without a verified model, retrieval falls back to the lexical
//! vectors and says so; it never labels those as neural.
use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use candle_core::{DType, Device, Tensor};
use candle_nn::VarBuilder;
use candle_transformers::models::bert::{BertModel, Config};
use reqwest::{blocking::Client, redirect, Url};
use serde::Serialize;
use sha2::{Digest, Sha256};
use unicode_categories::UnicodeCategories;
use unicode_normalization::UnicodeNormalization;

use super::EmbeddingProvider;

#[derive(Debug, Clone, Copy)]
pub struct PinnedFile {
    pub path: &'static str,
    pub sha256: &'static str,
    pub bytes: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct LocalModelSpec {
    pub repository: &'static str,
    pub revision: &'static str,
    /// Short name used in the stored model label.
    pub name: &'static str,
    pub dims: usize,
    /// Sequence limit including `[CLS]`/`[SEP]` (sentence-transformers' own).
    pub max_tokens: usize,
    pub files: &'static [PinnedFile],
}

/// Hashes taken from the Hugging Face LFS metadata of the pinned revision.
pub const MINILM_L6_V2: LocalModelSpec = LocalModelSpec {
    repository: "sentence-transformers/all-MiniLM-L6-v2",
    revision: "1110a243fdf4706b3f48f1d95db1a4f5529b4d41",
    name: "all-MiniLM-L6-v2",
    dims: 384,
    max_tokens: 256,
    files: &[
        PinnedFile {
            path: "config.json",
            sha256: "953f9c0d463486b10a6871cc2fd59f223b2c70184f49815e7efbcab5d8908b41",
            bytes: 612,
        },
        PinnedFile {
            path: "vocab.txt",
            sha256: "07eced375cec144d27c900241f3e339478dec958f92fddbc551f295c992038a3",
            bytes: 231_508,
        },
        PinnedFile {
            path: "1_Pooling/config.json",
            sha256: "4be450dde3b0273bb9787637cfbd28fe04a7ba6ab9d36ac48e92b11e350ffc23",
            bytes: 190,
        },
        PinnedFile {
            path: "model.safetensors",
            sha256: "53aa51172d142c89d9012cce15ae4d6cc0ca6895895114379cacb4fab128d9db",
            bytes: 90_868_376,
        },
    ],
};

impl LocalModelSpec {
    /// Label stored with every vector; it changes with the pinned revision,
    /// so vectors from another model version are never mixed in.
    pub fn model_id(&self) -> String {
        format!("neural:local/{}@{}", self.name, &self.revision[..8])
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum LocalModelStatus {
    Ready {
        model: String,
        dims: usize,
    },
    Missing {
        files: Vec<String>,
    },
    /// A file is present but does not match its pinned hash.
    Corrupt {
        file: String,
    },
}

fn sha_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Read a pinned file and return its bytes only if they match the pin.
fn read_verified(dir: &Path, file: &PinnedFile) -> Result<Vec<u8>, String> {
    let path = dir.join(file.path);
    let meta = std::fs::metadata(&path).map_err(|_| format!("{} is missing", file.path))?;
    if meta.len() != file.bytes {
        return Err(format!("{} does not match the pinned model", file.path));
    }
    let bytes = std::fs::read(&path).map_err(|e| format!("{}: {e}", file.path))?;
    if sha_hex(&bytes) != file.sha256 {
        return Err(format!("{} does not match the pinned model", file.path));
    }
    Ok(bytes)
}

/// Whether `dir` holds every pinned file with the pinned content.
pub fn model_status(dir: &Path, spec: &LocalModelSpec) -> LocalModelStatus {
    let missing: Vec<String> = spec
        .files
        .iter()
        .filter(|f| !dir.join(f.path).is_file())
        .map(|f| f.path.to_owned())
        .collect();
    if !missing.is_empty() {
        return LocalModelStatus::Missing { files: missing };
    }
    for file in spec.files {
        if read_verified(dir, file).is_err() {
            return LocalModelStatus::Corrupt {
                file: file.path.to_owned(),
            };
        }
    }
    LocalModelStatus::Ready {
        model: spec.model_id(),
        dims: spec.dims,
    }
}

fn hugging_face_host(url: &Url) -> bool {
    url.scheme() == "https"
        && url.host_str().is_some_and(|h| {
            h == "huggingface.co"
                || h.ends_with(".huggingface.co")
                || h == "hf.co"
                || h.ends_with(".hf.co")
        })
}

/// Fetch the pinned files into `dir`. Each file is streamed to a temporary
/// name, hashed as it arrives and renamed into place only when it matches
/// its pin. Redirects may only lead to Hugging Face hosts over HTTPS.
/// `progress` receives (bytes done, bytes total) across all files.
pub fn download_model(
    dir: &Path,
    spec: &LocalModelSpec,
    cancel: &AtomicBool,
    progress: &dyn Fn(u64, u64),
) -> Result<(), String> {
    let client = Client::builder()
        .timeout(Duration::from_secs(600))
        .connect_timeout(Duration::from_secs(20))
        .redirect(redirect::Policy::custom(|attempt| {
            if attempt.previous().len() >= 5 || !hugging_face_host(attempt.url()) {
                attempt.stop()
            } else {
                attempt.follow()
            }
        }))
        .build()
        .map_err(|e| e.to_string())?;
    let total: u64 = spec.files.iter().map(|f| f.bytes).sum();
    let mut done = 0u64;
    for file in spec.files {
        let target = dir.join(file.path);
        if read_verified(dir, file).is_ok() {
            done += file.bytes;
            progress(done, total);
            continue;
        }
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let url = format!(
            "https://huggingface.co/{}/resolve/{}/{}",
            spec.repository, spec.revision, file.path
        );
        let mut response = client
            .get(&url)
            .send()
            .map_err(|e| format!("model download failed: {}", e.without_url()))?;
        if !response.status().is_success() {
            return Err(format!(
                "model download of {} returned HTTP {}",
                file.path,
                response.status().as_u16()
            ));
        }
        let partial = PathBuf::from(format!("{}.partial", target.display()));
        let result = (|| {
            let mut out = std::fs::File::create(&partial).map_err(|e| e.to_string())?;
            let mut hasher = Sha256::new();
            let mut written = 0u64;
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                if cancel.load(Ordering::Relaxed) {
                    return Err("model download cancelled".to_string());
                }
                let n = response.read(&mut buf).map_err(|e| e.to_string())?;
                if n == 0 {
                    break;
                }
                written += n as u64;
                if written > file.bytes {
                    return Err(format!("{} is larger than the pinned file", file.path));
                }
                hasher.update(&buf[..n]);
                out.write_all(&buf[..n]).map_err(|e| e.to_string())?;
                progress(done + written, total);
            }
            out.sync_all().map_err(|e| e.to_string())?;
            let digest: String = hasher
                .finalize()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            if written != file.bytes || digest != file.sha256 {
                return Err(format!("{} failed pinned hash verification", file.path));
            }
            Ok(())
        })();
        if let Err(e) = result {
            let _ = std::fs::remove_file(&partial);
            return Err(e);
        }
        std::fs::rename(&partial, &target).map_err(|e| e.to_string())?;
        done += file.bytes;
    }
    Ok(())
}

// ------------------------------------------------------------ tokenizer

/// BERT uncased WordPiece, matching Hugging Face's `BertNormalizer`
/// (clean text, isolate CJK, strip accents, lowercase), `BertPreTokenizer`
/// and `WordPiece` (greedy longest match, `##` continuation, 100-char cap).
struct WordPiece {
    vocab: HashMap<String, u32>,
    unk: u32,
    cls: u32,
    sep: u32,
}

fn is_control(c: char) -> bool {
    !matches!(c, '\t' | '\n' | '\r') && c.is_other()
}

fn is_whitespace(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\r') || c.is_whitespace()
}

fn is_chinese(c: char) -> bool {
    matches!(c as u32,
        0x4E00..=0x9FFF | 0x3400..=0x4DBF | 0x20000..=0x2A6DF | 0x2A700..=0x2B73F
        | 0x2B740..=0x2B81F | 0x2B820..=0x2CEAF | 0xF900..=0xFAFF | 0x2F800..=0x2FA1F)
}

fn is_punctuation(c: char) -> bool {
    c.is_ascii_punctuation() || c.is_punctuation()
}

impl WordPiece {
    fn from_vocab(text: &str) -> Result<Self, String> {
        let vocab: HashMap<String, u32> = text
            .lines()
            .enumerate()
            .map(|(i, t)| (t.to_owned(), i as u32))
            .collect();
        let id = |t: &str| {
            vocab
                .get(t)
                .copied()
                .ok_or_else(|| format!("vocabulary has no {t}"))
        };
        Ok(Self {
            unk: id("[UNK]")?,
            cls: id("[CLS]")?,
            sep: id("[SEP]")?,
            vocab,
        })
    }

    fn normalize(text: &str) -> String {
        let mut cleaned = String::with_capacity(text.len());
        for c in text.chars() {
            if c == '\0' || c == '\u{fffd}' || is_control(c) {
                continue;
            }
            if is_whitespace(c) {
                cleaned.push(' ');
            } else if is_chinese(c) {
                cleaned.push(' ');
                cleaned.push(c);
                cleaned.push(' ');
            } else {
                cleaned.push(c);
            }
        }
        cleaned
            .nfd()
            .filter(|c| !c.is_mark_nonspacing())
            .flat_map(char::to_lowercase)
            .collect()
    }

    fn word_ids(&self, word: &str, out: &mut Vec<u32>) {
        if word.chars().count() > 100 {
            out.push(self.unk);
            return;
        }
        let mut pieces = Vec::new();
        let mut start = 0;
        while start < word.len() {
            let mut end = word.len();
            let mut found = None;
            while start < end {
                let piece = &word[start..end];
                let key = if start > 0 {
                    format!("##{piece}")
                } else {
                    piece.to_owned()
                };
                if let Some(&id) = self.vocab.get(&key) {
                    found = Some(id);
                    break;
                }
                end = word[..end].char_indices().next_back().map_or(0, |(i, _)| i);
            }
            let Some(id) = found else {
                out.push(self.unk);
                return;
            };
            pieces.push(id);
            start = end;
        }
        out.extend(pieces);
    }

    /// `[CLS] tokens [SEP]`, truncated to `max_tokens` in total.
    fn encode(&self, text: &str, max_tokens: usize) -> Vec<u32> {
        let normalized = Self::normalize(text);
        let mut ids = vec![self.cls];
        for chunk in normalized.split(is_whitespace).filter(|w| !w.is_empty()) {
            let mut word_start = 0;
            for (i, c) in chunk.char_indices() {
                if is_punctuation(c) {
                    if word_start < i {
                        self.word_ids(&chunk[word_start..i], &mut ids);
                    }
                    self.word_ids(&chunk[i..i + c.len_utf8()], &mut ids);
                    word_start = i + c.len_utf8();
                }
            }
            if word_start < chunk.len() {
                self.word_ids(&chunk[word_start..], &mut ids);
            }
            if ids.len() >= max_tokens - 1 {
                break;
            }
        }
        ids.truncate(max_tokens - 1);
        ids.push(self.sep);
        ids
    }
}

// ---------------------------------------------------------------- model

pub struct LocalNeuralEmbedder {
    spec: LocalModelSpec,
    tokenizer: WordPiece,
    model: BertModel,
    device: Device,
}

const MAX_LOCAL_BATCH: usize = 32;

impl LocalNeuralEmbedder {
    /// Load the model from `dir`, refusing anything that is not byte-for-byte
    /// the pinned revision.
    pub fn load(dir: &Path, spec: &LocalModelSpec) -> Result<Self, String> {
        let mut files: HashMap<&str, Vec<u8>> = HashMap::new();
        for file in spec.files {
            files.insert(file.path, read_verified(dir, file)?);
        }
        let config: Config = serde_json::from_slice(&files["config.json"])
            .map_err(|e| format!("model config: {e}"))?;
        let pooling: serde_json::Value = serde_json::from_slice(&files["1_Pooling/config.json"])
            .map_err(|e| format!("pooling config: {e}"))?;
        if config.hidden_size != spec.dims
            || pooling["pooling_mode_mean_tokens"] != serde_json::Value::Bool(true)
        {
            return Err("model architecture does not match its pinned description".into());
        }
        let tokenizer = WordPiece::from_vocab(
            std::str::from_utf8(&files["vocab.txt"]).map_err(|_| "vocabulary is not UTF-8")?,
        )?;
        let device = Device::Cpu;
        let weights = files.remove("model.safetensors").unwrap_or_default();
        let vb = VarBuilder::from_buffered_safetensors(weights, DType::F32, &device)
            .map_err(|e| format!("model weights: {e}"))?;
        let model = BertModel::load(vb, &config).map_err(|e| format!("model load: {e}"))?;
        Ok(Self {
            spec: *spec,
            tokenizer,
            model,
            device,
        })
    }

    pub fn dims(&self) -> usize {
        self.spec.dims
    }

    fn embed_batch(&self, texts: &[String]) -> candle_core::Result<Vec<Vec<f32>>> {
        let encoded: Vec<Vec<u32>> = texts
            .iter()
            .map(|t| self.tokenizer.encode(t, self.spec.max_tokens))
            .collect();
        let width = encoded.iter().map(Vec::len).max().unwrap_or(2);
        let mut ids = Vec::with_capacity(encoded.len() * width);
        let mut mask = Vec::with_capacity(encoded.len() * width);
        for e in &encoded {
            ids.extend(
                e.iter()
                    .copied()
                    .chain(std::iter::repeat_n(0, width - e.len())),
            );
            mask.extend(
                std::iter::repeat_n(1u32, e.len()).chain(std::iter::repeat_n(0, width - e.len())),
            );
        }
        let shape = (encoded.len(), width);
        let ids = Tensor::from_vec(ids, shape, &self.device)?;
        let mask = Tensor::from_vec(mask, shape, &self.device)?;
        let hidden = self.model.forward(&ids, &ids.zeros_like()?, Some(&mask))?;
        // Mean pooling over real (unpadded) tokens, then L2 normalisation.
        let mask = mask.to_dtype(DType::F32)?.unsqueeze(2)?;
        let summed = hidden.broadcast_mul(&mask)?.sum(1)?;
        let pooled = summed.broadcast_div(&mask.sum(1)?)?;
        let norm = pooled.sqr()?.sum_keepdim(1)?.sqrt()?;
        pooled.broadcast_div(&norm)?.to_vec2::<f32>()
    }
}

impl EmbeddingProvider for LocalNeuralEmbedder {
    fn model_id(&self) -> String {
        self.spec.model_id()
    }

    fn kind(&self) -> &'static str {
        "local"
    }

    fn revision(&self) -> Option<String> {
        Some(self.spec.revision.to_owned())
    }

    fn weights_sha256(&self) -> Option<String> {
        self.spec
            .files
            .iter()
            .find(|f| f.path == "model.safetensors")
            .map(|f| f.sha256.to_owned())
    }

    /// Project text is embedded in this process; `project_id` is unused
    /// because nothing is sent anywhere.
    fn embed(&self, _project_id: &str, texts: &[String]) -> Result<Vec<Vec<f32>>, String> {
        if texts.is_empty() || texts.len() > MAX_LOCAL_BATCH {
            return Err(format!("embed 1–{MAX_LOCAL_BATCH} texts per call"));
        }
        let vectors = self
            .embed_batch(texts)
            .map_err(|e| format!("local embedding failed: {e}"))?;
        if vectors
            .iter()
            .any(|v| v.len() != self.spec.dims || v.iter().any(|x| !x.is_finite()))
        {
            return Err("local model produced an invalid vector".into());
        }
        Ok(vectors)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tiny_vocab() -> WordPiece {
        WordPiece::from_vocab(
            "[PAD]\n[UNK]\n[CLS]\n[SEP]\nun\n##aff\n##able\nhello\n,\nworld\n!\ncafe\n東\n京",
        )
        .unwrap()
    }

    #[test]
    fn wordpiece_follows_bert_rules() {
        let v = tiny_vocab();
        assert_eq!(v.encode("unaffable", 256), vec![2, 4, 5, 6, 3]);
        // Punctuation is isolated, case folded, accents stripped.
        assert_eq!(v.encode("Hello,  WORLD!", 256), vec![2, 7, 8, 9, 10, 3]);
        assert_eq!(v.encode("Café", 256), vec![2, 11, 3]);
        // CJK characters become separate words; unknown words map to [UNK].
        assert_eq!(v.encode("東京xyz", 256), vec![2, 12, 13, 1, 3]);
        // Control characters are dropped, not split on.
        assert_eq!(v.encode("hel\u{7}lo", 256), vec![2, 7, 3]);
        assert_eq!(v.encode("", 256), vec![2, 3]);
        assert_eq!(v.encode(&"a".repeat(101), 256), vec![2, 1, 3]);
        assert_eq!(v.encode("hello world hello world", 4).len(), 4);
    }

    #[test]
    fn missing_or_tampered_model_files_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            model_status(dir.path(), &MINILM_L6_V2),
            LocalModelStatus::Missing { .. }
        ));
        for f in MINILM_L6_V2.files {
            let p = dir.path().join(f.path);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, b"not the model").unwrap();
        }
        assert_eq!(
            model_status(dir.path(), &MINILM_L6_V2),
            LocalModelStatus::Corrupt {
                file: "config.json".into()
            }
        );
        let err = LocalNeuralEmbedder::load(dir.path(), &MINILM_L6_V2)
            .err()
            .unwrap();
        assert!(err.contains("pinned"), "{err}");
    }

    #[test]
    fn redirects_are_limited_to_hugging_face_over_https() {
        for (url, ok) in [
            ("https://huggingface.co/x", true),
            ("https://cdn-lfs.huggingface.co/x", true),
            ("https://cas-bridge.xethub.hf.co/x", true),
            ("http://huggingface.co/x", false),
            ("https://evil-huggingface.co/x", false),
            ("https://huggingface.co.evil.com/x", false),
            ("https://127.0.0.1/x", false),
        ] {
            assert_eq!(hugging_face_host(&Url::parse(url).unwrap()), ok, "{url}");
        }
    }

    #[test]
    fn model_label_pins_the_revision() {
        assert_eq!(
            MINILM_L6_V2.model_id(),
            "neural:local/all-MiniLM-L6-v2@1110a243"
        );
    }
}
