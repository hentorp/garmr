// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! `garmr-embed` — sentence embeddings for semantic search (M4).
//!
//! A pure-Rust ([candle](https://github.com/huggingface/candle)) BERT embedder
//! loaded from LOCAL model files, so serving stays offline (no runtime network,
//! no C ONNX runtime). The reference model is `BAAI/bge-small-en-v1.5`:
//! 384-dim, ~128 MB, and — validated on real log lines — it puts semantically
//! related events close even with no shared keywords (e.g. "failed ssh
//! authentication" ↔ "invalid credentials rejected"), which is exactly the
//! recall keyword search (Tantivy BM25) misses.
//!
//! The embedder is CPU-only and single-model; `embed` takes the [CLS]-token
//! state (bge is trained for CLS pooling) and L2-normalizes, so a cosine
//! similarity is just a dot product ([`cosine`]). [`Embedder::embed_batch`]
//! runs many texts through ONE padded forward pass — the scalable path for
//! (re)indexing, where a per-message forward would dominate the cost.

use std::path::Path;

pub mod store;
pub use store::{Record, VectorStore};

use candle_core::{Device, IndexOp, Tensor};
use candle_nn::VarBuilder;
use candle_transformers::models::bert::{BertModel, Config, DTYPE};
use garmr_core::{Error, Result};
use tokenizers::Tokenizer;

/// Embedding dimensionality of the reference model (bge-small-en-v1.5).
pub const EMBED_DIM: usize = 384;

/// Model token limit; longer inputs are truncated (a single log line is far
/// shorter, but a pathological multi-KB message must not error the forward).
const MAX_TOKENS: usize = 512;

/// A loaded sentence-embedding model.
pub struct Embedder {
    model: BertModel,
    tokenizer: Tokenizer,
    device: Device,
}

impl Embedder {
    /// Load from a directory holding `config.json`, `tokenizer.json` and
    /// `model.safetensors` (a sentence-transformers BERT export, e.g.
    /// bge-small-en-v1.5). CPU, offline — no download happens here.
    pub fn load(model_dir: &Path) -> Result<Self> {
        let device = Device::Cpu;
        let config: Config = serde_json::from_str(
            &std::fs::read_to_string(model_dir.join("config.json"))
                .map_err(|e| Error::store(format!("embed config: {e}")))?,
        )
        .map_err(|e| Error::store(format!("embed config parse: {e}")))?;

        let mut tokenizer = Tokenizer::from_file(model_dir.join("tokenizer.json"))
            .map_err(|e| Error::store(format!("embed tokenizer: {e}")))?;
        // Truncate over-long inputs to the model's position limit.
        tokenizer
            .with_truncation(Some(tokenizers::TruncationParams {
                max_length: MAX_TOKENS,
                ..Default::default()
            }))
            .map_err(|e| Error::store(format!("embed tokenizer truncation: {e}")))?;

        let vb = unsafe {
            VarBuilder::from_mmaped_safetensors(
                &[model_dir.join("model.safetensors")],
                DTYPE,
                &device,
            )
            .map_err(|e| Error::store(format!("embed weights: {e}")))?
        };
        let model = BertModel::load(vb, &config)
            .map_err(|e| Error::store(format!("embed model load: {e}")))?;
        tracing::info!(dir = %model_dir.display(), dim = EMBED_DIM, "embedding model loaded");
        Ok(Self {
            model,
            tokenizer,
            device,
        })
    }

    /// Embed one text into an L2-normalized [`EMBED_DIM`] vector.
    pub fn embed(&self, text: &str) -> Result<Vec<f32>> {
        let enc = self
            .tokenizer
            .encode(text, true)
            .map_err(|e| Error::store(format!("embed tokenize: {e}")))?;
        let ids = Tensor::new(enc.get_ids(), &self.device)
            .and_then(|t| t.unsqueeze(0))
            .map_err(emap)?;
        let mask = Tensor::new(enc.get_attention_mask(), &self.device)
            .and_then(|t| t.unsqueeze(0))
            .map_err(emap)?;
        let token_type = ids.zeros_like().map_err(emap)?;
        let out = self
            .model
            .forward(&ids, &token_type, Some(&mask))
            .map_err(emap)?; // (1, seq, hidden)

        // bge-* is trained with [CLS]-token pooling (not mean pooling): the
        // sentence embedding is the first token's hidden state, L2-normalized.
        // Using position 0 also sidesteps any zero-mask division.
        let cls = out.i((0, 0)).map_err(emap)?; // (hidden,)
        let mut v = cls.to_vec1::<f32>().map_err(emap)?;
        let norm: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
        if norm > 0.0 {
            for x in &mut v {
                *x /= norm;
            }
        }
        Ok(v)
    }

    /// Embed many texts in ONE padded forward pass — the scalable indexing path.
    /// Right-pads to the batch's longest sequence (capped at [`MAX_TOKENS`]) and
    /// passes the attention mask, so a padded row's [CLS] embedding is identical
    /// to what [`embed`](Self::embed) would produce for that text alone. Returns
    /// one L2-normalized [`EMBED_DIM`] vector per input, in order. Empty input →
    /// empty output. Call it in chunks (e.g. 64) so the padded tensor stays
    /// bounded regardless of how many messages need embedding.
    pub fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>> {
        if texts.is_empty() {
            return Ok(Vec::new());
        }
        let encs = self
            .tokenizer
            .encode_batch(texts.to_vec(), true)
            .map_err(|e| Error::store(format!("embed tokenize batch: {e}")))?;
        let n = encs.len();
        let max_len = encs
            .iter()
            .map(|e| e.get_ids().len())
            .max()
            .unwrap_or(1)
            .clamp(1, MAX_TOKENS);

        let mut ids = Vec::with_capacity(n * max_len);
        let mut mask = Vec::with_capacity(n * max_len);
        for e in &encs {
            let eids = e.get_ids();
            let emask = e.get_attention_mask();
            for j in 0..max_len {
                // Right-pad with id 0 + mask 0 (truncate anything past max_len).
                ids.push(eids.get(j).copied().unwrap_or(0));
                mask.push(emask.get(j).copied().unwrap_or(0));
            }
        }
        let ids = Tensor::from_vec(ids, (n, max_len), &self.device).map_err(emap)?;
        let mask = Tensor::from_vec(mask, (n, max_len), &self.device).map_err(emap)?;
        let token_type = ids.zeros_like().map_err(emap)?;
        let out = self
            .model
            .forward(&ids, &token_type, Some(&mask))
            .map_err(emap)?; // (n, seq, hidden)

        let mut vecs = Vec::with_capacity(n);
        for i in 0..n {
            let cls = out.i((i, 0)).map_err(emap)?; // (hidden,)
            let mut v = cls.to_vec1::<f32>().map_err(emap)?;
            let norm: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
            if norm > 0.0 {
                for x in &mut v {
                    *x /= norm;
                }
            }
            vecs.push(v);
        }
        Ok(vecs)
    }
}

/// The model files that define the embedder's identity, in a FIXED order — the
/// content-addressed digest is over exactly these.
const MODEL_FILES: [&str; 3] = ["config.json", "tokenizer.json", "model.safetensors"];

/// Content digest of a model directory (`m1:<hex>`) — a domain-separated,
/// length-framed blake3 over the identity files ([`MODEL_FILES`]) in a fixed
/// order, streamed so the ~130 MB weights are never buffered whole. Deterministic
/// and tamper-sensitive: any changed byte in any file changes the digest. This is
/// the model's supply-chain identity — pin it (`GARMR_EMBED_MODEL_DIGEST`) so a
/// swapped/tampered model can never be loaded silently in an air-gapped SOC.
pub fn model_digest(dir: &Path) -> Result<String> {
    let mut h = blake3::Hasher::new();
    h.update(b"garmr-model-v1");
    for name in MODEL_FILES {
        let path = dir.join(name);
        let mut f = std::fs::File::open(&path)
            .map_err(|e| Error::store(format!("model_digest: open {name}: {e}")))?;
        let len = f
            .metadata()
            .map_err(|e| Error::store(format!("model_digest: stat {name}: {e}")))?
            .len();
        // name framing then length-prefixed streamed content (domain-separated so
        // no rename/concatenation can collide two different models).
        h.update(&(name.len() as u64).to_le_bytes());
        h.update(name.as_bytes());
        h.update(&len.to_le_bytes());
        std::io::copy(&mut f, &mut h)
            .map_err(|e| Error::store(format!("model_digest: read {name}: {e}")))?;
    }
    Ok(format!("m1:{}", &h.finalize().to_hex()[..32]))
}

impl Embedder {
    /// Load a model, VERIFYING it against an expected digest first (the airgap
    /// supply-chain gate). Computes [`model_digest`]; if `expected` is a non-empty
    /// pin it must match, else this refuses to load (a swapped/tampered model must
    /// never load silently). Returns the loaded embedder AND its digest so the
    /// caller can record the provenance (ledger + registry) and, on first run,
    /// learn the digest to pin. `expected = None` loads unpinned but still returns
    /// the digest.
    pub fn load_verified(dir: &Path, expected: Option<&str>) -> Result<(Self, String)> {
        let digest = model_digest(dir)?;
        if let Some(exp) = expected.map(str::trim).filter(|e| !e.is_empty()) {
            if exp != digest {
                return Err(Error::store(format!(
                    "embedding model digest mismatch: pinned {exp}, found {digest} — refusing to \
                     load (possible tampered or swapped model)"
                )));
            }
        }
        let e = Self::load(dir)?;
        Ok((e, digest))
    }
}

fn emap(e: candle_core::Error) -> Error {
    Error::store(format!("candle: {e}"))
}

/// Cosine similarity of two L2-normalized vectors — a plain dot product.
/// Returns 0.0 on a length mismatch (defensive; callers pass same-dim vectors).
pub fn cosine(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() {
        return 0.0;
    }
    a.iter().zip(b).map(|(x, y)| x * y).sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Load the model from `$GARMR_EMBED_MODEL` (the bge-small dir) — skipped
    /// when unset so the suite runs without the 128 MB weights present.
    fn embedder() -> Option<Embedder> {
        let dir = std::env::var_os("GARMR_EMBED_MODEL")?;
        Some(Embedder::load(Path::new(&dir)).expect("load model from GARMR_EMBED_MODEL"))
    }

    #[test]
    fn embeds_normalized_and_ranks_by_meaning() {
        let Some(e) = embedder() else {
            eprintln!("skip: set GARMR_EMBED_MODEL to a bge-small-en-v1.5 dir");
            return;
        };
        let q = e.embed("failed ssh authentication for user root").unwrap();
        assert_eq!(q.len(), EMBED_DIM);
        let norm: f32 = q.iter().map(|x| x * x).sum::<f32>().sqrt();
        assert!(
            (norm - 1.0).abs() < 1e-3,
            "vector must be L2-normalized, got norm {norm}"
        );

        // Keyword-free semantic match must beat an unrelated line.
        let close = e.embed("invalid credentials rejected on login").unwrap();
        let far = e
            .embed("kernel: disk full, no space left on device")
            .unwrap();
        let (s_close, s_far) = (cosine(&q, &close), cosine(&q, &far));
        assert!(
            s_close > s_far,
            "semantic {s_close} should beat unrelated {s_far}"
        );
        assert!(
            s_close > 0.5,
            "an auth-failure paraphrase should score high, got {s_close}"
        );
    }

    #[test]
    fn embed_batch_matches_per_text_embed() {
        let Some(e) = embedder() else {
            eprintln!("skip: set GARMR_EMBED_MODEL to a bge-small-en-v1.5 dir");
            return;
        };
        // Varying lengths so padding + the attention mask are exercised.
        let texts = [
            "failed ssh authentication for user root",
            "ok",
            "kernel: disk full, no space left on device attempt 4",
        ];
        let batch = e.embed_batch(&texts).unwrap();
        assert_eq!(batch.len(), texts.len());
        for (i, t) in texts.iter().enumerate() {
            let single = e.embed(t).unwrap();
            assert_eq!(batch[i].len(), EMBED_DIM);
            // A padded batch row's CLS embedding must match the standalone embed
            // (the mask makes padding a no-op) — high cosine, near-identical.
            assert!(
                cosine(&batch[i], &single) > 0.999,
                "batch vs single mismatch for {t:?}: cos {}",
                cosine(&batch[i], &single)
            );
        }
        assert!(e.embed_batch(&[]).unwrap().is_empty());
    }

    /// Write the three identity files (arbitrary bytes — `model_digest` hashes
    /// bytes, it doesn't parse them) into a fresh temp dir.
    fn fake_model(tag: &str, weights: &[u8]) -> std::path::PathBuf {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!("garmr-modeldig-{tag}-{n}"));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("config.json"), b"{}").unwrap();
        std::fs::write(dir.join("tokenizer.json"), b"{}").unwrap();
        std::fs::write(dir.join("model.safetensors"), weights).unwrap();
        dir
    }

    #[test]
    fn model_digest_is_deterministic_and_tamper_sensitive() {
        let a = fake_model("a", b"weights-v1");
        let d1 = model_digest(&a).unwrap();
        let d2 = model_digest(&a).unwrap();
        assert_eq!(d1, d2, "same bytes → same digest");
        assert!(d1.starts_with("m1:"));
        // A single changed byte in the weights changes the digest.
        let b = fake_model("b", b"weights-v2");
        assert_ne!(d1, model_digest(&b).unwrap());
        // A missing file is an error, not a silent pass.
        std::fs::remove_file(a.join("model.safetensors")).unwrap();
        assert!(model_digest(&a).is_err());
        std::fs::remove_dir_all(&a).ok();
        std::fs::remove_dir_all(&b).ok();
    }

    #[test]
    fn load_verified_refuses_a_mismatched_pin() {
        // The verify gate runs BEFORE the parse, so a wrong pin is rejected up
        // front (no real model needed to prove the supply-chain refusal).
        let dir = fake_model("pin", b"weights");
        let err = Embedder::load_verified(&dir, Some("m1:deadbeefdeadbeefdeadbeefdeadbeef"))
            .err()
            .expect("mismatched pin must refuse")
            .to_string();
        assert!(err.contains("digest mismatch"), "{err}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn cosine_handles_mismatch() {
        assert_eq!(cosine(&[1.0, 0.0], &[1.0]), 0.0);
        assert!((cosine(&[1.0, 0.0], &[1.0, 0.0]) - 1.0).abs() < 1e-6);
    }
}