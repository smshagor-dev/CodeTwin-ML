"""Independent reference for all-MiniLM-L6-v2: HF `tokenizers` + NumPy BERT.

Usage: python reference_embed.py <model_dir> <out.json>
Writes token ids and embeddings for a fixed sentence set so the Rust
implementation (own WordPiece + candle) can be checked for parity.
"""
import json
import math
import sys

import numpy as np
from safetensors.numpy import load_file
from tokenizers import Tokenizer

SENTENCES = [
    "The deployment failed because the database migration timed out.",
    "Database schema upgrade exceeded its time limit and the release broke.",
    "I like to eat fresh strawberries in the summer.",
    "Café naïve résumé — UNICODE Ünïcödé façade!",
    "fn main() { println!(\"hello, world\"); } // rust_snake_case identifiers",
    "東京は日本の首都です。中文字符测试",
    "unaffable antidisestablishmentarianism supercalifragilisticexpialidocious",
    "  tabs\tand\nnewlines   and   control\u0007chars  ",
    "",
]


def layer_norm(x, w, b, eps=1e-12):
    mu = x.mean(-1, keepdims=True)
    var = ((x - mu) ** 2).mean(-1, keepdims=True)
    return (x - mu) / np.sqrt(var + eps) * w + b


def gelu(x):
    # BERT "gelu" is the exact erf form.
    erf = np.vectorize(math.erf)
    return 0.5 * x * (1.0 + erf(x / math.sqrt(2.0)))


def main():
    model_dir, out = sys.argv[1], sys.argv[2]
    tok = Tokenizer.from_file(f"{model_dir}/tokenizer.json")
    tok.no_padding()
    tok.enable_truncation(max_length=256)
    w = {k: v.astype(np.float64) for k, v in load_file(f"{model_dir}/model.safetensors").items()}
    pre = "" if "embeddings.word_embeddings.weight" in w else "bert."
    g = lambda k: w[pre + k]
    heads, hidden = 12, 384
    hd = hidden // heads
    results = []
    for s in SENTENCES:
        enc = tok.encode(s)
        ids = np.array(enc.ids)
        n = len(ids)
        x = g("embeddings.word_embeddings.weight")[ids]
        x = x + g("embeddings.position_embeddings.weight")[:n]
        x = x + g("embeddings.token_type_embeddings.weight")[np.zeros(n, dtype=int)]
        x = layer_norm(x, g("embeddings.LayerNorm.weight"), g("embeddings.LayerNorm.bias"))
        for i in range(6):
            p = f"encoder.layer.{i}."
            lin = lambda t, name: t @ g(p + name + ".weight").T + g(p + name + ".bias")
            q = lin(x, "attention.self.query").reshape(n, heads, hd).transpose(1, 0, 2)
            k = lin(x, "attention.self.key").reshape(n, heads, hd).transpose(1, 0, 2)
            v = lin(x, "attention.self.value").reshape(n, heads, hd).transpose(1, 0, 2)
            att = q @ k.transpose(0, 2, 1) / math.sqrt(hd)
            att = np.exp(att - att.max(-1, keepdims=True))
            att = att / att.sum(-1, keepdims=True)
            ctx = (att @ v).transpose(1, 0, 2).reshape(n, hidden)
            a = lin(ctx, "attention.output.dense")
            x = layer_norm(a + x, g(p + "attention.output.LayerNorm.weight"), g(p + "attention.output.LayerNorm.bias"))
            h = gelu(lin(x, "intermediate.dense"))
            o = lin(h, "output.dense")
            x = layer_norm(o + x, g(p + "output.LayerNorm.weight"), g(p + "output.LayerNorm.bias"))
        pooled = x.mean(0)
        pooled = pooled / np.linalg.norm(pooled)
        results.append({"text": s, "ids": enc.ids, "embedding": [round(float(f), 7) for f in pooled]})
    with open(out, "w", encoding="utf-8") as f:
        json.dump({"model": "sentence-transformers/all-MiniLM-L6-v2",
                   "revision": "1110a243fdf4706b3f48f1d95db1a4f5529b4d41",
                   "cases": results}, f, ensure_ascii=False)
    sims = np.array([r["embedding"] for r in results[:3]])
    print("cos(0,1)", float(sims[0] @ sims[1]), "cos(0,2)", float(sims[0] @ sims[2]))
    for r in results:
        print(len(r["ids"]), r["ids"][:12])


if __name__ == "__main__":
    main()
