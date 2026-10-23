# Local Security Validation

These checks are explicit operator actions, not unattended scans. Run them
only on a computer you administer and on hosts that you own or have written
authorization to test. Default CI covers unit, local loopback TLS and
test-controlled subprocess fixtures. **It does not prove real Docker isolation
or load a pretrained neural model.**

## Verified TLS certificate observations

A standalone Python standard-library command validates a single explicitly
approved TLS endpoint, with normal CA chain verification, hostname matching,
certificate not-before/not-after, remaining validity days, negotiated TLS
version and the negotiated cipher. It pins one approved DNS answer immediately
before connecting. It never turns off trust checks or captures key material.

From the repository root on Windows PowerShell:

```powershell
$env:PYTHONPATH = "services/security"
python -m unittest discover -s services/security/tests -p test_tls_certificates.py -v

# Only a hostname and TCP port you explicitly own or may test:
python -m codetwin_security.tls_certificates --host YOUR-AUTHORIZED-HOST.example --port 443 --authorized
```

Linux/macOS:

```bash
PYTHONPATH=services/security python -m unittest discover -s services/security/tests -p test_tls_certificates.py -v
PYTHONPATH=services/security python -m codetwin_security.tls_certificates --host YOUR-AUTHORIZED-HOST.example --port 443 --authorized
```

For an owned loopback lab with a locally trusted test CA, append
`--allow-private --ca-file /path/to/trusted-lab-ca.pem`. The lab-only CA is
used to validate the endpoint, **not** to disable trust. Invalid certificates
and mismatched hostnames cause a nonzero exit code with a fixed diagnostic
category. Local tests generate disposable certificates using OpenSSL when
the executable is installed; otherwise that one optional test is skipped.
Do not confuse a successful single connection with a full supported-cipher,
OCSP, CT, revocation, DNSSEC or multi-endpoint audit.

The existing desktop Network Assessment continues to provide bounded HTTPS
HEAD trust and header observations only. The certificate validity and
TLS-version details in this section are produced by the separate explicit
Python command; the desktop has **not** yet integrated these fields.

## Real, network-disabled Docker/Trivy integration

Requires a Docker daemon on a trusted machine, a digest-pinned Trivy image
locally available, and its vulnerability database already preloaded. The
operator is responsible for choosing a trusted image/revision and for
allowing setup-time downloads outside the isolated container.

In PowerShell, from the repository root:

```powershell
$env:CODETWIN_DOCKER_PATH = (Get-Command docker).Source
$env:CODETWIN_TRIVY_IMAGE = "YOUR-APPROVED-TRIVY-IMAGE@sha256:EXACT-64-HEX-DIGEST"
$env:CODETWIN_TRIVY_DB_DIR = "C:\path\to\preloaded\trivy-db"
$env:CODETWIN_TEST_REAL_SANDBOX = "1"
docker image inspect $env:CODETWIN_TRIVY_IMAGE
cargo test -p codetwin-core --test native_real_sandbox -- --nocapture
```

On Linux, an example with environment already configured:

```bash
export CODETWIN_DOCKER_PATH="$(command -v docker)"
export CODETWIN_TRIVY_IMAGE="YOUR-APPROVED-TRIVY-IMAGE@sha256:EXACT-64-HEX-DIGEST"
export CODETWIN_TRIVY_DB_DIR="/path/to/preloaded/trivy-db"
export CODETWIN_TEST_REAL_SANDBOX=1
cargo test -p codetwin-core --test native_real_sandbox -- --nocapture
```

The DB directory must contain `trivy.db` and `metadata.json`. The isolated
worker uses `--network none`, `--read-only`, no privileges, capped memory/CPU,
a read-only project mount and an explicit local approval. A passing live
test verifies report parsing, a durable audit and the Docker process contract;
it is not proof that arbitrary host-level container escape is impossible.

A separate GitHub Actions workflow, **Offline Scanner Integration**, is
available via **Actions → Offline Scanner Integration → Run workflow** with
an explicitly chosen digest-pinned image. It downloads image/DB material
during setup, then invokes the actual network-disabled scanner. It must
be manually started and its run URL recorded; default CI is not a substitute.

## Actual pretrained neural embeddings

Use a trusted, already-downloaded local SentenceTransformer directory.
No API key is needed and the model server itself does not fetch anything.

PowerShell, first terminal:

```powershell
python -m pip install -r services/ml/requirements-embeddings.txt
$env:PYTHONPATH = "services/ml"
python -m codetwin_ml.embedding_api --model-dir "C:\path\to\your\local-model" --port 8765
```

PowerShell, second terminal:

```powershell
$env:PYTHONPATH = "services/ml"
$env:CODETWIN_TEST_REAL_EMBEDDINGS = "1"
$env:CODETWIN_TEST_MODEL_DIR = "C:\path\to\your\local-model"
$env:CODETWIN_EMBEDDING_ENDPOINT = "http://127.0.0.1:8765/v1/embeddings"
$env:CODETWIN_EMBEDDING_MODEL = "codetwin-local-embedding"
python -m unittest discover -s services/ml/tests -p test_real_embedding_model.py -v
cargo test -p codetwin-core --test native_embedding_provider -- --nocapture
```

This checks pretrained-vector normalization, consistent vector dimensions,
repeatability for identical text, separation for different text and the real
Rust-to-loopback HTTP contract. The separate **Real Local Neural Embedding
Integration** workflow is opt-in at **Actions → Real Local Neural Embedding
Integration → Run workflow**. Only its setup stage downloads public weights;
inference loads them with offline and remote-code-disabled settings.

## Evidence and limits

Save the actual run URL, commit SHA, OS/runtime versions, and sanitized test
result when reviewing integration readiness. Do **not** upload Docker secrets,
sensitive source trees, API keys or real user chat data. If Docker/model
requirements are absent, mark each live check **not run**, not passed. The
default CI tests and pinned local fixtures can pass while physical Docker
runtime isolation and real pretrained inference remain unverified.
