# ONNX Inference Runtime

CodeTwin ML's first executable ML adapter is deliberately narrow. It supports local CPU inference for integrity-checked `onnx-classification-v1` packages that opt into the `utf8-bytes-v1` contract. No model weights are bundled by this repository.

## Preconditions

A model can execute only when all of the following are true:

1. the package installed through the verified local model registry;
2. every current artifact still matches the manifest byte size and SHA-256;
3. the package backend is `onnx-classification-v1`;
4. the manifest declares a valid bounded inference contract;
5. the requested action is explicitly declared by the model;
6. the model's evaluation provenance includes at least one OpenMindAI Dataset routed for that action;
7. local `numpy`, `onnx`, and `onnxruntime` dependencies are available.

If multiple execution-ready models match an action, inference refuses to guess and requires an explicit model id and version.

## Input contract

`utf8-bytes-v1` is intentionally simple and reproducible. The model manifest declares one `int64` input name and `max_bytes` between 1 and 65,536.

For each request CodeTwin:

- encodes the input string as UTF-8 without normalization;
- rejects it if the byte length exceeds the model limit;
- maps each byte `b` to integer `b + 1`;
- reserves `0` for right padding;
- produces a fixed `[1, max_bytes]` tensor;
- never truncates silently.

The response records the UTF-8 byte length and SHA-256 of the exact input bytes rather than persisting raw source text.

## Output contract

The manifest declares exactly one logits output and 2-256 unique labels. The runtime requires one output vector whose length exactly matches that label list. Every logit must be finite. CodeTwin applies a numerically stable softmax and returns:

- the selected label;
- its confidence;
- every label probability;
- model id, version, backend, and package digest;
- evaluation provenance carried by the package;
- runtime/provider metadata.

The returned confidence is the model's normalized output for that request. It is not automatically converted into a deterministic CodeTwin finding and is not treated as proof of a defect or vulnerability.

## Runtime restrictions

The production adapter imports `onnx`, `numpy`, and `onnxruntime` only when real inference is requested. Unit tests inject a fake session so the normal Python CI suite can test the contract without downloading those optional dependencies.

Before creating an ONNX Runtime session, CodeTwin parses the model with external data disabled and rejects external tensor references throughout initializers and nested graph attributes. The executable model artifact is limited to 512 MiB. The ONNX Runtime session uses only `CPUExecutionProvider`, sequential execution, one intra-op thread, and one inter-op thread, with spinning disabled. Input and output sizes are bounded and model I/O descriptors are checked against the manifest contract.

Model packages do not provide custom native libraries, Python callbacks, repository commands, or shell hooks through this contract.

## Known limitation

This baseline does not provide a hard process-level memory limit or wall-clock timeout for ONNX execution. A malicious or pathological graph can still consume excessive resources inside the sidecar process despite the model-size, input-size, output-size, provider, and thread limits. A later hardening slice should move inference into an isolated worker process with enforceable timeout/memory policy before untrusted third-party model execution is treated as strongly sandboxed.

## Protocol

The sidecar exposes:

- `inference.plan` to report routing/readiness without running a model, including a distinct `runtime_unavailable` state when optional runtime dependencies are missing;
- `inference.run` to execute a ready classifier with `action`, `text`, and optional `model_id` / `model_version` selectors;
- `capabilities` to advertise only actions backed by an installed execution-ready model **and** available local runtime dependencies.

Missing models, ambiguous model selection, invalid input contracts, model I/O mismatch, dependency absence, and runtime failures return structured errors rather than fabricated predictions.
