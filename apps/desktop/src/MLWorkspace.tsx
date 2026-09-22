import { useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";

type AnalysisStatus = "queued" | "running" | "completed" | "failed" | "cancelled" | "interrupted";

type IndexSummary = {
  project_id: string;
  status: AnalysisStatus;
};

type SourceFileRecord = {
  id: string;
  project_id: string;
  relative_path: string;
  language: string | null;
  content_hash: string;
  byte_size: number;
};

type MlSidecarConfig = {
  pythonExecutable: string;
  sidecarRoot: string;
  pythonExecutableSha256: string | null;
  sidecarDigest: string | null;
};

type MlSidecarIdentity = {
  pythonExecutable: string;
  sidecarRoot: string;
  pythonExecutableSha256: string;
  sidecarDigest: string;
  codeFileCount: number;
  codeBytes: number;
};

type MlContainmentStatus = {
  processTreeContainment: boolean;
  memoryLimitBytes: number | null;
  activeProcessLimit: number | null;
  cpuTimeLimitSeconds: number | null;
  uiRestrictions: boolean;
  launchSuspendedBeforeAssignment: boolean;
  filesystemIsolation: boolean;
  networkIsolation: boolean;
};

type MlSidecarStatus = {
  configured: boolean;
  pythonExecutable: string;
  sidecarRoot: string;
  health: Record<string, unknown>;
  containment: MlContainmentStatus;
  identity: MlSidecarIdentity;
};

type MlScore = {
  label: string;
  score: number;
};

type MlInferenceRecord = {
  id: string;
  project_id: string;
  run_id: string;
  action: string;
  source_file_id: string | null;
  source_content_hash: string | null;
  input_sha256: string;
  input_utf8_bytes: number;
  preprocessing: string;
  model_id: string;
  model_version: string;
  backend: string;
  package_digest: string;
  prediction_label: string;
  prediction_confidence: number;
  scores: MlScore[];
  runtime: Record<string, unknown>;
  evaluation_provenance: Record<string, unknown>;
  created_at: string;
};

type MlGenerationResult = {
  action: string;
  source_file_id: string;
  source_content_hash: string;
  source_utf8_bytes: number;
  auto_execution: boolean;
  model: {
    id: string;
    version: string;
    backend: string;
    package_digest: string;
  };
  generation: {
    text: string;
    max_new_tokens: number;
    context_tokens: number;
    temperature: number;
    top_p: number;
  };
  runtime: Record<string, unknown>;
  evaluation_provenance: Record<string, unknown>;
};

type SidecarCapabilities = {
  inference?: string[];
  generation?: string[];
  models?: {
    installed?: number;
    ready?: number;
    execution_ready?: number;
    execution_implemented?: boolean;
  };
  datasets?: {
    actions?: string[];
  };
  desktop_containment?: MlContainmentStatus;
  note?: string;
};

type ModelInventory = {
  models?: Array<Record<string, unknown>>;
  execution_implemented?: boolean;
};

type InferencePlan = {
  action?: string;
  status?: string;
  execution_implemented?: boolean;
  runtime_available?: boolean;
  note?: string;
};

const PYTHON_KEY = "codetwin.ml.pythonExecutable";
const ROOT_KEY = "codetwin.ml.sidecarRoot";
const PYTHON_SHA_KEY = "codetwin.ml.pythonExecutableSha256";
const SIDECAR_DIGEST_KEY = "codetwin.ml.sidecarDigest";

export function MLWorkspace() {
  const [path, setPath] = useState("");
  const [projectId, setProjectId] = useState<string | null>(null);
  const [files, setFiles] = useState<SourceFileRecord[]>([]);
  const [selectedFileId, setSelectedFileId] = useState("");
  const [pythonExecutable, setPythonExecutable] = useState(() => localStorage.getItem(PYTHON_KEY) ?? "");
  const [sidecarRoot, setSidecarRoot] = useState(() => localStorage.getItem(ROOT_KEY) ?? "");
  const [pythonExecutableSha256, setPythonExecutableSha256] = useState(
    () => localStorage.getItem(PYTHON_SHA_KEY) ?? "",
  );
  const [sidecarDigest, setSidecarDigest] = useState(
    () => localStorage.getItem(SIDECAR_DIGEST_KEY) ?? "",
  );
  const [sidecarStatus, setSidecarStatus] = useState<MlSidecarStatus | null>(null);
  const [capabilities, setCapabilities] = useState<SidecarCapabilities | null>(null);
  const [models, setModels] = useState<ModelInventory | null>(null);
  const [action, setAction] = useState("defect_detection");
  const [plan, setPlan] = useState<InferencePlan | null>(null);
  const [history, setHistory] = useState<MlInferenceRecord[]>([]);
  const [selectedRecord, setSelectedRecord] = useState<MlInferenceRecord | null>(null);
  const [generationInstruction, setGenerationInstruction] = useState(
    "Review this source file and propose the smallest safe code change that addresses the selected action. Explain assumptions and do not output shell commands.",
  );
  const [generationResult, setGenerationResult] = useState<MlGenerationResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const config = useMemo<MlSidecarConfig>(
    () => ({
      pythonExecutable: pythonExecutable.trim(),
      sidecarRoot: sidecarRoot.trim(),
      pythonExecutableSha256: pythonExecutableSha256.trim() || null,
      sidecarDigest: sidecarDigest.trim() || null,
    }),
    [pythonExecutable, sidecarRoot, pythonExecutableSha256, sidecarDigest],
  );

  const availableActions = useMemo(() => {
    const actions = new Set<string>();
    for (const value of capabilities?.inference ?? []) actions.add(value);
    for (const value of capabilities?.generation ?? []) actions.add(value);
    for (const value of capabilities?.datasets?.actions ?? []) actions.add(value);
    if (action) actions.add(action);
    return [...actions].sort();
  }, [action, capabilities]);

  async function loadProject(id: string) {
    const [nextFiles, nextHistory] = await Promise.all([
      invoke<SourceFileRecord[]>("list_project_files", { projectId: id, search: null, limit: 500 }),
      invoke<MlInferenceRecord[]>("ml_inference_history", { projectId: id, action: null, limit: 100 }),
    ]);
    setFiles(nextFiles);
    setHistory(nextHistory);
    if (!selectedFileId || !nextFiles.some((item) => item.id === selectedFileId)) {
      setSelectedFileId(nextFiles[0]?.id ?? "");
    }
  }

  async function openProject() {
    if (!path.trim()) return;
    setBusy(true);
    setError(null);
    try {
      const index = await invoke<IndexSummary>("index_project", { path: path.trim() });
      setProjectId(index.project_id);
      setSelectedRecord(null);
      await loadProject(index.project_id);
    } catch (value) {
      setError(String(value));
    } finally {
      setBusy(false);
    }
  }

  function clearSidecarTrust() {
    setPythonExecutableSha256("");
    setSidecarDigest("");
    localStorage.removeItem(PYTHON_SHA_KEY);
    localStorage.removeItem(SIDECAR_DIGEST_KEY);
    setSidecarStatus(null);
    setCapabilities(null);
    setModels(null);
    setPlan(null);
  }

  function updatePythonExecutable(value: string) {
    setPythonExecutable(value);
    clearSidecarTrust();
  }

  function updateSidecarRoot(value: string) {
    setSidecarRoot(value);
    clearSidecarTrust();
  }

  async function connectSidecar() {
    if (!config.pythonExecutable || !config.sidecarRoot) return;
    setBusy(true);
    setError(null);
    try {
      const inspectionConfig: MlSidecarConfig = {
        pythonExecutable: config.pythonExecutable,
        sidecarRoot: config.sidecarRoot,
        pythonExecutableSha256: null,
        sidecarDigest: null,
      };
      const identity = await invoke<MlSidecarIdentity>("ml_sidecar_identity", {
        config: inspectionConfig,
      });
      const trustedConfig: MlSidecarConfig = {
        pythonExecutable: identity.pythonExecutable,
        sidecarRoot: identity.sidecarRoot,
        pythonExecutableSha256: identity.pythonExecutableSha256,
        sidecarDigest: identity.sidecarDigest,
      };
      const [health, caps, inventory] = await Promise.all([
        invoke<MlSidecarStatus>("ml_sidecar_health", { config: trustedConfig }),
        invoke<SidecarCapabilities>("ml_sidecar_capabilities", { config: trustedConfig }),
        invoke<ModelInventory>("ml_models", { config: trustedConfig }),
      ]);
      localStorage.setItem(PYTHON_KEY, identity.pythonExecutable);
      localStorage.setItem(ROOT_KEY, identity.sidecarRoot);
      localStorage.setItem(PYTHON_SHA_KEY, identity.pythonExecutableSha256);
      localStorage.setItem(SIDECAR_DIGEST_KEY, identity.sidecarDigest);
      setPythonExecutable(identity.pythonExecutable);
      setSidecarRoot(identity.sidecarRoot);
      setPythonExecutableSha256(identity.pythonExecutableSha256);
      setSidecarDigest(identity.sidecarDigest);
      setSidecarStatus(health);
      setCapabilities(caps);
      setModels(inventory);
      setPlan(null);
    } catch (value) {
      setSidecarStatus(null);
      setCapabilities(null);
      setModels(null);
      setError(String(value));
    } finally {
      setBusy(false);
    }
  }

  async function inspectPlan() {
    if (!action.trim()) return;
    setBusy(true);
    setError(null);
    try {
      const nextPlan = await invoke<InferencePlan>("ml_inference_plan", {
        action: action.trim(),
        config,
      });
      setPlan(nextPlan);
    } catch (value) {
      setPlan(null);
      setError(String(value));
    } finally {
      setBusy(false);
    }
  }

  async function runInference() {
    if (!projectId || !selectedFileId || !action.trim()) return;
    setBusy(true);
    setError(null);
    try {
      const record = await invoke<MlInferenceRecord>("run_ml_file_inference", {
        projectId,
        fileId: selectedFileId,
        action: action.trim(),
        modelId: null,
        modelVersion: null,
        config,
      });
      setSelectedRecord(record);
      await loadProject(projectId);
    } catch (value) {
      setError(String(value));
    } finally {
      setBusy(false);
    }
  }

  async function runGeneration() {
    if (!projectId || !selectedFileId || !action.trim() || !generationInstruction.trim()) return;
    setBusy(true);
    setError(null);
    try {
      const result = await invoke<MlGenerationResult>("run_ml_file_generation", {
        projectId,
        fileId: selectedFileId,
        action: action.trim(),
        instruction: generationInstruction.trim(),
        modelId: null,
        modelVersion: null,
        config,
      });
      setGenerationResult(result);
    } catch (value) {
      setGenerationResult(null);
      setError(String(value));
    } finally {
      setBusy(false);
    }
  }

  const selectedFile = files.find((item) => item.id === selectedFileId) ?? null;

  return (
    <main className="standalone-workspace ml-workspace">
      <header>
        <div>
          <p className="eyebrow">LOCAL MODEL EXECUTION</p>
          <h1>Local ML</h1>
          <p>Run verified local classification or bounded GGUF code generation against hash-checked indexed source. Generated text remains a review artifact and is never auto-executed.</p>
        </div>
      </header>

      {error && <p className="error banner" role="alert">{error}</p>}

      <section className="panel">
        <h2>Trusted sidecar</h2>
        <p>Configure the absolute Python executable and the CodeTwin <code>services/ml</code> directory. CodeTwin never discovers or executes a sidecar from the analyzed repository.</p>
        <div className="ml-config-grid">
          <label>
            <span>Python executable</span>
            <input value={pythonExecutable} onChange={(event) => updatePythonExecutable(event.target.value)} placeholder="C:\\Python312\\python.exe or /usr/bin/python3" />
          </label>
          <label>
            <span>Sidecar root</span>
            <input value={sidecarRoot} onChange={(event) => updateSidecarRoot(event.target.value)} placeholder=".../CodeTwin-ML/services/ml" />
          </label>
        </div>
        <div className="row">
          <button onClick={() => void connectSidecar()} disabled={busy || !config.pythonExecutable || !config.sidecarRoot}>{busy ? "Inspecting…" : "Inspect & trust sidecar"}</button>
          {sidecarStatus && <span className="status-good">Sidecar ready · protocol {String(sidecarStatus.health.protocol ?? "unknown")}</span>}
        </div>
        {sidecarStatus?.identity && (
          <div className="relationship-item">
            <strong>Trusted sidecar identity</strong>
            <span>{sidecarStatus.identity.codeFileCount} Python files · {sidecarStatus.identity.codeBytes} bytes</span>
            <small className="mono">Python SHA-256 {sidecarStatus.identity.pythonExecutableSha256}</small>
            <small className="mono">Sidecar digest {sidecarStatus.identity.sidecarDigest}</small>
          </div>
        )}
        {sidecarStatus?.containment && (
          <>
            <div className="grid ml-metrics">
              <Metric label="process tree contained" value={sidecarStatus.containment.processTreeContainment ? "yes" : "no"} />
              <Metric label="UI restrictions" value={sidecarStatus.containment.uiRestrictions ? "yes" : "no"} />
              <Metric label="CPU limit" value={sidecarStatus.containment.cpuTimeLimitSeconds ? `${sidecarStatus.containment.cpuTimeLimitSeconds}s` : "platform limit"} />
              <Metric label="process limit" value={sidecarStatus.containment.activeProcessLimit ?? "platform limit"} />
              <Metric label="filesystem isolation" value={sidecarStatus.containment.filesystemIsolation ? "yes" : "no"} />
              <Metric label="network isolation" value={sidecarStatus.containment.networkIsolation ? "yes" : "no"} />
            </div>
            {(!sidecarStatus.containment.filesystemIsolation || !sidecarStatus.containment.networkIsolation) && (
              <p className="warning banner">Local ML remains a trusted-runtime boundary. Process/resource/UI containment does not imply filesystem or network isolation.</p>
            )}
          </>
        )}
        {capabilities && (
          <div className="grid ml-metrics">
            <Metric label="installed models" value={capabilities.models?.installed ?? 0} />
            <Metric label="registry ready" value={capabilities.models?.ready ?? 0} />
            <Metric label="execution ready" value={capabilities.models?.execution_ready ?? 0} />
            <Metric label="classifier actions" value={capabilities.inference?.length ?? 0} />
            <Metric label="generation actions" value={capabilities.generation?.length ?? 0} />
          </div>
        )}
        {capabilities?.note && <p className="muted">{capabilities.note}</p>}
      </section>

      <section className="panel">
        <h2>Project</h2>
        <p>Indexing establishes the file identity and current SHA-256 used to prevent stale ML attribution.</p>
        <div className="row">
          <input aria-label="Repository path" value={path} onChange={(event) => setPath(event.target.value)} placeholder="C:\\work\\project or /home/user/project" />
          <button onClick={() => void openProject()} disabled={busy || !path.trim()}>{busy && !projectId ? "Opening…" : "Open & index"}</button>
        </div>
        {projectId && <p className="mono workspace-project-id">Project {projectId}</p>}
      </section>

      {projectId && (
        <section className="ml-layout">
          <div className="twin-column">
            <section className="panel compact">
              <h2>Inference request</h2>
              <label className="field-label">
                <span>Action</span>
                <input list="ml-actions" value={action} onChange={(event) => setAction(event.target.value)} />
                <datalist id="ml-actions">
                  {availableActions.map((item) => <option key={item} value={item} />)}
                </datalist>
              </label>
              <label className="field-label">
                <span>Indexed source file</span>
                <select value={selectedFileId} onChange={(event) => setSelectedFileId(event.target.value)}>
                  {files.map((file) => (
                    <option key={file.id} value={file.id}>{file.relative_path} · {file.byte_size} bytes</option>
                  ))}
                </select>
              </label>
              {selectedFile && (
                <div className="relationship-item">
                  <strong>{selectedFile.relative_path}</strong>
                  <span>{selectedFile.language ?? "unknown language"} · {selectedFile.byte_size} bytes</span>
                  <small className="mono">SHA-256 {selectedFile.content_hash}</small>
                </div>
              )}
              <div className="row ml-actions-row">
                <button onClick={() => void inspectPlan()} disabled={busy || !sidecarStatus || !action.trim()}>Check classifier plan</button>
                <button onClick={() => void runInference()} disabled={busy || !sidecarStatus || !selectedFileId || !action.trim()}>{busy ? "Running…" : "Run classifier & record"}</button>
              </div>
              <label className="field-label">
                <span>Local generation instruction</span>
                <textarea
                  rows={4}
                  value={generationInstruction}
                  onChange={(event) => setGenerationInstruction(event.target.value)}
                  maxLength={4096}
                />
              </label>
              <div className="row ml-actions-row">
                <button
                  onClick={() => void runGeneration()}
                  disabled={busy || !sidecarStatus || !selectedFileId || !action.trim() || !generationInstruction.trim()}
                >
                  {busy ? "Running…" : "Generate local suggestion"}
                </button>
              </div>
              {plan && (
                <div className="relationship-item">
                  <strong>{plan.status ?? "unknown plan"}</strong>
                  <span>runtime {plan.runtime_available === false ? "unavailable" : "available or not reported"}</span>
                  <small>{plan.note ?? "No additional plan note."}</small>
                </div>
              )}
              <p className="warning banner">The selected file is read only after its current bytes match the persisted index hash. Raw source text is sent only to the explicitly configured local sidecar. Generated text is never automatically applied to files or used as a live security payload.</p>
              {generationResult && (
                <div className="relationship-item">
                  <strong>Generated suggestion · {generationResult.model.id} {generationResult.model.version}</strong>
                  <small className="mono">Source SHA-256 {generationResult.source_content_hash} · auto execution {String(generationResult.auto_execution)}</small>
                  <pre style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>{generationResult.generation.text}</pre>
                </div>
              )}
            </section>

            <section className="panel compact">
              <h2>Model inventory</h2>
              <div className="relationship-list">
                {(models?.models ?? []).map((model, index) => (
                  <div className="relationship-item" key={`${String(model.id ?? "model")}-${String(model.version ?? index)}`}>
                    <strong>{String(model.name ?? model.id ?? "Unnamed model")}</strong>
                    <span>{String(model.id ?? "unknown id")} · {String(model.version ?? "unknown version")}</span>
                    <small>ready {String(model.ready ?? false)} · execution {String(model.execution_supported ?? false)}</small>
                  </div>
                ))}
                {!(models?.models?.length) && <p className="empty">No installed model has been reported by the configured sidecar.</p>}
              </div>
            </section>
          </div>

          <div className="twin-column wide">
            <section className="panel compact detail-panel">
              <h2>Selected prediction</h2>
              {selectedRecord ? (
                <>
                  <div className="finding-title-row">
                    <span className="severity severity-info">ML</span>
                    <strong>{selectedRecord.prediction_label}</strong>
                  </div>
                  <p>Model confidence {formatPercent(selectedRecord.prediction_confidence)}. This is model output, not a confirmed defect or vulnerability.</p>
                  <dl className="metadata-grid">
                    <dt>Action</dt><dd>{selectedRecord.action}</dd>
                    <dt>Model</dt><dd>{selectedRecord.model_id} · {selectedRecord.model_version}</dd>
                    <dt>Backend</dt><dd>{selectedRecord.backend}</dd>
                    <dt>Input bytes</dt><dd>{selectedRecord.input_utf8_bytes}</dd>
                    <dt>Input hash</dt><dd className="mono">{selectedRecord.input_sha256}</dd>
                    <dt>Package digest</dt><dd className="mono">{selectedRecord.package_digest}</dd>
                  </dl>
                  <div className="ml-score-list">
                    {selectedRecord.scores.map((score) => (
                      <div key={score.label} className="relationship-item">
                        <strong>{score.label}</strong>
                        <span>{formatPercent(score.score)}</span>
                      </div>
                    ))}
                  </div>
                </>
              ) : <p className="empty">Run inference or select a persisted history record.</p>}
            </section>

            <section className="panel compact">
              <h2>Inference history</h2>
              <div className="history-list ml-history-list">
                {history.map((record) => (
                  <button key={record.id} className={`history-item ml-history-item ${selectedRecord?.id === record.id ? "selected" : ""}`} onClick={() => setSelectedRecord(record)}>
                    <div><strong>{record.prediction_label}</strong><span>{record.created_at}</span></div>
                    <span>{record.action} · {formatPercent(record.prediction_confidence)}</span>
                    <small>{record.model_id} {record.model_version} · input {record.input_sha256.slice(0, 16)}…</small>
                  </button>
                ))}
                {!history.length && <p className="empty">No ML inference provenance has been persisted for this project.</p>}
              </div>
            </section>
          </div>
        </section>
      )}
    </main>
  );
}

function Metric({ label, value }: { label: string; value: string | number }) {
  return <article className="card"><h3>{label}</h3><p>{value}</p></article>;
}

function formatPercent(value: number) {
  return `${(value * 100).toFixed(2)}%`;
}
