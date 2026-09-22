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
};

type MlSidecarStatus = {
  configured: boolean;
  pythonExecutable: string;
  sidecarRoot: string;
  health: Record<string, unknown>;
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

type MlGenerationResult = {
  action: string;
  model: {
    id: string;
    version: string;
    backend: string;
    package_digest: string;
  };
  advisory: {
    summary: string;
    probe_intents: Array<{
      family: string;
      parameter: string | null;
      rationale: string;
    }>;
    repair_notes: string[];
  };
  runtime: Record<string, unknown>;
};

const PYTHON_KEY = "codetwin.ml.pythonExecutable";
const ROOT_KEY = "codetwin.ml.sidecarRoot";

export function MLWorkspace() {
  const [path, setPath] = useState("");
  const [projectId, setProjectId] = useState<string | null>(null);
  const [files, setFiles] = useState<SourceFileRecord[]>([]);
  const [selectedFileId, setSelectedFileId] = useState("");
  const [pythonExecutable, setPythonExecutable] = useState(() => localStorage.getItem(PYTHON_KEY) ?? "");
  const [sidecarRoot, setSidecarRoot] = useState(() => localStorage.getItem(ROOT_KEY) ?? "");
  const [sidecarStatus, setSidecarStatus] = useState<MlSidecarStatus | null>(null);
  const [capabilities, setCapabilities] = useState<SidecarCapabilities | null>(null);
  const [models, setModels] = useState<ModelInventory | null>(null);
  const [action, setAction] = useState("defect_detection");
  const [plan, setPlan] = useState<InferencePlan | null>(null);
  const [generationPlan, setGenerationPlan] = useState<InferencePlan | null>(null);
  const [generationResult, setGenerationResult] = useState<MlGenerationResult | null>(null);
  const [history, setHistory] = useState<MlInferenceRecord[]>([]);
  const [selectedRecord, setSelectedRecord] = useState<MlInferenceRecord | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const config = useMemo<MlSidecarConfig>(
    () => ({ pythonExecutable: pythonExecutable.trim(), sidecarRoot: sidecarRoot.trim() }),
    [pythonExecutable, sidecarRoot],
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

  async function connectSidecar() {
    if (!config.pythonExecutable || !config.sidecarRoot) return;
    setBusy(true);
    setError(null);
    try {
      const [health, caps, inventory] = await Promise.all([
        invoke<MlSidecarStatus>("ml_sidecar_health", { config }),
        invoke<SidecarCapabilities>("ml_sidecar_capabilities", { config }),
        invoke<ModelInventory>("ml_models", { config }),
      ]);
      localStorage.setItem(PYTHON_KEY, config.pythonExecutable);
      localStorage.setItem(ROOT_KEY, config.sidecarRoot);
      setSidecarStatus(health);
      setCapabilities(caps);
      setModels(inventory);
      setPlan(null);
      setGenerationPlan(null);
      setGenerationResult(null);
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

  async function inspectGenerationPlan() {
    if (!action.trim()) return;
    setBusy(true);
    setError(null);
    try {
      const nextPlan = await invoke<InferencePlan>("ml_generation_plan", {
        action: action.trim(),
        config,
      });
      setGenerationPlan(nextPlan);
    } catch (value) {
      setGenerationPlan(null);
      setError(String(value));
    } finally {
      setBusy(false);
    }
  }

  async function runGeneration() {
    if (!projectId || !selectedFileId || !action.trim()) return;
    setBusy(true);
    setError(null);
    try {
      const result = await invoke<MlGenerationResult>("run_ml_file_generation", {
        projectId,
        fileId: selectedFileId,
        action: action.trim(),
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
          <p>Run verified local classification or bounded GGUF advisory generation against hash-checked indexed source. Model output remains separate from deterministic findings and live-request authority.</p>
        </div>
      </header>

      {error && <p className="error banner" role="alert">{error}</p>}

      <section className="panel">
        <h2>Trusted sidecar</h2>
        <p>Configure the absolute Python executable and the CodeTwin <code>services/ml</code> directory. CodeTwin never discovers or executes a sidecar from the analyzed repository.</p>
        <div className="ml-config-grid">
          <label>
            <span>Python executable</span>
            <input value={pythonExecutable} onChange={(event) => setPythonExecutable(event.target.value)} placeholder="C:\\Python312\\python.exe or /usr/bin/python3" />
          </label>
          <label>
            <span>Sidecar root</span>
            <input value={sidecarRoot} onChange={(event) => setSidecarRoot(event.target.value)} placeholder=".../CodeTwin-ML/services/ml" />
          </label>
        </div>
        <div className="row">
          <button onClick={() => void connectSidecar()} disabled={busy || !config.pythonExecutable || !config.sidecarRoot}>{busy ? "Checking…" : "Check sidecar"}</button>
          {sidecarStatus && <span className="status-good">Sidecar ready · protocol {String(sidecarStatus.health.protocol ?? "unknown")}</span>}
        </div>
        {capabilities && (
          <div className="grid ml-metrics">
            <Metric label="installed models" value={capabilities.models?.installed ?? 0} />
            <Metric label="registry ready" value={capabilities.models?.ready ?? 0} />
            <Metric label="execution ready" value={capabilities.models?.execution_ready ?? 0} />
            <Metric label="classifier actions" value={capabilities.inference?.length ?? 0} />
            <Metric label="generator actions" value={capabilities.generation?.length ?? 0} />
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
                <button onClick={() => void inspectPlan()} disabled={busy || !sidecarStatus || !action.trim()}>Classifier plan</button>
                <button onClick={() => void runInference()} disabled={busy || !sidecarStatus || !selectedFileId || !action.trim()}>{busy ? "Running…" : "Run classifier"}</button>
                <button onClick={() => void inspectGenerationPlan()} disabled={busy || !sidecarStatus || !action.trim()}>Generator plan</button>
                <button onClick={() => void runGeneration()} disabled={busy || !sidecarStatus || !selectedFileId || !action.trim() || generationPlan?.status !== "ready"}>{busy ? "Running…" : "Generate advisory"}</button>
              </div>
              {plan && (
                <div className="relationship-item">
                  <strong>Classifier · {plan.status ?? "unknown plan"}</strong>
                  <small>{plan.note ?? "No additional plan note."}</small>
                </div>
              )}
              {generationPlan && (
                <div className="relationship-item">
                  <strong>Generator · {generationPlan.status ?? "unknown plan"}</strong>
                  <small>{generationPlan.note ?? "No additional plan note."}</small>
                </div>
              )}
              <p className="warning banner">The selected file is read only after its current bytes match the persisted index hash. Generative models return a strict safe-advisory schema with allow-listed probe intents; raw model-generated payloads are never sent directly to live targets.</p>
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
              <h2>Local generative advisory</h2>
              {generationResult ? (
                <>
                  <div className="finding-title-row">
                    <span className="severity severity-info">LOCAL GEN</span>
                    <strong>{generationResult.model.id} · {generationResult.model.version}</strong>
                  </div>
                  <p>{generationResult.advisory.summary}</p>
                  <div className="relationship-list">
                    {generationResult.advisory.probe_intents.map((intent, index) => (
                      <div className="relationship-item" key={intent.family + "-" + index}>
                        <strong>{intent.family}</strong>
                        <span>{intent.parameter ? "input " + intent.parameter : "route-level intent"}</span>
                        <small>{intent.rationale}</small>
                      </div>
                    ))}
                    {generationResult.advisory.repair_notes.map((note, index) => (
                      <div className="relationship-item" key={"repair-" + index}>
                        <strong>Repair note</strong>
                        <small>{note}</small>
                      </div>
                    ))}
                  </div>
                  <p className="warning banner">Probe intents are symbolic. The deterministic security engine, authorization scope, payload filter, and rate limits remain the only authority allowed to materialize a live request.</p>
                </>
              ) : (
                <p className="empty">No bounded generative advisory has been produced yet.</p>
              )}
            </section>

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
