import { useEffect, useMemo, useState } from "react";

import { chooseBenchmarkReportPath, workspaceApi } from "../api";
import { Icon } from "../Icon";
import type {
  BenchmarkReportFormat,
  BenchmarkRunSummary,
  BenchmarkTask,
  DatasetBenchmarkStatus,
} from "../types";
import { Panel, StatusBadge, formatDate } from "../ui";
import { useWorkspace } from "../WorkspaceContext";

const TASK_LABELS: Record<BenchmarkTask, string> = {
  vulnerability_detection: "Vulnerability detection",
  repair_pairs: "Fix pairs (quality)",
  secret_probe: "Secret scanner noise",
};

function percent(value: number | null | undefined): string {
  return value === null || value === undefined ? "n/a" : (value * 100).toFixed(1) + "%";
}

function decimal(value: number | null | undefined): string {
  return value === null || value === undefined ? "n/a" : value.toFixed(3);
}

function megabytes(bytes: number): string {
  return (bytes / 1_000_000).toFixed(1) + " MB";
}

export function DatasetBenchmarkPanel() {
  const { setToast } = useWorkspace();
  const [root, setRoot] = useState("");
  const [status, setStatus] = useState<DatasetBenchmarkStatus | null>(null);
  const [selected, setSelected] = useState<string[]>([]);
  const [split, setSplit] = useState("test");
  const [maxSamples, setMaxSamples] = useState(2000);
  const [runs, setRuns] = useState<BenchmarkRunSummary[]>([]);
  const [activeRunId, setActiveRunId] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function refresh(nextRoot: string | null) {
    try {
      const [nextStatus, nextRuns] = await Promise.all([
        workspaceApi.datasetBenchmarkStatus(nextRoot),
        workspaceApi.datasetBenchmarks(),
      ]);
      setStatus(nextStatus);
      setRuns(nextRuns);
      if (!nextRoot && nextStatus.datasets_root) setRoot(nextStatus.datasets_root);
      setSelected((current) =>
        current.length ? current : nextStatus.datasets.filter((item) => item.task && item.installed).map((item) => item.id),
      );
      setActiveRunId((current) => current ?? nextRuns[0]?.run_id ?? null);
    } catch (error) {
      setToast({ tone: "error", message: "Could not load dataset benchmark state: " + String(error) });
    }
  }

  useEffect(() => {
    void refresh(null);
  }, []);

  async function chooseRoot() {
    const picked = await workspaceApi.pickDatasetDirectory().catch(() => null);
    if (!picked) return;
    setRoot(picked);
    setSelected([]);
    await refresh(picked);
  }

  async function run() {
    setBusy(true);
    try {
      const summary = await workspaceApi.runDatasetBenchmark(root.trim() || null, selected, split, maxSamples);
      const problems = summary.datasets.filter((item) => item.status !== "evaluated").length;
      setToast({
        tone: summary.evaluated ? "success" : "info",
        message:
          `Benchmark finished: ${summary.evaluated} of ${summary.datasets.length} dataset(s) evaluated in ${(summary.duration_ms / 1000).toFixed(1)}s.` +
          (problems ? ` ${problems} could not be evaluated; see the details below.` : ""),
      });
      setActiveRunId(summary.run_id);
      await refresh(root.trim() || null);
    } catch (error) {
      setToast({ tone: "error", message: "Benchmark failed: " + String(error) });
    } finally {
      setBusy(false);
    }
  }

  async function exportReport(runId: string, format: BenchmarkReportFormat) {
    const path = await chooseBenchmarkReportPath(format);
    if (!path) return;
    try {
      const saved = await workspaceApi.exportDatasetBenchmark(runId, format, path);
      setToast({ tone: "success", message: "Saved " + saved });
    } catch (error) {
      setToast({ tone: "error", message: "Could not save report: " + String(error) });
    }
  }

  const datasets = status?.datasets ?? [];
  const installedCount = datasets.filter((item) => item.installed).length;
  const splits = useMemo(() => {
    const names = new Set<string>();
    for (const item of datasets) for (const name of item.splits) names.add(name.split("/").pop() ?? name);
    return [...names].sort();
  }, [datasets]);
  const activeRun = runs.find((item) => item.run_id === activeRunId) ?? null;
  const toggle = (id: string) =>
    setSelected((current) => (current.includes(id) ? current.filter((value) => value !== id) : [...current, id]));

  return (
    <div className="ws-security-tab-content">
      <div className="ws-security-toolbar ws-benchmark-toolbar">
        <div className="ws-advisory-path">
          <input
            aria-label="Installed dataset directory"
            placeholder="Installed OpenMindAI Dataset directory"
            value={root}
            onChange={(event) => setRoot(event.target.value)}
            onBlur={() => void refresh(root.trim() || null)}
          />
          <button className="ws-button ws-button-secondary" onClick={() => void chooseRoot()}>Browse…</button>
        </div>
        <select aria-label="Split" value={split} onChange={(event) => setSplit(event.target.value)}>
          {(splits.length ? splits : ["test"]).map((name) => (
            <option key={name} value={name}>{name} split</option>
          ))}
        </select>
        <label className="ws-benchmark-limit">
          Samples per dataset
          <input
            type="number"
            min={1}
            max={200000}
            value={maxSamples}
            onChange={(event) => setMaxSamples(Math.max(1, Math.min(200000, Number(event.target.value) || 1)))}
          />
        </label>
      </div>

      <section className="ws-analysis-metrics">
        <div><span><Icon name="file"/></span><strong>{installedCount}/{datasets.length}</strong><small>Datasets installed</small></div>
        <div><span><Icon name="scan"/></span><strong>{activeRun ? activeRun.evaluated : "-"}</strong><small>Evaluated last run</small></div>
        <div><span><Icon name="activity"/></span><strong>{decimal(activeRun?.datasets.find((item) => item.scores)?.scores?.f1)}</strong><small>Top-row F1</small></div>
        <div><span><Icon name="check"/></span><strong>{runs.length}</strong><small>Saved reports</small></div>
      </section>

      <div className="ws-security-layout ws-supply-layout">
        <Panel
          title="Benchmark datasets"
          action={
            <button className="ws-button ws-button-primary" disabled={busy || !selected.length} onClick={() => void run()}>
              <Icon name="scan"/>
              {busy ? "Running…" : "Run benchmark"}
            </button>
          }
        >
          <p className="ws-inline-empty">
            Scores CodeTwin's security analyzer and secret scanner against the pinned Hugging Face datasets the installer downloaded.
            Runs offline. Files are checked against their catalog SHA-256 before use.
          </p>
          {status && !status.root_exists && (
            <p className="ws-inline-empty ws-benchmark-hint">
              No dataset pack at this location. On Windows the installer offers it during setup. On macOS and Linux run
              {" "}<code>python3 install_openmindai_datasets.py --accept-dataset-terms</code> from the app's resources folder
              (or <code>scripts/</code> in the source tree), or choose another directory.
            </p>
          )}
          <div className="ws-benchmark-datasets">
            {datasets.map((item) => (
              <label key={item.id} className={item.task ? "" : "ws-disabled"}>
                <input
                  type="checkbox"
                  disabled={!item.task}
                  checked={selected.includes(item.id)}
                  onChange={() => toggle(item.id)}
                />
                <span>
                  <strong>{item.name}</strong>
                  <small>
                    {item.task ? TASK_LABELS[item.task] : "no benchmark"} · {item.repository} ·{" "}
                    <a href={item.license_url} target="_blank" rel="noreferrer">{item.license}</a> · {megabytes(item.download_bytes)}
                  </small>
                </span>
                <StatusBadge status={item.installed ? "installed" : "not_installed"}/>
              </label>
            ))}
          </div>
        </Panel>

        <Panel
          title={activeRun ? "Result · " + formatDate(activeRun.generated_at) : "Result"}
          action={
            activeRun ? (
              <div className="ws-benchmark-export">
                {(["html", "markdown", "json"] as const).map((format) => (
                  <button key={format} className="ws-button ws-button-secondary" onClick={() => void exportReport(activeRun.run_id, format)}>
                    {format === "markdown" ? "MD" : format.toUpperCase()}
                  </button>
                ))}
              </div>
            ) : undefined
          }
        >
          {!activeRun && <p className="ws-inline-empty">Run a benchmark to produce a report.</p>}
          {activeRun && (
            <div className="ws-finding-list">
              {activeRun.datasets.map((item) => (
                <article key={item.id}>
                  <StatusBadge status={item.status}/>
                  <div>
                    <strong>{item.name}</strong>
                    {item.scores ? (
                      <p>
                        {item.scored} scored · precision {percent(item.scores.precision)} · recall {percent(item.scores.recall)} ·
                        F1 {decimal(item.scores.f1)} (flag-everything baseline {decimal(item.scores.always_flag_f1)})
                      </p>
                    ) : item.pairs_evaluated !== null ? (
                      <p>{item.pairs_evaluated} fix pair(s) scored · {item.pairs_cleared_by_fix ?? 0} cleared by the fix</p>
                    ) : item.status === "evaluated" ? (
                      <p>{item.scored} text(s) scanned</p>
                    ) : null}
                    {item.secret_hits_per_thousand !== null && (
                      <small>Secret scanner: {item.secret_hits_per_thousand.toFixed(2)} hit(s) per 1,000 samples</small>
                    )}
                    {item.message && <small>{item.message}</small>}
                  </div>
                </article>
              ))}
            </div>
          )}
          <div className="ws-history-list">
            {runs.slice(0, 8).map((item) => (
              <div key={item.run_id}>
                <StatusBadge status={item.evaluated ? "completed" : "failed"}/>
                <p>
                  <button className="ws-link-button" onClick={() => setActiveRunId(item.run_id)}>
                    <strong>{item.evaluated} of {item.datasets.length} evaluated</strong>
                  </button>
                  <small>{item.split} split · up to {item.max_samples} samples · {(item.duration_ms / 1000).toFixed(1)}s</small>
                </p>
                <time>{formatDate(item.generated_at)}</time>
              </div>
            ))}
          </div>
        </Panel>
      </div>
    </div>
  );
}
