import { useEffect, useMemo, useState } from "react";

import { workspaceApi } from "../api";
import { Icon } from "../Icon";
import { navigate } from "../routes";
import type { ProjectOverview, ProjectProfile } from "../types";
import { ConfirmDialog, EmptyState, PageHeader, Panel, StatusBadge, formatDate, shortPath } from "../ui";
import { useWorkspace } from "../WorkspaceContext";

const emptyProfile: ProjectProfile = {
  languages: [],
  frameworks: [],
  package_managers: [],
  build_systems: [],
  test_frameworks: [],
  databases: [],
  ci_providers: [],
  project_kinds: [],
};

export function ProjectsPage() {
  const {
    projects,
    activeProjectId,
    setActiveProjectId,
    pickAndImportProject,
    reindexProject,
    removeProject,
    operation,
    setToast,
  } = useWorkspace();
  const [query, setQuery] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(activeProjectId);
  const [profile, setProfile] = useState<ProjectProfile>(emptyProfile);
  const [profileError, setProfileError] = useState<string | null>(null);
  const [removeTarget, setRemoveTarget] = useState<ProjectOverview | null>(null);
  const [removing, setRemoving] = useState(false);

  useEffect(() => {
    if (activeProjectId && selectedId !== activeProjectId) setSelectedId(activeProjectId);
  }, [activeProjectId, selectedId]);

  const visible = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    if (!normalized) return projects;
    return projects.filter((project) =>
      [project.display_name, project.root_path, project.git_remote ?? ""]
        .some((value) => value.toLowerCase().includes(normalized)),
    );
  }, [projects, query]);

  const selected = projects.find((project) => project.id === selectedId) ?? null;

  useEffect(() => {
    if (!selected) {
      setProfile(emptyProfile);
      setProfileError(null);
      return;
    }
    let cancelled = false;
    setProfileError(null);
    void workspaceApi.discoverProject(selected.root_path)
      .then((next) => { if (!cancelled) setProfile(next); })
      .catch((error) => {
        if (!cancelled) {
          setProfile(emptyProfile);
          setProfileError(String(error));
        }
      });
    return () => { cancelled = true; };
  }, [selected?.id, selected?.root_path]);

  function selectProject(project: ProjectOverview) {
    setSelectedId(project.id);
    setActiveProjectId(project.id);
  }

  async function confirmRemove() {
    if (!removeTarget) return;
    setRemoving(true);
    try {
      await removeProject(removeTarget);
      setSelectedId(null);
      setRemoveTarget(null);
    } catch (error) {
      setToast({ tone: "error", message: "Could not remove project: " + String(error) });
    } finally {
      setRemoving(false);
    }
  }

  return (
    <div>
      <PageHeader
        eyebrow="PERSISTED LOCAL PROJECTS"
        title="Projects"
        description="Projects are registered by the existing persistent indexer and remain available after CodeTwin restarts."
        actions={<button className="ws-button ws-button-primary" onClick={() => void pickAndImportProject()} disabled={operation !== null}><Icon name="folder"/>Add Project Folder</button>}
      />

      {!projects.length ? (
        <EmptyState
          icon="projects"
          title="No projects indexed"
          description="Choose a local repository folder. CodeTwin will validate it, discover the stack, run the existing Tree-sitter indexer, and persist the project."
          action={<button className="ws-button ws-button-primary" onClick={() => void pickAndImportProject()}><Icon name="folder"/>Add Project Folder</button>}
        />
      ) : (
        <div className="ws-split-layout">
          <Panel title="Project list" action={<span className="ws-count">{visible.length} projects</span>}>
            <label className="ws-search-field">
              <Icon name="search" size={18}/>
              <input aria-label="Search projects" placeholder="Search project name, path, or remote…" value={query} onChange={(event) => setQuery(event.target.value)}/>
            </label>
            <div className="ws-list-stack">
              {visible.map((project) => (
                <button key={project.id} className={"ws-project-row " + (selected?.id === project.id ? "selected" : "")} onClick={() => selectProject(project)}>
                  <span className="ws-project-icon"><Icon name="folder"/></span>
                  <span className="ws-list-main">
                    <strong>{project.display_name}</strong>
                    <small title={project.root_path}>{shortPath(project.root_path, 60)}</small>
                    <em>{project.file_count} files · {project.symbol_count} symbols · {project.language_count} languages</em>
                  </span>
                  <StatusBadge status={project.last_index_status}/>
                </button>
              ))}
              {!visible.length && <p className="ws-inline-empty">No projects match “{query}”.</p>}
            </div>
          </Panel>

          <Panel title={selected ? selected.display_name : "Project details"} className="ws-detail-panel">
            {!selected ? <p className="ws-inline-empty">Select a project to inspect its persistent index metadata.</p> : (
              <>
                <dl className="ws-detail-grid">
                  <dt>Folder</dt><dd className="ws-mono" title={selected.root_path}>{selected.root_path}</dd>
                  <dt>Git remote</dt><dd className="ws-mono">{selected.git_remote ?? "Not detected"}</dd>
                  <dt>Index status</dt><dd><StatusBadge status={selected.last_index_status}/></dd>
                  <dt>Last indexed</dt><dd>{formatDate(selected.last_indexed_at)}</dd>
                  <dt>Files</dt><dd>{selected.file_count.toLocaleString()}</dd>
                  <dt>Symbols</dt><dd>{selected.symbol_count.toLocaleString()}</dd>
                </dl>

                <div className="ws-detail-section">
                  <h3>Detected stack</h3>
                  {profileError && <p className="ws-warning-box">The project is still registered, but the folder could not be re-read: {profileError}</p>}
                  <div className="ws-chip-groups">
                    {([
                      ["Languages", profile.languages],
                      ["Frameworks", profile.frameworks],
                      ["Testing", profile.test_frameworks],
                      ["Databases", profile.databases],
                      ["Build", [...profile.package_managers, ...profile.build_systems]],
                    ] as Array<[string, string[]]>).map(([label, values]) => (
                      <div key={label}><span>{label}</span><p>{values.length ? values.map((value) => <b key={value}>{value}</b>) : <em>Not detected</em>}</p></div>
                    ))}
                  </div>
                </div>

                <div className="ws-button-row">
                  <button className="ws-button ws-button-primary" onClick={() => navigate("code-analysis")}><Icon name="code"/>Open Code Analysis</button>
                  <button className="ws-button ws-button-secondary" onClick={() => void reindexProject(selected)} disabled={operation !== null}><Icon name="refresh"/>Re-index</button>
                  <button className="ws-button ws-button-danger-ghost" onClick={() => setRemoveTarget(selected)}><Icon name="trash"/>Remove</button>
                </div>
              </>
            )}
          </Panel>
        </div>
      )}

      <ConfirmDialog
        open={removeTarget !== null}
        title="Remove project from CodeTwin?"
        description={removeTarget ? "Remove " + removeTarget.display_name + " and its local CodeTwin analysis records?" : ""}
        busy={removing}
        onClose={() => setRemoveTarget(null)}
        onConfirm={() => void confirmRemove()}
      />
    </div>
  );
}
