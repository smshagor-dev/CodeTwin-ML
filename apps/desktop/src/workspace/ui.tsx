import { useEffect, useId, useRef, type ReactNode } from "react";

import { Icon } from "./Icon";
import type { ProjectOverview } from "./types";

export function PageHeader({
  eyebrow,
  title,
  description,
  actions,
}: {
  eyebrow?: string;
  title: string;
  description?: string;
  actions?: ReactNode;
}) {
  return (
    <header className="ws-page-header">
      <div>
        {eyebrow && <p className="ws-eyebrow">{eyebrow}</p>}
        <h1>{title}</h1>
        {description && <p>{description}</p>}
      </div>
      {actions && <div className="ws-header-actions">{actions}</div>}
    </header>
  );
}

export function StatusBadge({ status }: { status: string | null | undefined }) {
  const value = status || "unknown";
  return <span className={"ws-status ws-status-" + value.replace(/[^a-z0-9_-]/gi, "-").toLowerCase()}>{value.replaceAll("_", " ")}</span>;
}

export function EmptyState({
  icon = "folder",
  title,
  description,
  action,
}: {
  icon?: Parameters<typeof Icon>[0]["name"];
  title: string;
  description: string;
  action?: ReactNode;
}) {
  return (
    <div className="ws-empty-state">
      <span className="ws-empty-icon"><Icon name={icon} size={28}/></span>
      <h2>{title}</h2>
      <p>{description}</p>
      {action}
    </div>
  );
}

export function LoadingState({ label = "Loading…" }: { label?: string }) {
  return <div className="ws-loading" role="status"><span className="ws-spinner"/>{label}</div>;
}

export function ProjectSelect({
  projects,
  value,
  onChange,
  label = "Project",
}: {
  projects: ProjectOverview[];
  value: string | null;
  onChange: (value: string) => void;
  label?: string;
}) {
  const id = useId();
  return (
    <label className="ws-field ws-project-select" htmlFor={id}>
      <span>{label}</span>
      <select id={id} value={value ?? ""} onChange={(event) => onChange(event.target.value)}>
        {!projects.length && <option value="">No projects</option>}
        {projects.map((project) => <option key={project.id} value={project.id}>{project.display_name}</option>)}
      </select>
    </label>
  );
}

export function Modal({
  open,
  title,
  description,
  children,
  onClose,
  footer,
}: {
  open: boolean;
  title: string;
  description?: string;
  children: ReactNode;
  onClose: () => void;
  footer?: ReactNode;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const previousFocus = useRef<HTMLElement | null>(null);

  useEffect(() => {
    if (!open) return;
    previousFocus.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const root = ref.current;
    const focusables = () => root?.querySelectorAll<HTMLElement>(
      'button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
    ) ?? [];
    focusables()[0]?.focus();

    function onKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") {
        event.preventDefault();
        onClose();
        return;
      }
      if (event.key !== "Tab") return;
      const nodes = Array.from(focusables());
      if (!nodes.length) return;
      const first = nodes[0];
      const last = nodes[nodes.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    }
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("keydown", onKeyDown);
      previousFocus.current?.focus();
    };
  }, [open, onClose]);

  if (!open) return null;
  return (
    <div className="ws-modal-backdrop" role="presentation" onMouseDown={(event) => {
      if (event.currentTarget === event.target) onClose();
    }}>
      <section className="ws-modal" ref={ref} role="dialog" aria-modal="true" aria-labelledby="ws-modal-title">
        <div className="ws-modal-head">
          <div><h2 id="ws-modal-title">{title}</h2>{description && <p>{description}</p>}</div>
          <button className="ws-icon-button" aria-label="Close dialog" onClick={onClose}><Icon name="close"/></button>
        </div>
        <div className="ws-modal-body">{children}</div>
        {footer && <div className="ws-modal-footer">{footer}</div>}
      </section>
    </div>
  );
}

export function ConfirmDialog({
  open,
  title,
  description,
  confirmLabel = "Remove",
  busy = false,
  onConfirm,
  onClose,
}: {
  open: boolean;
  title: string;
  description: string;
  confirmLabel?: string;
  busy?: boolean;
  onConfirm: () => void;
  onClose: () => void;
}) {
  return (
    <Modal open={open} onClose={onClose} title={title} description={description}
      footer={<>
        <button className="ws-button ws-button-secondary" onClick={onClose} disabled={busy}>Cancel</button>
        <button className="ws-button ws-button-danger" onClick={onConfirm} disabled={busy}>{busy ? "Working…" : confirmLabel}</button>
      </>}>
      <p className="ws-confirm-copy">This action updates CodeTwin's local persistent workspace. It does not delete files from the project folder or alter the remote repository.</p>
    </Modal>
  );
}

export function Panel({ title, action, children, className = "" }: { title: string; action?: ReactNode; children: ReactNode; className?: string }) {
  return <section className={"ws-panel " + className}><div className="ws-panel-head"><h2>{title}</h2>{action}</div>{children}</section>;
}

export function formatDate(value: string | null | undefined): string {
  if (!value) return "Never";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

export function shortPath(value: string, max = 68): string {
  if (value.length <= max) return value;
  const keep = Math.max(12, Math.floor((max - 1) / 2));
  return value.slice(0, keep) + "…" + value.slice(-keep);
}
