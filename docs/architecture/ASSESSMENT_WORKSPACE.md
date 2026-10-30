# Terminal-first assessment workspace

The **Workspace** route (`#/workspace`) is the primary screen. It shows one assessment as a single chronological stream: agent activity, tool calls, approvals and errors, with inline finding cards appearing where they were produced. Status categories are filters within this stream, not separate pages.

## Data flow (real data only)

```text
workflow_events (SQLite, seq) ──┐
workflow_tasks / tool_invocations ├─► codetwin-core::assessment_stream ──► Tauri
findings + finding_evidence ─────┤        (typed StreamItem pages,           │
security_finding_reviews ────────┘         AssessmentSummary)                │
                                                                             ▼
         push: `assessment://items` (watcher thread while a run executes)
         replay: `assessment_stream_page(run_id, cursor)` (load, reconnect, 2 s fallback poll)
                                    │
                 React: mergeItems() de-duplicates by key, keeps seq order,
                 updates re-delivered finding cards in place, caps at 20k items
```

- **Stream items:**
  - An **event** has `seq`, timestamp, assessment ID, agent (role), tool, stage tag, status, target, message, duration, correlation ID and related finding IDs.
  - A **finding card** is built from the analyzers' own stores:
    - AppSec findings: rule, CWE/OWASP, file location, stored evidence excerpts and the review verdict.
    - Secret findings: only the analyzer's redacted preview is shown.
    - Dependency advisories: OSV ID, CVE aliases, CVSS and fixed versions.
- **Verification is independent of severity:**
  - Static detection is always `potential`.
  - Only an operator review moves it to `confirmed`, `validating` (needs review) or `false_positive`. The review is bound to the scan run and file hash and is rejected if stale.
  - Analyzer status `resolved` maps to `resolved`.
  - `Passed` counts only completed checks that produced no findings, plus a completed evidence verification.
- **Impact and remediation text:**
  - For AppSec findings it is general CWE guidance, labelled *"General guidance for CWE-x (not generated from this code)"*.
  - For secrets it comes from the secret scanner.
  - For dependencies it comes from the OSV advisory.
  - It never comes from a model.
- **Execution state** comes from the workflow state machines: queued, running, awaiting approval, paused, completed, failed, cancelled, blocked.

## UI structure

| Area | Contents |
|---|---|
| Left sidebar | Workspace, Reports, Targets, Agents, Knowledge, Tools, Project Settings. An *Account* group with Usage, Organization (disabled: single local operator), Settings and Help Center. A *More* group keeps every existing area (Overview, Websites, Code Analysis, Security, Testing, Integrations, Deployments, Workflows, Support) plus Advanced tools. The sidebar is collapsible to an icon rail and the preference is kept in `localStorage`. |
| Toolbar | Breadcrumb with project and assessment selectors, stream search, run state, elapsed timer, Start/Pause/Resume/Stop, New assessment, provider indicator, context-panel toggle |
| Summary | Clickable counts for Findings, Critical, High, Medium, Low, Info, Potential, Confirmed and Passed checks. They act as filters. |
| Stream | Kind filter (all, findings, errors, tools, agents), agent filter, text search, pause display (execution continues; a counter of new events is shown), copy, `.log` and JSON download, expandable lines, auto-follow with scroll lock and *Jump to latest* |
| Finding card | Severity and verification badges, location, facts, description, evidence, impact, remediation with its basis, verification limits, last review. Actions: Confirm, Needs validation and False positive (each needs a note), Retest (re-runs AppSec analysis), Create fix task (opens the existing guided fix flow), Copy, Export evidence. *Accept risk* and *Assign* are disabled, with the reason shown. |
| Context panel | Target and approved capabilities, pending approvals (approve or reject the exact scope), progress, per-agent state with the running tool, attempts and duration (clicking an agent filters the stream), top findings, budgets |

Design tokens (`assessment.css`, `shell.css`) follow the CodeTwin palette (#0B1020 background, #06B6D4 accent, red, orange, yellow and blue severity colors). Inter is used for UI text and JetBrains Mono (with system monospace fallbacks) for terminal content. The workspace is always dark. The rest of the app uses the palette in dark and system-dark themes.

## Performance

- Lines and cards use `content-visibility: auto`, so off-screen rows skip layout and paint.
- At most 600 filtered rows are rendered at once; *Show earlier* pages back.
- The client caps memory at 20,000 items.
- `mergeItems` keeps array identity when nothing changes, and rows are memoized.
- The backend pages at most 500 events per call.

This is not a full windowed virtual list; very large expanded cards are still rendered when in range.

## Limitations

- **No mockup was available.** The visual direction follows the written specification and palette.
- **Not driven in a live desktop window.** It is verified by typecheck, unit tests and the production build only.
- **Analysis scope.** The workspace orchestrates passive analyzers through the workflow engine. It does not run active web testing or exploitation; that stays in the separately authorized web-security workflow. Sanitized command previews are not shown because workflow tools do not spawn commands.
- **No dynamic validation.** *Confirmed* means an operator recorded a confirmed review, not that the issue was dynamically exploited.
- **Resource usage.** CPU and memory usage are not measured; the context panel says so.
- **Unsupported actions.** Risk acceptance, assignment and report inclusion toggles are not supported by the local stores.

## Terminal view and replay

The stream is shown as a terminal window. It has a title bar (`codetwin@<target>: ~/assessments/<id>`), a LIVE/DONE/WAITING badge, an event count, a `$ codetwin assess …` prompt line, and a blinking cursor while agents work. Events that arrive after the page loads type in line by line. When a run settles, a `[process exited] state=… outcome=…` line appears.

**Replay** plays a settled assessment back line by line at 1×, 2×, 4× or 8× speed, like a recording. It only re-plays the events stored in SQLite and never generates or embellishes output. It is disabled while a run is live. Animations are turned off when the operating system requests reduced motion.
