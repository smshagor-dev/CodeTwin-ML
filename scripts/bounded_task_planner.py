"""Deterministic, non-executing task planner for approved CodeTwin workflows.

This module does not invoke models, tools, scanners, or subprocesses. An
executor must separately enforce project identity, operator approval, scope,
capability permissions, and evidence requirements.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Sequence

MAX_TASKS = 32
MAX_ID_LENGTH = 64
MAX_DESCRIPTION_LENGTH = 512
PASSIVE_CAPABILITIES = frozenset({"source_index", "static_analysis", "qa_discovery", "evidence_review"})
ACTIVE_CAPABILITIES = frozenset({"web_security_test", "repair_apply", "qa_execute"})
ALLOWED_CAPABILITIES = PASSIVE_CAPABILITIES | ACTIVE_CAPABILITIES


class PlanRejected(ValueError):
    """Invalid or unauthorized plan; never execute a partial plan."""


@dataclass(frozen=True)
class Task:
    task_id: str
    capability: str
    description: str
    dependencies: tuple[str, ...] = ()


@dataclass(frozen=True)
class ExecutionPlan:
    project_id: str
    levels: tuple[tuple[Task, ...], ...]
    requires_approval: bool


def build_plan(
    project_id: str,
    tasks: Sequence[Task],
    *,
    approved_capabilities: Mapping[str, bool] | None = None,
) -> ExecutionPlan:
    """Validate a bounded DAG and return deterministic parallel-ready levels.

    Approval flags are preflight inputs only, never durable authorization:
    executors must revalidate authorization at execution time.
    """
    if not isinstance(project_id, str) or not project_id.strip() or len(project_id) > 128:
        raise PlanRejected("Invalid project identity")
    if isinstance(tasks, (str, bytes)) or not isinstance(tasks, (list, tuple)) or not 1 <= len(tasks) <= MAX_TASKS:
        raise PlanRejected("Task count outside permitted bounds")
    if approved_capabilities is not None and not isinstance(approved_capabilities, Mapping):
        raise PlanRejected("Invalid approval mapping")
    by_id: dict[str, Task] = {}
    for task in tasks:
        if not isinstance(task, Task):
            raise PlanRejected("Invalid task")
        if not isinstance(task.task_id, str) or not task.task_id.isascii() or not task.task_id or len(task.task_id) > MAX_ID_LENGTH or not all(c.isalnum() or c in "_-" for c in task.task_id):
            raise PlanRejected("Invalid task identifier")
        if task.task_id in by_id:
            raise PlanRejected("Duplicate task identifier")
        if not isinstance(task.capability, str) or task.capability not in ALLOWED_CAPABILITIES:
            raise PlanRejected("Unknown capability")
        if not isinstance(task.description, str) or not task.description.strip() or len(task.description) > MAX_DESCRIPTION_LENGTH:
            raise PlanRejected("Invalid task description")
        if not isinstance(task.dependencies, tuple) or len(task.dependencies) > MAX_TASKS or any(not isinstance(d, str) for d in task.dependencies) or len(set(task.dependencies)) != len(task.dependencies):
            raise PlanRejected("Invalid dependencies")
        by_id[task.task_id] = task
    for task in tasks:
        if task.task_id in task.dependencies or any(d not in by_id for d in task.dependencies):
            raise PlanRejected("Unknown or self dependency")
        if task.capability in ACTIVE_CAPABILITIES and (
            approved_capabilities is None or approved_capabilities.get(task.capability) is not True
        ):
            raise PlanRejected("Active capability requires explicit approval")
    remaining = dict(by_id)
    completed: set[str] = set()
    levels: list[tuple[Task, ...]] = []
    while remaining:
        ready = tuple(sorted((t for t in remaining.values() if set(t.dependencies) <= completed), key=lambda t: t.task_id))
        if not ready:
            raise PlanRejected("Dependency cycle")
        levels.append(ready)
        for task in ready:
            completed.add(task.task_id)
            del remaining[task.task_id]
    return ExecutionPlan(project_id, tuple(levels), any(t.capability in ACTIVE_CAPABILITIES for t in tasks))
