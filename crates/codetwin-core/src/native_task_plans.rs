//! Validated, model-proposed review decomposition. No model can add executables.
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const ALLOWED: [&str; 6] = ["scout", "source", "secrets", "qa", "database", "runtime"];

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedSpecialist {
    pub role: String,
    pub objective: String,
    pub depends_on: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskProposal {
    pub tasks: Vec<PlannedSpecialist>,
    pub rationale: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskSchedule {
    pub batches: Vec<Vec<String>>,
    pub max_parallel: usize,
}

/// A strict, bounded task graph. Every dependency comes from an approved role.
pub fn validate_proposal(plan: &TaskProposal) -> Result<TaskSchedule, String> {
    if !(2..=ALLOWED.len()).contains(&plan.tasks.len())
        || plan.rationale.trim().is_empty()
        || plan.rationale.len() > 1200
    {
        return Err("A plan must have 2–6 tasks and a short rationale".into());
    }
    let mut positions = BTreeMap::new();
    for (index, task) in plan.tasks.iter().enumerate() {
        if !ALLOWED.contains(&task.role.as_str())
            || task.objective.trim().is_empty()
            || task.objective.len() > 300
            || task.depends_on.len() > 4
            || positions.insert(task.role.as_str(), index).is_some()
        {
            return Err("Invalid, duplicate, or unapproved specialist task".into());
        }
    }
    if !positions.contains_key("scout") || !positions.contains_key("source") {
        return Err("Project Recon and Source Auditor are mandatory".into());
    }
    for task in &plan.tasks {
        let mut seen = BTreeSet::new();
        for dependency in &task.depends_on {
            if dependency == &task.role || !positions.contains_key(dependency.as_str())
                || !seen.insert(dependency.as_str())
            {
                return Err("Duplicate, unknown or self-referential task dependency".into());
            }
            // CodeTwin's current native runtime preserves the audited role order.
            if positions[dependency.as_str()] >= positions[task.role.as_str()] {
                return Err("Dependencies must precede the consuming specialist".into());
            }
        }
        if task.role == "scout" && !task.depends_on.is_empty() {
            return Err("Project Recon must be the initial task".into());
        }
        if task.role == "source" && task.depends_on != ["scout"] {
            return Err("Source Auditor must depend on Project Recon".into());
        }
        if task.role != "scout" && task.role != "source"
            && !task.depends_on.iter().any(|dependency| dependency == "source")
        {
            return Err("Optional specialists must depend on verified source review".into());
        }
    }
    if plan.tasks.windows(2).any(|pair| {
        let first = ALLOWED.iter().position(|role| *role == pair[0].role);
        let second = ALLOWED.iter().position(|role| *role == pair[1].role);
        first >= second
    }) {
        return Err("Task order must preserve the audited specialist order".into());
    }
    if positions["scout"] != 0 || positions["source"] != 1 {
        return Err("Approved role order must begin with reconnaissance and source review".into());
    }

    let mut pending: BTreeSet<&str> = positions.keys().copied().collect();
    let mut done = BTreeSet::new();
    let mut batches = Vec::new();
    while !pending.is_empty() {
        let ready: Vec<String> = ALLOWED
            .iter()
            .copied()
            .filter(|role| pending.contains(role))
            .filter(|role| plan.tasks.iter().find(|task| task.role == *role)
                .is_some_and(|task| task.depends_on.iter().all(|dep| done.contains(dep.as_str()))))
            .map(str::to_string)
            .collect();
        if ready.is_empty() {
            return Err("Cyclic or unresolvable task graph".into());
        }
        for role in &ready {
            pending.remove(role.as_str());
            done.insert(role.as_str());
        }
        batches.push(ready);
    }
    Ok(TaskSchedule { batches, max_parallel: 2 })
}

pub fn parse_proposal(raw: &str) -> Result<(TaskProposal, TaskSchedule), String> {
    if raw.len() > 6000 {
        return Err("Model task plan exceeds the response size budget".into());
    }
    let plan: TaskProposal = serde_json::from_str(raw)
        .map_err(|_| "Model must return an exact JSON task plan".to_string())?;
    let schedule = validate_proposal(&plan)?;
    Ok((plan, schedule))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid() -> TaskProposal {
        TaskProposal {
            tasks: vec![
                PlannedSpecialist { role:"scout".into(), objective:"Inventory".into(), depends_on:vec![] },
                PlannedSpecialist { role:"source".into(), objective:"Review source".into(), depends_on:vec!["scout".into()] },
                PlannedSpecialist { role:"qa".into(), objective:"Find tests".into(), depends_on:vec!["source".into()] },
                PlannedSpecialist { role:"runtime".into(), objective:"Review config".into(), depends_on:vec!["source".into()] },
            ],
            rationale:"Bounded passive review".into(),
        }
    }

    #[test]
    fn independent_specialists_have_parallel_ready_batch() {
        let schedule = validate_proposal(&valid()).unwrap();
        assert_eq!(schedule.batches, vec![
            vec!["scout"],vec!["source"],vec!["qa","runtime"],
        ]);
        assert_eq!(schedule.max_parallel, 2);
    }

    #[test]
    fn model_cannot_add_commands_loosen_scope_or_bypass_source_review() {
        let mut plan=valid();
        plan.tasks[2].role="bash".into();
        assert!(validate_proposal(&plan).is_err());
        let mut plan=valid();
        plan.tasks[2].depends_on.clear();
        assert!(validate_proposal(&plan).is_err());
        let mut plan=valid();
        plan.tasks[3].depends_on=vec!["qa".into(),"source".into()];
        assert!(validate_proposal(&plan).is_ok());
        let mut plan=valid();
        plan.tasks[2].depends_on=vec!["runtime".into(),"source".into()];
        assert!(validate_proposal(&plan).is_err());
        let mut json=serde_json::to_value(valid()).unwrap();
        json["tasks"][0]["shell"]="rm -rf /";
        assert!(parse_proposal(&json.to_string()).is_err());
    }
}
