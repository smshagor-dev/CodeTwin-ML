//! Dependency graph validation (unknown nodes, self edges, cycles).
use std::collections::{BTreeMap, BTreeSet, VecDeque};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DagError {
    #[error("duplicate task key `{0}`")]
    DuplicateNode(String),
    #[error("task `{0}` depends on unknown task `{1}`")]
    UnknownDependency(String, String),
    #[error("task `{0}` depends on itself")]
    SelfDependency(String),
    #[error("dependency cycle involving: {0}")]
    Cycle(String),
}

/// Validate a dependency graph and return a deterministic topological order.
/// `edges` are `(task, depends_on)` pairs. `external` names nodes that already
/// exist outside this batch (for example completed work carried forward).
pub fn topological_order(
    nodes: &[String],
    edges: &[(String, String)],
    external: &BTreeSet<String>,
) -> Result<Vec<String>, DagError> {
    let mut indegree: BTreeMap<&str, usize> = BTreeMap::new();
    for node in nodes {
        if indegree.insert(node.as_str(), 0).is_some() {
            return Err(DagError::DuplicateNode(node.clone()));
        }
    }
    let mut dependents: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for (task, dep) in edges {
        if task == dep {
            return Err(DagError::SelfDependency(task.clone()));
        }
        if !indegree.contains_key(task.as_str()) {
            return Err(DagError::UnknownDependency(task.clone(), dep.clone()));
        }
        if indegree.contains_key(dep.as_str()) {
            *indegree.get_mut(task.as_str()).expect("checked") += 1;
            dependents
                .entry(dep.as_str())
                .or_default()
                .push(task.as_str());
        } else if !external.contains(dep) {
            return Err(DagError::UnknownDependency(task.clone(), dep.clone()));
        }
    }
    let mut ready: VecDeque<&str> = indegree
        .iter()
        .filter(|(_, d)| **d == 0)
        .map(|(n, _)| *n)
        .collect();
    let mut order = Vec::with_capacity(nodes.len());
    while let Some(node) = ready.pop_front() {
        order.push(node.to_owned());
        if let Some(children) = dependents.get(node) {
            let mut next: Vec<&str> = Vec::new();
            for child in children {
                let degree = indegree.get_mut(child).expect("known");
                *degree -= 1;
                if *degree == 0 {
                    next.push(child);
                }
            }
            next.sort_unstable();
            ready.extend(next);
        }
    }
    if order.len() != nodes.len() {
        let cyclic: Vec<&str> = indegree
            .iter()
            .filter(|(_, d)| **d > 0)
            .map(|(n, _)| *n)
            .collect();
        return Err(DagError::Cycle(cyclic.join(", ")));
    }
    Ok(order)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| (*x).to_owned()).collect()
    }
    fn e(v: &[(&str, &str)]) -> Vec<(String, String)> {
        v.iter()
            .map(|(a, b)| ((*a).to_owned(), (*b).to_owned()))
            .collect()
    }

    #[test]
    fn orders_diamond() {
        let order = topological_order(
            &s(&["a", "b", "c", "d"]),
            &e(&[("b", "a"), ("c", "a"), ("d", "b"), ("d", "c")]),
            &BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(order, s(&["a", "b", "c", "d"]));
    }

    #[test]
    fn rejects_cycles_self_edges_and_unknowns() {
        assert!(matches!(
            topological_order(
                &s(&["a", "b", "c"]),
                &e(&[("a", "c"), ("b", "a"), ("c", "b")]),
                &BTreeSet::new()
            ),
            Err(DagError::Cycle(_))
        ));
        assert!(matches!(
            topological_order(&s(&["a"]), &e(&[("a", "a")]), &BTreeSet::new()),
            Err(DagError::SelfDependency(_))
        ));
        assert!(matches!(
            topological_order(&s(&["a"]), &e(&[("a", "zzz")]), &BTreeSet::new()),
            Err(DagError::UnknownDependency(_, _))
        ));
        assert!(matches!(
            topological_order(&s(&["a", "a"]), &[], &BTreeSet::new()),
            Err(DagError::DuplicateNode(_))
        ));
    }

    #[test]
    fn accepts_external_completed_dependencies() {
        let external: BTreeSet<String> = ["done".to_owned()].into();
        assert!(topological_order(&s(&["a"]), &e(&[("a", "done")]), &external).is_ok());
    }

    #[test]
    fn pseudo_random_graphs_never_accept_a_cycle() {
        // Small deterministic property test: every accepted order respects edges.
        let mut seed: u64 = 0x9E37_79B9_7F4A_7C15;
        for _ in 0..300 {
            let n = 2 + (seed % 7) as usize;
            let nodes: Vec<String> = (0..n).map(|i| format!("t{i}")).collect();
            let mut edges = Vec::new();
            for _ in 0..(seed % 11) {
                seed = seed
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                let a = (seed >> 33) as usize % n;
                let b = (seed >> 17) as usize % n;
                if a != b {
                    edges.push((nodes[a].clone(), nodes[b].clone()));
                }
            }
            edges.sort();
            edges.dedup();
            if let Ok(order) = topological_order(&nodes, &edges, &BTreeSet::new()) {
                let pos: BTreeMap<&String, usize> =
                    order.iter().enumerate().map(|(i, n)| (n, i)).collect();
                for (task, dep) in &edges {
                    assert!(pos[dep] < pos[task]);
                }
            }
            seed = seed.rotate_left(7) ^ 0xA5A5;
        }
    }
}
