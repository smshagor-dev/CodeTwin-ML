//! Bounded, deterministic graph reasoning over persisted verified specialist edges.
//! Inferences describe workflow provenance, not proof that the software is secure.
use crate::{native_agent_knowledge::AgentKnowledge, Database};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphInference {
    pub run_id: String,
    pub selected_position: usize,
    pub ancestors: Vec<usize>,
    pub downstream_dependents: Vec<usize>,
    pub shortest_paths: Vec<Vec<usize>>,
    pub reachable_nodes: usize,
    pub orphaned_nodes: Vec<usize>,
    pub cycles_detected: bool,
}

pub struct GraphReasoner<'a> {
    db: &'a Database,
}
impl<'a> GraphReasoner<'a> {
    pub const fn new(db: &'a Database) -> Self {
        Self { db }
    }
    pub fn analyze(
        &self,
        project_id: &str,
        run_id: &str,
        position: usize,
    ) -> Result<GraphInference, String> {
        let graph = AgentKnowledge::new(self.db).graph(project_id, run_id)?;
        if graph.nodes.len() > 500 || graph.edges.len() > 1000 {
            return Err("Graph exceeds bounded reasoning limits".into());
        }
        let nodes = graph
            .nodes
            .iter()
            .map(|node| node.position)
            .collect::<BTreeSet<_>>();
        if !nodes.contains(&position) {
            return Err("Selected role is not indexed in this project".into());
        }
        let mut forward: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
        let mut reverse: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
        for edge in graph.edges {
            if !nodes.contains(&edge.from_position)
                || !nodes.contains(&edge.to_position)
                || edge.relation != "verified_handoff"
            {
                return Err("Knowledge graph contains an unverified reference".into());
            }
            forward
                .entry(edge.from_position)
                .or_default()
                .push(edge.to_position);
            reverse
                .entry(edge.to_position)
                .or_default()
                .push(edge.from_position);
        }
        let (descendant_paths, _) = walk(position, &forward);
        let (ancestor_paths, _) = walk(position, &reverse);
        let cycles_detected = graph_has_cycle(&nodes, &forward);
        let downstream_dependents = descendant_paths
            .keys()
            .copied()
            .filter(|id| *id != position)
            .collect::<Vec<_>>();
        let ancestors = ancestor_paths
            .keys()
            .copied()
            .filter(|id| *id != position)
            .collect::<Vec<_>>();
        let roots = nodes
            .iter()
            .copied()
            .filter(|id| !reverse.contains_key(id))
            .collect::<Vec<_>>();
        let mut reachable = BTreeSet::new();
        for root in &roots {
            let (paths, _) = walk(*root, &forward);
            reachable.extend(paths.keys().copied());
        }
        let orphans = nodes.difference(&reachable).copied().collect::<Vec<_>>();
        let shortest_paths = descendant_paths
            .into_values()
            .filter(|path| path.len() > 1)
            .take(50)
            .collect();
        Ok(GraphInference {
            run_id: run_id.into(),
            selected_position: position,
            ancestors,
            downstream_dependents,
            shortest_paths,
            reachable_nodes: reachable.len(),
            orphaned_nodes: orphans,
            cycles_detected,
        })
    }
}

/// Directed cycle detection over every node, including components not reachable
/// from the selected specialist. A topological ordering must consume all nodes.
fn graph_has_cycle(
    nodes: &BTreeSet<usize>,
    forward: &BTreeMap<usize, Vec<usize>>,
) -> bool {
    let mut indegree = nodes.iter().map(|id| (*id, 0usize)).collect::<BTreeMap<_, _>>();
    for neighbors in forward.values() {
        for next in neighbors {
            if let Some(count) = indegree.get_mut(next) {
                *count += 1;
            }
        }
    }
    let mut queue: VecDeque<usize> = indegree.iter()
        .filter_map(|(id,count)| (*count==0).then_some(*id))
        .collect();
    let mut removed = 0;
    while let Some(node) = queue.pop_front() {
        removed += 1;
        for next in forward.get(&node).into_iter().flatten() {
            if let Some(count) = indegree.get_mut(next) {
                *count -= 1;
                if *count == 0 { queue.push_back(*next); }
            }
        }
    }
    removed != nodes.len()
}

/// Breadth-first path tracing with cycle detection and 500-node cap.
fn walk(start: usize, edges: &BTreeMap<usize, Vec<usize>>) -> (BTreeMap<usize, Vec<usize>>, bool) {
    let mut paths = BTreeMap::new();
    let mut queue = VecDeque::from([start]);
    paths.insert(start, vec![start]);
    let mut cycle = false;
    while let Some(current) = queue.pop_front() {
        if paths.len() > 500 {
            break;
        }
        let path = paths[&current].clone();
        for next in edges.get(&current).into_iter().flatten() {
            if path.contains(next) {
                cycle = true;
                continue;
            }
            if !paths.contains_key(next) {
                let mut expanded = path.clone();
                expanded.push(*next);
                paths.insert(*next, expanded);
                queue.push_back(*next);
            }
        }
    }
    (paths, cycle)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn graph_paths_and_cycles_are_bounded() {
        let edges = BTreeMap::from([(0, vec![1, 2]), (1, vec![2]), (2, vec![3])]);
        let (paths, cycle) = walk(0, &edges);
        assert!(!cycle);
        assert_eq!(paths[&3], vec![0, 2, 3]);
        let cyclic = BTreeMap::from([(0, vec![1]), (1, vec![0])]);
        assert!(walk(0, &cyclic).1);
        assert!(graph_has_cycle(&BTreeSet::from([0, 1]), &cyclic));
        assert!(!graph_has_cycle(&BTreeSet::from([0, 1, 2, 3]), &edges));
    }
}
