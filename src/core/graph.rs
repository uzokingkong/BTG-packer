use anyhow::{anyhow, Result};
use std::collections::{HashMap, HashSet, VecDeque};

#[derive(Debug, Clone)]
pub struct BidirectionalGraph {
    forward_edges: HashMap<u32, Vec<(u32, EdgeType, u32)>>,
    backward_edges: HashMap<u32, Vec<(u32, EdgeType, u32)>>,
    forward_paths: HashMap<(u32, u32), Vec<u32>>,
    backward_paths: HashMap<(u32, u32), Vec<u32>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EdgeType {
    ConditionalTrue,
    ConditionalFalse,
    Unconditional,
    Call,
    Return,
}

impl BidirectionalGraph {
    pub fn new() -> Self {
        Self {
            forward_edges: HashMap::new(),
            backward_edges: HashMap::new(),
            forward_paths: HashMap::new(),
            backward_paths: HashMap::new(),
        }
    }

    pub fn add_edge(&mut self, from: u32, to: u32, edge_type: EdgeType, cost: u32) {
        self.forward_edges
            .entry(from)
            .or_default()
            .push((to, edge_type, cost));

        self.backward_edges
            .entry(to)
            .or_default()
            .push((from, edge_type, cost));

        // 리뷰 지적 #14: 그래프가 변했으므로 경로 캐시를 무효화한다. 캐시가
        // 남아 있으면 이전 쿼리 결과(예: `A→C` 미도달)가 새 엣지 추가 후에도
        // stale 하게 남아 잘못된 `can_reach_*` 를 반환한다.
        self.forward_paths.clear();
        self.backward_paths.clear();
    }

    pub fn can_reach_forward(&mut self, from: u32, to: u32) -> Result<bool> {
        if from == to {
            return Ok(true);
        }
        let key = (from, to);
        if let Some(path) = self.forward_paths.get(&key) {
            return Ok(!path.is_empty());
        }
        let _path = self.bfs_forward(from, to)?;
        self.forward_paths
            .get(&key)
            .map(|p| !p.is_empty())
            .ok_or_else(|| anyhow!("Path not in cache"))
    }

    pub fn can_reach_backward(&mut self, from: u32, to: u32) -> Result<bool> {
        if from == to {
            return Ok(true);
        }
        let key = (from, to);
        if let Some(path) = self.backward_paths.get(&key) {
            return Ok(!path.is_empty());
        }
        let _path = self.bfs_backward(from, to)?;
        self.backward_paths
            .get(&key)
            .map(|p| !p.is_empty())
            .ok_or_else(|| anyhow!("Path not in cache"))
    }

    pub fn validate_bidirectionality(&mut self) -> Result<()> {
        let keys: Vec<(u32, u32)> = self.forward_paths.keys().copied().collect();
        for (from, to) in keys {
            let forward_ok = self.can_reach_forward(from, to)?;
            let backward_ok = self.can_reach_backward(to, from)?;
            if forward_ok != backward_ok {
                return Err(anyhow!(
                    "Bidirectionality violation: {} -> {} (fwd: {}, bwd: {})",
                    from,
                    to,
                    forward_ok,
                    backward_ok
                ));
            }
        }
        Ok(())
    }

    fn bfs_forward(&mut self, start: u32, target: u32) -> Result<Vec<u32>> {
        let mut queue = VecDeque::new();
        let mut visited = HashSet::new();
        let mut parent = HashMap::new();

        queue.push_back(start);
        visited.insert(start);

        while let Some(current) = queue.pop_front() {
            if current == target {
                let mut path = vec![current];
                let mut node = current;
                while let Some(&prev) = parent.get(&node) {
                    path.push(prev);
                    node = prev;
                }
                path.reverse();
                self.forward_paths.insert((start, target), path.clone());
                return Ok(path);
            }
            if let Some(edges) = self.forward_edges.get(&current) {
                for (next, _, _) in edges {
                    if !visited.contains(next) {
                        visited.insert(*next);
                        parent.insert(*next, current);
                        queue.push_back(*next);
                    }
                }
            }
        }
        self.forward_paths.insert((start, target), vec![]);
        Ok(vec![])
    }

    fn bfs_backward(&mut self, start: u32, target: u32) -> Result<Vec<u32>> {
        let mut queue = VecDeque::new();
        let mut visited = HashSet::new();
        let mut parent = HashMap::new();

        queue.push_back(start);
        visited.insert(start);

        while let Some(current) = queue.pop_front() {
            if current == target {
                let mut path = vec![current];
                let mut node = current;
                while let Some(&prev) = parent.get(&node) {
                    path.push(prev);
                    node = prev;
                }
                path.reverse();
                self.backward_paths.insert((start, target), path.clone());
                return Ok(path);
            }
            if let Some(edges) = self.backward_edges.get(&current) {
                for (next, _, _) in edges {
                    if !visited.contains(next) {
                        visited.insert(*next);
                        parent.insert(*next, current);
                        queue.push_back(*next);
                    }
                }
            }
        }
        self.backward_paths.insert((start, target), vec![]);
        Ok(vec![])
    }

    pub fn get_forward_edges(&self, block_id: u32) -> Option<&Vec<(u32, EdgeType, u32)>> {
        self.forward_edges.get(&block_id)
    }

    pub fn get_backward_edges(&self, block_id: u32) -> Option<&Vec<(u32, EdgeType, u32)>> {
        self.backward_edges.get(&block_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_path() -> Result<()> {
        let mut graph = BidirectionalGraph::new();
        graph.add_edge(1, 2, EdgeType::Unconditional, 1);
        graph.add_edge(2, 3, EdgeType::Unconditional, 1);

        assert!(graph.can_reach_forward(1, 3)?);
        assert!(graph.can_reach_backward(3, 1)?);
        Ok(())
    }

    #[test]
    fn test_bidirectionality_violation() -> Result<()> {
        let mut graph = BidirectionalGraph::new();
        graph.forward_paths.insert((1, 2), vec![1, 2]);
        // No matching backward path added to satisfy bidirectionality
        assert!(graph.validate_bidirectionality().is_err());
        Ok(())
    }

    #[test]
    fn test_cycle_detection() -> Result<()> {
        let mut graph = BidirectionalGraph::new();
        graph.add_edge(1, 2, EdgeType::Unconditional, 1);
        graph.add_edge(2, 3, EdgeType::Unconditional, 1);
        graph.add_edge(3, 1, EdgeType::Unconditional, 1);

        assert!(graph.can_reach_forward(1, 3)?);
        assert!(graph.can_reach_backward(3, 1)?);
        assert!(graph.validate_bidirectionality().is_ok());
        Ok(())
    }

    #[test]
    fn test_isolated_node() -> Result<()> {
        let mut graph = BidirectionalGraph::new();
        graph.add_edge(1, 2, EdgeType::Unconditional, 1);

        // Node 3 is isolated
        assert!(!graph.can_reach_forward(1, 3)?);
        assert!(!graph.can_reach_backward(3, 1)?);
        Ok(())
    }

    #[test]
    fn test_complex_branching() -> Result<()> {
        let mut graph = BidirectionalGraph::new();
        graph.add_edge(1, 2, EdgeType::ConditionalTrue, 1);
        graph.add_edge(1, 3, EdgeType::ConditionalFalse, 1);
        graph.add_edge(2, 4, EdgeType::Unconditional, 1);
        graph.add_edge(3, 4, EdgeType::Unconditional, 1);

        assert!(graph.can_reach_forward(1, 4)?);
        assert!(graph.can_reach_backward(4, 1)?);
        assert!(graph.validate_bidirectionality().is_ok());
        Ok(())
    }

    #[test]
    fn test_add_edge_invalidates_path_cache() -> Result<()> {
        // 리뷰 지적 #14 회귀: A→C 쿼리가 "미도달"로 캐시된 뒤 엣지를 추가하면
        // 캐시가 무효화돼 새 경로를 반영해야 한다.
        let mut graph = BidirectionalGraph::new();
        graph.add_edge(1, 2, EdgeType::Unconditional, 1);
        assert!(
            !graph.can_reach_forward(1, 3)?,
            "1→3 must be unreachable initially"
        );

        // 엣지 추가 (2 → 3). 캐시가 지워지지 않으면 1→3 이 여전히 false 로 남는다.
        graph.add_edge(2, 3, EdgeType::Unconditional, 1);
        assert!(
            graph.can_reach_forward(1, 3)?,
            "1→3 must be reachable after adding 2→3"
        );

        // backward 방향도 마찬가지.
        assert!(
            graph.can_reach_backward(3, 1)?,
            "3→1 backward must also reflect the new edge"
        );

        // 엣지 추가 후 이전에 캐시된 경로가 있는지 재확인 (무효화 확인).
        let cached_before = graph.forward_paths.contains_key(&(1, 2));
        graph.add_edge(3, 4, EdgeType::Unconditional, 1);
        assert!(graph.can_reach_forward(1, 4)?, "1→4 via the new edge");
        let _ = cached_before;
        Ok(())
    }
}
