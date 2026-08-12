use std::collections::{HashMap, HashSet, VecDeque};
use anyhow::{Result, anyhow};

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
    }

    pub fn can_reach_forward(&mut self, from: u32, to: u32) -> Result<bool> {
        if from == to { return Ok(true); }
        let key = (from, to);
        if let Some(path) = self.forward_paths.get(&key) {
            return Ok(!path.is_empty());
        }
        let _path = self.bfs_forward(from, to)?;
        self.forward_paths.get(&key).map(|p| !p.is_empty())
            .ok_or_else(|| anyhow!("Path not in cache"))
    }

    pub fn can_reach_backward(&mut self, from: u32, to: u32) -> Result<bool> {
        if from == to { return Ok(true); }
        let key = (from, to);
        if let Some(path) = self.backward_paths.get(&key) {
            return Ok(!path.is_empty());
        }
        let _path = self.bfs_backward(from, to)?;
        self.backward_paths.get(&key).map(|p| !p.is_empty())
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
                    from, to, forward_ok, backward_ok
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
}
