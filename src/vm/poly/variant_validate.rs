//! Build-time validation; no hashing or allocation in guest dispatch.
use super::VirtualIsaSpec;
use crate::vm::threaded::VmRuntimeLayout;
use anyhow::{ensure, Result};

pub fn validate_contract(spec: &VirtualIsaSpec, layout: &VmRuntimeLayout) -> Result<()> {
    layout.validate()?;
    ensure!(
        spec.family_profile == spec.family.profile(),
        "variant family profile mismatch"
    );
    ensure!(
        spec.opcode_map.len() == spec.reverse_opcode_map.len(),
        "variant opcode map size mismatch"
    );
    for (op, token) in &spec.opcode_map {
        ensure!(
            spec.reverse_opcode_map.get(token) == Some(op),
            "variant opcode maps are not bijective"
        );
    }
    ensure!(
        spec.branch_cond_map.len() == spec.reverse_branch_cond_map.len(),
        "variant condition map size mismatch"
    );
    for (condition, token) in &spec.branch_cond_map {
        ensure!(
            spec.reverse_branch_cond_map.get(token) == Some(condition),
            "variant condition maps are not bijective"
        );
    }
    let mut seen = [false; 16];
    for (logical, &physical) in spec.register_permutation.iter().enumerate() {
        ensure!((physical as usize) < 16, "variant register out of bounds");
        ensure!(!seen[physical as usize], "variant duplicate register slot");
        seen[physical as usize] = true;
        ensure!(
            spec.reverse_reg_permutation[physical as usize] as usize == logical,
            "variant register inverse mismatch"
        );
    }
    // Match the supported semantic set, not randomly selected tokens. Existing
    // ISA uses the entire byte space and currently reserves no opcode token.
    let supported = VirtualIsaSpec::from_seed_and_family(0, spec.family);
    ensure!(
        spec.opcode_map.len() == supported.opcode_map.len()
            && supported
                .opcode_map
                .keys()
                .all(|op| spec.opcode_map.contains_key(op)),
        "variant has unsupported or missing opcode semantics"
    );
    ensure!(
        spec.branch_cond_map.len() == supported.branch_cond_map.len()
            && supported
                .branch_cond_map
                .keys()
                .all(|cond| spec.branch_cond_map.contains_key(cond)),
        "variant has unsupported or missing branch semantics"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_corrupt_contracts() {
        let spec = VirtualIsaSpec::from_seed(42);
        let layout = VmRuntimeLayout::from_seed(42);
        let mut bad = spec.clone();
        bad.register_permutation[0] = 16;
        assert!(validate_contract(&bad, &layout).is_err());
        let mut bad = spec.clone();
        bad.reverse_opcode_map.clear();
        assert!(validate_contract(&bad, &layout).is_err());
        let mut bad = spec.clone();
        let (op, token) = bad
            .opcode_map
            .iter()
            .next()
            .map(|(op, token)| (*op, *token))
            .unwrap();
        bad.opcode_map.remove(&op);
        bad.reverse_opcode_map.remove(&token);
        assert!(validate_contract(&bad, &layout).is_err());
        let mut bad_layout = layout.clone();
        bad_layout.vregs[0] = -8;
        assert!(validate_contract(&spec, &bad_layout).is_err());
    }
}
