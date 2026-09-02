// ==============================================================================
// BTG - Boot-stub placement: --vm-oep program lift - split from place.rs
// ==============================================================================
// M6 Phase-2 (--vm-oep): program lift performed once. Program VM bytecode is
// produced together with whether the original entry block is excluded (native).

use crate::pipeline::PipelineContext;
use crate::vm;
use anyhow::Result;

fn coalesce_cross_family_fallthroughs(
    plan: &mut vm::poly::ProductionFamilyPlan,
    ranges: &[vm::poly::FunctionOpRange],
    program: &vm::risc::RiscProgram,
) -> usize {
    let mut ordered: Vec<_> = ranges.iter().collect();
    ordered.sort_by_key(|range| range.start_op);
    let mut changed = 0;
    // Walk backwards so a split function's body family propagates through thin
    // entry/prologue fragments while preserving its explicit incoming call edge.
    for pair in ordered.windows(2).rev() {
        let source = pair[0];
        let target = pair[1];
        if source.end_op != target.start_op || source.end_op == 0 {
            continue;
        }
        let Some(last) = program.instrs.get(source.end_op - 1) else {
            continue;
        };
        if matches!(
            last.op,
            vm::risc::RiscOp::VirtualBranch {
                cond: vm::risc::BranchCondition::Always
            } | vm::risc::RiscOp::VirtualRet
                | vm::risc::RiscOp::VirtualIndirectJump
                | vm::risc::RiscOp::Halt
                | vm::risc::RiscOp::Trap
        ) {
            continue;
        }
        let Some(target_family) = plan
            .assignment_for(target.function_id)
            .map(|assignment| assignment.family)
        else {
            continue;
        };
        let Some(source_assignment) = plan
            .assignments
            .iter_mut()
            .find(|assignment| assignment.function_id == source.function_id)
        else {
            continue;
        };
        if source_assignment.family != target_family {
            source_assignment.family = target_family;
            source_assignment.incoming_bridge = None;
            changed += 1;
        }
    }
    changed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::poly::{FunctionOpRange, VmArchitectureFamily};
    use crate::vm::risc::{MicroInstr, RiscOp, RiscProgram};

    #[test]
    fn linear_fallthrough_uses_the_body_family() {
        let functions = [0x1000, 0x1002];
        let mut plan = vm::poly::ProductionFamilyPlan::new(7, functions[0], &functions);
        plan.assignments[0].family = VmArchitectureFamily::Stack;
        plan.assignments[1].family = VmArchitectureFamily::FusedCisc;
        let ranges = [
            FunctionOpRange {
                function_id: functions[0],
                start_op: 0,
                end_op: 1,
            },
            FunctionOpRange {
                function_id: functions[1],
                start_op: 1,
                end_op: 2,
            },
        ];
        let program = RiscProgram::new(vec![
            MicroInstr::new(RiscOp::Mov),
            MicroInstr::new(RiscOp::VirtualRet),
        ]);

        assert_eq!(coalesce_cross_family_fallthroughs(&mut plan, &ranges, &program), 1);
        assert_eq!(
            plan.assignment_for(functions[0]).unwrap().family,
            VmArchitectureFamily::FusedCisc
        );
        assert_eq!(
            plan.assignment_for(functions[1]).unwrap().family,
            VmArchitectureFamily::FusedCisc
        );
    }
}

pub(crate) fn lift_program(
    ctx: &PipelineContext,
    image_base: u64,
    vm_oep_effective: bool,
    vm_commercial: bool,
) -> Result<(
    Vec<u8>,
    bool,
    u64,
    Option<std::collections::HashMap<u64, usize>>,
    Option<vm::threaded::PreparedSuperOpProgram>,
    Option<crate::pipeline::VmCoverageMetrics>,
    Vec<crate::pipeline::ownership::FunctionOwnershipDiagnostic>,
    Vec<vm::chunk_crypto::BytecodeChunk>,
    Option<vm::poly::ProductionFamilyPlan>,
    Option<Vec<vm::poly::FamilyOpPartition>>,
    Option<vm::multi_family::MaterializedMultiFamilyProgram>,
    Vec<crate::vm::data_lifetime::LiteralObject>,
    crate::pipeline::reports::UnsupportedInstructionReport,
)> {
    // P3 (G1): 상용 프로그램 리프트의 ip_map (source-IP -> micro-op index) — the
    // VirtualBranch native handler uses it to resolve branch targets to bytecode
    // byte offsets. Populated in the lift below and passed to build_prog_vm_mod.
    let mut vm_prog_ip_map: Option<std::collections::HashMap<u64, usize>> = None;
    let mut vm_prog_superops: Option<vm::threaded::PreparedSuperOpProgram> = None;
    let mut vm_coverage = None;
    let mut ownership_report = Vec::new();
    let mut vm_prog_chunks = Vec::new();
    let mut vm_family_plan = None;
    let mut vm_family_partitions = None;
    let mut vm_multi_family = None;
    let mut data_lifetime_objects = Vec::new();
    let mut unsupported_report = crate::pipeline::reports::UnsupportedInstructionReport::new();

    let (vm_prog_bytecode, vm_oep_native_entry, oep_va): (Vec<u8>, bool, u64) = if vm_oep_effective
    {
        let base_va = image_base + ctx.target_info.text_rva as u64;
        let ep_va = image_base + ctx.target_info.entry_point_rva as u64;
        let (prog_bytecode, entry_native): (Vec<u8>, bool) = if vm_commercial {
            let lift = vm::text_lift::lift_program_cfg_commercial_with_model(
                &ctx.target_info.text_bytes,
                base_va,
                ep_va,
                &ctx.target_info.relayed_sections,
                image_base,
                &ctx.vm_data_lifetime_objects,
                ctx.poly_vm_seed,
                ctx.program_model.as_ref(),
            )?;
            data_lifetime_objects = lift.data_lifetime_objects.clone();
            unsupported_report = lift.unsupported_report.clone();
            vm_prog_ip_map = lift.program.ip_map().cloned();
            let mut plan = vm::poly::ProductionFamilyPlan::new(
                ctx.poly_vm_seed,
                lift.entry_function_id,
                &lift.virtualized_function_ids,
            );
            // Diagnostic-only control used to distinguish core commercial
            // execution from cross-family ABI/state handoff failures.
            if std::env::var_os("BTG_FORCE_SINGLE_FAMILY").is_some() {
                for assignment in &mut plan.assignments {
                    assignment.family = plan.entry_family;
                    assignment.incoming_bridge = None;
                }
            }
            let coalesced_fallthroughs = coalesce_cross_family_fallthroughs(
                &mut plan,
                &lift.function_op_ranges,
                &lift.program,
            );
            if coalesced_fallthroughs != 0 {
                println!(
                    "[+] P2-10 coalesced {} linear cross-family fallthrough region(s)",
                    coalesced_fallthroughs
                );
            }
            println!(
                "[+] P2-10 production family plan: {} VM-owned function(s), {} represented family/families, {} cross-family bridge requirement(s), entry={:?}",
                plan.assignments.len(),
                plan.represented_families().len(),
                plan.cross_family_bridge_count(),
                plan.entry_family,
            );
            let entry_family = plan.entry_family;
            let partitions = plan
                .partition_regions(&lift.function_op_ranges, lift.program.instrs.len())
                .map_err(anyhow::Error::msg)?;
            let partitioned_functions: usize = partitions
                .iter()
                .map(|partition| partition.regions.len())
                .sum();
            let family_op_counts: Vec<_> = partitions
                .iter()
                .map(|partition| {
                    (
                        partition.family,
                        partition
                            .regions
                            .iter()
                            .map(|range| range.end_op - range.start_op)
                            .sum::<usize>(),
                    )
                })
                .collect();
            let partitioned_ops = family_op_counts
                .iter()
                .map(|(_, count)| *count)
                .sum::<usize>();
            let max_family_ops = family_op_counts
                .iter()
                .map(|(_, count)| *count)
                .max()
                .unwrap_or(0);
            if partitioned_ops >= 1_000
                && (partitions.len() < 3 || max_family_ops.saturating_mul(2) >= partitioned_ops)
                && std::env::var_os("BTG_FORCE_SINGLE_FAMILY").is_none()
            {
                return Err(anyhow::anyhow!(
                    "P2-12 runtime-instance ownership gate failed: instances={} max_ops={}/{}",
                    partitions.len(),
                    max_family_ops,
                    partitioned_ops
                ));
            }
            println!(
                "[+] P2-10 family op partition: {} backend partition(s), {} function region(s), {} total RISC op(s)",
                partitions.len(),
                partitioned_functions,
                lift.function_op_ranges
                    .iter()
                    .map(|range| range.end_op - range.start_op)
                    .sum::<usize>(),
            );
            println!(
                "[+] P2-12 runtime anchor gate: {} independent instance(s), max instruction ownership {}/{} ({:.2}%), family integrity topologies={}",
                partitions.len(),
                max_family_ops,
                partitioned_ops,
                if partitioned_ops == 0 { 0.0 } else { max_family_ops as f64 * 100.0 / partitioned_ops as f64 },
                partitions.len(),
            );
            let multi_family =
                vm::multi_family::MultiFamilyProgramPlan::build(&lift.program, &plan, &partitions)
                    .map_err(anyhow::Error::msg)?;
            let materialized = multi_family
                .materialize(ctx.poly_vm_seed)
                .map_err(anyhow::Error::msg)?;
            println!(
                "[+] P2-10 multi-family materialization: {} independent bytecode module(s), {} canonical cross-family route(s)",
                materialized.modules.len(),
                materialized.route_table.len(),
            );
            vm_multi_family = Some(materialized);
            vm_family_partitions = Some(partitions);
            vm_family_plan = Some(plan);
            vm_coverage = Some(crate::pipeline::VmCoverageMetrics {
                vm_blocks: lift.virtualized_blocks,
                total_blocks: lift.blocks,
                vm_instructions: lift.virtualized_instructions,
                total_instructions: lift.total_instructions,
                vm_functions: lift.virtualized_functions,
                total_functions: lift.total_functions,
                unresolved_internal_edges: ctx.program_model.as_ref().map(|model| {
                    model
                        .indirect_targets
                        .edge_metrics()
                        .unresolved_internal_edges
                }),
                unsupported_instructions: Some(lift.unsupported_report.occurrence_count()),
                // Multi-family materialization above crosses the production
                // encoder capability gate, so reaching this point is measured
                // zero rather than an unmeasured default.
                capability_mismatches: Some(0),
                hot_path_profiled: lift.hot_path_profiled,
                hot_vm_weight: lift.hot_vm_weight,
                hot_total_weight: lift.hot_total_weight,
                sensitive_regions: lift.sensitive_regions,
            });
            ownership_report = lift.ownership_report.clone();
            if let Some(model) = ctx.program_model.as_ref() {
                crate::pipeline::ownership::apply_canonical_indirect_ownership(
                    model,
                    &mut ownership_report,
                );
            }
            let prepared =
                vm::threaded::SuperOperatorSynthesizer::prepare_commercial_program_for_family(
                    &lift.program,
                    ctx.poly_vm_seed,
                    entry_family,
                )?;
            if let Some(ref p) = prepared {
                let fused_occurrences: usize = p
                    .assigned
                    .iter()
                    .map(|superop| superop.plan.occurrences.len())
                    .sum();
                let dispatch_savings: usize = p
                    .assigned
                    .iter()
                    .map(|superop| superop.plan.candidate.estimated_dispatch_savings)
                    .sum();
                println!(
                    "[+] --vm-commercial P5: selected {} build-local super-op(s), fused {} occurrence(s), removed {} dispatch(es) ({} -> {} stream instructions)",
                    p.assigned.len(),
                    fused_occurrences,
                    dispatch_savings,
                    lift.program.instrs.len(),
                    p.rewritten_offsets.len(),
                );
            } else {
                println!(
                    "[+] --vm-commercial P5: no profitable super-op sequence; using primitive polymorphic stream"
                );
            }
            let (bc, offsets) = if let Some(ref p) = prepared {
                (p.bytecode.clone(), p.metadata.original_byte_offsets.clone())
            } else {
                let mut enc = crate::vm::poly::PolymorphicEncoder::new_for_family(
                    ctx.poly_vm_seed,
                    entry_family,
                );
                enc.encode_with_offsets(&lift.program)?
            };
            if vm_commercial {
                vm_prog_chunks = vm::chunk_crypto::plan_chunks(
                    bc.len(),
                    &offsets,
                    ctx.poly_vm_seed,
                    vm::chunk_crypto::DEFAULT_CHUNK_BYTES,
                );
                println!(
                    "[+] commercial VM: planned {} instruction-aligned bytecode key epoch(s), max {}B",
                    vm_prog_chunks.len(),
                    vm::chunk_crypto::DEFAULT_CHUNK_BYTES
                );
            }
            vm_prog_superops = prepared;
            // P3/P5 mapping: offsets always correspond to original micro-op
            // indices, even when multiple fused body members share one offset.
            if crate::vm::mapper::active() {
                crate::vm::mapper::fill_risc_poly_offsets(&offsets);
            }
            (bc, lift.entry_native)
        } else {
            let lift = vm::text_lift::lift_program_cfg(
                &ctx.target_info.text_bytes,
                base_va,
                ep_va,
                &ctx.target_info.relayed_sections,
                image_base,
                &ctx.target_info.original_pe_bytes,
            )?;
            (lift.bytecode, lift.entry_native)
        };
        if prog_bytecode.is_empty() {
            // T0-1 FIX: 초소형 타깃(1.5KB 등)에서 lift 결과가 빈 bytecode인 경우,
            // Err를 반환하면 호출자가 vm_prog_mod=None, vm_oep_effective=true인 상태로
            // 부트 스텁 빌드를 진행해 존재하지 않는 VM 모듈 포인터(vm_prog_entry_va=0)를
            // 심어 런타임 크래시를 유발한다.
            // 대신 native OEP 폴백(entry_native=true)으로 처리: 부트 스텁이 복호화 완료 후
            // OEP로 직접 점프 (Program VM 실행 없음). 동작은 --vm 단독 모드와 동일.
            println!(
                "[!] T0-1: --vm-oep{} lifted empty program (target too small or all blocks excluded) — \
                 forcing native OEP fallback (entry_native=true). Boot stub will jump directly to OEP.",
                if vm_commercial { " --vm-commercial" } else { "" }
            );
            (Vec::new(), true, ep_va)
        } else {
            (prog_bytecode, entry_native, ep_va)
        }
    } else {
        (Vec::new(), false, 0)
    };

    Ok((
        vm_prog_bytecode,
        vm_oep_native_entry,
        oep_va,
        vm_prog_ip_map,
        vm_prog_superops,
        vm_coverage,
        ownership_report,
        vm_prog_chunks,
        vm_family_plan,
        vm_family_partitions,
        vm_multi_family,
        data_lifetime_objects,
        unsupported_report,
    ))
}
