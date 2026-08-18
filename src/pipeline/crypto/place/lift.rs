// ==============================================================================
// BTG - Boot-stub placement: --vm-oep program lift - split from place.rs
// ==============================================================================
// M6 Phase-2 (--vm-oep): program lift performed once. Program VM bytecode is
// produced together with whether the original entry block is excluded (native).

use crate::pipeline::PipelineContext;
use crate::vm;
use anyhow::Result;

pub(crate) fn lift_program(
    ctx: &PipelineContext,
    image_base: u64,
    vm_oep_effective: bool,
    vm_commercial: bool,
) -> Result<(Vec<u8>, bool, u64, Option<std::collections::HashMap<u64, usize>>)> {
    // P3 (G1): 상용 프로그램 리프트의 ip_map (source-IP -> micro-op index) — the
    // VirtualBranch native handler uses it to resolve branch targets to bytecode
    // byte offsets. Populated in the lift below and passed to build_prog_vm_mod.
    let mut vm_prog_ip_map: Option<std::collections::HashMap<u64, usize>> = None;

    let (vm_prog_bytecode, vm_oep_native_entry, oep_va): (Vec<u8>, bool, u64) = if vm_oep_effective {
        let base_va = image_base + ctx.target_info.text_rva as u64;
        let ep_va = image_base + ctx.target_info.entry_point_rva as u64;
        let (prog_bytecode, entry_native): (Vec<u8>, bool) = if vm_commercial {
            let lift = vm::text_lift::lift_program_cfg_commercial(
                &ctx.target_info.text_bytes,
                base_va,
                ep_va,
                &ctx.target_info.relayed_sections,
                image_base,
            )?;
            vm_prog_ip_map = lift.program.ip_map().cloned();
            let mut enc = crate::vm::poly::PolymorphicEncoder::new(ctx.poly_vm_seed);
            // P3 (G1): 상용 리프트 매핑 — commercial.rs가 lift 시점에 기록한 RISC
            // 엔트리에 per-micro-op 폴리 바이트코드 오프셋을 채운다 (--map/--sym-map).
            let (bc, offsets) = enc.encode_with_offsets(&lift.program)?;
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

    Ok((vm_prog_bytecode, vm_oep_native_entry, oep_va, vm_prog_ip_map))
}