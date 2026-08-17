// ==============================================================================
// Programmatic pack entrypoint (review P2-9).
//
// Turns the CLI-driven pipeline (`main.rs`) into a callable library API so
// external Rust code can pack a PE without going through clap/argv. This is the
// lib-side twin of the `--full` CLI path (obf_level 3 + the default crypto
// stack, no anti-debug/dispatcher-reencrypt so the caller gets a working,
// relocatable protected PE without extra OS hooks).
// ==============================================================================

use crate::pe::TargetPeInfo;
use crate::pipeline::PipelineContext;
use crate::pipeline::{pass1_slice, pass2_shuffle, pass3_encode, pass4_section, patch_data, build, crypto};
use anyhow::Result;
use rand::RngCore;
use std::path::Path;

/// Run the full protection pipeline over an input PE and return the protected
/// PE bytes. `obf_level` is 1..3 (default 3); `crypto_coverage` is 0..100.
/// `output_path`가 `Some`이면 결과를 그 경로에 기록하고, `None`이면 바이트만
/// 반환한다 (리뷰 지적 #29: 라이브러리 API가 호출자 cwd에 부수 파일을 만들지
/// 않도록 — 파일 기록은 호출자가 명시적으로 요청할 때만).
pub fn run_full(
    input_pe: &[u8],
    obf_level: u32,
    crypto_coverage: u32,
    output_path: Option<&Path>,
) -> Result<Vec<u8>> {
    let info = TargetPeInfo::parse(input_pe)?;

    // Dispatcher RVA computed the same way as main.rs (after the last section).
    let section_alignment = if info.section_alignment == 0 { 0x1000 } else { info.section_alignment };
    let dispatcher_rva: u32 = info
        .relayed_sections
        .iter()
        .map(|s| {
            s.virtual_address
                + ((s.virtual_size.max(s.bytes.len() as u32) + section_alignment - 1) / section_alignment)
                    * section_alignment
        })
        .max()
        .unwrap_or(0x2000);
    let dispatcher_va = info.image_base + dispatcher_rva as u64;

    let obf = obf_level.clamp(1, 3) as usize;
    let mut ctx = PipelineContext::new(info, dispatcher_va, dispatcher_rva, obf);
    // v6: MBA key schedule constant (once per pack) — P3-1: from the ctx RNG.
    ctx.mba_constant = ctx.rng.next_u32();

    pass1_slice::run(&mut ctx)?;
    pass2_shuffle::run(&mut ctx)?;
    pass3_encode::run(&mut ctx)?;
    pass4_section::run(&mut ctx, false, true, false)?;

    let relayed = ctx.target_info.relayed_sections.clone();
    patch_data::run(&mut ctx, relayed)?;

    crypto::run(&mut ctx, true, false, false, crypto_coverage, true, false, false, false)?;

    // build::run writes to the given path; pass the caller's optional path.
    // None → build in-memory only (no side-effect file in the caller's cwd).
    let bytes = build::run(&ctx, output_path)?;
    Ok(bytes)
}
