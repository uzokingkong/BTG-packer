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

/// Run the full protection pipeline over an input PE and return the protected
/// PE bytes. `obf_level` is 1..3 (default 3); `crypto_coverage` is 0..100.
pub fn run_full(
    input_pe: &[u8],
    obf_level: u32,
    crypto_coverage: u32,
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
    // v6: MBA key schedule constant (once per pack).
    ctx.mba_constant = { use rand::RngCore; rand::thread_rng().next_u32() };

    pass1_slice::run(&mut ctx)?;
    pass2_shuffle::run(&mut ctx)?;
    pass3_encode::run(&mut ctx)?;
    pass4_section::run(&mut ctx, false, true, false)?;

    let relayed = ctx.target_info.relayed_sections.clone();
    patch_data::run(&mut ctx, relayed)?;

    crypto::run(&mut ctx, true, false, false, crypto_coverage, true, false, false, false)?;

    // build::run writes to a path; emit into a temp buffer in the caller's cwd.
    let out_path = std::path::PathBuf::from("protected_btg_lib.exe");
    let bytes = build::run(&ctx, &out_path)?;
    Ok(bytes)
}
