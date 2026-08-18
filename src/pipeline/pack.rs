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
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use std::path::Path;

/// Run the full protection pipeline over an input PE and return the protected
/// PE bytes. `obf_level` is 1..3 (default 3); `crypto_coverage` is 0..100.
/// `output_path`가 `Some`이면 결과를 그 경로에 기록하고, `None`이면 바이트만
/// 반환한다 (리뷰 지적 #29: 라이브러리 API가 호출자 cwd에 부수 파일을 만들지
/// 않도록 — 파일 기록은 호출자가 명시적으로 요청할 때만).
///
/// P3-1 (결정적 빌드): `seed`가 `Some`이면 `ctx.rng`를 단일 시드 RNG로 고정해
/// 셔플/mba_constant/crypto 시드/폴리 시드/레이아웃 패드가 모두 그 시드에서
/// 파생되게 한다. 같은 input+seed+config → 같은 output. `None`이면 엔트로피.
pub fn run_full(
    input_pe: &[u8],
    obf_level: u32,
    crypto_coverage: u32,
    output_path: Option<&Path>,
    seed: Option<u64>,
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
    // P3-1 (결정적 빌드): --seed가 주어지면 ctx.rng를 단일 시드 RNG로 고정.
    // 셔플/mba_constant/crypto 시드/폴리 시드/레이아웃 패드가 모두 이 RNG에서
    // 파생되므로, 같은 input+seed+config → 같은 output.
    if let Some(seed) = seed {
        ctx.rng = StdRng::seed_from_u64(seed);
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::sha256_hex;

    /// P3-1 (상용 3-1): 동일 seed → 바이트 동일 output. 같은 input + seed +
    /// config로 run_full을 두 번 호출하면 산출 PE 바이트가 완전히 같아야 한다.
    /// 결정적 빌드(재현·디버깅·상용 배포)의 핵심 계약이다.
    #[test]
    fn deterministic_seed_same_bytes() {
        let input = crate::pe::generate_dummy_target_pe().expect("generate dummy PE");
        let a = run_full(&input, 3, 100, None, Some(0x1234)).expect("pack a");
        let b = run_full(&input, 3, 100, None, Some(0x1234)).expect("pack b");
        assert_eq!(a, b, "same seed must produce byte-identical output");
        // sanity: the output is a real, non-empty PE and differs from input
        assert!(!a.is_empty());
        assert_ne!(a, input, "output should differ from the plain input");
        // also assert the input hash used by the manifest is stable
        assert_eq!(sha256_hex(&input), sha256_hex(&input));
    }

    /// P3-1: 서로 다른 seed → (보통) 서로 다른 output. 결정적이면서도 seed에
    /// 따라 산출이 달라져 배포 다양성을 준다.
    #[test]
    fn deterministic_seed_different_bytes_for_different_seed() {
        let input = crate::pe::generate_dummy_target_pe().expect("generate dummy PE");
        let a = run_full(&input, 3, 100, None, Some(0x1234)).expect("pack seed A");
        let c = run_full(&input, 3, 100, None, Some(0x5678)).expect("pack seed B");
        assert_ne!(a, c, "different seeds should (usually) differ in output");
    }
}
