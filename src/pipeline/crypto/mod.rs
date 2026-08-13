// ==============================================================================
// BTG (Bidirectional Trigger Graph) - v3 Composite VM Crypto Layer
// ==============================================================================
//
// 목표: "실제 암호화/보호" — 기존 v2까지는 .textb 블록 코드와 .rdata 문자열이
// 모두 평문으로 남아 있어, 덤프/정적 분석으로 바로 읽을 수 있었다. v3는
// 아래 두 영역을 **실제 키 기반 스트림 암호(RC4-256)** 로 암호화한다:
//
//   1) .textb 블록 코드 영역 [first_block_offset .. max_phys_end)
//   2) read-only 섹션(.rdata/.rodata)의 문자열 리터럴 런
//
// 런타임에는 새 **부트 스텁(boot stub)** 이 PE 진입점에서 실행되어:
//   - 안티디버그 검사 (PEB 기반, 정상 경로만 통과)
//   - RC4 키 스케줄 복원 (시드 + 이미지베이스 유도 상수)
//   - 코드 영역 + 문자열 런 in-place 복호화
//   - 기존 OEP/디스패처로 제어권 이관
// 를 수행한다. 부트 스텁은 섹션 tail의 BOOT_AREA_RESERVE 영역에 배치된다.
//
// 키 파생: key[i] = seed_masked[i] ^ key_mix(i, k1, k2, k3)   (v10 비선형 믹스)
//   seed_masked[i] = seed[i] ^ 0xA7   (seed는 매 패킹마다 랜덤)
//   k1 = (image_base u32) ^ SALT1, k2 = (image_base>>32) + SALT2, k3 = SALT3
//   key_mix는 vm/ksa.rs의 단일 소스 — 패커/부트 스텁/VM이 항상 일치.
//   → 정적 파일에서 단순 추출 불가, 실행 시점에만 복원됨
// ==============================================================================

use crate::crypto::{chain_encrypt, BlockCryptoMeta, CryptoProvider};
use crate::pipeline::pass4_section::BOOT_AREA_RESERVE;
use crate::pipeline::PipelineContext;
use anyhow::Result;
use rand::RngCore;

mod bootstub;
pub(crate) mod cipher;
mod encode;
mod iat;
mod integrity;
mod memharden;
mod payload;
mod perblock;
mod place;
mod scan;
mod vm_embed;

pub use cipher::Rc4;
pub use integrity::crc32;

/// 문자열 런 최대 개수 / 총 바이트 상한 (성능 보호)
pub(crate) const MAX_STRING_RUNS: usize = 512;

/// 부트 스탭의 안티디버그 블록 길이 (고정 73바이트)
pub(crate) const ANTI_DEBUG_BLOCK_LEN: usize = 73;
pub(crate) const MAX_STRING_TOTAL: usize = 1 << 20;
pub(crate) const IMPORT_MBA_C: u32 = 0x9E37_79B9;

#[cfg(test)]
mod tests;

pub fn run(
    ctx: &mut PipelineContext,
    enabled: bool,
    anti_debug: bool,
    vm: bool,
    coverage: u32,
    payload_relocate: bool,
    integrity: bool,
    chained: bool,
    reencrypt: bool,
) -> Result<()> {
    // v9: crypto가 꺼져 있어도 IAT 은닉/메모리 하드닝/페이로드 재배치가 요청되면
    // 경량 부트 스텁(RC4 없이 안티디버그→복사→IAT 해석→메모리 하드닝→디스패치)을
    // 설치해야 한다. 그 외에는 아무것도 할 게 없다.
    if !enabled && !ctx.iat_hide && !ctx.mem_harden && !payload_relocate {
        return Ok(());
    }
    // v9: --integrity 조합 구현 — chained(평문 CRC) / reencrypt(암호문·파일 CRC)
    if chained && integrity {
        println!("[+] v5 Integrity + v7 Chained-Crypto: CRC over decrypted code (chain loop runs first)");
    }
    if reencrypt && integrity {
        println!("[+] v5 Integrity + v8 Re-Encrypt: CRC over ciphertext as stored in file (boot-time tamper check)");
    }
    if chained && vm {
        println!("[!] --chained-crypto takes precedence over --vm (VM KSA bypassed; chain uses its own KSA)");
    }
    if reencrypt && chained {
        println!("[!] --dispatcher-reencrypt takes precedence over --chained-crypto (boot-stub bulk decryption bypassed; blocks stay individually encrypted)");
    }
    let no_crypto = !enabled;
    let chained_effective = enabled && chained && !reencrypt;
    let vm_effective = enabled && vm && !chained_effective && !reencrypt;
    let vm_oep_effective = vm_effective && ctx.vm_oep;
    let m8_mod = ctx.m8 && vm_effective;
    let integrity_effective = integrity && enabled;

    // ── M7: on-demand 재암호화(anti-dump) — 원본 .text/.data/.rdata 런을 파일에는
    // 암호문으로 유지하고(이미 boot-decrypt run 등록됨), 실행 중 on-demand로만
    // 복호화→사용→재암호화한다. 여기선 런이 파일에 암호문 상태로 남음을 보장하고,
    // 부트 스텁이 복호화 후 재암호화하는 on-demand 경로를 로그로 확인한다.
    if ctx.m7 {
        println!("[+] M7 on-demand re-encrypt: boot-decrypt runs stay ciphertext at rest; on-demand decrypt→use→re-encrypt (anti-dump)");
    }

    // ── 1. 레이아웃 정보 읽기 (아직 btg를 빌리지 않은 상태 — &ctx만 사용) ────
    let layout = ctx.layout()?;
    let num_blocks = layout.shuffled_blocks.len();
    if num_blocks == 0 {
        return Ok(());
    }

    let image_base = ctx.target_info.image_base;
    let dispatcher_va = ctx.dispatcher_va;
    let dispatcher_rva = (dispatcher_va - image_base) as u32;
    let boot_off = ctx.boot_entry_offset as usize;
    let first_block_offset = ctx.first_block_offset;

    // 코드 영역 범위 계산
    let mut max_phys_end = first_block_offset;
    for block in &layout.shuffled_blocks {
        let logical_id = block.id as usize;
        let off = layout.table_offsets[logical_id] as usize;
        max_phys_end = max_phys_end.max(off + block.instructions.len());
    }
    let full_code_len = (max_phys_end - first_block_offset) as u32;
    // v4: 암호화 커버리지 — 코드 영역의 앞부분만 RC4로 암호화 (엔트로피 제어)
    // v8(Phase 0.3): 재암호화는 모든 블록이 개별 암호화되어야 하므로 100으로 강제.
    // v9: crypto-off + payload-relocate → 코드 영역 전체를 (평문 그대로) .vdata로 이동
    let coverage_effective = if reencrypt { 100 } else { coverage };
    let code_len = if vm_oep_effective {
        // C-1 (--vm-oep): 리프트된 프로그램은 원본 코드를 VM에서 실행하지만, 네이티브 CRT
        // (ucrtbase!initterm_e 등)는 데이터 섹션의 함수 포인터로 원본 코드를 직접 호출한다.
        // .btg 코드 블록을 암호화하면 네이티브가 암호문을 실행해 0xc0000005로 크래시한다
        // (기존 C-1 런타임 통합 블로커). 따라서 --vm-oep에서는 코드 블록을 평문으로 유지해
        // 네이티브 초기화자/콜백 호출이 동작하게 한다. (문자열/데이터 은닉은 별도 유지)
        0
    } else if no_crypto {
        if payload_relocate { full_code_len } else { 0 }
    } else if coverage_effective >= 100 {
        full_code_len
    } else {
        ((full_code_len as u64 * coverage_effective as u64) / 100).min(full_code_len as u64) as u32
    };
    if code_len < full_code_len {
        println!(
            "[+] v4 Crypto coverage: {:.0}% of code region encrypted ({} / {} bytes) — entropy reduced",
            (code_len as f64 / full_code_len as f64) * 100.0,
            code_len,
            full_code_len
        );
    }

    let (block_keys, total_blocks) = perblock::collect_block_keys(ctx, &layout, reencrypt);

    // ── 2. 키 상수 생성 ──────────────────────────────────────────────────────
    let mut rng = rand::thread_rng();
    let salt1: u32 = rng.next_u32();
    let salt2: u32 = rng.next_u32();
    let salt3: u32 = rng.next_u32();
    let k1 = (image_base as u32) ^ salt1;
    let k2 = ((image_base >> 32) as u32).wrapping_add(salt2);
    let k3 = salt3;

    let runs = scan::gather_runs(ctx, no_crypto, vm_oep_effective);

    println!(
        "[+] v3 Crypto: code region 0x{:X}..0x{:X} ({} bytes), {} string runs encrypted.",
        first_block_offset, max_phys_end, code_len, runs.len()
    );

    let (seed_masked, seed_stored, key) = cipher::derive_seed_and_key(&mut rng, image_base, k1, k2, k3);

    // ── 5. 이제 서로 다른 필드(btg_section_data / patched_sections)만 빌려서 ──
    //    복호화 순서와 동일하게 암호화 (코드 영역 → 런 순서) ────────────────────
    let btg = ctx.btg_section_data.as_mut()
        .ok_or_else(|| anyhow::anyhow!("btg_section_data not set — run Pass 4 first"))?;
    if boot_off == 0 || boot_off + BOOT_AREA_RESERVE > btg.bytes.len() {
        return Err(anyhow::anyhow!("Boot area not reserved by Pass 4 (boot_off=0x{:X})", boot_off));
    }
    let mut rc4;

    // 5a. 코드 영역
    // v5(--integrity) CRC 소스:
    //   - reencrypt: 파일에 저장된 **암호문**(부트 스텁이 복호화 없이 그대로 검사)
    //   - chained/plain: **평문** (부트 스텁이 복호화 후 검사)
    // v9: crypto-off에는 integrity 없음.
    let code_start = first_block_offset;
    let code_end = code_start + code_len as usize;
    let mut crc_source: Option<Vec<u8>> = if integrity_effective && !reencrypt {
        Some(btg.bytes[code_start..code_end].to_vec())
    } else {
        None
    };
    if reencrypt {
        // v8(Phase 0.3): 코드 영역을 통째로 암호화하지 않고, 블록별 MBA 키로
        // 개별 RC4 암호화한다. 디스패처가 매 디스패치마다 해당 블록만 복호화하고
        // 직전 블록을 재암호화한다. 문자열 런은 아래에서 영역 없이 시작하는
        // fresh RC4 스트림으로 암호화한다 (부트 스텁도 영역 복호화를 생략).
        // plan.txt 3단계: 블록 메타데이터(offset/length/block_id)로 키를 유도.
        for (off, len, key_u32) in &block_keys {
            let meta = BlockCryptoMeta::new(*off as u32, *off as u64, *len as u32);
            let mut rc4b = <Rc4 as CryptoProvider>::from_key(&key_u32.to_le_bytes());
            rc4b
                .encrypt_block(&meta, &mut btg.bytes[*off..*off + *len])
                .map_err(|e| anyhow::anyhow!("reencrypt block {}: {}", meta.block_id, e))?;
        }
        if integrity_effective {
            crc_source = Some(btg.bytes[code_start..code_end].to_vec());
        }
        rc4 = Rc4::new(&key);
        println!(
            "[+] v8 Dispatcher Re-Encrypt: {} blocks individually RC4-encrypted with per-block MBA keys (boot-stub bulk decryption skipped)",
            total_blocks
        );
    } else if chained_effective {
        // v7: 청크 체이닝 암호화 — Key_i = 이전 청크 평문(256B), chunk0 = seed anchor.
        // 반환된 마지막 256B 윈도우가 문자열/리졸브 테이블 런의 키가 된다.
        // (crypto 계층 chain_encrypt — boot 스텁 셸코드와 동일 알고리즘 유지)
        let mut anchor = [0u8; 256];
        anchor.copy_from_slice(&seed_masked);
        let chain_key = chain_encrypt(&mut btg.bytes[code_start..code_end], &anchor);
        rc4 = Rc4::new(&chain_key);
        println!(
            "[+] v7 Chained-Crypto: {} bytes code region chained in 256B chunks (skip-ahead blocked)",
            code_len
        );
    } else if !no_crypto {
        rc4 = Rc4::new(&key);
        rc4.crypt(&mut btg.bytes[code_start..code_end]);
    } else {
        // v9: crypto-off — 코드 영역은 그대로 둔다 (payload-relocate 시 아래에서 이동)
        rc4 = Rc4::new(&key);
    }

    // 5a-1. v4 payload-relocate: (암호화된) 코드 영역을 실행 불가 데이터 섹션으로 이동
    //       (.textb는 0x00 스테이징만 남아 엔트로피 급감, 부트 스텁이 로드 시 복사+복호화)
    // v9: crypto-off에서도 동작 — 평문 코드를 .vdata로 옮기고 부트 스텁이 복사.
    let mut payload_bytes: Vec<u8> = Vec::new();
    if payload_relocate && code_len > 0 {
        payload_bytes = btg.bytes[code_start..code_end].to_vec();
        btg.bytes[code_start..code_end].fill(0);
        println!(
            "[+] v4 Payload Relocate: {} bytes moved to .vdata (executable section zeroed)",
            code_len
        );
    }

    // 5b. 문자열 런 (부트 스텁 런 테이블과 같은 순서) — CryptoProvider.apply
    for run in &runs {
        let sec = &mut ctx.patched_sections[run.sec_idx];
        rc4.apply(&mut sec.bytes[run.offset..run.offset + run.len]);
    }

    place::place_boot_stub(
        ctx,
        &mut rc4,
        &runs,
        &seed_stored,
        crc_source,
        payload_bytes,
        no_crypto,
        anti_debug,
        vm_effective,
        vm_oep_effective,
        chained_effective,
        reencrypt,
        integrity_effective,
        payload_relocate,
        image_base,
        dispatcher_va,
        dispatcher_rva,
        boot_off,
        code_start,
        code_len,
        k1,
        k2,
        k3,
        m8_mod,
        &mut rng,
    )?;
    Ok(())
}
