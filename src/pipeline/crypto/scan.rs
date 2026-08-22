// ==============================================================================
// String-run scanning (read-only data runs protected by the RC4 boot-decrypt loop)
// ==============================================================================

use super::{MAX_STRING_RUNS, MAX_STRING_TOTAL};
use crate::pe::builder::SectionData;
use crate::pipeline::patch_data::{collect_protected_rva_ranges, locate_security_cookie};
use crate::pipeline::PipelineContext;

pub(crate) struct StringRun {
    /// 대상 섹션 인덱스 (ctx.patched_sections 기준)
    pub(crate) sec_idx: usize,
    /// 섹션 내 오프셋
    pub(crate) offset: usize,
    /// 런 길이 (바이트)
    pub(crate) len: usize,
    /// 절대 VA (부트 스텁 런 테이블용)
    pub(crate) va: u64,
}

fn is_printable_ascii(b: u8) -> bool {
    (0x20..=0x7E).contains(&b) || b == b'\t'
}

pub(crate) fn scan_string_runs(
    sections: &mut [SectionData],
    image_base: u64,
    protected: &[(u32, u32)],
) -> Vec<StringRun> {
    let mut runs = Vec::new();
    let mut total = 0usize;

    for (sec_idx, sec) in sections.iter().enumerate() {
        // 대상: read-only 데이터 섹션 (이름 기준). .pdata/.rsrc/.textb 제외.
        let name = sec.name.to_lowercase();
        let is_data_sec = (name.starts_with(".rdata")
            || name.starts_with(".rodata")
            || name.contains("const")
            || name.starts_with(".sdata"))
            && !name.starts_with(".pdata")
            && !name.starts_with(".rsrc")
            && !name.starts_with(".text");
        if !is_data_sec || sec.bytes.is_empty() {
            continue;
        }

        let mut i = 0usize;
        while i < sec.bytes.len() && runs.len() < MAX_STRING_RUNS {
            // ── UTF-16LE 런 우선 검사 (문자+0x00 쌍) ─────────────────────────────
            // FIX: 과거 구현은 ASCII 스캔이 첫 문자를 소비한 뒤 그 위치에서 wide 스캔을
            // 시작해서, "H\0e\0l\0l\0o\0" 같은 UTF-16LE 문자열의 첫 글자를 ASCII가
            // 먹어치워 wide 런을 절대 감지하지 못했다 (dead code). i에서 쌍을 먼저 검사한다.
            let wide_start = i;
            let mut w = i;
            while w + 1 < sec.bytes.len()
                && is_printable_ascii(sec.bytes[w])
                && sec.bytes[w + 1] == 0
            {
                w += 2;
            }
            let wide_len = w - wide_start;
            // Bug-1 fix: NUL(0x00)로 종료된 wide 런만 채택하고, 4바이트 정렬 경계로만
            // 자른다. usize 크기의 Rust 상태 워드(Once/AtomicUsize)가 런 경계에 절대
            // 걸치지 않게 되어, 부분 XOR로 상태가 오염되는 일이 없어야 한다.
            if wide_len >= 16 && w < sec.bytes.len() && sec.bytes[w] == 0 {
                let ws = (wide_start + 3) & !3;
                let we = w & !3;
                if we > ws && (we - ws) >= 8 {
                    push_run(
                        &mut runs,
                        &mut total,
                        sec_idx,
                        ws,
                        we - ws,
                        image_base,
                        sec,
                        protected,
                    );
                    i = w;
                    continue;
                }
            }

            // ── ASCII 런 ──
            let ascii_start = i;
            while i < sec.bytes.len() && is_printable_ascii(sec.bytes[i]) {
                i += 1;
            }
            let ascii_len = i - ascii_start;
            // Bug-1 fix: NUL(0x00)로 종료된 문자열만 채택 + 4바이트 정렬 경계로 절단.
            // 비-정렬 프린터블 덩어리(구조체 필드 등)를 런으로 잡지 않아 Rust 상태 워드가
            // 런 안에 포함되거나 런 경계에 걸치지 않는다.
            let nul_terminated = i < sec.bytes.len() && sec.bytes[i] == 0;
            let ast = (ascii_start + 3) & !3;
            let ae = i & !3;
            if nul_terminated && ascii_len >= 8 && ae > ast && (ae - ast) >= 8 {
                push_run(
                    &mut runs,
                    &mut total,
                    sec_idx,
                    ast,
                    ae - ast,
                    image_base,
                    sec,
                    protected,
                );
            }
            if i == ascii_start {
                // 비-프린터블 바이트: wide도 ASCII도 아니면 1바이트 건너뜀 (무한 루프 방지)
                i += 1;
            }
        }
        if total >= MAX_STRING_TOTAL {
            println!(
                "[!] v3 Crypto: string run total reached cap ({} bytes).",
                MAX_STRING_TOTAL
            );
            break;
        }
    }

    runs
}

fn push_run(
    runs: &mut Vec<StringRun>,
    total: &mut usize,
    sec_idx: usize,
    offset: usize,
    len: usize,
    image_base: u64,
    sec: &SectionData,
    protected: &[(u32, u32)],
) {
    if *total + len > MAX_STRING_TOTAL || runs.len() >= MAX_STRING_RUNS {
        return;
    }
    let rva = sec.virtual_address + offset as u32;
    let rva_end = rva + len as u32;
    // 로더가 로드 전에 읽는 영역(import, IAT, LoadConfig, cookie 등)은 건너뛴다.
    for &(ps, pe) in protected {
        if ps >= rva_end {
            break;
        }
        if rva < pe && rva_end > ps {
            return;
        }
    }
    runs.push(StringRun {
        sec_idx,
        offset,
        len,
        va: image_base + rva as u64,
    });
    *total += len;
}

pub(crate) fn gather_runs(
    ctx: &mut PipelineContext,
    no_crypto: bool,
    vm_oep_effective: bool,
) -> Vec<StringRun> {
    let image_base = ctx.target_info.image_base;
    let mut runs = if no_crypto || vm_oep_effective {
        // C-1 (--vm-oep): --no-crypto와 동일하게 부트-복호화 런을 비운다.
        Vec::new()
    } else {
        let cookie_rva = locate_security_cookie(ctx, &ctx.patched_sections);
        let protected = collect_protected_rva_ranges(ctx, &ctx.patched_sections, cookie_rva);
        scan_string_runs(&mut ctx.patched_sections, image_base, &protected)
    };

    if !no_crypto && !vm_oep_effective {
        // v58 (Phase 2.5-fix): the original `.text` is deliberately NOT registered
        // as a boot-decrypt run. The loader runs the PE's TLS callbacks BEFORE the
        // entry point (boot stub), and those callbacks execute the ORIGINAL .text
        // code (plus whatever it direct-calls). If the whole section were encrypted
        // here ("hide .text at rest", v14), the TLS callback would execute
        // ciphertext and the process dies instantly with 0xC0000005 before the
        // boot stub ever decrypts. The design's "safe copy" intent (patch_data.rs /
        // build.rs: keep the original .text as an executable plaintext copy for
        // TLS/CRT/native-bridge paths) is restored: the real executing code lives
        // in the encrypted .textb blocks, so hiding the dead .text copy buys no
        // protection while breaking every TLS-callback target.

        // ── v14: 원본 데이터(.rdata/.data/.rodata)도 런타임 복호화로 은닉 ────────
        // 공격자가 flag 비교용 target_table 같은 원본 프로그램 데이터를 .rdata에서
        // 평문으로 읽는 것을 차단한다. 로더가 부트 전에 읽는 import/IAT/TLS/LoadConfig/
        // cookie 범위(collect_protected_rva_ranges)는 제외해 로더가 깨지지 않게 한다.
        let cookie_rva = locate_security_cookie(ctx, &ctx.patched_sections);
        let protected = collect_protected_rva_ranges(ctx, &ctx.patched_sections, cookie_rva);
        // C-1 fix (--vm-oep): 리프트된 프로그램은 원본 .rdata/.data/.rodata를 절대 VA로
        // 직접 읽는다(예: .rdata에 저장된 데이터 포인터). 이 섹션들을 v14 "전체 데이터 런"으로
        // 암호화하면 부트 스텁 복호화의 키스트림 정렬이 어긋나(또는 데이터가 원본 포인터로
        // 복원되지 않아) 리프트 코드가 쓰레기 주소를 읽고 0xC0000005로 크래시한다.
        // 문자열 은닉은 scan_string_runs(아래)이 이미 처리하므로, --vm-oep에서는
        // 전체 데이터 런 암호화를 건너뛰어 포인터/데이터 영역을 평문으로 유지한다.
        // Bug-1 fix: `.data`는 제외 — Rust 런타임의 `Once`/`OnceLock`/`AtomicUsize` 상태
        // 워드가 초기화된 쓰기 가능 정적 데이터로 `.data`(및 .bss)에 살기 때문. 전체 런으로
        // XOR하면 셧다운 cleanup이 그 상태를 POISONED로 읽어 `once.rs:166` 패닉을 일으킨다.
        // `.data`를 런에서 빼 평문으로 유지하면 상태 워드가 절대 암호화 런 안에 들어가지 않는다.
        // (읽기 전용 `.rdata`/`.rodata`만 은닉.)
        if ctx.vm_oep {
            // skip full-data-run encryption in --vm-oep (data pointers must stay plaintext)
            println!("[+] --vm-oep: skipping full .rdata/.rodata boot-decrypt runs (lifted program reads data pointers as plaintext)");
        } else {
            for data_name in [".rdata", ".rodata"] {
                let Some(ti) = ctx
                    .patched_sections
                    .iter()
                    .position(|s| s.name == data_name)
                else {
                    continue;
                };
                let tsec = &ctx.patched_sections[ti];
                if tsec.bytes.is_empty() {
                    continue;
                }
                let sec_start = tsec.virtual_address;
                let sec_end = sec_start + tsec.bytes.len() as u32;
                // protected 범위와 교차하는 것만 [sec_start, sec_end)로 클리핑 후 정렬/병합
                let mut pv: Vec<(u32, u32)> = protected
                    .iter()
                    .filter(|&&(st, en)| en > sec_start && st < sec_end)
                    .map(|&(st, en)| (st.max(sec_start), en.min(sec_end)))
                    .collect();
                pv.sort_unstable();
                pv.dedup();
                let mut pos = sec_start;
                let mut n_runs = 0usize;
                for (ps, pe) in pv {
                    if ps > pos {
                        let off = (pos - sec_start) as usize;
                        let len = (ps - pos) as usize;
                        runs.push(StringRun {
                            sec_idx: ti,
                            offset: off,
                            len,
                            va: image_base + pos as u64,
                        });
                        n_runs += 1;
                    }
                    pos = pos.max(pe);
                }
                if pos < sec_end {
                    let off = (pos - sec_start) as usize;
                    let len = (sec_end - pos) as usize;
                    runs.push(StringRun {
                        sec_idx: ti,
                        offset: off,
                        len,
                        va: image_base + pos as u64,
                    });
                    n_runs += 1;
                }
                if n_runs > 0 {
                    println!(
                    "[+] v14: {} {} bytes registered as {} boot-decrypt run(s) (loader-critical dirs excluded)",
                    data_name,
                    tsec.bytes.len(),
                    n_runs
                );
                }
            }
        }
    }

    runs
}
