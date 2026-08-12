// ==============================================================================
// BTG - Anti-Debugging Shellcode Generator (Raw Byte Encoding)
// ==============================================================================
// 안티 디버깅 기법을 raw bytes로 직접 생성하여 iced-x86 API 의존성을 최소화.
//
// 적용 기법:
// 1. PEB.BeingDebugged (PEB+0x02, PEB = GS:[0x60]) 검사
// 2. PEB.NtGlobalFlag (PEB+0xBC) & 0x70 검사
// 3. ProcessHeap.Flags ([PEB.ProcessHeap + 0x70]) & 0x70 검사
// 4. 탐지 시 Ud2 (SIGILL)
//
// v10 FIX (이전 버전은 3중으로 망가져 있었음):
//   a) GS:[0x30]을 읽어 ProcessHeap으로 오인 — GS:[0x30]은 TEB.Self이므로
//      세 번째 검사가 엉뚱한 메모리(TEB+0x70)를 검사했다.
//      → PEB(GS:[0x60]) → [PEB+0x30] → [ProcessHeap+0x70] 순서로 수정.
//   b) 정상 경로가 ud2로 fall-through (마지막 jne 뒤에 skip 점프가 없어
//      디버거 유무와 무관하게 항상 SIGILL) → ud2 직전에 jmp rel32 추가.
//   c) pass4가 섹션 tail에 배치만 하고 아무도 점프하지 않아 **실행되지 않았음**
//      → OEP 스텁이 이 셸코드로 점프하고, 정상 경로는 끝의 jmp로 디스패처
//      (섹션 오프셋 0x20)에 도달하도록 배선.
// ==============================================================================

/// 안티 디버깅 셸코드를 raw bytes로 생성한다.
///
/// 레이아웃 (72 bytes):
/// ```text
/// 0x00: mov rax, gs:[0x60]        ; PEB
/// 0x09: movzx eax, byte [rax+2]   ; BeingDebugged
/// 0x0D: test eax, eax
/// 0x0F: jnz +0x35                 ; → ud2 @0x46
/// 0x11: mov rax, gs:[0x60]
/// 0x1A: mov eax, [rax+0xBC]       ; NtGlobalFlag
/// 0x20: and eax, 0x70
/// 0x25: jnz +0x1F                 ; → ud2 @0x46
/// 0x27: mov rax, gs:[0x60]
/// 0x30: mov rax, [rax+0x30]       ; ProcessHeap
/// 0x34: mov eax, [rax+0x70]       ; Heap.Flags
/// 0x3A: and eax, 0x70
/// 0x3F: jnz +0x05                 ; → ud2 @0x46
/// 0x41: jmp rel32 dispatcher      ; 정상 경로 → 디스패처 (섹션 오프셋 0x20)
/// 0x46: ud2
/// ```
///
/// 정상 경로(디버거 없음)는 마지막 jmp로 디스패처 본체에 도달.
/// 디버거 탐지 시 Ud2로 SIGILL 발생.
pub fn build_anti_debug_shellcode(ad_va: u64, dispatcher_va: u64) -> Vec<u8> {
    let mut b = Vec::with_capacity(ANTI_DEBUG_SIZE);
    // ── PEB.BeingDebugged 검사 ──────────────────────────────────────────────
    b.extend_from_slice(&[
        0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, // mov rax, gs:[0x60] (PEB)
        0x0F, 0xB6, 0x40, 0x02,                               // movzx eax, byte [rax+2]
        0x85, 0xC0,                                           // test eax, eax
        0x75, 0x35,                                           // jnz +0x35 → ud2 @0x46
    ]);
    // ── PEB.NtGlobalFlag 검사 ───────────────────────────────────────────────
    b.extend_from_slice(&[
        0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, // mov rax, gs:[0x60]
        0x8B, 0x80, 0xBC, 0x00, 0x00, 0x00,                   // mov eax, [rax+0xBC]
        0x25, 0x70, 0x00, 0x00, 0x00,                         // and eax, 0x70
        0x75, 0x1F,                                           // jnz +0x1F → ud2 @0x46
    ]);
    // ── ProcessHeap.Flags 검사 ───────────────────────────────────────────────
    b.extend_from_slice(&[
        0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, // mov rax, gs:[0x60]
        0x48, 0x8B, 0x40, 0x30,                               // mov rax, [rax+0x30] (ProcessHeap)
        0x8B, 0x80, 0x70, 0x00, 0x00, 0x00,                   // mov eax, [rax+0x70] (Heap.Flags)
        0x25, 0x70, 0x00, 0x00, 0x00,                         // and eax, 0x70
        0x75, 0x05,                                           // jnz +0x05 → ud2 @0x46
    ]);
    // ── 정상 경로: 디스패처로 점프 (rel32) ──────────────────────────────────
    let jmp_off = b.len() as u64; // 0x41
    let next_ip = ad_va + jmp_off + 5;
    let disp = (dispatcher_va as i64).wrapping_sub(next_ip as i64) as u32;
    b.extend_from_slice(&[0xE9]);
    b.extend_from_slice(&disp.to_le_bytes());
    // ── 크래시: Ud2 ──────────────────────────────────────────────────────────
    b.extend_from_slice(&[0x0F, 0x0B]);
    debug_assert_eq!(b.len(), ANTI_DEBUG_SIZE, "anti-debug shellcode layout drift");
    b
}

/// 안티 디버깅 셸코드의 길이 (고정 72 bytes)
pub const ANTI_DEBUG_SIZE: usize = 72;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anti_debug_size() {
        let code = build_anti_debug_shellcode(0x140001000, 0x140000020);
        assert_eq!(code.len(), ANTI_DEBUG_SIZE, "Anti-debug code must be exactly 72 bytes");
    }

    #[test]
    fn test_anti_debug_contains_ud2() {
        let code = build_anti_debug_shellcode(0x140001000, 0x140000020);
        // 마지막 2바이트는 ud2 (0x0F 0x0B)
        assert_eq!(&code[code.len()-2..], &[0x0F, 0x0B]);
    }

    #[test]
    fn test_anti_debug_has_gs_prefix() {
        let code = build_anti_debug_shellcode(0x140001000, 0x140000020);
        // 첫 번째 바이트는 GS 세그먼트 접두사 (0x65)
        assert_eq!(code[0], 0x65);
    }

    #[test]
    fn test_anti_debug_normal_path_skips_ud2() {
        // v10 FIX 회귀: 정상(비디버그) 경로가 ud2에 도달하면 안 된다.
        // 마지막 jnz(0x3F)의 fall-through는 0x41의 jmp rel32 → 디스패처여야 하고,
        // ud2(0x46)는 세 jnz의 타깃이어야 한다.
        let ad_va = 0x140001000u64;
        let disp_va = 0x140002000u64;
        let code = build_anti_debug_shellcode(ad_va, disp_va);
        // 마지막 검사의 jnz는 0x3F에 있고, 그 직후(0x41)는 E9(jmp rel32).
        assert_eq!(code[0x3F], 0x75, "check #3 must be a short jcc");
        assert_eq!(code[0x41], 0xE9, "normal path must jmp to the dispatcher");
        // jmp rel32 타깃 검증: disp = dispatcher_va - (ad_va + 0x41 + 5)
        let disp = i32::from_le_bytes(code[0x42..0x46].try_into().unwrap()) as i64;
        let target = (ad_va as i64) + 0x41 + 5 + disp;
        assert_eq!(target as u64, disp_va, "jmp must land on the dispatcher");
        // ud2 위치 고정 (마지막 2바이트) + 세 jnz의 rel 타깃이 ud2 시작(0x46)인지
        for off in [0x0Fusize, 0x25, 0x3F] {
            let rel = code[off + 1] as i8 as i64;
            let target = off as i64 + 2 + rel;
            assert_eq!(target, 0x46, "jnz @0x{:X} must target ud2 @0x46", off);
        }
        // PEB 접근이 gs:[0x60] 기반인지 (gs:[0x30] 버그 회귀 방지)
        assert!(code.windows(9).any(|w| w == [0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00]),
            "all PEB reads must use gs:[0x60]");
        // ProcessHeap는 [PEB+0x30] 경유 (mov rax,[rax+0x30])
        assert!(code.windows(4).any(|w| w == [0x48, 0x8B, 0x40, 0x30]));
    }
}
