// ==============================================================================
// BTG - Anti-Debugging Shellcode Generator (Raw Byte Encoding)
// ==============================================================================
// 안티 디버깅 기법을 raw bytes로 직접 생성하여 iced-x86 API 의존성을 최소화.
//
// 적용 기법:
// 1. PEB.BeingDebugged (PEB+0x02, PEB = GS:[0x60]) 검사
// 2. PEB.NtGlobalFlag (PEB+0xBC) & 0x70 검사
// 3. ProcessHeap.Flags ([PEB.ProcessHeap + 0x70]) & 0x70 검사
// 4. 탐지 시 정책별 처리 (readccc §4.5 graceful failure):
//    - Trap: Ud2 (SIGILL) — 민감 프로파일 기본 (기존 동작)
//    - Hang: 무한 루프 (`jmp $`) — 분석 도구 고정
//    - Warn: 정상 경로로 계속 (fail-open, consumer/diagnostic) — 검사는
//      위험 신호로만 쓰고 정상 고객 환경을 파괴하지 않는다.
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

/// readccc §4.5: 탐지 실패 시 처리 정책 (profile-controlled risk signal).
///
/// | 정책 | 동작 | 프로파일 |
/// |---|---|---|
/// | `Trap` | `ud2` (SIGILL) | sensitive (기본) |
/// | `Hang` | `jmp $` 무한 루프 | research/툴 고정 |
/// | `Warn` | 정상 경로로 계속 (fail-open) | consumer/diagnostic |
/// | `Poison` | 상태 오염 후 계속 (stealth poison) | stealth / anti-analysis |
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum AntiDebugPolicy {
    /// 탐지 시 `ud2` (SIGILL) — 민감 프로파일 기본.
    #[value(name = "trap")]
    Trap,
    /// 탐지 시 무한 루프 (`jmp $`) — 분석 툴 고정.
    #[value(name = "hang")]
    Hang,
    /// 탐지 시 정상 경로로 계속 (fail-open) — consumer/diagnostic.
    #[value(name = "warn")]
    Warn,
    /// 탐지 시 상태 오염(Stealth Poison) 후 계속 — 즉시 트랩 없이 런타임 가비지 연산 유도.
    #[value(name = "poison")]
    Poison,
}

impl AntiDebugPolicy {
    /// 매니페스트/로그용 이름.
    pub fn as_str(&self) -> &'static str {
        match self {
            AntiDebugPolicy::Trap => "trap",
            AntiDebugPolicy::Hang => "hang",
            AntiDebugPolicy::Warn => "warn",
            AntiDebugPolicy::Poison => "poison",
        }
    }
}

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
/// 디버거 탐지 시 `policy`에 따라 처리 (readccc §4.5 graceful failure):
/// - Trap: Ud2로 SIGILL 발생 (기본, sensitive)
/// - Hang: `jmp $` 무한 루프 (research/툴 고정)
/// - Warn: fail-open — 정상 경로로 계속 (consumer/diagnostic, 검사는 위험 신호)
pub fn build_anti_debug_shellcode(ad_va: u64, dispatcher_va: u64, policy: AntiDebugPolicy) -> Vec<u8> {
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
    // ── 실패 경로 (policy별, 항상 2바이트 고정) ──────────────────────────────
    match policy {
        // Trap: ud2 (SIGILL) — sensitive 기본
        AntiDebugPolicy::Trap => b.extend_from_slice(&[0x0F, 0x0B]),
        // Hang: `jmp $` (EB FE) — 무한 루프, 분석 툴 고정
        AntiDebugPolicy::Hang => b.extend_from_slice(&[0xEB, 0xFE]),
        // Poison: Stealth state poisoning — jumps back to 0x41 (EB F9) with non-zero RAX
        // to poison the initial dispatcher key/state without immediate trap.
        AntiDebugPolicy::Poison => b.extend_from_slice(&[0xEB, 0xF9]),
        // Warn: fail-open — 세 jnz가 정상 경로(0x41의 jmp rel32)로 향하도록
        // 디스패치 직전의 정상 jmp로 리다이렉트. 실패 슬롯은 도달 불가 nop.
        AntiDebugPolicy::Warn => {
            // jnz@0x0F: next_ip=0x11 → 타깃 0x41, disp = 0x41 - 0x11 = 0x30
            b[0x10] = 0x30;
            // jnz@0x25: next_ip=0x27 → 타깃 0x41, disp = 0x41 - 0x27 = 0x1A
            b[0x26] = 0x1A;
            // jnz@0x3F: next_ip=0x41 → 타깃 0x41, disp = 0x00
            b[0x40] = 0x00;
            // 실패 슬롯(0x46)은 도달 불가 — nop nop
            b.extend_from_slice(&[0x90, 0x90]);
        }
    }
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
        let code = build_anti_debug_shellcode(0x140001000, 0x140000020, AntiDebugPolicy::Trap);
        assert_eq!(code.len(), ANTI_DEBUG_SIZE, "Anti-debug code must be exactly 72 bytes");
    }

    #[test]
    fn test_anti_debug_contains_ud2() {
        let code = build_anti_debug_shellcode(0x140001000, 0x140000020, AntiDebugPolicy::Trap);
        // 마지막 2바이트는 ud2 (0x0F 0x0B)
        assert_eq!(&code[code.len()-2..], &[0x0F, 0x0B]);
    }

    #[test]
    fn test_anti_debug_has_gs_prefix() {
        let code = build_anti_debug_shellcode(0x140001000, 0x140000020, AntiDebugPolicy::Trap);
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
        let code = build_anti_debug_shellcode(ad_va, disp_va, AntiDebugPolicy::Trap);
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

    /// readccc §4.5: Hang 정책 — 탐지 시 무한 루프 (`jmp $` = EB FE).
    #[test]
    fn test_anti_debug_hang_policy() {
        let code = build_anti_debug_shellcode(0x140001000, 0x140002000, AntiDebugPolicy::Hang);
        assert_eq!(code.len(), ANTI_DEBUG_SIZE);
        // 실패 슬롯(0x46)이 EB FE (jmp $)여야 하고, 세 jnz가 여기로 향해야 한다.
        assert_eq!(&code[0x46..0x48], &[0xEB, 0xFE], "hang slot must be jmp $");
        for off in [0x0Fusize, 0x25, 0x3F] {
            let rel = code[off + 1] as i8 as i64;
            let target = off as i64 + 2 + rel;
            assert_eq!(target, 0x46, "jnz @0x{:X} must target hang slot @0x46", off);
        }
    }

    /// readccc §4.5: Warn 정책 — fail-open. 세 jnz가 정상 경로(0x41의 jmp rel32)로
    /// 리다이렉트되어 탐지 시에도 디스패처로 계속 진행한다.
    #[test]
    fn test_anti_debug_warn_policy_fail_open() {
        let ad_va = 0x140001000u64;
        let disp_va = 0x140002000u64;
        let code = build_anti_debug_shellcode(ad_va, disp_va, AntiDebugPolicy::Warn);
        assert_eq!(code.len(), ANTI_DEBUG_SIZE);
        // 세 jnz가 0x41(정상 경로 jmp rel32)로 향해야 한다.
        for off in [0x0Fusize, 0x25, 0x3F] {
            let rel = code[off + 1] as i8 as i64;
            let target = off as i64 + 2 + rel;
            assert_eq!(target, 0x41, "jnz @0x{:X} must redirect to normal path @0x41", off);
        }
        // 0x41의 jmp rel32는 여전히 디스패처를 가리켜야 한다.
        let disp = i32::from_le_bytes(code[0x42..0x46].try_into().unwrap()) as i64;
        let target = (ad_va as i64) + 0x41 + 5 + disp;
        assert_eq!(target as u64, disp_va, "jmp must land on the dispatcher");
        // 실패 슬롯(0x46)은 도달 불가 nop (크래시 없음).
        assert_eq!(&code[0x46..0x48], &[0x90, 0x90]);
    }

    /// Stealth: Poison 정책 — 탐지 시 EB F9 (jmp -7)로 0x41(디스패처 점프)로 복귀.
    #[test]
    fn test_anti_debug_poison_policy() {
        let code = build_anti_debug_shellcode(0x140001000, 0x140002000, AntiDebugPolicy::Poison);
        assert_eq!(code.len(), ANTI_DEBUG_SIZE);
        assert_eq!(&code[0x46..0x48], &[0xEB, 0xF9], "poison slot must be jmp -7 to 0x41");
    }

    /// readccc §4.5: 모든 정책에서 정상 경로(디스패처 점프)는 동일하게 유지되어야 한다.
    #[test]
    fn test_anti_debug_policies_share_normal_path() {
        let ad_va = 0x140001000u64;
        let disp_va = 0x140002000u64;
        for policy in [AntiDebugPolicy::Trap, AntiDebugPolicy::Hang, AntiDebugPolicy::Warn, AntiDebugPolicy::Poison] {
            let code = build_anti_debug_shellcode(ad_va, disp_va, policy);
            assert_eq!(code.len(), ANTI_DEBUG_SIZE);
            let disp = i32::from_le_bytes(code[0x42..0x46].try_into().unwrap()) as i64;
            let target = (ad_va as i64) + 0x41 + 5 + disp;
            assert_eq!(target as u64, disp_va, "normal path must land on dispatcher");
        }
    }

    /// readccc §4.5: 정책 이름 라운드트립.
    #[test]
    fn test_anti_debug_policy_as_str() {
        assert_eq!(AntiDebugPolicy::Trap.as_str(), "trap");
        assert_eq!(AntiDebugPolicy::Hang.as_str(), "hang");
        assert_eq!(AntiDebugPolicy::Warn.as_str(), "warn");
        assert_eq!(AntiDebugPolicy::Poison.as_str(), "poison");
    }
}
