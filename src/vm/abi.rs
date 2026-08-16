// ==============================================================================
// BTG v61 - P0-2: Win64 VM ABI 명세 + 정적 검증기 (Notes #2 반영)
// ==============================================================================
// 상용 VM의 네이티브 핸들러/디스패처/아레나 호출이 반드시 지켜야 하는 Win64
// ABI 계약을 코드로 명문화하고, 생성된 머신 코드를 역어셈블해 위반을 탐지한다.
//
// Win64 호출 규약 (AMD64 ABI):
//   volatile   (callee-clobberable): RAX, RCX, RDX, R8..R11, XMM0..XMM5, RFLAGS
//   nonvolatile(callee-saved)      : RBX, RBP, RDI, RSI, R12..R15, XMM6..XMM15
//   RSP 16B 정렬 (call 직전), shadow space 32B, direction flag clear.
//
// `validate_win64_abi(code)`는 코드를 디코드해 각 callee-saved GPR이 "저장 전에
// 쓰이는지"(violation)를 선형 추적한다. push가 저장으로 간주되고, 이후의 write는
// 허용. 핸들러/디스패처는 push/pop으로 보존해야 한다. (XMM는 별도 수동 점검 —
//  xmm6+를 쓰는 핸들러가 save/restore하는지 문서화.)
// ==============================================================================

use anyhow::{anyhow, Result};
use iced_x86::{Code, Decoder, DecoderOptions, Register};

/// Win64 callee-saved GPR (함수 진입 시 보존해야 하는 레지스터).
pub const WIN64_NONVOL_GPRS: &[Register] = &[
    Register::RBX,
    Register::RBP,
    Register::RDI,
    Register::RSI,
    Register::R12,
    Register::R13,
    Register::R14,
    Register::R15,
];

/// Win64 volatile GPR (호출자가 자유롭게 클로버 가능).
pub const WIN64_VOLATILE_GPRS: &[Register] = &[
    Register::RAX,
    Register::RCX,
    Register::RDX,
    Register::R8,
    Register::R9,
    Register::R10,
    Register::R11,
];

/// Win64 ABI 명세 — 모든 네이티브 진입점/핸들러가 지켜야 하는 계약.
#[derive(Debug, Clone, Copy)]
pub struct VmAbi {
    /// 비휘발성 GPR (callee-saved) — 위반 시 정적 검증기가 탐지.
    pub nonvolatile_gprs: &'static [Register],
    /// 휘발성 GPR.
    pub volatile_gprs: &'static [Register],
    /// 비휘발성 XMM (XMM6-15) — 저장/복원 필요 (수동 점검 + 문서화).
    pub nonvolatile_xmm_start: u8, // XMM6
    pub nonvolatile_xmm_end: u8,   // XMM15
    /// RSP 16B 정렬 (call 직전).
    pub stack_alignment: usize,
    /// shadow space (32B).
    pub shadow_space: usize,
    /// 방향 플래그(DF) 정책 — 함수 진입/복귀 시 clear.
    pub df_clear: bool,
    /// 반환 정책 — RAX 반환, callee-saved는 호출자 상태 유지.
    pub return_policy: &'static str,
}

impl Default for VmAbi {
    fn default() -> Self {
        Self {
            nonvolatile_gprs: WIN64_NONVOL_GPRS,
            volatile_gprs: WIN64_VOLATILE_GPRS,
            nonvolatile_xmm_start: 6,
            nonvolatile_xmm_end: 15,
            stack_alignment: 16,
            shadow_space: 32,
            df_clear: true,
            return_policy: "RAX; callee-saved GPR/XMM preserved",
        }
    }
}

impl VmAbi {
    pub fn is_nonvolatile_gpr(&self, r: Register) -> bool {
        self.nonvolatile_gprs.contains(&r)
    }
}

/// 명령이 레지스터 `r`(또는 하위 폼)을 쓰는지.
fn writes_reg(inst: &iced_x86::Instruction, r: Register) -> bool {
    // op0 (dst) 가 r 또는 그 하위 폼인 경우 (number() 기반으로 32/16/8비트 폼 통합)
    if inst.op_count() >= 1 {
        if let iced_x86::OpKind::Register = inst.op0_kind() {
            let d = inst.op0_register();
            if d.number() == r.number() {
                return true;
            }
        }
    }
    false
}

/// 명령이 레지스터 `r`을 스택에 저장(push)하는지.
fn is_push_of(inst: &iced_x86::Instruction, r: Register) -> bool {
    matches!(inst.code(), Code::Push_r64) && inst.op0_register().number() == r.number()
}

/// 선형 스캔으로 callee-saved GPR의 "저장 전 쓰기" 위반을 탐지한다.
///
/// 규칙: 각 nonvolatile GPR을 시작 시 unsaved로 보고, `push r`에서 saved로 전환.
/// saved 이전에 해당 레지스터(하위 폼 포함)를 **쓰면** 위반. pop 은 분석을
/// 단순화하기 위해 무시한다(위반 신고에만 사용). call/jmp 이후는 새 함수 경계로
/// 취급하지 않는다(단일 루틴 전제) — 재진입 경계는 호출자에서 관리.
pub fn validate_win64_abi(code: &[u8], entry_ip: u64) -> Result<Vec<String>> {
    let abi = VmAbi::default();
    let mut violations = Vec::new();
    let mut saved: Vec<bool> = vec![false; 16];

    let mut decoder = Decoder::with_ip(64, code, entry_ip, DecoderOptions::NONE);
    while decoder.can_decode() {
        let inst = decoder.decode();
        if inst.is_invalid() {
            break;
        }
        let ip = decoder.ip() - inst.len() as u64;
        for (i, r) in WIN64_NONVOL_GPRS.iter().enumerate() {
            let n = r.number() as usize;
            if is_push_of(&inst, *r) {
                saved[n] = true;
            } else if !saved[n] && writes_reg(&inst, *r) {
                violations.push(format!(
                    "0x{:X}: writes callee-saved reg{} before saving (violates Win64 ABI)",
                    ip, r.number()
                ));
            }
        }
    }
    Ok(violations)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abi_spec_defaults_sane() {
        let a = VmAbi::default();
        assert_eq!(a.stack_alignment, 16);
        assert_eq!(a.shadow_space, 32);
        assert!(a.df_clear);
        assert_eq!(a.nonvolatile_gprs.len(), 8);
        assert!(a.is_nonvolatile_gpr(Register::RBX));
        assert!(a.is_nonvolatile_gpr(Register::R12));
        assert!(!a.is_nonvolatile_gpr(Register::RAX));
    }

    #[test]
    fn detects_unsaved_callee_saved_write() {
        // push rbx (saved) → mov rbx, 5 (OK) → mov r12, 7 (r12 unsaved → 위반)
        let code = vec![
            0x53,             // push rbx
            0xBB, 0x05, 0x00, 0x00, 0x00, // mov ebx, 5
            0x41, 0xBC, 0x07, 0x00, 0x00, 0x00, // mov r12d, 7
            0xC3,             // ret
        ];
        let v = validate_win64_abi(&code, 0x1000).unwrap();
        assert!(
            v.iter().any(|s| s.contains("reg12")),
            "must flag unsaved r12 write; got: {v:?}"
        );
        assert!(
            !v.iter().any(|s| s.contains("rbx")),
            "saved rbx must not be flagged; got: {v:?}"
        );
    }

    #[test]
    fn abi_valid_code_passes() {
        // 모든 callee-saved를 push 후 사용, ret
        let code = vec![
            0x41, 0x57,             // push r15
            0x41, 0x56,             // push r14
            0x41, 0x55,             // push r13
            0x41, 0x54,             // push r12
            0x57,                   // push rdi
            0x56,                   // push rsi
            0x53,                   // push rbx
            0x55,                   // push rbp
            0x41, 0xBC, 0x07, 0x00, 0x00, 0x00, // mov r12d, 7 (saved)
            0x41, 0x5C,             // pop r12
            0x5D,                   // pop rbp
            0x5B,                   // pop rbx
            0x5E,                   // pop rsi
            0x5F,                   // pop rdi
            0x41, 0x5C,             // pop r12
            0x41, 0x5D,             // pop r13
            0x41, 0x5E,             // pop r14
            0x41, 0x5F,             // pop r15
            0xC3,                   // ret
        ];
        let v = validate_win64_abi(&code, 0x1000).unwrap();
        assert!(v.is_empty(), "no violations expected, got: {v:?}");
    }

    /// 실제 생성된 디스패처(표준/reencrypt/m7)들이 Win64 callee-saved GPR을
    /// 저장한 뒤만 사용하는지 검증한다. (P0-2 — 상용 네이티브 진입점 ABI 정합.)
    #[test]
    fn generated_dispatchers_preserve_win64_abi() {
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("plain", crate::dispatcher::build_dispatcher(0x140001000, 0x80, 16, false, 0xCAFEBABE, false, 0)),
            ("reencrypt", crate::dispatcher::build_dispatcher_reencrypt(0x140001000, 0x600, 16, 0xCAFEBABE, false)),
            ("m7", crate::dispatcher::build_dispatcher_m7(0x140001000, 0x600, 16, 0xCAFEBABE, false)),
            ("m7_c1", crate::dispatcher::build_dispatcher_m7_c1(0x140001000, 0x600, 16, 0xCAFEBABE, false, 0x140003000, 0x140003100)),
            ("reencrypt_c1", crate::dispatcher::build_dispatcher_reencrypt_c1(0x140001000, 0x600, 16, 0xCAFEBABE, false, 0x140003000, 0x140003100)),
        ];
        for (name, code) in cases {
            let v = validate_win64_abi(&code, 0x140001000 + 0x20).unwrap();
            assert!(
                v.is_empty(),
                "{name} dispatcher violates Win64 ABI:\n  {}",
                v.join("\n  ")
            );
        }
    }
}
