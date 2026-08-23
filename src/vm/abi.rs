// ==============================================================================
// ==============================================================================
//
//   volatile   (callee-clobberable): RAX, RCX, RDX, R8..R11, XMM0..XMM5, RFLAGS
//   nonvolatile(callee-saved)      : RBX, RBP, RDI, RSI, R12..R15, XMM6..XMM15
//
// ==============================================================================

use anyhow::{anyhow, Result};
use iced_x86::{Code, Decoder, DecoderOptions, Register};

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

pub const WIN64_VOLATILE_GPRS: &[Register] = &[
    Register::RAX,
    Register::RCX,
    Register::RDX,
    Register::R8,
    Register::R9,
    Register::R10,
    Register::R11,
];

#[derive(Debug, Clone, Copy)]
pub struct VmAbi {
    pub nonvolatile_gprs: &'static [Register],
    pub volatile_gprs: &'static [Register],
    pub nonvolatile_xmm_start: u8, // XMM6
    pub nonvolatile_xmm_end: u8, // XMM15
    pub stack_alignment: usize,
    /// shadow space (32B).
    pub shadow_space: usize,
    pub df_clear: bool,
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

fn writes_reg(inst: &iced_x86::Instruction, r: Register) -> bool {
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

fn is_push_of(inst: &iced_x86::Instruction, r: Register) -> bool {
    matches!(inst.code(), Code::Push_r64) && inst.op0_register().number() == r.number()
}

///
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
                    ip,
                    r.number()
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
        let code = vec![
            0x53, // push rbx
            0xBB, 0x05, 0x00, 0x00, 0x00, // mov ebx, 5
            0x41, 0xBC, 0x07, 0x00, 0x00, 0x00, // mov r12d, 7
            0xC3, // ret
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
        let code = vec![
            0x41, 0x57, // push r15
            0x41, 0x56, // push r14
            0x41, 0x55, // push r13
            0x41, 0x54, // push r12
            0x57, // push rdi
            0x56, // push rsi
            0x53, // push rbx
            0x55, // push rbp
            0x41, 0xBC, 0x07, 0x00, 0x00, 0x00, // mov r12d, 7 (saved)
            0x41, 0x5C, // pop r12
            0x5D, // pop rbp
            0x5B, // pop rbx
            0x5E, // pop rsi
            0x5F, // pop rdi
            0x41, 0x5C, // pop r12
            0x41, 0x5D, // pop r13
            0x41, 0x5E, // pop r14
            0x41, 0x5F, // pop r15
            0xC3, // ret
        ];
        let v = validate_win64_abi(&code, 0x1000).unwrap();
        assert!(v.is_empty(), "no violations expected, got: {v:?}");
    }

    #[test]
    fn generated_dispatchers_preserve_win64_abi() {
        let cases: Vec<(&str, Vec<u8>)> = vec![
            (
                "plain",
                crate::dispatcher::build_dispatcher(
                    0x140001000,
                    0x80,
                    16,
                    false,
                    0xCAFEBABE,
                    false,
                    0,
                    2,
                ),
            ),
            (
                "reencrypt",
                crate::dispatcher::build_dispatcher_reencrypt(
                    0x140001000,
                    0x600,
                    16,
                    0xCAFEBABE,
                    false,
                )
                .unwrap(),
            ),
            (
                "m7",
                crate::dispatcher::build_dispatcher_m7(0x140001000, 0x600, 16, 0xCAFEBABE, false)
                    .unwrap(),
            ),
            (
                "m7_c1",
                crate::dispatcher::build_dispatcher_m7_c1(
                    0x140001000,
                    0x600,
                    16,
                    0xCAFEBABE,
                    false,
                    0x140003000,
                    0x140003100,
                )
                .unwrap(),
            ),
            (
                "reencrypt_c1",
                crate::dispatcher::build_dispatcher_reencrypt_c1(
                    0x140001000,
                    0x600,
                    16,
                    0xCAFEBABE,
                    false,
                    0x140003000,
                    0x140003100,
                )
                .unwrap(),
            ),
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
