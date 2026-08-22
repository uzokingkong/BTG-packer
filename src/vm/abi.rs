// ==============================================================================
// BTG v61 - P0-2: Win64 VM ABI 筌뤿굞苑?+ ?類ㅼ읅 野꺜筌앹빓由?(Notes #2 獄쏆꼷??
// ==============================================================================
// ?怨몄뒠 VM????쇱뵠?怨뺥닏 ?紐껊굶???遺용뮞??μ퓗/?袁⑥쟿???紐꾪뀱??獄쏆꼶諭??筌왖?녹뮇鍮???롫뮉 Win64
// ABI ?④쑴鍮???꾨뗀諭뜻에?筌뤿굝揆?酉釉?? ??밴쉐???믩챷???꾨뗀諭띄몴???堉??덊닜???袁⑥뺘???癒???뺣뼄.
//
// Win64 ?紐꾪뀱 域뱀뮇鍮?(AMD64 ABI):
//   volatile   (callee-clobberable): RAX, RCX, RDX, R8..R11, XMM0..XMM5, RFLAGS
//   nonvolatile(callee-saved)      : RBX, RBP, RDI, RSI, R12..R15, XMM6..XMM15
//   RSP 16B ?類ｌ졊 (call 筌욊낯??, shadow space 32B, direction flag clear.
//
// `validate_win64_abi(code)`???꾨뗀諭띄몴??遺욱맜??쀫퉸 揶?callee-saved GPR??"?????袁⑸퓠
// ?怨쀬뵠?遺?"(violation)???醫륁굨 ?곕뗄???뺣뼄. push揶쎛 ???關?앮에?揶쏄쑴竊??랁? ??꾩뜎??write??
// ??됱뒠. ?紐껊굶???遺용뮞??μ퓗??push/pop??곗쨮 癰귣똻???곷튊 ??뺣뼄. (XMM??癰귢쑬猷???롫짗 ?癒? ??
//  xmm6+???怨뺣뮉 ?紐껊굶??? save/restore??롫뮉筌왖 ?얜챷苑??)
// ==============================================================================

use anyhow::{anyhow, Result};
use iced_x86::{Code, Decoder, DecoderOptions, Register};

/// Win64 callee-saved GPR (??λ땾 筌욊쑴????癰귣똻???곷튊 ??롫뮉 ?????쎄숲).
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

/// Win64 volatile GPR (?紐꾪뀱?癒? ?癒??嚥?苡???以덅린?揶쎛??.
pub const WIN64_VOLATILE_GPRS: &[Register] = &[
    Register::RAX,
    Register::RCX,
    Register::RDX,
    Register::R8,
    Register::R9,
    Register::R10,
    Register::R11,
];

/// Win64 ABI 筌뤿굞苑???筌뤴뫀諭???쇱뵠?怨뺥닏 筌욊쑴????紐껊굶??? 筌왖?녹뮇鍮???롫뮉 ?④쑴鍮?
#[derive(Debug, Clone, Copy)]
pub struct VmAbi {
    /// ??쑵?띈쳸?뽮쉐 GPR (callee-saved) ???袁⑥뺘 ???類ㅼ읅 野꺜筌앹빓由겼첎? ?癒?.
    pub nonvolatile_gprs: &'static [Register],
    /// ??롮뻣??GPR.
    pub volatile_gprs: &'static [Register],
    /// ??쑵?띈쳸?뽮쉐 XMM (XMM6-15) ??????癰귣벊???袁⑹뒄 (??롫짗 ?癒? + ?얜챷苑??.
    pub nonvolatile_xmm_start: u8, // XMM6
    pub nonvolatile_xmm_end: u8, // XMM15
    /// RSP 16B ?類ｌ졊 (call 筌욊낯??.
    pub stack_alignment: usize,
    /// shadow space (32B).
    pub shadow_space: usize,
    /// 獄쎻뫚堉????삋域?DF) ?類ㅼ퐠 ????λ땾 筌욊쑴??癰귣벀? ??clear.
    pub df_clear: bool,
    /// 獄쏆꼹???類ㅼ퐠 ??RAX 獄쏆꼹?? callee-saved???紐꾪뀱???怨밴묶 ?醫?.
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

/// 筌뤿굝議???????쎄숲 `r`(?癒?뮉 ??륁맄 ?????怨뺣뮉筌왖.
fn writes_reg(inst: &iced_x86::Instruction, r: Register) -> bool {
    // op0 (dst) 揶쎛 r ?癒?뮉 域???륁맄 ??깆뵥 野껋럩??(number() 疫꿸퀡而??곗쨮 32/16/8??쑵????????)
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

/// 筌뤿굝議???????쎄숲 `r`????쎄문??????push)??롫뮉筌왖.
fn is_push_of(inst: &iced_x86::Instruction, r: Register) -> bool {
    matches!(inst.code(), Code::Push_r64) && inst.op0_register().number() == r.number()
}

/// ?醫륁굨 ??쇳떔??곗쨮 callee-saved GPR??"???????怨뚮┛" ?袁⑥뺘???癒???뺣뼄.
///
/// 域뱀뮇?? 揶?nonvolatile GPR????뽰삂 ??unsaved嚥?癰귣떯?? `push r`?癒?퐣 saved嚥??袁れ넎.
/// saved ??곸읈???????????쎄숲(??륁맄 ????釉???**?怨뺛늺** ?袁⑥뺘. pop ?? ?브쑴苑??
/// ??λ떄?酉釉?묾??袁る퉸 ?얜똻???뺣뼄(?袁⑥뺘 ?醫됲?癒?춸 ????. call/jmp ??꾩뜎??????λ땾 野껋럡?롦에?
/// ?띯몿???? ??낅뮉????μ뵬 ?룐뫂???袁⑹젫) ????彛??野껋럡????紐꾪뀱?癒?퓠???온??
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
        // push rbx (saved) ??mov rbx, 5 (OK) ??mov r12, 7 (r12 unsaved ???袁⑥뺘)
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
        // 筌뤴뫀諭?callee-saved??push ?????? ret
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

    /// ??쇱젫 ??밴쉐???遺용뮞??μ퓗(???/reencrypt/m7)??쇱뵠 Win64 callee-saved GPR??
    /// ???館釉???살춸 ?????롫뮉筌왖 野꺜筌앹빜釉?? (P0-2 ???怨몄뒠 ??쇱뵠?怨뺥닏 筌욊쑴???ABI ?類λ?.)
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
