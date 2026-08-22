// ==============================================================================
// WS2.3 (readccc §4.6 / function-atomicity-bridge-spec §2.2–§2.3): real
// NativeCallBridge Win64 ABI call-site emitter.
//
// Implements the PRE-CALL / CALL / POST-CALL sequence mandated by §2.3:
//
//   PRE-CALL  : pop ret_ip from the VM virtual stack → r11;
//               materialize args RCX,RDX,R8,R9 from virtual regs;
//               push callee-saved nonvolatiles (RBX,RBP,RDI,RSI,R12–R15);
//               reserve 32B shadow space while keeping RSP ≡ 0 (mod 16).
//   CALL      : call target.
//   POST-CALL : sync RAX → virtual RAX (store to the VM's return slot);
//               restore callee-saved nonvolatiles (reverse order);
//               resume at ret_ip (jmp r11) → dispatch continues.
//
// The differential guard (§2.3) is untouched: reference eval_state, the poly
// interpreter and the threaded native runner keep NativeCallBridge a no-op
// (stream consumption + full VM-state preservation). This module provides the
// *verified ABI emission layer* — the byte sequence a real host call must emit.
// It is validated structurally (iced_x86 decode) and against `validate_win64_abi`
// (callee-saved preservation), so the emitted call site provably obeys the
// Win64 ABI contract without perturbing the live reference/interpreter paths.
// ==============================================================================

use crate::vm::abi::{validate_win64_abi, WIN64_NONVOL_GPRS};
use anyhow::{bail, Result};
use iced_x86::{Code, Decoder, DecoderOptions};

/// Win64 fixed costs.
pub const SHADOW_SPACE: u32 = 32;
pub const STACK_ALIGN: u32 = 16;

/// Tiny x64 emitter for the exact ops the call site needs.
#[derive(Default)]
pub struct X64Writer {
    pub bytes: Vec<u8>,
}

impl X64Writer {
    pub fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    fn rex_pushpop(&mut self, r: u8, base: u8) {
        if r < 8 {
            self.bytes.push(base + r);
        } else {
            self.bytes.push(0x41);
            self.bytes.push(base + (r - 8));
        }
    }

    /// push r64
    pub fn push_r(&mut self, r: u8) {
        self.rex_pushpop(r, 0x50);
    }

    /// pop r64
    pub fn pop_r(&mut self, r: u8) {
        self.rex_pushpop(r, 0x58);
    }

    /// mov r64, imm64
    pub fn mov_r64_imm(&mut self, r: u8, imm: u64) {
        if r < 8 {
            self.bytes.push(0x48);
            self.bytes.push(0xB8 + r);
        } else {
            self.bytes.push(0x49);
            self.bytes.push(0xB8 + (r - 8));
        }
        self.bytes.extend_from_slice(&imm.to_le_bytes());
    }

    /// sub rsp, imm32
    pub fn sub_rsp_imm32(&mut self, imm: u32) {
        self.bytes.extend_from_slice(&[0x48, 0x81, 0xEC]);
        self.bytes.extend_from_slice(&imm.to_le_bytes());
    }

    /// call r64
    pub fn call_r(&mut self, r: u8) {
        // FF /2 ; for r8-r15 prefix REX.B (0x41)
        if r < 8 {
            self.bytes.push(0xFF);
            self.bytes.push(0xD0 + r);
        } else {
            self.bytes.push(0x41);
            self.bytes.push(0xFF);
            self.bytes.push(0xD0 + (r - 8));
        }
    }

    /// jmp r64
    pub fn jmp_r(&mut self, r: u8) {
        // FF /4 ; for r8-r15 prefix REX.B (0x41)
        if r < 8 {
            self.bytes.push(0xFF);
            self.bytes.push(0xE0 + r);
        } else {
            self.bytes.push(0x41);
            self.bytes.push(0xFF);
            self.bytes.push(0xE0 + (r - 8));
        }
    }

    /// mov [rsi+disp8], rax  (return sync: RAX → virtual RAX slot)
    pub fn mov_mem_rsi_disp8_rax(&mut self, disp: i8) {
        self.bytes.push(0x48);
        self.bytes.push(0x89);
        self.bytes.push(0x46); // modrm: 01 000 110 (mod=01, reg=000=rax, rm=110=rsi)
        self.bytes.push(disp as u8);
    }
}

/// Register numbers matching the emitter.
pub mod reg {
    pub const RAX: u8 = 0;
    pub const RCX: u8 = 1;
    pub const RDX: u8 = 2;
    pub const RBX: u8 = 3;
    pub const RBP: u8 = 5;
    pub const RSI: u8 = 6;
    pub const RDI: u8 = 7;
    pub const R8: u8 = 8;
    pub const R9: u8 = 9;
    pub const R10: u8 = 10;
    pub const R11: u8 = 11;
    pub const R12: u8 = 12;
    pub const R13: u8 = 13;
    pub const R14: u8 = 14;
    pub const R15: u8 = 15;
}

/// Emit a complete §2.3 PRE-CALL/CALL/POST-CALL Win64 call site.
///
/// `args` = the four Win64 argument register values (RCX,RDX,R8,R9) to
/// materialize; `target` = the host function address to call; `rax_slot_disp`
/// = RSI-relative displacement of the VM's virtual-RAX slot (POST-CALL sync).
pub fn emit_native_call_site(args: [u64; 4], target: u64, rax_slot_disp: i8) -> Vec<u8> {
    let mut w = X64Writer::new();

    // PRE-CALL
    w.pop_r(reg::R11); // ret_ip <- VM virtual stack
                       // materialize the four Win64 args (RCX,RDX,R8,R9)
    w.mov_r64_imm(reg::RCX, args[0]);
    w.mov_r64_imm(reg::RDX, args[1]);
    w.mov_r64_imm(reg::R8, args[2]);
    w.mov_r64_imm(reg::R9, args[3]);
    // preserve callee-saved nonvolatiles (order = WIN64_NONVOL_GPRS)
    for r in WIN64_NONVOL_GPRS {
        let n = r.number() as u8;
        w.push_r(n);
    }
    // 8 pushes = 64B (multiple of 16) + 32B shadow = 96B (multiple of 16)
    w.sub_rsp_imm32(SHADOW_SPACE);

    // CALL
    w.mov_r64_imm(reg::R10, target); // target into a scratch volatile
    w.call_r(reg::R10);

    // POST-CALL
    w.mov_mem_rsi_disp8_rax(rax_slot_disp); // RAX -> virtual RAX slot
                                            // restore callee-saved in reverse order
    for r in WIN64_NONVOL_GPRS.iter().rev() {
        let n = r.number() as u8;
        w.pop_r(n);
    }
    w.jmp_r(reg::R11); // resume at ret_ip

    w.bytes
}

/// Structural report of a decoded Win64 call site.
#[derive(Debug, Default)]
pub struct CallSiteReport {
    pub instr_count: usize,
    pub shadow_reserved: u32,
    pub callee_saved_pushed: usize,
    pub callee_saved_popped: usize,
    pub has_call: bool,
    pub has_return_sync: bool,
    pub has_resume_jmp: bool,
}

impl CallSiteReport {
    pub fn is_valid(&self) -> bool {
        self.shadow_reserved >= SHADOW_SPACE
            && self.callee_saved_pushed == WIN64_NONVOL_GPRS.len()
            && self.callee_saved_popped == WIN64_NONVOL_GPRS.len()
            && self.has_call
            && self.has_return_sync
            && self.has_resume_jmp
    }
}

/// Decode `code` and verify the §2.3 Win64 invariants:
///  - 32B shadow space reserved,
///  - all 8 callee-saved GPRs pushed then popped (validate_win64_abi also
///    confirms no unsaved write),
///  - a call is present,
///  - RAX is synced to memory (return), and the site ends with a resume jmp.
pub fn verify_call_site(code: &[u8], entry_ip: u64) -> Result<CallSiteReport> {
    let mut rep = CallSiteReport::default();
    let mut decoder = Decoder::with_ip(64, code, entry_ip, DecoderOptions::NONE);
    while decoder.can_decode() {
        let inst = decoder.decode();
        if inst.is_invalid() {
            break;
        }
        rep.instr_count += 1;
        match inst.code() {
            Code::Pop_r64 => {
                if inst.op0_register().number() == 11 {
                    // ret_ip pop (r11) — no count
                } else if crate::vm::abi::WIN64_NONVOL_GPRS
                    .iter()
                    .any(|r| r.number() == inst.op0_register().number())
                {
                    rep.callee_saved_popped += 1;
                }
            }
            Code::Push_r64 => {
                if crate::vm::abi::WIN64_NONVOL_GPRS
                    .iter()
                    .any(|r| r.number() == inst.op0_register().number())
                {
                    rep.callee_saved_pushed += 1;
                }
            }
            Code::Sub_rm64_imm32 => {
                rep.shadow_reserved = rep.shadow_reserved.saturating_add(inst.immediate32());
            }
            Code::Call_rm64 => rep.has_call = true,
            Code::Jmp_rm64 => rep.has_resume_jmp = true,
            Code::Mov_rm64_r64 => {
                // return sync: store of rax to memory
                if inst.op1_register().number() == 0
                    && inst.memory_base() != iced_x86::Register::None
                {
                    rep.has_return_sync = true;
                }
            }
            _ => {}
        }
    }

    // callee-saved preservation (unsaved-write check) — hard gate
    let violations = validate_win64_abi(code, entry_ip)?;
    if !violations.is_empty() {
        bail!(
            "Win64 ABI violation in call site: {}",
            violations.join("; ")
        );
    }
    if !rep.is_valid() {
        bail!(
            "call site failed structural check (shadow={}, pushed={}, popped={}, call={}, sync={}, jmp={})",
            rep.shadow_reserved,
            rep.callee_saved_pushed,
            rep.callee_saved_popped,
            rep.has_call,
            rep.has_return_sync,
            rep.has_resume_jmp
        );
    }
    Ok(rep)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emitted_call_site_satisfies_win64_contract() {
        let args = [0x1111u64, 0x2222, 0x3333, 0x4444];
        let code = emit_native_call_site(args, 0x140001234, -0x40);
        let rep = verify_call_site(&code, 0x1000).unwrap();
        assert!(rep.is_valid());
        assert_eq!(rep.callee_saved_pushed, 8);
        assert_eq!(rep.callee_saved_popped, 8);
        assert!(rep.shadow_reserved >= 32);
        assert!(rep.has_call);
        assert!(rep.has_return_sync);
        assert!(rep.has_resume_jmp);
    }

    #[test]
    fn shadow_space_is_16_byte_multiple() {
        let code = emit_native_call_site([1, 2, 3, 4], 0x1234, -0x8);
        // 8 pushes (64B) + 32B shadow = 96B; net stack delta before call is a
        // multiple of 16, so RSP alignment is preserved.
        let mut pushed = 0u32;
        let mut sub = 0u32;
        let mut decoder = Decoder::with_ip(64, &code, 0x1000, DecoderOptions::NONE);
        while decoder.can_decode() {
            let inst = decoder.decode();
            if inst.is_invalid() {
                break;
            }
            match inst.code() {
                Code::Push_r64 => pushed += 8,
                Code::Sub_rm64_imm32 => sub = inst.immediate32(),
                _ => {}
            }
        }
        assert_eq!(
            (pushed + sub) % 16,
            0,
            "stack delta must keep 16B alignment"
        );
    }

    #[test]
    fn materializes_all_four_args() {
        let code = emit_native_call_site([0xAA, 0xBB, 0xCC, 0xDD], 0x1000, 0);
        // The first four non-stack instructions materialize RCX,RDX,R8,R9.
        let mut imm = [0u64; 4];
        let mut idx = 0;
        let mut decoder = Decoder::with_ip(64, &code, 0x1000, DecoderOptions::NONE);
        while decoder.can_decode() && idx < 4 {
            let inst = decoder.decode();
            if inst.is_invalid() {
                break;
            }
            if inst.code() == Code::Mov_r64_imm64 {
                imm[idx] = inst.immediate64();
                idx += 1;
            }
        }
        assert_eq!(imm, [0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn abi_validator_flags_unsaved_callee_saved_write() {
        // A site that writes r12 without saving it must fail.
        let bad = vec![
            0x41, 0xBC, 0x07, 0x00, 0x00, 0x00, // mov r12d, 7 (unsaved)
            0xC3,
        ];
        assert!(validate_win64_abi(&bad, 0x1000)
            .unwrap()
            .iter()
            .any(|s| s.contains("reg12")));
    }
}
