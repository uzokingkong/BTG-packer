// ==============================================================================
// BTG v26+ - P3 (G1): Commercial-engine whole-program VM module builder
// ==============================================================================
//
// `build_program_vm_commercial` wraps a whole-program RISC lift (from
// `text_lift::lift_program_cfg_commercial`) that has been `PolymorphicEncoder`-
// encoded into rolling-key bytecode, into the same `VmModule { code, table,
// bytecode }` shape the existing `place.rs` program-VM embed path expects. The
// module is:
//
//   code     = [entry stub][DirectThreadedNativeRunner::build_all_handlers]
//   table    = 256 x u64 handler table (poly opcode -> handler VA)
//   bytecode = polymorphic rolling-key bytecode (at-rest encrypted)
//
// The entry stub preserves Win64 callee-saved regs (R12..R15) and sets up the
// commercial ABI (R12=VIP, R13=VSP base, R14=rolling key, R15=handler table,
// RDX=state) then tail-dispatches — compatible with how `place.rs`'s boot stub
// dispatches the program VM (it pre-loads the original entry GPRs into the state
// buffer at `state_va` and calls the module entry).
// ==============================================================================

use crate::vm::poly::VirtualIsaSpec;
use crate::vm::risc::RiscOp;
use crate::vm::threaded::{DirectTailEmitter, DirectThreadedNativeRunner};
use crate::vm::VmModule;
use anyhow::{Result, anyhow};
use iced_x86::{Code, Instruction, Register};

/// Commercial VM state buffer size (harness layout: REGS 0x80 + TEMPS 0x40 +
/// FLAGS + VSP + padding = 0x100). Used to place the virtual stack base (R13)
/// right after the state buffer for the embedded program VM.
pub const COMMERCIAL_STATE_SIZE: u64 = 0x100;

/// P3 (G1): --vm-oep 상용 엔진 백엔드 프로그램 VM 모듈.
///
/// `lift_program_cfg_commercial`(RISC) + `PolymorphicEncoder`로 만든 폴리모픽
/// 롤링키 바이트코드를, `place.rs`의 기존 `VmModule`{code, table, bytecode} 임베드
/// 경로에 그대로 꽂히는 모듈로 감싼다:
///
/// * `code`    — [entry stub][DirectThreadedNativeRunner::build_all_handlers]
///               entry stub은 Win64 callee-saved(R12..R15) 저장 후 commercial
///               ABI(R12=VIP, R13=VSP base, R14=rolling key, R15=handler table,
///               RDX=state)를 세팅하고 tail-dispatch한다.
/// * `table`   — 256 x u64 핸들러 테이블 (poly opcode → 핸들러 VA).
/// * `bytecode`— 폴리모픽 롤링키 바이트코드 (at-rest 암호화 대상).
///
/// 상용 경로 실행 정합(부트 스텁이 state 버퍼에 entry GPR을 심고 이 엔트리로
/// 디스패치하는 것)은 T1-4 네이티브 하네스로 호스트 검증된다 (`run_native_poly` ==
/// `RiscProgram::eval_state`). 부트 스텁의 rolling-key 디스패치 재배선은
/// T1-4 임베드 런타임 완성의 별도 항목이다.
pub fn build_program_vm_commercial(
    code_va: u64,
    table_va: u64,
    bytecode_va: u64,
    bytecode: Vec<u8>,
    state_va: u64,
    seed: u64,
) -> Result<VmModule> {
    // ── entry stub: Win64 callee-saved(R12..R15) 저장 + commercial ABI 세팅 ──
    let mut es = Vec::new();
    for r in [Register::R12, Register::R13, Register::R14, Register::R15] {
        es.push(Instruction::with1(Code::Push_r64, r).map_err(|e| anyhow!("{e}"))?);
    }
    // R12 = VIP (bytecode base), R13 = VSP base (state 바로 뒤 — 호출자가 예약한
    // 스택 영역), R14 = rolling key (seed), R15 = handler table base,
    // RDX = state buffer base (boot stub이 entry GPR을 state vregs에 심은 버퍼).
    es.push(Instruction::with2(Code::Mov_r64_imm64, Register::R12, bytecode_va).map_err(|e| anyhow!("{e}"))?);
    es.push(Instruction::with2(Code::Mov_r64_imm64, Register::R13, state_va.wrapping_add(COMMERCIAL_STATE_SIZE)).map_err(|e| anyhow!("{e}"))?);
    es.push(Instruction::with2(Code::Mov_r64_imm64, Register::R14, seed).map_err(|e| anyhow!("{e}"))?);
    es.push(Instruction::with2(Code::Mov_r64_imm64, Register::R15, table_va).map_err(|e| anyhow!("{e}"))?);
    es.push(Instruction::with2(Code::Mov_r64_imm64, Register::RDX, state_va).map_err(|e| anyhow!("{e}"))?);
    DirectTailEmitter::emit_tail_dispatch(&mut es)?;
    let entry = DirectTailEmitter::assemble(es, code_va)?;

    // ── handler code (build_all_handlers) — entry 바로 뒤 ──
    let handler_base_va = code_va + entry.len() as u64;
    let handlers = DirectThreadedNativeRunner::build_all_handlers(handler_base_va)?;
    let mut handler_code = Vec::new();
    for (_name, _va, code) in &handlers {
        handler_code.extend_from_slice(code);
    }

    // ── 256-entry handler table: poly opcode → handler VA ──
    let spec = VirtualIsaSpec::from_seed(seed);
    let mut table = vec![0u8; 256 * 8];
    let va_of = |name: &str| handlers.iter().find(|(n, _, _)| n == name).map(|(_, v, _)| *v);
    let halt_va = va_of("HALT").unwrap_or(code_va);
    let mut set_slot = |op: RiscOp, name: &str| {
        if let (Some(b), Some(h)) = (spec.opcode_for(op), va_of(name)) {
            let e = b as usize * 8;
            table[e..e + 8].copy_from_slice(&h.to_le_bytes());
        }
    };
    // build_all_handlers 순서: NOR, ADD, SHR, SHL, PUSH, POP, MEM_RD, MEM_WR,
    // SET_FLAG, HALT (10개). 폭별 메모리 op/산술시프트/분기/브리지는 이 10개
    // 핸들러만으로는 커버되지 않는다 — 아래에서 HALT(safe landing)로 매핑.
    set_slot(RiscOp::Nor, "NOR");
    set_slot(RiscOp::AddWithCarry, "ADD");
    set_slot(RiscOp::ShiftRight, "SHR");
    set_slot(RiscOp::ShiftLeft, "SHL");
    set_slot(RiscOp::VirtualPush, "PUSH");
    set_slot(RiscOp::VirtualPop, "POP");
    set_slot(RiscOp::MemoryRead { width: 8 }, "MEM_RD");
    set_slot(RiscOp::MemoryWrite { width: 8 }, "MEM_WR");
    set_slot(RiscOp::SetFlag, "SET_FLAG");
    set_slot(RiscOp::Halt, "HALT");
    // 미매핑(미지원/미구현) opcode는 HALT(safe landing)로.
    for (_op, b) in &spec.opcode_map {
        let e = *b as usize * 8;
        if table[e..e + 8].iter().all(|&x| x == 0) {
            table[e..e + 8].copy_from_slice(&halt_va.to_le_bytes());
        }
    }

    let mut code = Vec::with_capacity(entry.len() + handler_code.len());
    code.extend_from_slice(&entry);
    code.extend_from_slice(&handler_code);
    Ok(VmModule { code, table, bytecode })
}
