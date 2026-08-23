use super::*;
use crate::vm::risc::{RiscEvalState, RiscProgram};
use iced_x86::{BlockEncoder, BlockEncoderOptions, Instruction, InstructionBlock};
use iced_x86::{Decoder, DecoderOptions};
use std::collections::HashMap;

/// 獄쏅뗄???甕곌쑵?곭몴??귐뗫늄??뉖릭?????뮞-IP ???紐껊쑔??筌띾벊??筌ｂ뫀????袁⑥쨮域밸챶???筌띾슢諭??
/// (?브쑨由???繹먭퍔??eval_state??VIP ?紐껊쑔??살쨮 癰궰??묐릭疫??袁る맙.)
fn lift(raw: &[u8], ip: u64) -> RiscProgram {
    let mut decoder = Decoder::with_ip(64, raw, ip, DecoderOptions::NONE);
    let mut lifter = RiscLifter::new();
    let mut ip_map = HashMap::new();
    while decoder.can_decode() {
        let inst = decoder.decode();
        ip_map.insert(inst.ip(), lifter.desynth.instrs.len());
        lifter.lift_instruction(&inst).unwrap();
    }
    RiscProgram::with_ip_map(lifter.desynth.instrs, ip_map)
}

fn run(raw: &[u8], ip: u64, init: [u64; 16]) -> RiscEvalState {
    let prog = lift(raw, ip);
    prog.eval_state(&init)
}

fn regs(st: &RiscEvalState) -> [u64; 16] {
    st.regs
}

#[test]
fn unsupported_opcode_error_preserves_guest_diagnostic() {
    let raw = [0xF4]; // HLT is intentionally kept native.
    let ip = 0x1400_0123_4;
    let mut decoder = Decoder::with_ip(64, &raw, ip, DecoderOptions::NONE);
    let inst = decoder.decode();
    let mut lifter = RiscLifter::new();

    let error = lifter
        .lift_instruction_with_bytes(&inst, &raw)
        .expect_err("HLT must remain unsupported");
    let diagnostic = error
        .downcast_ref::<RiscLiftError>()
        .expect("typed lift diagnostic");
    assert_eq!(diagnostic.ip, ip);
    assert_eq!(diagnostic.raw_bytes.as_deref(), Some(raw.as_slice()));
    assert_eq!(diagnostic.code, Code::Hlt);
    assert!(diagnostic.operands.to_ascii_lowercase().contains("hlt"));
    assert!(diagnostic.reason.contains("unsupported opcode"));

    let rendered = error.to_string();
    assert!(rendered.contains("ip=0x0000000140001234"));
    assert!(rendered.contains("bytes=[F4]"));
    assert!(rendered.contains("code=Hlt"));
}

#[test]
fn operand_error_keeps_location_without_raw_byte_api() {
    let raw = [0x88, 0xC4]; // mov ah, al; high-byte destinations are rejected.
    let ip = 0x1800_0040_0;
    let mut decoder = Decoder::with_ip(64, &raw, ip, DecoderOptions::NONE);
    let inst = decoder.decode();
    let mut lifter = RiscLifter::new();

    let error = lifter
        .lift_instruction(&inst)
        .expect_err("AH cannot be represented by the vreg model");
    let diagnostic = error
        .downcast_ref::<RiscLiftError>()
        .expect("operand failure is wrapped at the instruction boundary");
    assert_eq!(diagnostic.ip, ip);
    assert_eq!(diagnostic.raw_bytes, None);
    assert_eq!(diagnostic.code, Code::Mov_rm8_r8);
    assert!(diagnostic.operands.to_ascii_lowercase().contains("ah"));
    assert!(diagnostic.reason.contains("invalid dst"));
    assert!(error.to_string().contains("bytes=[<unavailable>]"));
}

#[test]
fn test_lift_trap_instruction_parity() {
    for (name, raw, expected_code) in [
        ("int3", &[0xCC][..], Code::Int3),
        ("ud2", &[0x0F, 0x0B][..], Code::Ud2),
        ("int imm8", &[0xCD, 0x29][..], Code::Int_imm8),
    ] {
        let mut decoder = Decoder::with_ip(64, raw, 0x140001000, DecoderOptions::NONE);
        let inst = decoder.decode();
        assert_eq!(inst.code(), expected_code, "{name}: decoded opcode");

        let mut lifter = RiscLifter::new();
        lifter.lift_instruction(&inst).unwrap();
        assert_eq!(lifter.desynth.instrs.len(), 1, "{name}: one micro-op");
        let trap = &lifter.desynth.instrs[0];
        assert_eq!(trap.op, RiscOp::Trap, "{name}: exact trap lowering");
        assert_eq!(trap.dst, None, "{name}: trap has no destination");
        assert_eq!(trap.src1, None, "{name}: trap has no source");
        assert_eq!(trap.src2, None, "{name}: trap has no second source");
    }
}

#[test]
fn test_lift_trap_preserves_registers_and_flags() {
    // mov rax, 0x1234; cmp rax, rax establishes ZF; trap; mov rax, 0x5678
    // The post-trap write must not execute, and trap itself must not alter state.
    let prefix = [
        0x48, 0xC7, 0xC0, 0x34, 0x12, 0x00, 0x00, // mov rax, 0x1234
        0x48, 0x39, 0xC0, // cmp rax, rax
    ];
    let suffix = [0x48, 0xC7, 0xC0, 0x78, 0x56, 0x00, 0x00]; // mov rax, 0x5678
    let cases: [(&str, &[u8]); 3] = [
        ("int3", &[0xCC]),
        ("ud2", &[0x0F, 0x0B]),
        ("int imm8", &[0xCD, 0x29]),
    ];

    let mut baseline_raw = prefix.to_vec();
    baseline_raw.push(0xC3); // RET lowers to Halt without changing state.
    let baseline = run(&baseline_raw, 0x140001000, [0u64; 16]);

    for (name, trap_bytes) in cases {
        let mut raw = prefix.to_vec();
        raw.extend_from_slice(trap_bytes);
        raw.extend_from_slice(&suffix);
        let trapped = run(&raw, 0x140001000, [0u64; 16]);

        assert_eq!(trapped.regs, baseline.regs, "{name}: registers unchanged");
        assert_eq!(trapped.flags, baseline.flags, "{name}: flags unchanged");
        assert_eq!(trapped.regs[0], 0x1234, "{name}: execution stops at trap");
    }
}

#[test]
fn test_lift_rip_relative_lea_without_memory_access() {
    // 0x140001000: lea rax,[rip+0x1234]
    // next IP is 0x140001007, therefore RAX = 0x14000223B.
    let raw64 = [0x48, 0x8D, 0x05, 0x34, 0x12, 0x00, 0x00];
    let st64 = run(&raw64, 0x140001000, [0u64; 16]);
    assert_eq!(regs(&st64)[0], 0x14000223B);

    // 32-bit LEA writes EAX and must zero-extend into RAX.
    let raw32 = [0x8D, 0x05, 0x34, 0x12, 0x00, 0x00];
    let st32 = run(&raw32, 0x1_4000_1000, [u64::MAX; 16]);
    assert_eq!(regs(&st32)[0], 0x4000_223A);
}

#[test]
fn test_lift_x86_to_risc_stream() {
    // x86 machine code:
    // mov rax, 100
    // mov rbx, 50
    // add rax, rbx
    // xor rax, 0x1234
    // ret
    let raw_bytes = [
        0x48, 0xC7, 0xC0, 0x64, 0x00, 0x00, 0x00, // mov rax, 100
        0x48, 0xC7, 0xC3, 0x32, 0x00, 0x00, 0x00, // mov rbx, 50
        0x48, 0x01, 0xD8, // add rax, rbx
        0x48, 0x35, 0x34, 0x12, 0x00, 0x00, // xor rax, 0x1234
        0xC3, // ret
    ];

    let mut decoder = Decoder::with_ip(64, &raw_bytes, 0x140001000, DecoderOptions::NONE);
    let mut lifter = RiscLifter::new();

    while decoder.can_decode() {
        let inst = decoder.decode();
        lifter.lift_instruction(&inst).unwrap();
    }

    let prog = RiscProgram::new(lifter.desynth.instrs);
    let regs = [0u64; 16];
    let out = prog.eval_registers(&regs);

    // (100 + 50) ^ 0x1234 = 150 ^ 4660 = 4734 (0x127E)
    assert_eq!(out[0], (100 + 50) ^ 0x1234);
    assert_eq!(out[3], 50); // rbx = 50
}

/// A: CALL ??RET ?類ｋ궗. call??癰귣벀? 雅뚯눘??next_ip)???紐꾨뻻??랁?callee嚥??브쑨由?
/// callee ??쎈뻬 ??ret(Halt)揶쎛 癰귣벀? 雅뚯눘?쇘몴???쎄문????ｋ┸??
#[test]
fn test_lift_call_ret_roundtrip() {
    // 0x140001000: call 0x140001014  (E8 rel32)
    // 0x140001005: mov rcx, 1        (fallthrough, 沃섎챷???
    // 0x14000100C: mov rdx, 2        (沃섎챷???
    // 0x140001013: ret
    // 0x140001014: mov rbx, 7        (callee)
    // 0x14000101B: ret
    let raw = [
        0xE8, 0x0F, 0x00, 0x00, 0x00, // call 0x140001014
        0x48, 0xC7, 0xC1, 0x01, 0x00, 0x00, 0x00, // mov rcx, 1
        0x48, 0xC7, 0xC2, 0x02, 0x00, 0x00, 0x00, // mov rdx, 2
        0xC3, // ret
        0x48, 0xC7, 0xC3, 0x07, 0x00, 0x00, 0x00, // mov rbx, 7
        0xC3, // ret
    ];
    let st = run(&raw, 0x140001000, [0u64; 16]);
    // callee ??쎈뻬
    assert_eq!(regs(&st)[3], 7, "rbx set in callee");
    // P0-1: callee 의 ret 가 호출자 next_ip(ip_map)로 **복귀**해 fallthrough 실행.
    assert_eq!(
        regs(&st)[1],
        1,
        "rcx executed after return (VM→VM call roundtrip)"
    );
    assert_eq!(
        regs(&st)[2],
        2,
        "rdx executed after return (VM→VM call roundtrip)"
    );
    // 복귀 주소는 pop 되어 스택이 비고, 최상위(빈 스택) ret 는 Halt.
    assert_eq!(st.stack.len(), 0, "return address popped by callee ret");
}

/// A(揶쏄쑴??: Call_rm64 ??push 癰귣벀? 雅뚯눘??+ 揶쏄쑴???브쑨由??????쎄숲 揶?.
#[test]
fn test_lift_call_indirect_register() {
    // rax = callee 雅뚯눘?쇗에??λ뜃由??
    // 0x140001000: call rax   (FF D0)
    // 0x140001002: mov rcx, 9  (沃섎챷???
    // 0x140001009: ret
    // 0x14000100A: mov rbx, 0x2A  (callee)
    // 0x140001011: ret
    let raw = [
        0xFF, 0xD0, // call rax
        0x48, 0xC7, 0xC1, 0x09, 0x00, 0x00, 0x00, // mov rcx, 9
        0xC3, // ret
        0x48, 0xC7, 0xC3, 0x2A, 0x00, 0x00, 0x00, // mov rbx, 0x2A
        0xC3, // ret
    ];
    let mut init = [0u64; 16];
    init[0] = 0x14000100A; // rax = callee
    let lifted = lift(&raw, 0x140001000);
    assert_eq!(lifted.instrs[1].op, RiscOp::VirtualIndirectCall);
    let st = run(&raw, 0x140001000, init);
    assert_eq!(regs(&st)[3], 0x2A, "indirect callee executed");
    // P0-1: 간접 call 도 복귀해 fallthrough 실행.
    assert_eq!(
        regs(&st)[1],
        9,
        "fallthrough executed after indirect call return"
    );
    assert_eq!(st.stack.len(), 0, "return address popped by callee ret");
}

#[test]
fn test_lift_indirect_jump_is_typed_and_unknown_target_fails_closed() {
    // jmp rax; mov rbx, 0x2a. An unregistered runtime target must not be
    // interpreted as a micro-instruction index and must not fall through.
    let raw = [
        0xFF, 0xE0, // jmp rax
        0x48, 0xC7, 0xC3, 0x2A, 0x00, 0x00, 0x00, // mov rbx, 0x2a
        0xC3, // ret
    ];
    let prog = lift(&raw, 0x140001000);
    assert_eq!(prog.instrs[0].op, RiscOp::VirtualIndirectJump);

    let mut init = [0u64; 16];
    init[0] = 1; // Previously this could be treated as instruction index 1.
    let st = prog.eval_state(&init);
    assert_eq!(st.regs[3], 0, "unknown route halts before fallthrough");
}

/// B: JE taken / JE not-taken / JNE taken.
#[test]
fn test_lift_jcc_je_jne() {
    // cmp rax, rbx; je 0x14000100D; mov rcx,1; ret; 0x14000100D: mov rdx,2; ret
    let raw_je = [
        0x48, 0x39, 0xD8, // cmp rax, rbx
        0x74, 0x08, // je 0x14000100D
        0x48, 0xC7, 0xC1, 0x01, 0x00, 0x00, 0x00, // mov rcx, 1
        0xC3, // ret
        0x48, 0xC7, 0xC2, 0x02, 0x00, 0x00, 0x00, // mov rdx, 2
        0xC3, // ret
    ];
    // JE taken: rax == rbx
    let mut init = [0u64; 16];
    init[0] = 0x20;
    init[3] = 0x20;
    let st = run(&raw_je, 0x140001000, init);
    assert_eq!(regs(&st)[1], 0, "JE taken: rcx skipped");
    assert_eq!(regs(&st)[2], 2, "JE taken: rdx reached");

    // JE not-taken: rax != rbx
    let mut init2 = [0u64; 16];
    init2[0] = 0x20;
    init2[3] = 0x10;
    let st2 = run(&raw_je, 0x140001000, init2);
    assert_eq!(regs(&st2)[1], 1, "JE not-taken: rcx executed");
    assert_eq!(regs(&st2)[2], 0, "JE not-taken: rdx not reached");

    // JNE taken (opcode 75): rax != rbx ??branch taken
    let mut raw_jne = raw_je;
    raw_jne[3] = 0x75;
    let st3 = run(&raw_jne, 0x140001000, init2);
    assert_eq!(regs(&st3)[1], 0, "JNE taken: rcx skipped");
    assert_eq!(regs(&st3)[2], 2, "JNE taken: rdx reached");
}

/// B + C: CMP ??JG (signed) taken / not-taken.
#[test]
fn test_lift_cmp_then_jg() {
    // cmp rax, rbx; jg 0x14000100D; mov rcx,1; ret; 0x14000100D: mov rdx,7; ret
    let raw = [
        0x48, 0x39, 0xD8, // cmp rax, rbx
        0x7F, 0x08, // jg 0x14000100D
        0x48, 0xC7, 0xC1, 0x01, 0x00, 0x00, 0x00, // mov rcx, 1
        0xC3, 0x48, 0xC7, 0xC2, 0x07, 0x00, 0x00, 0x00, // mov rdx, 7
        0xC3,
    ];
    // JG taken: 5 > 3
    let mut init = [0u64; 16];
    init[0] = 5;
    init[3] = 3;
    let st = run(&raw, 0x140001000, init);
    assert_eq!(regs(&st)[1], 0, "JG taken: rcx skipped");
    assert_eq!(regs(&st)[2], 7, "JG taken: rdx reached");

    // JG not-taken: 3 < 5 (negative result ??SF=1, OF=0 ??not greater)
    let mut init2 = [0u64; 16];
    init2[0] = 3;
    init2[3] = 5;
    let st2 = run(&raw, 0x140001000, init2);
    assert_eq!(regs(&st2)[1], 1, "JG not-taken: rcx executed");
    assert_eq!(regs(&st2)[2], 0, "JG not-taken: rdx not reached");
}

/// D: 筌롫뗀?덄뵳???깅염?怨쀬쁽 ?怨쀫떊 (read-modify-write + reg?由멷m).
#[test]
fn test_lift_memory_operand_arith() {
    // 0x140001000: mov dword [rbx], 10
    // 0x140001006: add rax, [rbx]        (rax = 0 + 10)
    // 0x140001009: add qword [rbx], 5    ([rbx] = 10 + 5 = 15)
    // 0x14000100D: mov rcx, [rbx]        (rcx = 15)
    // 0x140001010: ret
    let raw = [
        0xC7, 0x03, 0x0A, 0x00, 0x00, 0x00, // mov dword [rbx], 10
        0x48, 0x03, 0x03, // add rax, [rbx]
        0x48, 0x83, 0x03, 0x05, // add qword [rbx], 5
        0x48, 0x8B, 0x0B, // mov rcx, [rbx]
        0xC3, // ret
    ];
    let mut init = [0u64; 16];
    init[3] = 0x1000; // rbx = addr
    let st = run(&raw, 0x140001000, init);
    assert_eq!(regs(&st)[0], 10, "rax = 0 + mem10");
    assert_eq!(regs(&st)[1], 15, "rcx = 15 after read-modify-write");
    // [0x1000..0x1008] = 15 (qword little-endian)
    let mut memval = 0u64;
    for i in 0..8 {
        memval |= (st.mem.get(&(0x1000 + i)).copied().unwrap_or(0) as u64) << (i * 8);
    }
    assert_eq!(memval, 15, "memory updated by add qword [rbx],5");
}

/// E: SHL/SHR ??쀫늄??
#[test]
fn test_lift_shifts() {
    // 0x140001000: shl rax, cl   (rax = 16 << 2 = 64)
    // 0x140001003: shr rax, 2    (rax = 64 >> 2 = 16)
    // 0x140001007: ret
    let raw = [
        0x48, 0xD3, 0xE0, // shl rax, cl
        0x48, 0xC1, 0xE8, 0x02, // shr rax, 2
        0xC3,
    ];
    let mut init = [0u64; 16];
    init[0] = 16;
    init[1] = 2; // cl = 2
    let st = run(&raw, 0x140001000, init);
    assert_eq!(regs(&st)[0], 16, "16 << 2 then >> 2 = 16");
}

/// F: MOVZX 0-?類ㅼ삢.
#[test]
fn test_lift_movzx() {
    // 0x140001000: movzx rax, al   (rax = 0xFF)
    // 0x140001003: movzx rax, bx   (rax = 0xFFFF)
    // 0x140001007: ret
    let raw = [
        0x48, 0x0F, 0xB6, 0xC0, // movzx rax, al
        0x48, 0x0F, 0xB7, 0xC3, // movzx rax, bx
        0xC3,
    ];
    let mut init = [0u64; 16];
    init[0] = 0x1234_FF00_0000_00FF;
    init[3] = 0x0000_0000_0001_FFFF; // bx = 0xFFFF
    let st = run(&raw, 0x140001000, init);
    assert_eq!(regs(&st)[0], 0xFFFF, "movzx rax, bx zero-extends");
}

/// SAR (?怨쀫떊 ?怨쀫? ??쀫늄??: ???땾 揶쏅?? ?봔????쑵?껃첎? ?醫???뺣뼄.
#[test]
fn test_lift_sar_arithmetic_shift() {
    // 0x140001000: sar rax, 2   (rax = -16 >> 2 = -4)
    // 0x140001003: sar rax, 1   (rax = -4 >> 1 = -2)
    // 0x140001006: ret
    let raw = [
        0x48, 0xC1, 0xF8, 0x02, // sar rax, 2
        0x48, 0xD1, 0xF8, // sar rax, 1
        0xC3,
    ];
    let mut init = [0u64; 16];
    init[0] = (-16i64) as u64; // 0xFFFFFFFFFFFFFFF0
    let st = run(&raw, 0x140001000, init);
    // -16 >> 2 = -4 ; -4 >> 1 = -2
    assert_eq!(regs(&st)[0] as i64, -2, "SAR preserves sign bit");
}

/// MOVSX (?봔???類ㅼ삢): 8/16-bit ???뮞???봔???類ㅼ삢.
#[test]
fn test_lift_movsx_sign_extension() {
    // 0x140001000: movsx rax, al   (al = 0xFF ??-1)
    // 0x140001003: movsx rax, bx   (bx = 0x8000 ??-32768)
    // 0x140001007: ret
    let raw = [
        0x48, 0x0F, 0xBE, 0xC0, // movsx rax, al
        0x48, 0x0F, 0xBF, 0xC3, // movsx rax, bx
        0xC3,
    ];
    let mut init = [0u64; 16];
    init[0] = 0xFF; // al = 0xFF ??sign-extend ??-1
    init[3] = 0x8000; // bx = 0x8000 ??-32768
    let st = run(&raw, 0x140001000, init);
    assert_eq!(regs(&st)[0] as i64, -32768, "movsx sign-extends 16-bit");
}

/// JP/JNP: ??ㅲ봺?????삋域밸챷肉??怨뺚뀲 ?브쑨由?
#[test]
fn test_lift_jp_jnp_parity() {
    // cmp al, 3 (0b11 ??1??揶쏆뮇??2 ??筌욎빘????PF=1) ; jp 0x14000100B ; ret
    // 0x14000100B: mov rbx, 7
    // 0x140001000: cmp rax,3 (4B: 48 83 F8 03)  0x140001004: jp +1 ??0x140001007 (mov rbx,7 ??뽰삂)
    // 3 - 3 = 0 ??low byte 0b0 (0 ones, even) ??PF=1 ??JP taken.
    let raw_jp = [
        0x48, 0x83, 0xF8, 0x03, // cmp rax, 3
        0x7A, 0x01, // jp +1 ??0x140001007
        0xC3, // ret (0x140001006) ??沃섎챷???
        0x48, 0xC7, 0xC3, 0x07, 0x00, 0x00, 0x00, // mov rbx, 7 (0x140001007)
        0xC3,
    ];
    let mut init = [0u64; 16];
    init[0] = 3;
    let st = run(&raw_jp, 0x140001000, init);
    assert_eq!(regs(&st)[3], 7, "JP taken when parity even (PF set)");
}

/// JECXZ: ECX==0 ?????브쑨由?
#[test]
fn test_lift_jrcxz_counter_jump() {
    // 0x140001000: jrcxz +8 ??0x14000100A (mov rbx,7 ??뽰삂); 0x140001002 mov rbx,1; 0x140001009 ret
    // 64??쑵??筌뤴뫀諭?癒?퐣 E3??JRCXZ (RCX==0). 燁삳똻????브쑨由?嚥≪뮇彛?野꺜筌앹빘??
    let raw = [
        0xE3, 0x08, // jrcxz +8 ??0x14000100A
        0x48, 0xC7, 0xC3, 0x01, 0x00, 0x00, 0x00, // mov rbx, 1
        0xC3, 0x48, 0xC7, 0xC3, 0x07, 0x00, 0x00, 0x00, // mov rbx, 7 (0x14000100A)
        0xC3,
    ];
    // RCX == 0 ??taken
    let st = run(&raw, 0x140001000, [0u64; 16]);
    assert_eq!(regs(&st)[3], 7, "JRCXZ taken when RCX==0");
    // RCX != 0 ??not taken
    let mut init = [0u64; 16];
    init[1] = 5;
    let st2 = run(&raw, 0x140001000, init);
    assert_eq!(regs(&st2)[3], 1, "JRCXZ not taken when RCX!=0");
}

/// ?類? unsigned ?브쑨由? JA(CF=0?弛쯊=0) vs JAE(CF=0) ??揶쏆늿????筌△뫁??野꺜筌?
#[test]
fn test_lift_ja_jae_unsigned_boundary() {
    // cmp rax, rbx (rax==rbx ??ZF=1, CF=0)
    // ja 0x14000100D ??not taken (ZF=1)
    // jae 0x14000100D ??taken (CF=0)
    let raw = [
        0x48, 0x39, 0xD8, // cmp rax, rbx
        0x77, 0x08, // ja +8
        0x48, 0xC7, 0xC1, 0x01, 0x00, 0x00, 0x00, // mov rcx, 1 (ja not taken)
        0xC3, 0x48, 0xC7, 0xC2, 0x02, 0x00, 0x00, 0x00, // mov rdx, 2 (target)
        0xC3,
    ];
    let mut init = [0u64; 16];
    init[0] = 5;
    init[3] = 5;
    let st = run(&raw, 0x140001000, init);
    // JA(Above): ZF=1 ???嚥?not taken ??rcx=1 ??쎈뻬
    assert_eq!(regs(&st)[1], 1, "JA not taken when operands equal (ZF=1)");
    assert_eq!(regs(&st)[2], 0, "JA target not reached");
}

/// JBE(CF=1 ??ZF=1): 揶쏆늿????CF=0, ZF=1) taken.
#[test]
fn test_lift_jbe_unsigned_boundary() {
    // cmp rax, rbx (rax==rbx ??ZF=1, CF=0)
    // jbe 0x14000100D ??taken (ZF=1)
    let raw = [
        0x48, 0x39, 0xD8, // cmp rax, rbx
        0x76, 0x08, // jbe +8
        0x48, 0xC7, 0xC1, 0x01, 0x00, 0x00, 0x00, // mov rcx, 1 (not reached)
        0xC3, 0x48, 0xC7, 0xC2, 0x02, 0x00, 0x00, 0x00, // mov rdx, 2 (target)
        0xC3,
    ];
    let mut init = [0u64; 16];
    init[0] = 5;
    init[3] = 5;
    let st = run(&raw, 0x140001000, init);
    assert_eq!(regs(&st)[2], 2, "JBE taken when equal (ZF=1)");
    assert_eq!(regs(&st)[1], 0, "JBE target reached, fallthrough skipped");
}

/// ?袁⑥쨮嚥≪뮄?/?癒곕툡嚥≪뮄?? push rbp; mov rbp,rsp ... leave; ret.
#[test]
fn test_lift_prologue_epilogue_leave() {
    // 0x140001000: push rbp
    // 0x140001001: mov rbp, rsp
    // 0x140001004: mov rax, 5
    // 0x14000100B: leave
    // 0x14000100C: ret
    let raw = [
        0x55, // push rbp
        0x48, 0x89, 0xE5, // mov rbp, rsp
        0x48, 0xC7, 0xC0, 0x05, 0x00, 0x00, 0x00, // mov rax, 5
        0xC9, // leave
        0xC3, // ret
    ];
    let mut init = [0u64; 16];
    init[5] = 0x200; // rbp
    init[4] = 0x1000; // rsp
    let st = run(&raw, 0x140001000, init);
    assert_eq!(regs(&st)[0], 5, "rax = 5");
    assert_eq!(regs(&st)[5], 0x200, "rbp restored by leave pop");
    assert_eq!(regs(&st)[4], 0x1000, "rsp = rbp after leave");
    assert_eq!(st.stack.len(), 0, "push/pop balanced");
}

/// 32??쑵???????쎄숲 ?怨뚮┛ zero-extension: mov eax + add eax ???怨몄맄 32??쑵?껆몴?0??곗쨮.
/// `add eax, ebx`(ebx=1)??64??쑵?껅에?뺣뮉 0x100000000(??쑵??32 ?紐낅샒)?????筌?x86?? 0??곗쨮 揶쏅Ŋ???
#[test]
fn test_lift_32bit_write_zero_extends_upper_bits() {
    // 0x140001000: mov eax, 0xFFFFFFFF   (B8 FF FF FF FF)
    // 0x140001005: add eax, ebx          (01 D8)  ??ebx = 1 (?????쎄숲 ???뮞)
    // 0x140001007: ret
    let raw = [
        0xB8, 0xFF, 0xFF, 0xFF, 0xFF, // mov eax, 0xFFFFFFFF
        0x01, 0xD8, // add eax, ebx
        0xC3, // ret
    ];
    let mut init = [0u64; 16];
    init[3] = 1; // ebx = 1
    let st = run(&raw, 0x140001000, init);
    assert_eq!(
        regs(&st)[0] & 0xFFFF_FFFF_0000_0000,
        0,
        "32-bit write must zero the upper 32 bits"
    );
    assert_eq!(
        regs(&st)[0],
        0,
        "0xFFFFFFFF + 1 == 0 (wraps, zero-extended)"
    );
}

/// 32??쑵???????쎄숲 ??猷??zero-extension: mov eax, ebx ??RBX????륁맄 32??쑵?껓쭕??띯뫂釉??
/// ?怨몄맄 32??쑵?껆몴?0??곗쨮 ?類ｂ봺??뺣뼄.
#[test]
fn test_lift_32bit_mov_reg_source_zero_extends() {
    // 0x140001000: mov rbx, 0xFFFFFFFF00000001  (48 BB 01 00 00 00 FF FF FF FF)
    // 0x14000100A: mov eax, ebx                  (89 D8)
    // 0x14000100C: ret
    let raw = [
        0x48, 0xBB, 0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, // mov rbx, imm64
        0x89, 0xD8, // mov eax, ebx
        0xC3,
    ];
    let st = run(&raw, 0x140001000, [0u64; 16]);
    assert_eq!(regs(&st)[0], 1, "mov eax, ebx takes low 32 bits of rbx");
    assert_eq!(
        regs(&st)[0] & 0xFFFF_FFFF_0000_0000,
        0,
        "mov r32,r32 zero-extends the destination"
    );
}

/// MOV writes must keep x86 partial-register and flag semantics.  In
/// particular, AL/AX writes preserve the destination's upper bits, while
/// EAX writes zero-extend; none of the three may modify RFLAGS.
#[test]
fn test_lift_mov_partial_register_write_preserves_upper_bits_and_flags() {
    let mut init = [0u64; 16];
    init[0] = 0x1122_3344_5566_7788; // RAX
    init[3] = 0xAABB_CCDD_EEFF_0011; // RBX

    // cmp eax,eax sets ZF. MOV must leave that flag intact.
    let al = run(&[0x39, 0xC0, 0x88, 0xD8, 0xC3], 0x140001000, init);
    assert_eq!(
        regs(&al)[0],
        0x1122_3344_5566_7711,
        "mov al,bl preserves RAX[63:8]"
    );
    assert_ne!(al.flags & 0x40, 0, "mov al,bl preserves ZF");

    let ax = run(&[0x39, 0xC0, 0x66, 0x89, 0xD8, 0xC3], 0x140001000, init);
    assert_eq!(
        regs(&ax)[0],
        0x1122_3344_5566_0011,
        "mov ax,bx preserves RAX[63:16]"
    );
    assert_ne!(ax.flags & 0x40, 0, "mov ax,bx preserves ZF");

    let eax = run(&[0x39, 0xC0, 0x89, 0xD8, 0xC3], 0x140001000, init);
    assert_eq!(
        regs(&eax)[0],
        0x0000_0000_EEFF_0011,
        "mov eax,ebx zero-extends"
    );
    assert_ne!(eax.flags & 0x40, 0, "mov eax,ebx preserves ZF");
}

/// 32??쑵????쀫늄????쏅땾??mod 32(31 筌띾뜆???: shl eax,32 == shl eax,0, sar eax,32 == sar eax,0.
/// ?????쎄숲(CL) 燁삳똻???32??0??곗쨮 筌띾뜆???留??
#[test]
fn test_lift_32bit_shift_count_masked_mod32() {
    let mut init = [0u64; 16];
    init[0] = 0x8000_0000; // bit 31 set

    // shl eax, 32 (C1 E0 20) ??count 32 ??masked to 0
    let raw_shl = [0xC1, 0xE0, 0x20, 0xC3]; // shl eax,32 ; ret
    let st = run(&raw_shl, 0x140001000, init);
    assert_eq!(regs(&st)[0], 0x8000_0000, "shl eax,32 == shl eax,0");
    assert_eq!(
        regs(&st)[0] & 0xFFFF_FFFF_0000_0000,
        0,
        "32-bit shift result is zero-extended"
    );

    // sar eax, 32 (C1 F8 20) ??count 32 ??masked to 0
    let raw_sar = [0xC1, 0xF8, 0x20, 0xC3]; // sar eax,32 ; ret
    let st2 = run(&raw_sar, 0x140001000, init);
    assert_eq!(regs(&st2)[0], 0x8000_0000, "sar eax,32 == sar eax,0");

    // ?????쎄숲 燁삳똻??? shl eax, cl with cl=32 ??masked to 0
    let raw_shl_cl = [0xD3, 0xE0, 0xC3]; // shl eax, cl ; ret
    let mut init2 = [0u64; 16];
    init2[0] = 0x8000_0000;
    init2[1] = 32; // cl = 32 (??륁맄 8??쑵??
    let st3 = run(&raw_shl_cl, 0x140001000, init2);
    assert_eq!(regs(&st3)[0], 0x8000_0000, "shl eax,cl(32) == shl eax,0");
}

// ???? P2: ??덉쨮 ?곕떽????귐뗫늄??野껋럥以?筌△뫀踰?野꺜筌?(?醫륁굨 ?됰뗀以???μ맄 ??덊뒄) ????????????????????????????

/// MUL r64 ??RDX:RAX = RAX * rm (unsigned). low ??dst(RAX), high ??RDX.
#[test]
fn test_lift_mul_rm64() {
    // 0x140001000: mul rbx   (48 F7 E3)
    // 0x140001003: ret
    let raw = [0x48, 0xF7, 0xE3, 0xC3];
    let mut init = [0u64; 16];
    init[0] = 0x8000_0000_0000_0000; // rax
    init[3] = 2; // rbx
    let st = run(&raw, 0x140001000, init);
    assert_eq!(
        regs(&st)[0],
        0,
        "MUL low word = 0x10000000000000000 mod 2^64"
    );
    assert_eq!(regs(&st)[2], 1, "MUL high = 1 (RDX)");
}

/// IMUL r64,r64 (2-op) ??dst = low(src1*src2).
#[test]
fn test_lift_imul_2op() {
    // 0x140001000: imul rax, rbx   (48 0F AF C3)
    // 0x140001004: ret
    let raw = [0x48, 0x0F, 0xAF, 0xC3, 0xC3];
    let mut init = [0u64; 16];
    init[0] = 7;
    init[3] = 6;
    let st = run(&raw, 0x140001000, init);
    assert_eq!(regs(&st)[0], 42, "IMUL 2-op product");
}

/// IMUL r64,r64,imm8 (3-op) ??dst = src*imm.
#[test]
fn test_lift_imul_3op_imm() {
    // 0x140001000: imul rax, rbx, 5   (48 6B C3 05)
    // 0x140001004: ret
    let raw = [0x48, 0x6B, 0xC3, 0x05, 0xC3];
    let mut init = [0u64; 16];
    init[3] = 9; // rbx
    let st = run(&raw, 0x140001000, init);
    assert_eq!(regs(&st)[0], 45, "IMUL 3-op imm product");
}

/// DIV r64 ??RDX:RAX / rm ??RAX=quotient, RDX=remainder.
#[test]
fn test_lift_div_rm64() {
    // 0x140001000: div rbx   (48 F7 F3)
    // 0x140001003: ret
    let raw = [0x48, 0xF7, 0xF3, 0xC3];
    let mut init = [0u64; 16];
    init[0] = 1000; // rax
    init[2] = 0; // rdx
    init[3] = 7; // rbx
    let st = run(&raw, 0x140001000, init);
    assert_eq!(regs(&st)[0], 142, "DIV quotient");
    assert_eq!(regs(&st)[2], 6, "DIV remainder");
}

/// IDIV r64 ??signed divide.
#[test]
fn test_lift_idiv_rm64() {
    // 0x140001000: idiv rbx   (48 F7 FB)
    // 0x140001003: ret
    let raw = [0x48, 0xF7, 0xFB, 0xC3];
    let mut init = [0u64; 16];
    init[0] = (-1000i64) as u64; // rax
    init[2] = (-1i64) as u64; // rdx = sign-extended
    init[3] = 7; // rbx
    let st = run(&raw, 0x140001000, init);
    assert_eq!(regs(&st)[0] as i64, -142, "IDIV quotient");
    assert_eq!(regs(&st)[2] as i64, -6, "IDIV remainder");
}

/// BSWAP r64 ??byte order reversal.
#[test]
fn test_lift_bswap() {
    // 0x140001000: bswap rax   (48 0F C8)
    // 0x140001003: ret
    let raw = [0x48, 0x0F, 0xC8, 0xC3];
    let mut init = [0u64; 16];
    init[0] = 0x0102_0304_0506_0708;
    let st = run(&raw, 0x140001000, init);
    assert_eq!(regs(&st)[0], 0x0807_0605_0403_0201, "BSWAP reverses bytes");
}

/// BSF / BSR ??least/most-significant set bit index.
#[test]
fn test_lift_bsf_bsr() {
    // 0x140001000: bsf rax, rbx   (48 0F BC C3)
    // 0x140001004: bsr rcx, rbx   (48 0F BD CB)
    // 0x140001008: ret
    let raw = [0x48, 0x0F, 0xBC, 0xC3, 0x48, 0x0F, 0xBD, 0xCB, 0xC3];
    let mut init = [0u64; 16];
    init[3] = 0x1000; // rbx
    let st = run(&raw, 0x140001000, init);
    assert_eq!(regs(&st)[0], 12, "BSF index of bit 12");
    assert_eq!(regs(&st)[1], 12, "BSR index of bit 12");
}

/// TZCNT / LZCNT / POPCNT.
#[test]
fn test_lift_tzcnt_lzcnt_popcnt() {
    // tzcnt rax, rbx   F3 48 0F BC C3
    // lzcnt rcx, rbx   F3 48 0F BD CB
    // popcnt rdx, rbx  F3 48 0F B8 D3
    let raw = [
        0xF3, 0x48, 0x0F, 0xBC, 0xC3, 0xF3, 0x48, 0x0F, 0xBD, 0xCB, 0xF3, 0x48, 0x0F, 0xB8, 0xD3,
        0xC3,
    ];
    let mut init = [0u64; 16];
    init[3] = 0x1000; // rbx
    let st = run(&raw, 0x140001000, init);
    assert_eq!(regs(&st)[0], 12, "TZCNT = ctz(0x1000)");
    assert_eq!(regs(&st)[1], 51, "LZCNT = 63-12");
    assert_eq!(regs(&st)[2], 1, "POPCNT(0x1000) = 1");
}

/// SETcc ??flag-conditional byte write (equal ??SETE=1, SETNE=0).
#[test]
fn test_lift_setcc() {
    // cmp rax, rbx (48 39 D8) ; sete al (0F 94 C0) ; setne bl (0F 95 C3) ; ret
    let raw = [0x48, 0x39, 0xD8, 0x0F, 0x94, 0xC0, 0x0F, 0x95, 0xC3, 0xC3];
    let mut init = [0u64; 16];
    init[0] = 5;
    init[3] = 5;
    let st = run(&raw, 0x140001000, init);
    assert_eq!(regs(&st)[0] & 0xFF, 1, "SETE when equal");
    assert_eq!(regs(&st)[3] & 0xFF, 0, "SETNE when equal ??0");
}

/// CMOVcc ??conditional move (equal ??CMOVE takes).
#[test]
fn test_lift_cmovcc() {
    // cmp rax, rbx (48 39 D8) ; cmove rcx, rdx (48 0F 44 CA) ; ret
    let raw = [0x48, 0x39, 0xD8, 0x48, 0x0F, 0x44, 0xCA, 0xC3];
    let mut init = [0u64; 16];
    init[0] = 5;
    init[3] = 5;
    init[2] = 0xDEAD;
    let st = run(&raw, 0x140001000, init);
    assert_eq!(regs(&st)[1], 0xDEAD, "CMOVE taken when equal");
}

/// TEST ??AND flags without writing a destination.
#[test]
fn test_lift_test() {
    // test rax, rbx (48 85 D8) ; ret
    let raw = [0x48, 0x85, 0xD8, 0xC3];
    let mut init = [0u64; 16];
    init[0] = 0;
    init[3] = 0;
    let st = run(&raw, 0x140001000, init);
    assert_ne!(
        st.flags & crate::vm::risc::flags::VFLAG_ZF,
        0,
        "TEST 0&0 ??ZF"
    );
    // nonzero result ??ZF clear
    let mut init2 = [0u64; 16];
    init2[0] = 0xF0;
    init2[3] = 0xF0;
    let st2 = run(&raw, 0x140001000, init2);
    assert_eq!(
        st2.flags & crate::vm::risc::flags::VFLAG_ZF,
        0,
        "TEST F0&F0 ??!ZF"
    );
}

/// XCHG r64,r64 ??register swap.
#[test]
fn test_lift_xchg_reg() {
    // 0x140001000: xchg rax, rbx (48 87 D8) ; ret
    let raw = [0x48, 0x87, 0xD8, 0xC3];
    let mut init = [0u64; 16];
    init[0] = 1;
    init[3] = 2;
    let st = run(&raw, 0x140001000, init);
    assert_eq!(regs(&st)[0], 2, "XCHG rax");
    assert_eq!(regs(&st)[3], 1, "XCHG rbx");
}

/// XADD r64,r64 ??dst += src; src = old dst.
#[test]
fn test_lift_xadd_reg() {
    // 0x140001000: xadd rax, rbx (48 0F C1 D8) ; ret
    let raw = [0x48, 0x0F, 0xC1, 0xD8, 0xC3];
    let mut init = [0u64; 16];
    init[0] = 3;
    init[3] = 5;
    let st = run(&raw, 0x140001000, init);
    assert_eq!(regs(&st)[0], 8, "XADD dst = 3+5");
    assert_eq!(regs(&st)[3], 3, "XADD src = old dst");
}

/// INC / DEC ??width-masked register forms (INC preserves CF).
#[test]
fn test_lift_inc_dec() {
    // inc eax (FF C0) ; dec rax (48 FF C8) ; ret
    let raw = [0xFF, 0xC0, 0x48, 0xFF, 0xC8, 0xC3];
    let mut init = [0u64; 16];
    init[0] = 5;
    let st = run(&raw, 0x140001000, init);
    assert_eq!(regs(&st)[0], 5, "inc eax(5??) then dec rax(6??)");
}

/// RET imm16 ??RSP += imm before Halt.
#[test]
fn test_lift_ret_imm16() {
    // 0x140001000: ret 8 (C2 08 00)
    let raw = [0xC2, 0x08, 0x00];
    let st = run(&raw, 0x140001000, [0u64; 16]);
    assert_eq!(regs(&st)[4], 8, "RET imm16 advances RSP by 8");
}

/// PUSH r64 / POP r64 ??stack roundtrip.
#[test]
fn test_lift_push_pop() {
    // push rax (50) ; pop rbx (5B) ; ret
    let raw = [0x50, 0x5B, 0xC3];
    let mut init = [0u64; 16];
    init[0] = 0xCAFE;
    let st = run(&raw, 0x140001000, init);
    assert_eq!(regs(&st)[3], 0xCAFE, "push rax; pop rbx");
    assert_eq!(st.vsp, 0, "push/pop balanced");
}

/// CMPXCHG (mem form) ??lift path emits CompareExchange micro-op.
#[test]
fn test_lift_cmpxchg_mem() {
    // cmpxchg [rax], rbx (48 0F B1 18) ; ret
    let raw = [0x48, 0x0F, 0xB1, 0x18, 0xC3];
    let prog = lift(&raw, 0x140001000);
    assert!(
        prog.instrs
            .iter()
            .any(|i| matches!(i.op, RiscOp::CompareExchange { width: 8 })),
        "CMPXCHG mem lifts to CompareExchange"
    );
}

/// XCHG mem?遊켩g ??lift path emits memory RMW (read + write).
#[test]
fn test_lift_xchg_mem() {
    // xchg [rax], rbx (48 87 18) ; ret
    let raw = [0x48, 0x87, 0x18, 0xC3];
    let prog = lift(&raw, 0x140001000);
    // P0-4: 메모리 XCHG 는 암시적 LOCK — AtomicExchange 단일 원자로 lift.
    let has_atomic = prog
        .instrs
        .iter()
        .any(|i| matches!(i.op, RiscOp::AtomicExchange { .. }));
    let has_rd = prog
        .instrs
        .iter()
        .any(|i| matches!(i.op, RiscOp::MemoryRead { .. }));
    let has_wr = prog
        .instrs
        .iter()
        .any(|i| matches!(i.op, RiscOp::MemoryWrite { .. }));
    assert!(has_atomic, "XCHG mem lifts to AtomicExchange");
    assert!(
        !has_rd && !has_wr,
        "XCHG mem must not decompose into non-atomic RMW"
    );
}

/// XADD (mem form) ??lift path emits atomic LOCK XADD.
#[test]
fn test_lift_xadd_mem() {
    // xadd [rax], rbx (48 0F C1 18) ; ret
    let raw = [0x48, 0x0F, 0xC1, 0x18, 0xC3];
    let prog = lift(&raw, 0x140001000);
    // P0-4: LOCK XADD 는 원자 RMW — AtomicAdd 단일 원자로 lift.
    let has_atomic = prog
        .instrs
        .iter()
        .any(|i| matches!(i.op, RiscOp::AtomicAdd { .. }));
    let has_rd = prog
        .instrs
        .iter()
        .any(|i| matches!(i.op, RiscOp::MemoryRead { .. }));
    let has_wr = prog
        .instrs
        .iter()
        .any(|i| matches!(i.op, RiscOp::MemoryWrite { .. }));
    assert!(has_atomic, "XADD mem lifts to AtomicAdd");
    assert!(
        !has_rd && !has_wr,
        "XADD mem must not decompose into non-atomic RMW"
    );
}

/// BMI1 ANDN ??lift path emits NOT+AND (VEX encoding via BlockEncoder).
#[test]
fn test_lift_andn() {
    use iced_x86::{
        BlockEncoder, BlockEncoderOptions, Code, Instruction, InstructionBlock, Register,
    };
    let insts = vec![
        Instruction::with3(
            Code::VEX_Andn_r64_r64_rm64,
            Register::RAX,
            Register::RBX,
            Register::RCX,
        )
        .unwrap(),
        Instruction::with(Code::Retnq),
    ];
    let blk = InstructionBlock::new(&insts, 0x140001000);
    let enc = BlockEncoder::encode(64, blk, BlockEncoderOptions::NONE).unwrap();
    let mut init = [0u64; 16];
    init[3] = 0x0F; // rbx (vreg 3)
    init[1] = 0xFF; // rcx (vreg 1)
    let st = run(&enc.code_buffer, 0x140001000, init);
    assert_eq!(regs(&st)[0], 0xF0, "ANDN = ~rbx & rcx = ~0x0F & 0xFF");
}

// ???? P2: ?얜챷???ops 筌△뫀踰?野꺜筌?(?醫륁굨 ?됰뗀以???μ맄 ??덊뒄) ????????????????????????????????????????????????????

/// ???뮞??筌롫뗀?덄뵳????? ?귐??遺얜탵??`width`獄쏅뗄???疫꿸퀡以?
fn seed_mem(mem: &mut HashMap<u64, u8>, addr: u64, width: u8, val: u64) {
    for i in 0..width {
        mem.insert(addr.wrapping_add(i as u64), (val >> (i as u64 * 8)) as u8);
    }
}

/// ???뮞??筌롫뗀?덄뵳????? ?귐??遺얜탵??`width`獄쏅뗄?????꾨┛.
fn read_mem(mem: &HashMap<u64, u8>, addr: u64, width: u8) -> u64 {
    let mut v = 0u64;
    for i in 0..width {
        v |= (*mem.get(&addr.wrapping_add(i as u64)).unwrap_or(&0) as u64) << (i as u64 * 8);
    }
    v
}

/// lift + `eval_state_with_mem` ??쎈뻬 ????
fn run_mem(raw: &[u8], ip: u64, init: [u64; 16], mem: HashMap<u64, u8>) -> RiscEvalState {
    lift(raw, ip).eval_state_with_mem(&init, mem)
}

#[test]
fn test_lift_mov_mem_bh_preserves_flags() {
    // cmp rax,rax; mov byte ptr [rsp+2Ah],bh; ret.  CMP establishes ZF,
    // and the following MOV must not disturb it.
    let raw = [0x48, 0x39, 0xc0, 0x88, 0x7c, 0x24, 0x2a, 0xc3];
    let mut init = [0u64; 16];
    init[3] = 0x1122_3344_5566_a5ff;
    init[4] = 0x2000;
    let st = lift(&raw, 0x140001000).eval_state_with_mem(&init, HashMap::new());
    assert_eq!(st.mem.get(&0x202a), Some(&0xa5), "BH byte stored");
    assert_ne!(
        st.flags & crate::vm::risc::flags::VFLAG_ZF,
        0,
        "MOV must preserve ZF"
    );
}

/// BlockEncoder 嚥?x86 筌뤿굝議??됰뗀以??獄쏅뗄??紐껋쨮 ?紐꾪맜??
fn enc_block(insts: Vec<Instruction>) -> Vec<u8> {
    let blk = InstructionBlock::new(&insts, 0x140001000);
    BlockEncoder::encode(64, blk, BlockEncoderOptions::NONE)
        .unwrap()
        .code_buffer
}

/// XMM(i) ????揶쎛??雅뚯눘??(?귐뗫늄?怨? ??덉뵬 ?④쑴鍮?.
fn xmm_slot(idx: u8) -> u64 {
    super::XMM_SLOT_BASE + (idx as u64) * 16
}

/// MOVSB (??μ뵬) ??[rdi]=[rsi]; rsi/rdi += 1.
#[test]
fn test_lift_movsb_single() {
    let raw = [0xA4, 0xC3];
    let mut init = [0u64; 16];
    init[6] = 0x1000;
    init[7] = 0x2000;
    let mut mem = HashMap::new();
    mem.insert(0x1000, 0xAB);
    let st = run_mem(&raw, 0x140001000, init, mem);
    assert_eq!(st.regs[6], 0x1001, "rsi advanced by 1");
    assert_eq!(st.regs[7], 0x2001, "rdi advanced by 1");
    assert_eq!(st.mem.get(&0x2000), Some(&0xAB), "byte copied");
}

/// STOSD (??μ뵬) ??[rdi]=EAX; rdi+=4.
#[test]
fn test_lift_stosd_single() {
    let raw = [0xAB, 0xC3];
    let mut init = [0u64; 16];
    init[0] = 0xDEAD_BEEF;
    init[7] = 0x2000;
    let st = run_mem(&raw, 0x140001000, init, HashMap::new());
    assert_eq!(st.regs[7], 0x2004, "rdi advanced by 4");
    assert_eq!(read_mem(&st.mem, 0x2000, 4), 0xDEAD_BEEF, "dword stored");
}

/// LODSW (??μ뵬) ??AX = [rsi] (0-?類ㅼ삢); rsi+=2.
#[test]
fn test_lift_lodsw_single() {
    let raw = [0x66, 0xAD, 0xC3];
    let mut init = [0u64; 16];
    init[0] = 0x1122_3344_5566_7788; // RAX upper bits must be PRESERVED
    init[6] = 0x1000;
    let mut mem = HashMap::new();
    seed_mem(&mut mem, 0x1000, 2, 0x7AB9);
    let st = run_mem(&raw, 0x140001000, init, mem);
    // LODSW writes only AX: upper 48 bits of RAX stay intact.
    assert_eq!(
        st.regs[0], 0x1122_3344_5566_7AB9,
        "AX written, upper bits preserved"
    );
    assert_eq!(st.regs[6], 0x1002, "rsi advanced by 2");
}

/// SCASB (??μ뵬) ??flags = AL - [rdi]; rdi+=1.
#[test]
fn test_lift_scasb_single() {
    let raw = [0xAE, 0xC3];
    let mut init = [0u64; 16];
    init[0] = 0x20;
    init[7] = 0x2000;
    let mut mem = HashMap::new();
    mem.insert(0x2000, 0x20);
    let st = run_mem(&raw, 0x140001000, init, mem);
    assert_eq!(st.regs[7], 0x2001, "rdi advanced");
    assert_ne!(
        st.flags & crate::vm::risc::flags::VFLAG_ZF,
        0,
        "AL == [rdi] -> ZF"
    );
}

/// CMPSQ (??μ뵬) ??flags = [rsi] - [rdi]; rsi+=8; rdi+=8.
#[test]
fn test_lift_cmpsq_single() {
    let raw = [0x48, 0xA7, 0xC3];
    let mut init = [0u64; 16];
    init[6] = 0x1000;
    init[7] = 0x2000;
    let mut mem = HashMap::new();
    seed_mem(&mut mem, 0x1000, 8, 0x1234);
    seed_mem(&mut mem, 0x2000, 8, 0x1234);
    let st = run_mem(&raw, 0x140001000, init, mem);
    assert_eq!(st.regs[6], 0x1008, "rsi advanced by 8");
    assert_eq!(st.regs[7], 0x2008, "rdi advanced by 8");
    assert_ne!(
        st.flags & crate::vm::risc::flags::VFLAG_ZF,
        0,
        "equal -> ZF"
    );
}

/// REP MOVSB ??燁삳똻?????쇱뒲 ?룐뫂遊? rcx ???돩, rsi/rdi += n*count, 筌롫뗀?덄뵳?癰귣벊沅?
#[test]
fn test_lift_rep_movsb() {
    let raw = [0xF3, 0xA4, 0xC3];
    let mut init = [0u64; 16];
    init[6] = 0x1000;
    init[7] = 0x2000;
    init[1] = 3;
    let mut mem = HashMap::new();
    mem.insert(0x1000, 0x11);
    mem.insert(0x1001, 0x22);
    mem.insert(0x1002, 0x33);
    let st = run_mem(&raw, 0x140001000, init, mem);
    assert_eq!(st.regs[1], 0, "rcx consumed");
    assert_eq!(st.regs[6], 0x1003, "rsi += 3");
    assert_eq!(st.regs[7], 0x2003, "rdi += 3");
    assert_eq!(st.mem.get(&0x2000), Some(&0x11));
    assert_eq!(st.mem.get(&0x2002), Some(&0x33));
}

/// v65: `std; rep movsb` ??DF=1 ??rsi/rdi DECREMENTED, bytes copied backward.
#[test]
fn test_lift_std_rep_movsb_backward() {
    let raw = [0xFD, 0xF3, 0xA4, 0xC3]; // std; rep movsb
    let mut init = [0u64; 16];
    init[6] = 0x1002; // rsi = last byte of source {0x11,0x22,0x33}
    init[7] = 0x2003; // rdi = last byte of dest
    init[1] = 3;
    let mut mem = HashMap::new();
    mem.insert(0x1000, 0x11);
    mem.insert(0x1001, 0x22);
    mem.insert(0x1002, 0x33);
    let st = run_mem(&raw, 0x140001000, init, mem);
    assert_eq!(st.regs[1], 0, "rcx consumed");
    assert_eq!(st.regs[6], 0x0FFF, "std rsi -= 3");
    assert_eq!(st.regs[7], 0x2000, "std rdi -= 3");
    // iter i writes [rdi] BEFORE decrementing: 0x2003,0x2002,0x2001
    assert_eq!(
        st.mem.get(&0x2003),
        Some(&0x33),
        "backward copy: first iter writes [0x2003]"
    );
    assert_eq!(st.mem.get(&0x2002), Some(&0x22));
    assert_eq!(st.mem.get(&0x2001), Some(&0x11));
    // DF bit must remain set in the modelled flags
    assert_ne!(
        st.flags & crate::vm::risc::flags::VFLAG_DF,
        0,
        "std leaves DF set"
    );
}

/// REP STOSB ???룐뫂遊썸에?筌롫뗀?덄뵳?筌?쑴??묾?
#[test]
fn test_lift_rep_stosb() {
    let raw = [0xF3, 0xAA, 0xC3];
    let mut init = [0u64; 16];
    init[0] = 0x5A;
    init[7] = 0x2000;
    init[1] = 4;
    let st = run_mem(&raw, 0x140001000, init, HashMap::new());
    assert_eq!(st.regs[1], 0, "rcx consumed");
    assert_eq!(st.regs[7], 0x2004, "rdi += 4");
    for i in 0..4u64 {
        assert_eq!(st.mem.get(&(0x2000 + i)), Some(&0x5A), "byte {i} stored");
    }
}

/// REP LODSQ ???룐뫂遊썸에?RAX 揶쏄퉮??(筌띾뜆?筌?嚥≪뮆諭?, rsi += 8*count.
#[test]
fn test_lift_rep_lodsq() {
    let raw = [0xF3, 0x48, 0xAD, 0xC3];
    let mut init = [0u64; 16];
    init[6] = 0x1000;
    init[1] = 3;
    let mut mem = HashMap::new();
    seed_mem(&mut mem, 0x1000, 8, 111);
    seed_mem(&mut mem, 0x1008, 8, 222);
    seed_mem(&mut mem, 0x1010, 8, 333);
    let st = run_mem(&raw, 0x140001000, init, mem);
    assert_eq!(st.regs[1], 0, "rcx consumed");
    assert_eq!(st.regs[6], 0x1018, "rsi += 24");
    assert_eq!(st.regs[0], 333, "last loaded qword");
}

/// REPE SCASB ???븍뜆?ょ㎉?뤿퓠??餓λ쵎?? rdi/rcx ??餓λ쵎??獄쏆꼶?ф틦?? 筌욊쑵六? 筌ㅼ뮇伊????삋域?= 筌띾뜆?筌???쑨??
#[test]
fn test_lift_repe_scasb_stops_on_mismatch() {
    let raw = [0xF3, 0xAE, 0xC3];
    let mut init = [0u64; 16];
    init[0] = 0x20;
    init[7] = 0x2000;
    init[1] = 3;
    let mut mem = HashMap::new();
    mem.insert(0x2000, 0x20); // match -> continue
    mem.insert(0x2001, 0x21); // mismatch -> stop
    let st = run_mem(&raw, 0x140001000, init, mem);
    assert_eq!(st.regs[7], 0x2002, "two iterations advanced rdi");
    assert_eq!(st.regs[1], 1, "rcx = 3-2");
    assert_eq!(
        st.flags & crate::vm::risc::flags::VFLAG_ZF,
        0,
        "final compare not equal -> ZF clear"
    );
}

/// REPNE CMPSW ????깊뒄?癒?퐣 餓λ쵎??(REPNE ??ZF=1 ?癒?퐣 ?類?).
#[test]
fn test_lift_repne_cmpsw_stops_on_match() {
    let raw = [0xF2, 0x66, 0xA7, 0xC3];
    let mut init = [0u64; 16];
    init[6] = 0x1000;
    init[7] = 0x2000;
    init[1] = 4;
    let mut mem = HashMap::new();
    seed_mem(&mut mem, 0x1000, 2, 0x1111);
    seed_mem(&mut mem, 0x2000, 2, 0x2222);
    seed_mem(&mut mem, 0x1002, 2, 0x3333);
    seed_mem(&mut mem, 0x2002, 2, 0x3333);
    let st = run_mem(&raw, 0x140001000, init, mem);
    assert_eq!(st.regs[6], 0x1004, "two iters advanced rsi");
    assert_eq!(st.regs[7], 0x2004, "two iters advanced rdi");
    assert_eq!(st.regs[1], 2, "rcx = 4-2");
    assert_ne!(
        st.flags & crate::vm::risc::flags::VFLAG_ZF,
        0,
        "final compare equal -> ZF set"
    );
}

// ???? P2: SSE/FPU ??쇰???筌△뫀踰?野꺜筌?????????????????????????????????????????????????????????????????????????????????????

/// ADDSD xmm0, xmm1 ??1.5 + 2.25 = 3.75.
#[test]
fn test_lift_addsd() {
    let raw = enc_block(vec![
        Instruction::with2(Code::Addsd_xmm_xmmm64, Register::XMM0, Register::XMM1).unwrap(),
        Instruction::with(Code::Retnq),
    ]);
    let mut mem = HashMap::new();
    seed_mem(&mut mem, xmm_slot(0), 8, 1.5f64.to_bits());
    seed_mem(&mut mem, xmm_slot(1), 8, 2.25f64.to_bits());
    let st = run_mem(&raw, 0x140001000, [0u64; 16], mem);
    assert_eq!(
        f64::from_bits(read_mem(&st.mem, xmm_slot(0), 8)),
        3.75,
        "1.5 + 2.25"
    );
}

/// MULSD + DIVSD ??(3.0 * 2.0) / 4.0 = 1.5.
#[test]
fn test_lift_mulsd_divsd() {
    let raw = enc_block(vec![
        Instruction::with2(Code::Mulsd_xmm_xmmm64, Register::XMM0, Register::XMM1).unwrap(),
        Instruction::with2(Code::Divsd_xmm_xmmm64, Register::XMM0, Register::XMM2).unwrap(),
        Instruction::with(Code::Retnq),
    ]);
    let mut mem = HashMap::new();
    seed_mem(&mut mem, xmm_slot(0), 8, 3.0f64.to_bits());
    seed_mem(&mut mem, xmm_slot(1), 8, 2.0f64.to_bits());
    seed_mem(&mut mem, xmm_slot(2), 8, 4.0f64.to_bits());
    let st = run_mem(&raw, 0x140001000, [0u64; 16], mem);
    assert_eq!(
        f64::from_bits(read_mem(&st.mem, xmm_slot(0), 8)),
        1.5,
        "mul then div"
    );
}

/// SUBSS (f32) ??5.5f32 - 1.25f32 = 4.25f32.
#[test]
fn test_lift_subss() {
    let raw = enc_block(vec![
        Instruction::with2(Code::Subss_xmm_xmmm32, Register::XMM0, Register::XMM1).unwrap(),
        Instruction::with(Code::Retnq),
    ]);
    let mut mem = HashMap::new();
    seed_mem(&mut mem, xmm_slot(0), 4, 5.5f32.to_bits() as u64);
    seed_mem(&mut mem, xmm_slot(1), 4, 1.25f32.to_bits() as u64);
    let st = run_mem(&raw, 0x140001000, [0u64; 16], mem);
    assert_eq!(
        f32::from_bits(read_mem(&st.mem, xmm_slot(0), 4) as u32),
        4.25f32
    );
}

/// CVTSI2SD xmm0, rax ???類ㅻ땾 -> double.
#[test]
fn test_lift_cvtsi2sd() {
    let raw = enc_block(vec![
        Instruction::with2(Code::Cvtsi2sd_xmm_rm64, Register::XMM0, Register::RAX).unwrap(),
        Instruction::with(Code::Retnq),
    ]);
    let mut init = [0u64; 16];
    init[0] = 42;
    let st = run_mem(&raw, 0x140001000, init, HashMap::new());
    assert_eq!(f64::from_bits(read_mem(&st.mem, xmm_slot(0), 8)), 42.0);
}

/// CVTSS2SD (f32->f64) + CVTSD2SS (f64->f32).
#[test]
fn test_lift_cvtss2sd_cvtsd2ss() {
    let raw = enc_block(vec![
        Instruction::with2(Code::Cvtss2sd_xmm_xmmm32, Register::XMM1, Register::XMM0).unwrap(),
        Instruction::with2(Code::Cvtsd2ss_xmm_xmmm64, Register::XMM2, Register::XMM1).unwrap(),
        Instruction::with(Code::Retnq),
    ]);
    let mut mem = HashMap::new();
    seed_mem(&mut mem, xmm_slot(0), 4, 2.5f32.to_bits() as u64);
    let st = run_mem(&raw, 0x140001000, [0u64; 16], mem);
    assert_eq!(
        f64::from_bits(read_mem(&st.mem, xmm_slot(1), 8)),
        2.5,
        "f32->f64"
    );
    assert_eq!(
        f32::from_bits(read_mem(&st.mem, xmm_slot(2), 4) as u32),
        2.5f32,
        "f64->f32"
    );
}

/// CVTTSS2SI(trunc) vs CVTSS2SI(nearest-even) ??half-way 獄쏆꼷?긺뵳?筌△뫁??
#[test]
fn test_lift_cvttss2si_trunc_vs_cvtss2si_round() {
    let raw = enc_block(vec![
        Instruction::with2(Code::Cvttss2si_r64_xmmm32, Register::RAX, Register::XMM0).unwrap(), // trunc(2.5)=2
        Instruction::with2(Code::Cvtss2si_r64_xmmm32, Register::RBX, Register::XMM0).unwrap(), // rne(2.5)=2
        Instruction::with2(Code::Cvttss2si_r64_xmmm32, Register::RCX, Register::XMM1).unwrap(), // trunc(3.5)=3
        Instruction::with2(Code::Cvtss2si_r64_xmmm32, Register::RDX, Register::XMM1).unwrap(), // rne(3.5)=4
        Instruction::with(Code::Retnq),
    ]);
    let mut mem = HashMap::new();
    seed_mem(&mut mem, xmm_slot(0), 4, 2.5f32.to_bits() as u64);
    seed_mem(&mut mem, xmm_slot(1), 4, 3.5f32.to_bits() as u64);
    let st = run_mem(&raw, 0x140001000, [0u64; 16], mem);
    assert_eq!(st.regs[0] as i64, 2, "trunc(2.5)=2 (rax)");
    assert_eq!(st.regs[3] as i64, 2, "rne(2.5)=2 even (rbx)");
    assert_eq!(st.regs[1] as i64, 3, "trunc(3.5)=3 (rcx)");
    assert_eq!(st.regs[2] as i64, 4, "rne(3.5)=4 even (rdx)");
}

/// MOVSD xmm0, xmm1 (?????쎄숲 嚥≪뮆諭??? ????륁맄 8獄쏅뗄???癰귣벊沅?
#[test]
fn test_lift_movsd_reg() {
    let raw = enc_block(vec![
        Instruction::with2(Code::Movsd_xmm_xmmm64, Register::XMM0, Register::XMM1).unwrap(),
        Instruction::with(Code::Retnq),
    ]);
    let mut mem = HashMap::new();
    seed_mem(&mut mem, xmm_slot(1), 8, 9.75f64.to_bits());
    let st = run_mem(&raw, 0x140001000, [0u64; 16], mem);
    assert_eq!(f64::from_bits(read_mem(&st.mem, xmm_slot(0), 8)), 9.75);
}

/// MOVSD [rax], xmm0 (筌롫뗀?덄뵳???쎈꽅?? + MOVSD xmm1, [rax] (筌롫뗀?덄뵳?嚥≪뮆諭?.
#[test]
fn test_lift_movsd_mem_load_store() {
    let raw = enc_block(vec![
        Instruction::with2(
            Code::Movsd_xmmm64_xmm,
            iced_x86::MemoryOperand::with_base(Register::RAX),
            Register::XMM0,
        )
        .unwrap(),
        Instruction::with2(
            Code::Movsd_xmm_xmmm64,
            Register::XMM1,
            iced_x86::MemoryOperand::with_base(Register::RAX),
        )
        .unwrap(),
        Instruction::with(Code::Retnq),
    ]);
    let mut init = [0u64; 16];
    init[0] = 0x4000;
    let mut mem = HashMap::new();
    seed_mem(&mut mem, xmm_slot(0), 8, 1234.5f64.to_bits());
    let st = run_mem(&raw, 0x140001000, init, mem);
    assert_eq!(
        f64::from_bits(read_mem(&st.mem, 0x4000, 8)),
        1234.5,
        "stored to mem"
    );
    assert_eq!(
        f64::from_bits(read_mem(&st.mem, xmm_slot(1), 8)),
        1234.5,
        "loaded back to xmm1"
    );
}

// ???? P2: BMI (BLSR/BLSMSK/BLSI/BZHI) 筌△뫀踰?野꺜筌?????????????????????????????????????????????????????????

/// BLSR r64 ??x & (x-1) (lowest set bit clear).
#[test]
fn test_lift_blsr() {
    let raw = enc_block(vec![
        Instruction::with2(Code::VEX_Blsr_r64_rm64, Register::RAX, Register::RBX).unwrap(),
        Instruction::with(Code::Retnq),
    ]);
    let mut init = [0u64; 16];
    init[3] = 0b1110;
    let st = run_mem(&raw, 0x140001000, init, HashMap::new());
    assert_eq!(st.regs[0], 0b1100, "BLSR(0b1110) = 0b1110 & 0b1101");
}

/// BLSMSK r64 ??x ^ (x-1).
#[test]
fn test_lift_blsmsk() {
    let raw = enc_block(vec![
        Instruction::with2(Code::VEX_Blsmsk_r64_rm64, Register::RAX, Register::RBX).unwrap(),
        Instruction::with(Code::Retnq),
    ]);
    let mut init = [0u64; 16];
    init[3] = 0b1110;
    let st = run_mem(&raw, 0x140001000, init, HashMap::new());
    assert_eq!(st.regs[0], 0b0011, "BLSMSK(0b1110) = 0b1110 ^ 0b1101");
}

/// BLSI r64 ??x & -x (lowest set bit).
#[test]
fn test_lift_blsi() {
    let raw = enc_block(vec![
        Instruction::with2(Code::VEX_Blsi_r64_rm64, Register::RAX, Register::RBX).unwrap(),
        Instruction::with(Code::Retnq),
    ]);
    let mut init = [0u64; 16];
    init[3] = 0x18;
    let st = run_mem(&raw, 0x140001000, init, HashMap::new());
    assert_eq!(st.regs[0], 0b1000, "BLSI(0x18) = lowest set bit");
}

/// BZHI r64, r/m64, r64 ??dst = x & ((1<<idx)-1).
#[test]
fn test_lift_bzhi() {
    let raw = enc_block(vec![
        Instruction::with3(
            Code::VEX_Bzhi_r64_rm64_r64,
            Register::RAX,
            Register::RBX,
            Register::RCX,
        )
        .unwrap(),
        Instruction::with(Code::Retnq),
    ]);
    let mut init = [0u64; 16];
    init[3] = 0xFF;
    init[1] = 4;
    let st = run_mem(&raw, 0x140001000, init, HashMap::new());
    assert_eq!(st.regs[0], 0x0F, "BZHI(0xFF, 4) = 0x0F");
}

// ── R7: 8/16-bit 논리(XOR/AND/OR)·시프트(SHL/SHR)·NEG/NOT ────────────────
// 참조: 레거시 `vm/lifter/arith.rs::lift_narrow_arith`, `vm/lifter/mod.rs`
// (Xor_rm8/16, And_rm8/16, Or_rm8/16, Shl_rm8/16, Shr_rm8/16, Neg/Not_rm8/16).
// 검증 포인트: (a) 8/16비트 결과의 상위 비트 보존(레지스터), (b) 플래그 폭.

/// R7: 8-bit XOR register (상위 비트 보존).
#[test]
fn test_lift_8bit_xor_reg_preserve_upper() {
    // xor al, bl   (0x30 0xD8) — AL=0x5A ^ BL=0x0F = 0x55, 상위 56비트 보존.
    let raw = [0x30, 0xD8, 0xC3];
    let mut init = [0u64; 16];
    init[0] = 0x1122_3344_5566_775A; // RAX 상위 비트 + AL=0x5A
    init[3] = 0x0000_0000_0000_000F; // BL = 0x0F
    let st = run(&raw, 0x140001000, init);
    assert_eq!(
        regs(&st)[0],
        0x1122_3344_5566_7755,
        "XOR AL low byte, upper preserved"
    );
}

/// R7: 16-bit AND register (상위 비트 보존).
#[test]
fn test_lift_16bit_and_reg_preserve_upper() {
    // and ax, bx  (0x66 0x21 0xD8) — AX = 0x7FFF & 0x0F0F = 0x0F0F.
    let raw = [0x66, 0x21, 0xD8, 0xC3];
    let mut init = [0u64; 16];
    init[0] = 0x1122_3344_5566_7FFF;
    init[3] = 0x0000_0000_0000_0F0F;
    let st = run(&raw, 0x140001000, init);
    assert_eq!(
        regs(&st)[0],
        0x1122_3344_5566_0F0F,
        "AND AX low word, upper preserved"
    );
}

/// R7: 8-bit OR immediate (AL = AL | 0x0F).
#[test]
fn test_lift_8bit_or_imm() {
    // or al, 0x0F  (0x0C 0x0F) — AL = 0x10 | 0x0F = 0x1F.
    let raw = [0x0C, 0x0F, 0xC3];
    let mut init = [0u64; 16];
    init[0] = 0x1122_3344_5566_7710;
    let st = run(&raw, 0x140001000, init);
    assert_eq!(regs(&st)[0], 0x1122_3344_5566_771F, "OR AL imm");
}

/// R7: 8/16-bit XOR memory RMW (레지스터 피연산자 마스킹).
#[test]
fn test_lift_8bit_xor_mem_rmw() {
    // xor byte ptr [rbx], al  (0x30 0x03) — [0x1000] ^= AL.
    let raw = [0x30, 0x03, 0xC3];
    let mut init = [0u64; 16];
    init[3] = 0x1000;
    init[0] = 0x0000_0000_0000_000F; // AL = 0x0F
    let mut mem = HashMap::new();
    mem.insert(0x1000, 0x51);
    let st = run_mem(&raw, 0x140001000, init, mem);
    assert_eq!(st.mem.get(&0x1000), Some(&0x5E), "mem byte ^= AL");
}

/// R7: 8-bit SHL register (카운트 mod 8 경계 + 상위 보존).
#[test]
fn test_lift_8bit_shl_reg() {
    // shl al, 2  (0xC0 0xE0 0x02) — AL = 0x40 << 2 = 0x00 (8-bit wrap).
    let raw = [0xC0, 0xE0, 0x02, 0xC3];
    let mut init = [0u64; 16];
    init[0] = 0x1122_3344_5566_7740;
    let st = run(&raw, 0x140001000, init);
    assert_eq!(
        regs(&st)[0],
        0x1122_3344_5566_7700,
        "SHL AL,2 = 0x00, upper preserved"
    );
}

/// R7: 16-bit SHR register (상위 워드 0, 상위 비트 보존).
#[test]
fn test_lift_16bit_shr_reg() {
    // shr ax, 4  (0x66 0xC1 0xE8 0x04) — AX = 0x8000 >> 4 = 0x0800.
    let raw = [0x66, 0xC1, 0xE8, 0x04, 0xC3];
    let mut init = [0u64; 16];
    init[0] = 0x1122_3344_5566_8000;
    let st = run(&raw, 0x140001000, init);
    assert_eq!(regs(&st)[0], 0x1122_3344_5566_0800, "SHR AX,4");
}

/// R7: 8/16-bit NEG/NOT (플래그 + 상위 보존).
#[test]
fn test_lift_8bit_neg_not() {
    // neg al (0xF6 0xD8); not al (0xF6 0xD0)
    let raw = [0xF6, 0xD8, 0xF6, 0xD0, 0xC3];
    let mut init = [0u64; 16];
    init[0] = 0x1122_3344_5566_7701; // AL = 1 → NEG = 0xFF → NOT = 0x00
    let st = run(&raw, 0x140001000, init);
    assert_eq!(regs(&st)[0], 0x1122_3344_5566_7700, "NEG then NOT AL");
}

/// R7: 16-bit NEG memory (부호 반전 + 메모리 폭 쓰기).
#[test]
fn test_lift_16bit_neg_mem() {
    // neg word ptr [rbx]  (0x66 0xF7 0x1B) — [0x1000] = -0x0010 = 0xFFF0.
    let raw = [0x66, 0xF7, 0x1B, 0xC3];
    let mut init = [0u64; 16];
    init[3] = 0x1000;
    let mut mem = HashMap::new();
    mem.insert(0x1000, 0x10);
    mem.insert(0x1001, 0x00);
    let st = run_mem(&raw, 0x140001000, init, mem);
    let mut v = 0u64;
    for i in 0..2 {
        v |= (*st.mem.get(&(0x1000 + i)).unwrap_or(&0) as u64) << (i * 8);
    }
    assert_eq!(v, 0xFFF0, "NEG word [mem] = 0xFFF0");
}

// ── P1 (②): packed SSE — XMM 슬롯 기반 128-bit 정수 연산 ───────────────────
// lifter → `eval_state`(참조) 실행. 검증 포인트:
// (a) 요소 단위 연산 (PADDQ 에서 lane 간 캐리 미전파 — 보고서 ② 핵심),
// (b) RFLAGS 불변 (packed 정수 연산은 x86 에서도 플래그를 안 바꾼다),
// (c) 메모리 소스/대상 폼.

/// 16바이트 시드 (하위 8B + 상위 8B).
fn seed_slot(mem: &mut HashMap<u64, u8>, addr: u64, lo: u64, hi: u64) {
    seed_mem(mem, addr, 8, lo);
    seed_mem(mem, addr + 8, 8, hi);
}

fn read_slot(mem: &HashMap<u64, u8>, addr: u64) -> (u64, u64) {
    (read_mem(mem, addr, 8), read_mem(mem, addr + 8, 8))
}

/// PADDQ lane 경계 — lane 0 이 캐리를 만들면 lane 1 로 **전파되지 않아야** 한다.
/// (64-bit add 로 분해했다면 캐리가 전파되어 틀렸을 케이스)
#[test]
fn test_lift_paddq_no_lane_carry() {
    let raw = enc_block(vec![
        Instruction::with2(Code::Paddq_xmm_xmmm128, Register::XMM0, Register::XMM1).unwrap(),
        Instruction::with(Code::Retnq),
    ]);
    let mut mem = HashMap::new();
    // xmm0.lane0 = 0xFFFF_FFFF_FFFF_FFFF, xmm0.lane1 = 0x11
    seed_slot(&mut mem, xmm_slot(0), 0xFFFF_FFFF_FFFF_FFFF, 0x11);
    // xmm1.lane0 = 1, xmm1.lane1 = 0x22
    seed_slot(&mut mem, xmm_slot(1), 1, 0x22);
    let st = run_mem(&raw, 0x140001000, [0u64; 16], mem);
    let (lo, hi) = read_slot(&st.mem, xmm_slot(0));
    assert_eq!(lo, 0, "lane0 wraps: 0xFFFF.. + 1 = 0");
    assert_eq!(hi, 0x33, "lane1 = 0x11 + 0x22 (no carry from lane0)");
}

/// PADDD 4× 32-bit 요소 단위 가산.
#[test]
fn test_lift_paddd_lanes() {
    let raw = enc_block(vec![
        Instruction::with2(Code::Paddd_xmm_xmmm128, Register::XMM0, Register::XMM1).unwrap(),
        Instruction::with(Code::Retnq),
    ]);
    let mut mem = HashMap::new();
    // seed_slot 은 little-endian → dword lane0=bytes0-3, lane1=bytes4-7...
    // xmm0: lane0=0x10, lane1=0xFFFF_FFFF, lane2=0x30, lane3=0xFFFF_FFFF
    seed_slot(
        &mut mem,
        xmm_slot(0),
        0xFFFF_FFFF_0000_0010,
        0xFFFF_FFFF_0000_0030,
    );
    // xmm1: lane0=0x20, lane1=0x1, lane2=0x40, lane3=0x2
    seed_slot(
        &mut mem,
        xmm_slot(1),
        0x0000_0001_0000_0020,
        0x0000_0002_0000_0040,
    );
    let st = run_mem(&raw, 0x140001000, [0u64; 16], mem);
    let (lo, hi) = read_slot(&st.mem, xmm_slot(0));
    // lane0=0x30, lane1=0xFFFF_FFFF+1=0 (wrap, no carry to lane2)
    assert_eq!(lo, 0x0000_0000_0000_0030, "dword lanes wrap independently");
    // lane2=0x70, lane3=0xFFFF_FFFF+2=1
    assert_eq!(hi, 0x0000_0001_0000_0070, "dword lanes wrap independently");
}

/// PADDB — 16× 8-bit 요소 가산 (각 바이트 랩).
#[test]
fn test_lift_paddb_lanes() {
    let raw = enc_block(vec![
        Instruction::with2(Code::Paddb_xmm_xmmm128, Register::XMM0, Register::XMM1).unwrap(),
        Instruction::with(Code::Retnq),
    ]);
    let mut mem = HashMap::new();
    seed_slot(
        &mut mem,
        xmm_slot(0),
        0xFF_FF_FF_FF_FF_FF_FF_FF,
        0x01_01_01_01_01_01_01_01,
    );
    seed_slot(
        &mut mem,
        xmm_slot(1),
        0x01_01_01_01_01_01_01_01,
        0x01_01_01_01_01_01_01_01,
    );
    let st = run_mem(&raw, 0x140001000, [0u64; 16], mem);
    let (lo, hi) = read_slot(&st.mem, xmm_slot(0));
    assert_eq!(lo, 0, "8-bit lanes wrap: 0xFF+1 = 0");
    assert_eq!(hi, 0x02_02_02_02_02_02_02_02, "8-bit lanes add");
}

/// PSUBQ 요소 단위 감산.
#[test]
fn test_lift_psubq() {
    let raw = enc_block(vec![
        Instruction::with2(Code::Psubq_xmm_xmmm128, Register::XMM0, Register::XMM1).unwrap(),
        Instruction::with(Code::Retnq),
    ]);
    let mut mem = HashMap::new();
    seed_slot(&mut mem, xmm_slot(0), 0x10, 0xFFFF_FFFF_FFFF_FFFF);
    seed_slot(&mut mem, xmm_slot(1), 0x20, 0x1);
    let st = run_mem(&raw, 0x140001000, [0u64; 16], mem);
    let (lo, hi) = read_slot(&st.mem, xmm_slot(0));
    assert_eq!(lo, 0xFFFF_FFFF_FFFF_FFF0, "lane0: 0x10 - 0x20 wraps");
    assert_eq!(hi, 0xFFFF_FFFF_FFFF_FFFE, "lane1: 0xFFFF.. - 1");
}

/// PXOR / PAND / POR / PANDN 16바이트 비트열 연산.
#[test]
fn test_lift_packed_logic() {
    let raw = enc_block(vec![
        Instruction::with2(Code::Pxor_xmm_xmmm128, Register::XMM0, Register::XMM1).unwrap(),
        Instruction::with2(Code::Pand_xmm_xmmm128, Register::XMM2, Register::XMM1).unwrap(),
        Instruction::with2(Code::Por_xmm_xmmm128, Register::XMM3, Register::XMM1).unwrap(),
        Instruction::with2(Code::Pandn_xmm_xmmm128, Register::XMM4, Register::XMM1).unwrap(),
        Instruction::with(Code::Retnq),
    ]);
    let mut mem = HashMap::new();
    // xmm0 = 0x0F0F..., xmm1 = 0xFF00...
    seed_slot(
        &mut mem,
        xmm_slot(0),
        0x0F0F_0F0F_0F0F_0F0F,
        0x0F0F_0F0F_0F0F_0F0F,
    );
    seed_slot(
        &mut mem,
        xmm_slot(1),
        0xFF00_FF00_FF00_FF00,
        0xFF00_FF00_FF00_FF00,
    );
    // xmm2 = 0xAAAA..., xmm3 = 0x5555..., xmm4 = 0xFFFF...
    seed_slot(
        &mut mem,
        xmm_slot(2),
        0xAAAA_AAAA_AAAA_AAAA,
        0xAAAA_AAAA_AAAA_AAAA,
    );
    seed_slot(
        &mut mem,
        xmm_slot(3),
        0x5555_5555_5555_5555,
        0x5555_5555_5555_5555,
    );
    seed_slot(
        &mut mem,
        xmm_slot(4),
        0xFFFF_FFFF_FFFF_FFFF,
        0xFFFF_FFFF_FFFF_FFFF,
    );
    let st = run_mem(&raw, 0x140001000, [0u64; 16], mem);
    let (x0lo, _) = read_slot(&st.mem, xmm_slot(0));
    let (x2lo, _) = read_slot(&st.mem, xmm_slot(2));
    let (x3lo, _) = read_slot(&st.mem, xmm_slot(3));
    let (x4lo, _) = read_slot(&st.mem, xmm_slot(4));
    assert_eq!(
        x0lo,
        0x0F0F_0F0F_0F0F_0F0F ^ 0xFF00_FF00_FF00_FF00,
        "PXOR bytewise"
    );
    assert_eq!(
        x2lo,
        0xAAAA_AAAA_AAAA_AAAA & 0xFF00_FF00_FF00_FF00,
        "PAND bytewise"
    );
    assert_eq!(
        x3lo,
        0x5555_5555_5555_5555 | 0xFF00_FF00_FF00_FF00,
        "POR bytewise"
    );
    assert_eq!(
        x4lo,
        0xFFFF_FFFF_FFFF_FFFF & !0xFF00_FF00_FF00_FF00,
        "PANDN = a & ~b"
    );
}

/// PCMPEQD — 요소 단위 등가: 같으면 전-1, 다르면 0.
#[test]
fn test_lift_pcmpeqd() {
    let raw = enc_block(vec![
        Instruction::with2(Code::Pcmpeqd_xmm_xmmm128, Register::XMM0, Register::XMM1).unwrap(),
        Instruction::with(Code::Retnq),
    ]);
    let mut mem = HashMap::new();
    // lane0: 0x11111111 == lane0 of src; lane1: 0x22222222 != 0x33333333
    seed_slot(&mut mem, xmm_slot(0), 0x2222_2222_1111_1111, 0);
    seed_slot(
        &mut mem,
        xmm_slot(1),
        0x3333_3333_1111_1111,
        0x4444_4444_4444_4444,
    );
    let st = run_mem(&raw, 0x140001000, [0u64; 16], mem);
    let (lo, _) = read_slot(&st.mem, xmm_slot(0));
    // lane0 == -> 0xFFFF_FFFF, lane1 != -> 0
    assert_eq!(
        lo, 0x0000_0000_FFFF_FFFF,
        "PCMPEQD equal lane all-ones, diff lane 0"
    );
}

/// MOVDQU — XMM ↔ 메모리 16바이트 이동 (load + store).
#[test]
fn test_lift_movdqu_mem_load_store() {
    let raw = enc_block(vec![
        Instruction::with2(
            Code::Movdqu_xmmm128_xmm,
            iced_x86::MemoryOperand::with_base(Register::RAX),
            Register::XMM0,
        )
        .unwrap(),
        Instruction::with2(
            Code::Movdqu_xmm_xmmm128,
            Register::XMM1,
            iced_x86::MemoryOperand::with_base(Register::RAX),
        )
        .unwrap(),
        Instruction::with(Code::Retnq),
    ]);
    let mut init = [0u64; 16];
    init[0] = 0x5000;
    let mut mem = HashMap::new();
    seed_slot(
        &mut mem,
        xmm_slot(0),
        0xDEAD_BEEF_CAFE_1234,
        0x1122_3344_5566_7788,
    );
    let st = run_mem(&raw, 0x140001000, init, mem);
    assert_eq!(
        read_slot(&st.mem, 0x5000),
        (0xDEAD_BEEF_CAFE_1234, 0x1122_3344_5566_7788),
        "stored 16B to mem"
    );
    assert_eq!(
        read_slot(&st.mem, xmm_slot(1)),
        (0xDEAD_BEEF_CAFE_1234, 0x1122_3344_5566_7788),
        "loaded 16B back to xmm1"
    );
}

/// PADDD xmm0, [rax] — 메모리 소스 폼 (유효주소에서 16바이트 읽기).
#[test]
fn test_lift_paddd_mem_src() {
    let raw = enc_block(vec![
        Instruction::with2(
            Code::Paddd_xmm_xmmm128,
            Register::XMM0,
            iced_x86::MemoryOperand::with_base(Register::RAX),
        )
        .unwrap(),
        Instruction::with(Code::Retnq),
    ]);
    let mut init = [0u64; 16];
    init[0] = 0x5000;
    let mut mem = HashMap::new();
    // xmm0: lane0=2, lane1=1, lane2=4, lane3=3
    seed_slot(
        &mut mem,
        xmm_slot(0),
        0x0000_0001_0000_0002,
        0x0000_0003_0000_0004,
    );
    // mem:   lane0=0xB, lane1=0xA, lane2=0xD, lane3=0xC
    seed_slot(
        &mut mem,
        0x5000,
        0x0000_000A_0000_000B,
        0x0000_000C_0000_000D,
    );
    let st = run_mem(&raw, 0x140001000, init, mem);
    let (lo, hi) = read_slot(&st.mem, xmm_slot(0));
    assert_eq!(lo, 0x0000_000B_0000_000D, "lane0+mem0=0xD, lane1+mem1=0xB");
    assert_eq!(hi, 0x0000_000F_0000_0011, "lane2+mem2=0x11, lane3+mem3=0xF");
}

/// packed SSE lift 는 RiscOp::Packed* 를 만들고 SetFlag 를 만들지 않는다.
#[test]
fn test_lift_packed_no_flag_write() {
    let raw = enc_block(vec![
        Instruction::with2(Code::Paddd_xmm_xmmm128, Register::XMM0, Register::XMM1).unwrap(),
        Instruction::with2(Code::Movdqu_xmm_xmmm128, Register::XMM2, Register::XMM3).unwrap(),
        Instruction::with(Code::Retnq),
    ]);
    let prog = lift(&raw, 0x140001000);
    let packed = prog
        .instrs
        .iter()
        .filter(|i| matches!(i.op, RiscOp::PackedAdd { .. } | RiscOp::PackedMove))
        .count();
    let flag_writes = prog
        .instrs
        .iter()
        .filter(|i| matches!(i.op, RiscOp::SetFlag))
        .count();
    assert_eq!(packed, 2, "PADDD + MOVDQU lifted to Packed ops");
    assert_eq!(flag_writes, 0, "packed integer ops never write RFLAGS");
}
