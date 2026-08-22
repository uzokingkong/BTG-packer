use super::*;
use iced_x86::{Code, Decoder, DecoderOptions, OpKind, Register};

#[test]
fn test_reencrypt_dispatcher_builds_and_validates() {
    let code = build_dispatcher_reencrypt(0x140001000, 0x600, 16, 0xCAFEBABE, false).unwrap();
    assert!(!code.is_empty());
    assert!(validate_dispatcher(&code).is_ok());
    // ??뽰삂?? pushfq(0x9C), 筌띾뜆?筌띾맩? ret(0xC3)
    assert_eq!(code[0], 0x9C);
    assert_eq!(*code.last().unwrap(), 0xC3);
    // ??釉?紐낆넅 ?遺용뮞??μ퓗????롪컶 獄쏅뗄??????醫딅뼣?????뵠???怨몃열 ??됰퓠 ??쇰선揶쎛????뺣뼄
    assert!(
        code.len() < 0x600 - 0x20,
        "dispatcher too large: {}",
        code.len()
    );
}

#[test]
fn test_reencrypt_dispatcher_size_va_independent() {
    let a = build_dispatcher_reencrypt(0x140001000, 0x200, 16, 0xCAFEBABE, false).unwrap();
    let b = build_dispatcher_reencrypt(0x180000000, 0x999, 64, 0x12345678, false).unwrap();
    let c = build_dispatcher_reencrypt(0x140001000, 0x200, 16, 0xCAFEBABE, false).unwrap();
    assert_eq!(
        a.len(),
        b.len(),
        "length must be VA/table/constant independent"
    );
    assert_eq!(a, c, "deterministic for same inputs");
}

#[test]
fn test_reencrypt_dispatcher_rip_references_in_section() {
    // RIP-relative 筌〓챷?쒎첎? 筌뤴뫀紐?.btg ?諭????? (?諭?↑린醫롮뵠???癒곕늄???뵠??疫뀀챷????뵠????
    // 揶쎛?귐뗪텕?遺?. iced??RIP 筌롫뗀?덄뵳???깅염?怨쀬쁽??memory_displacement64()??**???
    // ip-relative 雅뚯눘??*(ip+len+rawdisp)嚥?獄쏆꼹????嚥?域?揶??癒?퍥????쑨???뺣뼄.
    let va = 0x140001000u64;
    let table_off = 0x600usize;
    let nb = 16usize;
    let code = build_dispatcher_reencrypt(va, table_off, nb, 0xCAFEBABE, false).unwrap();
    let len_table_va = va + (table_off + nb * 4) as u64;
    let table_va = va + table_off as u64;
    let mut dec = Decoder::with_ip(64, &code, va + 0x20, DecoderOptions::NONE);
    while dec.can_decode() {
        let inst = dec.decode();
        if matches!(inst.memory_base(), Register::RIP) {
            let target = inst.memory_displacement64(); // ??? ??繹?(iced 域뱀뮇鍮?
            assert!(
                target == va || target == table_va || target == len_table_va,
                "RIP target 0x{:X} not in .btg tables (va=0x{:X} table=0x{:X} len=0x{:X})",
                target,
                va,
                table_va,
                len_table_va
            );
        }
    }
}

/// ?遺용뮞??μ퓗揶쎛 筌욊쑴????쎄문?癒?퐣 ???돩??롫뮉 ??????? ??堉??덊닜嚥??④쑴沅??뺣뼄.
/// (??쎈??N揶쏆뮆? push ???遺용뮞??μ퓗揶쎛 ?類μ넇??N揶쏆뮆? ???돩??곷튊 ??繹??됰뗀以??RSP揶쎛
/// ?癒?궚????깊뒄??뺣뼄. ???돩揶쎛 ?怨몄몵筌??遺용뮞??ν뒄筌띾뜄????쎄문 ?袁⑸땾 ??8B ??욱닎??)
fn net_stack_slots_consumed(code: &[u8], base_va: u64) -> i32 {
    let mut dec = Decoder::with_ip(64, code, base_va, DecoderOptions::NONE);
    let mut pushes = 0i32;
    let mut pops = 0i32;
    let mut lea_rsp_slots = 0i32;
    let mut ret = false;
    while dec.can_decode() {
        let inst = dec.decode();
        if inst.is_invalid() {
            break;
        }
        match inst.code() {
            Code::Push_r64 | Code::Pushfq => pushes += 1,
            Code::Pop_r64 | Code::Popfq => pops += 1,
            Code::Lea_r64_m if inst.op0_register() == Register::RSP => {
                lea_rsp_slots += (inst.memory_displacement64() as i32) / 8;
            }
            Code::Retnq => ret = true,
            _ => {}
        }
    }
    assert!(ret, "dispatcher must end with ret");
    -pushes + pops + lea_rsp_slots + 1 // +1 = ret揶쎛 1????pop
}

#[test]
fn test_plain_dispatcher_stack_balance_two_slots() {
    // v10 FIX ??? (??곗뺘 筌뤴뫀諭?8B ??쎄문 ?袁⑸땾):
    // ??곗뺘 ?遺용뮞??μ퓗??2-?紐꾨뻻 域뱀뮇鍮?[seed][target]??筌띿쉸???類μ넇??2???숋쭕?
    // ???돩??곷튊 ??뺣뼄. (v8~v9?癒?뮉 ?됰뗀以???쎈??3?紐꾨뻻?????筌??遺용뮞??μ퓗揶쎛
    // 2???숋쭕????돩???遺용뮞??ν뒄筌띾뜄??8獄쏅뗄??硫? ??λ릭??
    let code = build_dispatcher(0x140001000, 0x80, 16, false, 0xCAFEBABE, false, 0, 2);
    let consumed = net_stack_slots_consumed(&code, 0x140001020);
    assert_eq!(
        consumed, 2,
        "plain dispatcher must consume exactly 2 stack slots (got {})",
        consumed
    );
    // trace 筌뤴뫀諭?INT3 1B)??揶쏆늿? 域뱀쥚??
    let code_t = build_dispatcher(0x140001000, 0x80, 16, true, 0xCAFEBABE, false, 0, 2);
    assert_eq!(net_stack_slots_consumed(&code_t, 0x140001020), 2);
}

#[test]
fn test_dispatcher_ring_buffer_injects_and_validates() {
    // v13.4d diag: block_ring=true ????ring write ??쀂???? ??쇰선揶쎛??
    // ?遺용뮞??μ퓗???????validate/stack-balance ??筌띾슣???곷튊 ??뺣뼄.
    let va: u64 = 0x140001000;
    let to: usize = 0x600;
    // ring ?怨몃열 VA = dispatcher_va + table_offset - RING_REGION
    let ring_va = va + to as u64 - RING_REGION as u64;
    let code = build_dispatcher(va, to, 16, false, 0xCAFEBABE, true, ring_va, 2);
    assert!(!code.is_empty());
    assert!(validate_dispatcher(&code).is_ok());
    // ?遺용뮞??μ퓗揶쎛 ring ?怨몃열??燁삘뫀苡??롢늺 ????(disp_base + len <= ring_va)
    assert!(
        (va + 0x20) + code.len() as u64 <= ring_va,
        "dispatcher {} bytes overflows into ring region @0x{:X}",
        code.len(),
        ring_va
    );
    // disasm ?? ring base(r11 ???雅뚯눘?? ???④쑴沅??롫뮉 mov r64,imm64 ??鈺곕똻???곷튊 ??뺣뼄.
    let mut dec = Decoder::with_ip(64, &code, va + 0x20, DecoderOptions::NONE);
    let mut found_base = false;
    let mut found_store = false;
    for _ in 0..512 {
        if !dec.can_decode() {
            break;
        }
        let inst = dec.decode();
        if inst.code() == Code::Mov_r64_imm64
            && inst.op0_register() == Register::R11
            && inst.immediate64() as u64 == ring_va
        {
            found_base = true;
        }
        // [r11 + rax*4] ?紐껊쑔????쎈꽅??(ring[index] = block_id)
        if inst.code() == Code::Mov_rm32_r32
            && inst.memory_base() == Register::R11
            && inst.memory_index() == Register::RAX
        {
            found_store = true;
        }
    }
    assert!(found_base, "ring base (mov r11, imm64=ring_va) not found");
    assert!(found_store, "ring indexed store not found");
    // ring off ?????뮉 base store 揶쎛 ??곷선????뺣뼄.
    let code_off = build_dispatcher(va, to, 16, false, 0xCAFEBABE, false, 0, 2);
    let mut dec2 = Decoder::with_ip(64, &code_off, va + 0x20, DecoderOptions::NONE);
    let mut base_off = false;
    for _ in 0..512 {
        if !dec2.can_decode() {
            break;
        }
        let inst = dec2.decode();
        if inst.code() == Code::Mov_r64_imm64
            && inst.op0_register() == Register::R11
            && inst.immediate64() as u64 == ring_va
        {
            base_off = true;
        }
    }
    assert!(!base_off, "ring must be absent when block_ring=false");
}

#[test]
fn test_reencrypt_expand_loop_preserves_len_edx() {
    // v14-2 regression (hello_fix.exe 0xC000001D @ block 3101):
    // block_crypt's key256 ExpandLoop used EDX as its loop counter,
    // clobbering the block length the caller passes in EDX. PRGA then ran
    // with len=0 -> no block was ever decrypted -> every encrypted block
    // executed as ciphertext. The loop counter must use a scratch register
    // (R8D) so EDX keeps the length for the PRGA call.
    let code = build_dispatcher_reencrypt(0x140001000, 0x600, 16, 0xCAFEBABE, false).unwrap();
    let mut dec = Decoder::with_ip(64, &code, 0x140001020, DecoderOptions::NONE);
    let mut dec_edx = 0usize;
    let mut mov_edx_64 = 0usize;
    let mut dec_r8d = 0usize;
    while dec.can_decode() {
        let inst = dec.decode();
        if inst.is_invalid() {
            break;
        }
        match inst.code() {
            Code::Dec_rm32 if inst.op0_register() == Register::EDX => dec_edx += 1,
            Code::Mov_r32_imm32
                if inst.op0_register() == Register::EDX && inst.immediate32() == 64 =>
            {
                mov_edx_64 += 1;
            }
            Code::Dec_rm32 if inst.op0_register() == Register::R8D => dec_r8d += 1,
            _ => {}
        }
    }
    assert_eq!(dec_edx, 0, "ExpandLoop must not clobber EDX (block length)");
    assert_eq!(
        mov_edx_64, 0,
        "ExpandLoop counter must not be initialized from EDX"
    );
    assert!(
        dec_r8d > 0,
        "ExpandLoop counter should use a scratch register (R8D)"
    );
}

#[test]
fn test_reencrypt_dispatcher_stack_balance_three_slots() {
    // ??釉?紐낆넅 ?遺용뮞??μ퓗??3-?紐꾨뻻 域뱀뮇鍮?[seed][target][current]??筌띿쉸??
    // ?類μ넇??3????????돩??곷튊 ??뺣뼄.
    let code = build_dispatcher_reencrypt(0x140001000, 0x600, 16, 0xCAFEBABE, false).unwrap();
    let consumed = net_stack_slots_consumed(&code, 0x140001020);
    assert_eq!(
        consumed, 3,
        "reencrypt dispatcher must consume exactly 3 stack slots (got {})",
        consumed
    );
}

/// O1: --obf-level 1/2/3 이 디스패처의 MBA 키 스케줄을 실질적으로 달리 만드는지.
/// 패커 `compute_key(seed,id,C,level)` 와 일치해야 하므로, 레벨별로 다른 명령
/// 시퀀스(1=단순 XOR, 2=+2*(s&b) MBA, 3=+s&b overlap)가 emit 되는지 검증한다.
#[test]
fn test_dispatcher_obf_level_changes_key_schedule() {
    let code1 = build_dispatcher(0x140001000, 0x80, 16, false, 0xCAFEBABE, false, 0, 1);
    let code2 = build_dispatcher(0x140001000, 0x80, 16, false, 0xCAFEBABE, false, 0, 2);
    let code3 = build_dispatcher(0x140001000, 0x80, 16, false, 0xCAFEBABE, false, 0, 3);
    // 레벨별 코드가 서로 달라야 한다 (레벨이 실제 변환을 바꾼다).
    assert_ne!(code1, code2, "level 1 vs level 2 must differ");
    assert_ne!(code2, code3, "level 2 vs level 3 must differ");
    assert_ne!(code1, code3, "level 1 vs level 3 must differ");

    // level 1: MBA 항등식 lea eax, [rax + r11*2] 가 없어야 한다 (단순 XOR 만).
    assert!(
        !decode_key_schedule_has_mba_lea(&code1),
        "level 1 must not contain the 2*(s&b) MBA LEA"
    );
    // level 2: lea eax,[rax+r11*2] 는 있지만 overlap add 는 없어야 한다.
    assert!(
        decode_key_schedule_has_mba_lea(&code2),
        "level 2 must contain the 2*(s&b) MBA LEA"
    );
    // level 3: level 2 에 추가로 `add eax, r11d`(overlap) 가 있어야 한다.
    assert!(
        decode_key_schedule_has_mba_lea(&code3),
        "level 3 must contain the 2*(s&b) MBA LEA"
    );
    assert!(
        decode_key_schedule_has_overlap_add(&code3),
        "level 3 must add (s&b) overlap after the XOR"
    );
}

/// 디스패처 코드에서 MBA 키 스케줄의 `lea eax, [rax + r11*2]`(인덱스 r11 scale 2)
/// 를 찾는지 여부. (다른 LEA(rip-relative/rsp)와 구분하기 위해 메모리 피연산자 확인.)
fn decode_key_schedule_has_mba_lea(code: &[u8]) -> bool {
    let mut dec = Decoder::with_ip(64, code, 0x140001020, DecoderOptions::NONE);
    while dec.can_decode() {
        let ins = dec.decode();
        if ins.code() == Code::Lea_r32_m
            && ins.memory_base() == Register::RAX
            && ins.memory_index() == Register::R11
            && ins.memory_index_scale() == 2
        {
            return true;
        }
    }
    false
}

/// 디스패처 코드에서 level-3 overlap add (`add eax, r11d` = Add_rm32_r32 with
/// r11d right after the XOR with the mba constant) 를 찾는지 여부.
fn decode_key_schedule_has_overlap_add(code: &[u8]) -> bool {
    let mut dec = Decoder::with_ip(64, code, 0x140001020, DecoderOptions::NONE);
    let mut seq: Vec<(Code, u8)> = Vec::new();
    while dec.can_decode() {
        let ins = dec.decode();
        let op1 = if ins.op_count() > 1 && ins.op1_kind() == OpKind::Register {
            ins.op1_register() as u8
        } else {
            0
        };
        seq.push((ins.code(), op1));
    }
    seq.windows(2).any(|w| {
        w[0].0 == Code::Xor_rm32_imm32
            && w[1].0 == Code::Add_rm32_r32
            && w[1].1 == Register::R11D as u8
    })
}
