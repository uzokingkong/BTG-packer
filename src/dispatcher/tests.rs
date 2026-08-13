use super::*;
use iced_x86::{Code, Decoder, DecoderOptions, Register};


    #[test]
    fn test_reencrypt_dispatcher_builds_and_validates() {
        let code = build_dispatcher_reencrypt(0x140001000, 0x600, 16, 0xCAFEBABE, false);
        assert!(!code.is_empty());
        assert!(validate_dispatcher(&code).is_ok());
        // 시작은 pushfq(0x9C), 마지막은 ret(0xC3)
        assert_eq!(code[0], 0x9C);
        assert_eq!(*code.last().unwrap(), 0xC3);
        // 재암호화 디스패처는 수백 바이트 — 할당된 테이블 영역 안에 들어가야 한다
        assert!(code.len() < 0x600 - 0x20, "dispatcher too large: {}", code.len());
    }

    #[test]
    fn test_reencrypt_dispatcher_size_va_independent() {
        let a = build_dispatcher_reencrypt(0x140001000, 0x200, 16, 0xCAFEBABE, false);
        let b = build_dispatcher_reencrypt(0x180000000, 0x999, 64, 0x12345678, false);
        let c = build_dispatcher_reencrypt(0x140001000, 0x200, 16, 0xCAFEBABE, false);
        assert_eq!(a.len(), b.len(), "length must be VA/table/constant independent");
        assert_eq!(a, c, "deterministic for same inputs");
    }

    #[test]
    fn test_reencrypt_dispatcher_rip_references_in_section() {
        // RIP-relative 참조가 모두 .btg 섹션 내부 (섹션베이스/점프테이블/길이테이블)를
        // 가리키는지. iced는 RIP 메모리 피연산자의 memory_displacement64()를 **절대
        // ip-relative 주소**(ip+len+rawdisp)로 반환하므로 그 값 자체를 비교한다.
        let va = 0x140001000u64;
        let table_off = 0x600usize;
        let nb = 16usize;
        let code = build_dispatcher_reencrypt(va, table_off, nb, 0xCAFEBABE, false);
        let len_table_va = va + (table_off + nb * 4) as u64;
        let table_va = va + table_off as u64;
        let mut dec = Decoder::with_ip(64, &code, va + 0x20, DecoderOptions::NONE);
        while dec.can_decode() {
            let inst = dec.decode();
            if matches!(inst.memory_base(), Register::RIP) {
                let target = inst.memory_displacement64(); // 절대 타깃 (iced 규약)
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

    /// 디스패처가 진입 스택에서 소비하는 슬롯 수를 역어셈블로 계산한다.
    /// (스텁이 N개를 push → 디스패처가 정확히 N개를 소비해야 타깃 블록의 RSP가
    /// 원본과 일치한다. 소비가 적으면 디스패치마다 스택 누수 → 8B 어긋남.)
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
        -pushes + pops + lea_rsp_slots + 1 // +1 = ret가 1슬롯 pop
    }

    #[test]
    fn test_plain_dispatcher_stack_balance_two_slots() {
        // v10 FIX 회귀 (일반 모드 8B 스택 누수):
        // 일반 디스패처는 2-푸시 규약 [seed][target]에 맞춰 정확히 2슬롯만
        // 소비해야 한다. (v8~v9에는 블록 스텁이 3푸시를 했지만 디스패처가
        // 2슬롯만 소비해 디스패치마다 8바이트가 남았음)
        let code = build_dispatcher(0x140001000, 0x80, 16, false, 0xCAFEBABE, false, 0);
        let consumed = net_stack_slots_consumed(&code, 0x140001020);
        assert_eq!(
            consumed, 2,
            "plain dispatcher must consume exactly 2 stack slots (got {})",
            consumed
        );
        // trace 모드(INT3 1B)도 같은 균형
        let code_t = build_dispatcher(0x140001000, 0x80, 16, true, 0xCAFEBABE, false, 0);
        assert_eq!(net_stack_slots_consumed(&code_t, 0x140001020), 2);
    }

    #[test]
    fn test_dispatcher_ring_buffer_injects_and_validates() {
        // v13.4d diag: block_ring=true 일 때 ring write 시퀀스가 들어가고
        // 디스패처는 여전히 validate/stack-balance 를 만족해야 한다.
        let va: u64 = 0x140001000;
        let to: usize = 0x600;
        // ring 영역 VA = dispatcher_va + table_offset - RING_REGION
        let ring_va = va + to as u64 - RING_REGION as u64;
        let code = build_dispatcher(va, to, 16, false, 0xCAFEBABE, true, ring_va);
        assert!(!code.is_empty());
        assert!(validate_dispatcher(&code).is_ok());
        // 디스패처가 ring 영역을 침범하면 안 됨 (disp_base + len <= ring_va)
        assert!(
            (va + 0x20) + code.len() as u64 <= ring_va,
            "dispatcher {} bytes overflows into ring region @0x{:X}",
            code.len(), ring_va
        );
        // disasm 후, ring base(r11 절대주소) 를 계산하는 mov r64,imm64 이 존재해야 한다.
        let mut dec = Decoder::with_ip(64, &code, va + 0x20, DecoderOptions::NONE);
        let mut found_base = false;
        let mut found_store = false;
        for _ in 0..512 {
            if !dec.can_decode() { break; }
            let inst = dec.decode();
            if inst.code() == Code::Mov_r64_imm64
                && inst.op0_register() == Register::R11
                && inst.immediate64() as u64 == ring_va
            {
                found_base = true;
            }
            // [r11 + rax*4] 인덱스 스토어 (ring[index] = block_id)
            if inst.code() == Code::Mov_rm32_r32
                && inst.memory_base() == Register::R11
                && inst.memory_index() == Register::RAX
            {
                found_store = true;
            }
        }
        assert!(found_base, "ring base (mov r11, imm64=ring_va) not found");
        assert!(found_store, "ring indexed store not found");
        // ring off 일 때는 base store 가 없어야 한다.
        let code_off = build_dispatcher(va, to, 16, false, 0xCAFEBABE, false, 0);
        let mut dec2 = Decoder::with_ip(64, &code_off, va + 0x20, DecoderOptions::NONE);
        let mut base_off = false;
        for _ in 0..512 {
            if !dec2.can_decode() { break; }
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
        let code = build_dispatcher_reencrypt(0x140001000, 0x600, 16, 0xCAFEBABE, false);
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
        // 재암호화 디스패처는 3-푸시 규약 [seed][target][current]에 맞춰
        // 정확히 3슬롯을 소비해야 한다.
        let code = build_dispatcher_reencrypt(0x140001000, 0x600, 16, 0xCAFEBABE, false);
        let consumed = net_stack_slots_consumed(&code, 0x140001020);
        assert_eq!(
            consumed, 3,
            "reencrypt dispatcher must consume exactly 3 stack slots (got {})",
            consumed
        );
    }

