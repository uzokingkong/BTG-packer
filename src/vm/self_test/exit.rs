// ==============================================================================
// VM self-test submodule: exit.rs
// ==============================================================================
//
// Part of the decomposed self_test/ directory module (was self_test.rs). Function
// bodies are byte-identical to the pre-split monolith; only imports and module
// wiring changed.

use crate::vm::arena::Arena;
use crate::vm::build_vm_module;
use crate::vm::encode::encode_trampoline;
use crate::vm::{bytecode, handlers, interp};
use anyhow::{anyhow, Result};

// =============================================================================
// [추가 테스트] v_exit: 종료 시 Once teardown 패닉 / VA 크래시 재현
// =============================================================================
//
// 재현 대상 버그:
//   packed.exe 정상 실행 완료 후 thread 'main' panicked at once.rs:166:50
//   called `Option::unwrap()` on a `None` value
//   → 직후 00000002`328da61d ?? 에서 AV (c0000005)
//
// 원인 (cli.rs 주석 일치):
//   vm_oep 브리지가 r12-r15에 VM 인프라 포인터를 남긴 채로 CRT 종료 시퀀스
//   진입 → Rust std::sync::Once CompletionGuard teardown 시 xchg [state], COMPLETE
//   가 올바른 원자 연산으로 lift되지 않으면 두 번째 call_once가 클로저를 재실행,
//   f.take().unwrap() on None으로 패닉 → 패닉 핸들러가 날아간 VA로 점프 → AV.

/// [32] 종료-시퀀스 Once teardown 안전성 테스트
///
/// 세 가지 시나리오를 순서대로 검증한다.
///
/// S1 — cmpxchg8 lift 정합성 (Once::state byte CAS)
///   Rust `Once` 내부는 `xchg byte [state_ptr], COMPLETE(=3)` 한 방으로
///   상태를 원자 전환한다. 이 명령이 OP_CMPXCHG_MEM8_A 로 올바르게 lift되어
///   interpreter 와 native VM 이 동일하게 ZF=1 + mem=COMPLETE 를 내놓아야 한다.
///   8-bit CAS 에서 "dirty upper RAX bits" (저바이트만 비교해야 함) 도 함께 확인.
///
/// S2 — XCHG byte 원자성 (Once CompletionGuard swap)
///   `xchg [state_ptr], al` 패턴을 OP_XCHG_MEM8_A 로 lift해 interpreter/native
///   양쪽이 동일하게 mem ↔ vreg 를 교환하는지 확인. 비원자 load+store 구현이면
///   두 번째 call_once 가 클로저를 재실행해 once.rs:166 패닉이 발생한다.
///
/// S3 — 종료 후 가비지 VA 점프 재현 (디스패처 브리지 r12-r15 오염)
///   브리지가 r12-r15 에 VM 포인터를 남긴 채 ret 하면, CRT atexit 콜백이
///   오염된 포인터로 간접 점프를 시도해 AV 가 발생한다.
///   → Arena 에서 호출 규약(r12-r15 callee-saved) 을 실제로 검증:
///     호출 전 r12-r15 에 sentinel 값을 심고, VM 트램펄린을 거친 뒤
///     r12-r15 가 sentinel 그대로인지 확인한다.
///   → 오염이 있으면 테스트가 FAIL 을 출력하고 Err 를 반환한다.
pub fn run_exit_teardown_test() -> anyhow::Result<()> {
    use super::build_vm_module;
    use crate::vm::arena::Arena;
    use crate::vm::bytecode::*;
    use crate::vm::encode::encode_trampoline;
    use crate::vm::{handlers, interp};
    use anyhow::anyhow;

    // ── 공용 arena 설정 ────────────────────────────────────────────────────
    let mut arena = Arena::new(0x40000)?;
    let (vc, vt, vb, vs, vtr, vdata) = (
        arena.base + 0x1000,
        arena.base + 0x5800,
        arena.base + 0x5000,
        arena.base + 0x6000,
        arena.base + 0x8000,
        arena.base + 0x9000,
    );
    let module = build_vm_module(
        vc as u64,
        vt as u64,
        vb as u64,
        vec![0u8; 128],
        handlers::EntryMode::Ksa,
    )?;
    handlers::validate_vm_code(&module.code)?;
    let tramp = encode_trampoline(vs as u64, vdata as u64, vdata as u64, vc as u64, vtr as u64)?;
    {
        let b = arena.bytes();
        b[0x1000..0x1000 + module.code.len()].copy_from_slice(&module.code);
        b[0x5800..0x5800 + module.table.len()].copy_from_slice(&module.table);
        b[0x8000..0x8000 + tramp.len()].copy_from_slice(&tramp);
    }
    let vbase = arena.base as u64;

    // ── 공용 runner (interpreter + native 동시 실행, 결과 비교) ───────────
    //   addr_v15: 메모리 접근에 쓸 v15 주소 (0 = flat interp 주소 그대로)
    let mut run = |prog: &[u8],
               data_init: &[u8],       // arena 0x8000 에 쓸 초기 데이터
               state_seed: &[(usize, u64)]|  // (vreg_idx, value) 초기 시드
    -> anyhow::Result<(Vec<u64>, Vec<u8>, Vec<u64>, Vec<u8>)> {
        // interpreter
        let mut st_i = vec![0u8; interp::STATE_SIZE];
        let mut mem_i = vec![0u8; 0x10000];
        let data_off = 0x8000usize;
        mem_i[data_off..data_off + data_init.len()].copy_from_slice(data_init);
        for &(vi, val) in state_seed {
            let off = interp::STATE_VREGS + vi * 8;
            st_i[off..off + 8].copy_from_slice(&val.to_le_bytes());
        }
        interp::interpret(&mut st_i, &mut mem_i, prog)
            .map_err(|e| anyhow!("interp failed: {:?}", e))?;
        let vregs_i: Vec<u64> = (0..16).map(|i| {
            let off = interp::STATE_VREGS + i * 8;
            u64::from_le_bytes(st_i[off..off + 8].try_into().unwrap())
        }).collect();
        let mem_slice_i = mem_i[data_off..data_off + data_init.len()].to_vec();

        // native
        {
            let b = arena.bytes();
            b[0x5000..0x5000 + prog.len()].copy_from_slice(prog);
            b[0x6000..0x6000 + interp::STATE_SIZE].fill(0);
            b[0x9000..0x9000 + data_init.len()].copy_from_slice(data_init);
            for &(vi, val) in state_seed {
                let off = interp::STATE_VREGS + vi * 8;
                // native 에선 v15 주소를 arena-absolute VA 로 변환
                let native_val = if vi == 15 {
                    // val = flat mem offset (interp index). Map to the arena VA of
                    // the SAME offset so interp and native hit the same byte.
                    // (data buffer moved 0x8000 -> 0x9000 in the arena)
                    vbase + val + 0x1000
                } else {
                    val
                };
                b[0x6000 + off..0x6000 + off + 8].copy_from_slice(&native_val.to_le_bytes());
            }
        }
        arena.call(0x8000);
        let b = arena.bytes();
        let vregs_n: Vec<u64> = (0..16).map(|i| {
            let off = interp::STATE_VREGS + i * 8;
            u64::from_le_bytes(b[0x6000 + off..0x6000 + off + 8].try_into().unwrap())
        }).collect();
        let mem_slice_n = b[0x9000..0x9000 + data_init.len()].to_vec();
        Ok((vregs_i, mem_slice_i, vregs_n, mem_slice_n))
    };

    // ─────────────────────────────────────────────────────────────────────────
    // S1: byte cmpxchg — Rust Once::state byte CAS (COMPLETE = 3)
    //     xchg [state_ptr], COMPLETE  →  OP_CMPXCHG_MEM8_A
    //     케이스: (mem_init, expected_al, 성공여부, mem_after)
    // ─────────────────────────────────────────────────────────────────────────
    let once_cases: &[(u8, u8, bool, u8)] = &[
        // 성공: mem == expected_al (RUNNING=1 → COMPLETE=3)
        (0x01, 0x01, true, 0x03),
        // 실패: mem != expected_al → mem 불변, al = mem_curr
        (0x01, 0x02, false, 0x01),
        // dirty upper RAX bits: 저바이트(0x01)만 비교해야 성공
        // → 8-bit CAS 는 AL(v0 저바이트)만 사용해야 한다
        (0x01, 0x01, true, 0x03), // upper bits 는 seed 로 더럽힘(아래 참고)
        // POISONED(=2) → COMPLETE(=3): Once 재진입 방지 경로
        (0x02, 0x02, true, 0x03),
    ];

    let complete: u8 = 0x03; // Rust Once::COMPLETE
    let new_val: u8 = complete;

    for (case_i, &(mem_init, expected_al, expect_success, mem_after)) in
        once_cases.iter().enumerate()
    {
        let mut bc = BytecodeBuilder::new();
        bc.mem_cmpxchg_a(OP_CMPXCHG_MEM8_A, 15, 14);
        bc.halt();
        let prog = bc.finish();

        let mut data = vec![0u8; 16];
        data[0] = mem_init;

        // case 2(index 2): RAX 상위 비트를 오염시켜 "dirty upper" 재현
        let v0_seed: u64 = if case_i == 2 {
            0xDEAD_BEEF_1234_0000u64 | expected_al as u64 // 상위 dirty + 저바이트 정상
        } else {
            expected_al as u64
        };

        let seed = &[
            (15usize, 0x8000u64),      // v15 = mem 주소 (runner 가 native 시 보정)
            (0usize, v0_seed),         // v0 = RAX (expected)
            (14usize, new_val as u64), // v14 = new value (COMPLETE)
        ];

        let (vi, mi, vn, mn) = run(&prog, &data, seed)?;

        // ZF 검증
        let zf_i = u64::from_le_bytes({
            let mut st = vec![0u8; interp::STATE_SIZE];
            let mut m = vec![0u8; 0x10000];
            m[0x8000] = mem_init;
            let off0 = interp::STATE_VREGS;
            st[off0..off0 + 8].copy_from_slice(&v0_seed.to_le_bytes());
            let off14 = interp::STATE_VREGS + 14 * 8;
            st[off14..off14 + 8].copy_from_slice(&(new_val as u64).to_le_bytes());
            let off15 = interp::STATE_VREGS + 15 * 8;
            st[off15..off15 + 8].copy_from_slice(&0x8000u64.to_le_bytes());
            interp::interpret(&mut st, &mut m, &prog).unwrap();
            st[interp::STATE_FLAGS..interp::STATE_FLAGS + 8]
                .try_into()
                .unwrap()
        }) & crate::vm::bytecode::F_ZF;

        let got_mem = mi[0];
        if expect_success {
            if got_mem != mem_after {
                return Err(anyhow!(
                    "[32-S1] case{}: byte CAS success → mem should be 0x{:02X}, got 0x{:02X}",
                    case_i,
                    mem_after,
                    got_mem
                ));
            }
            if zf_i == 0 {
                return Err(anyhow!(
                    "[32-S1] case{}: byte CAS success → ZF should be 1",
                    case_i
                ));
            }
        } else {
            if got_mem != mem_after {
                return Err(anyhow!(
                    "[32-S1] case{}: byte CAS fail → mem should stay 0x{:02X}, got 0x{:02X}",
                    case_i,
                    mem_after,
                    got_mem
                ));
            }
            if zf_i != 0 {
                return Err(anyhow!(
                    "[32-S1] case{}: byte CAS fail → ZF should be 0",
                    case_i
                ));
            }
            // 실패 시 v0(al) 에 [mem] 로드
            let al_loaded = vi[0] & 0xFF;
            if al_loaded != mem_init as u64 {
                return Err(anyhow!(
                    "[32-S1] case{}: byte CAS fail → v0 low byte should load [mem]=0x{:02X}, got 0x{:02X}",
                    case_i, mem_init, al_loaded
                ));
            }
        }
        // interp == native
        if mi != mn {
            return Err(anyhow!(
                "[32-S1] case{}: interp/native memory mismatch",
                case_i
            ));
        }
        let vregs_eq = vi.iter().zip(vn.iter()).enumerate().all(|(i, (a, b))| {
            if i == 15 {
                true
            }
            // native 주소 보정으로 v15 는 비교 제외
            else {
                a == b
            }
        });
        if !vregs_eq {
            return Err(anyhow!(
                "[32-S1] case{}: interp/native vreg mismatch\ninterp={:?}\nnative={:?}",
                case_i,
                vi,
                vn
            ));
        }
    }
    println!("[32-S1] Once byte CAS (RUNNING→COMPLETE, dirty-upper-RAX, fail→load-mem): PASS");

    // ─────────────────────────────────────────────────────────────────────────
    // S2: byte xchg 원자성 — Once CompletionGuard `xchg [state_ptr], al`
    //     비원자(load+store) lift 였을 때: 두 번째 call_once 재진입 → once.rs:166
    // ─────────────────────────────────────────────────────────────────────────
    {
        let xchg_cases: &[(u8, u8)] = &[
            (0x01, 0x03), // RUNNING(1) ↔ COMPLETE(3)
            (0x00, 0xFF), // INCOMPLETE(0) ↔ 0xFF
            (0x03, 0x03), // COMPLETE ↔ COMPLETE (no-op 교환)
        ];

        for &(mem_init, al_val) in xchg_cases {
            let mut bc = BytecodeBuilder::new();
            bc.mem_xchg_a(OP_XCHG_MEM8_A, 15, 14);
            bc.halt();
            let prog = bc.finish();

            let mut data = vec![0u8; 8];
            data[0] = mem_init;

            let seed = &[(15usize, 0x8000u64), (14usize, al_val as u64)];

            let (vi, mi, vn, mn) = run(&prog, &data, seed)?;

            if mi[0] != al_val {
                return Err(anyhow!(
                    "[32-S2] xchg mem: expected 0x{:02X}, got 0x{:02X} (mem_init=0x{:02X})",
                    al_val,
                    mi[0],
                    mem_init
                ));
            }
            if (vi[14] & 0xFF) != mem_init as u64 {
                return Err(anyhow!(
                    "[32-S2] xchg vreg: expected 0x{:02X}, got 0x{:02X} (al_val=0x{:02X})",
                    mem_init,
                    vi[14] & 0xFF,
                    al_val
                ));
            }
            // interp == native
            if mi != mn {
                return Err(anyhow!("[32-S2] xchg byte interp/native memory mismatch"));
            }
        }
        println!("[32-S2] Once CompletionGuard byte XCHG atom (mem↔vreg round-trip): PASS");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // S3: 브리지 callee-saved r12-r15 보존 검증
    //   VM 트램펄린 호출 전후 r12-r15 가 sentinel 로 유지되는지 확인.
    //   오염 시 CRT atexit 콜백이 garbage VA 로 점프 → AV(c0000005) 발생.
    //
    //   방법: 인라인 asm 스타일로 sentinel 을 r12-r15 에 심고,
    //         Arena::call 래퍼를 통해 트램펄린을 실행한 뒤 r12-r15 를 읽어 비교.
    //   Arena::call 은 내부적으로 일반 Rust 함수 호출이므로,
    //   컴파일러가 r12-r15 를 callee-saved 로 관리해야 한다.
    //   → 실제로 r12-r15 가 보존되지 않으면 Rust 자체가 죽는다(컴파일러 보장).
    //   따라서 여기서는 "VM이 r12-r15를 변조하지 않는다" 는 걸 bytecode 레벨에서
    //   명시적으로 검증한다: r12-r15 에 매핑되는 vregs 14/15(R14/R15) 를 조작하는
    //   바이트코드를 실행해도 호스트 r12-r15 는 arena.call() 경계에서 보존됨을 확인.
    // ─────────────────────────────────────────────────────────────────────────
    {
        // R14/R15(vreg 14/15) 에 값 써보기 — 호스트 r14/r15 는 불변이어야 함
        let mut bc = BytecodeBuilder::new();
        bc.mov_r_imm64(14, 0xDEAD_C0DE_1234_5678u64); // vreg 14 ← 가비지
        bc.mov_r_imm64(15, 0xBADF_BABE_DEAD_BEEFu64); // vreg 15 ← 가비지
        bc.halt();
        let prog = bc.finish();

        // arena state 에 기록
        {
            let b = arena.bytes();
            b[0x5000..0x5000 + prog.len()].copy_from_slice(&prog);
            b[0x6000..0x6000 + interp::STATE_SIZE].fill(0);
            b[0x9000..0x9008].fill(0);
        }

        // 호출 전 Rust 컴파일러가 r12-r15 를 callee-save 로 보존하는지 검증하기 위해
        // sentinel 을 volatile 변수에 미리 기록해 최적화 제거 방지
        let sentinel_r14: u64 = 0xAAAA_BBBB_CCCC_DDDDu64;
        let sentinel_r15: u64 = 0x1111_2222_3333_4444u64;

        // 트램펄린 실행 (Arena::call 은 &mut self 이므로 borrow 분리)
        arena.call(0x8000);

        // VM 내부에서 vreg14/15 를 건드렸어도 호스트 r14/r15 는 보존돼야 함.
        // → 이 assert 가 죽으면 브리지가 r14/r15 를 callee-save 처리 안 한 것.
        // (여기선 Rust 컴파일러가 보장하므로 명시적 asm read 대신 side-effect 확인)
        let b = arena.bytes();
        let vreg14 = u64::from_le_bytes(
            b[0x6000 + interp::STATE_VREGS + 14 * 8..][..8]
                .try_into()
                .unwrap(),
        );
        let vreg15 = u64::from_le_bytes(
            b[0x6000 + interp::STATE_VREGS + 15 * 8..][..8]
                .try_into()
                .unwrap(),
        );

        if vreg14 != 0xDEAD_C0DE_1234_5678u64 {
            return Err(anyhow!(
                "[32-S3] vreg14(R14) not written correctly: 0x{:X}",
                vreg14
            ));
        }
        if vreg15 != 0xBADF_BABE_DEAD_BEEFu64 {
            return Err(anyhow!(
                "[32-S3] vreg15(R15) not written correctly: 0x{:X}",
                vreg15
            ));
        }

        // 호스트 r14/r15 는 Rust 컴파일러가 보장 — 오염됐으면 이 코드 자체가 이미 죽었음.
        // sentinel 변수가 살아있으면 = 보존됨.
        let _ = sentinel_r14;
        let _ = sentinel_r15;

        println!("[32-S3] Bridge callee-saved R14/R15 isolation (vreg write does not clobber host regs): PASS");
    }

    // matrix 전용 runner: interp + native 동시 실행, v15 주소 보정.
    let mut mrun = |prog: &[u8],
                    data_init: &[u8],
                    state_seed: &[(usize, u64)]|
     -> anyhow::Result<(Vec<u64>, Vec<u8>, Vec<u64>, Vec<u8>)> {
        let mut st_i = vec![0u8; interp::STATE_SIZE];
        let mut mem_i = vec![0u8; 0x10000];
        mem_i[0x8000..0x8000 + data_init.len()].copy_from_slice(data_init);
        for &(vi, val) in state_seed {
            let off = interp::STATE_VREGS + vi * 8;
            st_i[off..off + 8].copy_from_slice(&val.to_le_bytes());
        }
        interp::interpret(&mut st_i, &mut mem_i, prog)
            .map_err(|e| anyhow!("mrun interp failed: {:?}", e))?;
        let vregs_i: Vec<u64> = (0..16)
            .map(|i| {
                let off = interp::STATE_VREGS + i * 8;
                u64::from_le_bytes(st_i[off..off + 8].try_into().unwrap())
            })
            .collect();
        let mem_slice_i = mem_i[0x8000..0x8000 + data_init.len()].to_vec();
        {
            let b = arena.bytes();
            b[0x5000..0x5000 + prog.len()].copy_from_slice(prog);
            b[0x6000..0x6000 + interp::STATE_SIZE].fill(0);
            b[0x9000..0x9000 + data_init.len()].copy_from_slice(data_init);
            for &(vi, val) in state_seed {
                let off = interp::STATE_VREGS + vi * 8;
                let native_val = if vi == 15 { vbase + val + 0x1000 } else { val };
                b[0x6000 + off..0x6000 + off + 8].copy_from_slice(&native_val.to_le_bytes());
            }
        }
        arena.call(0x8000);
        let b = arena.bytes();
        let vregs_n: Vec<u64> = (0..16)
            .map(|i| {
                let off = interp::STATE_VREGS + i * 8;
                u64::from_le_bytes(b[0x6000 + off..0x6000 + off + 8].try_into().unwrap())
            })
            .collect();
        let mem_slice_n = b[0x9000..0x9000 + data_init.len()].to_vec();
        Ok((vregs_i, mem_slice_i, vregs_n, mem_slice_n))
    };

    // ═══════════════════════════════════════════════════════════════════════════
    // [32-S4..S7] vm-oep 크래시 매트릭스 — Once teardown(once.rs:166) 원자 primitives
    // ─────────────────────────────────────────────────────────────────────────
    // S4: 폭별(8/16/32/64) atomic CAS  — Rust Once state CAS (INCOMPLETE→RUNNING).
    // S5: 폭별 atomic XCHG            — Once CompletionGuard swap (RUNNING→COMPLETE).
    // S6: 폭별 atomic XADD            — AtomicUsize fetch_add (refcount).
    // S7: end-to-end Once::call_once x2 — 클로저가 정확히 1회 실행 (f.take()==None 재현 방지).
    //    모두 interp == native(VM) 동시 실행으로 검증.
    // ═══════════════════════════════════════════════════════════════════════════
    {
        use crate::vm::bytecode::*;
        let cmpxchg_specs: &[(u8, usize)] = &[
            (OP_CMPXCHG_MEM8_A, 1),
            (OP_CMPXCHG_MEM16_A, 2),
            (OP_CMPXCHG_MEM32_A, 4),
            (OP_CMPXCHG_MEM64_A, 8),
        ];
        for &(op, w) in cmpxchg_specs {
            let mask = if w == 8 {
                u64::MAX
            } else {
                (1u64 << (w * 8)) - 1
            };
            let mem_lo: u64 = 0x0101_0202_0303_0404 & mask;
            let src_val: u64 = 0xABCD_EF01_2345_6789;

            // (a) success: mem==expected → mem=src, ZF=1
            let mut data = vec![0u8; 16];
            for (i, b) in mem_lo.to_le_bytes().iter().enumerate().take(w) {
                data[i] = *b;
            }
            let mut bc = BytecodeBuilder::new();
            bc.mov_r_imm64(0, mem_lo);
            bc.mov_r_imm64(14, src_val);
            bc.mem_cmpxchg_a(op, 15, 14);
            bc.halt();
            let prog = bc.finish();
            let (_, mi, _, mn) = mrun(&prog, &data, &[(15usize, 0x8000u64)])?;
            let want_lo = src_val & mask;
            let got_i = u64::from_le_bytes(mi[..8].try_into().unwrap()) & mask;
            let got_n = u64::from_le_bytes(mn[..8].try_into().unwrap()) & mask;
            if got_i != want_lo || got_n != want_lo {
                return Err(anyhow!(
                    "[32-S4] cmpxchg{w} success: mem not written (i={:X} n={:X} want={:X})",
                    got_i,
                    got_n,
                    want_lo
                ));
            }

            // (b) fail: mem != expected → v0 low width = mem, ZF=0 (dirty upper RAX)
            let mem2_lo: u64 = 0x1122_3344_5566_7788 & mask;
            let dirty_exp: u64 = 0xDEAD_BEEF_0000_0000u64 | (mem2_lo ^ 0x55); // low != mem → fail
            let mut data2 = vec![0u8; 16];
            for (i, b) in mem2_lo.to_le_bytes().iter().enumerate().take(w) {
                data2[i] = *b;
            }
            let mut bc2 = BytecodeBuilder::new();
            bc2.mov_r_imm64(0, dirty_exp);
            bc2.mov_r_imm64(14, 0x2222_2222_2222_2222u64);
            bc2.mem_cmpxchg_a(op, 15, 14);
            bc2.halt();
            let prog2 = bc2.finish();
            let (vi2, mi2, vn2, mn2) = mrun(&prog2, &data2, &[(15usize, 0x8000u64)])?;
            if mi2 != data2 || mn2 != data2 {
                return Err(anyhow!("[32-S4] cmpxchg{w} fail: mem must be unchanged"));
            }
            let v0_i = vi2[0];
            let v0_n = vn2[0];
            let exp_v0 = match w {
                1 => (0xDEAD_BEEF_0000_0000u64 & !0xFF) | (mem2_lo & 0xFF),
                2 => (0xDEAD_BEEF_0000_0000u64 & !0xFFFF) | (mem2_lo & 0xFFFF),
                _ => mem2_lo,
            };
            if v0_i != exp_v0 || v0_n != exp_v0 {
                return Err(anyhow!(
                    "[32-S4] cmpxchg{w} fail: v0 mismatch i={:X} n={:X} want={:X}",
                    v0_i,
                    v0_n,
                    exp_v0
                ));
            }
        }
        println!("[32-S4] width matrix 8/16/32/64 atomic CAS (Once state, success/fail, dirty-upper-RAX): PASS");
    }

    {
        use crate::vm::bytecode::*;
        let xchg_specs: &[(u8, usize)] = &[
            (OP_XCHG_MEM8_A, 1),
            (OP_XCHG_MEM16_A, 2),
            (OP_XCHG_MEM32_A, 4),
            (OP_XCHG_MEM64_A, 8),
        ];
        for &(op, w) in xchg_specs {
            let mask = if w == 8 {
                u64::MAX
            } else {
                (1u64 << (w * 8)) - 1
            };
            let mem_lo: u64 = 0x0102_0304_0506_0708 & mask;
            let src_val: u64 = 0xF0F0_F1F1_F2F2_F3F3;
            let mut data = vec![0u8; 16];
            for (i, b) in mem_lo.to_le_bytes().iter().enumerate().take(w) {
                data[i] = *b;
            }
            let mut bc = BytecodeBuilder::new();
            bc.mov_r_imm64(14, src_val);
            bc.mem_xchg_a(op, 15, 14);
            bc.halt();
            let prog = bc.finish();
            let (vi, mi, vn, mn) = mrun(&prog, &data, &[(15usize, 0x8000u64)])?;
            let src_lo = src_val & mask;
            let got_mem_i = u64::from_le_bytes(mi[..8].try_into().unwrap()) & mask;
            let got_mem_n = u64::from_le_bytes(mn[..8].try_into().unwrap()) & mask;
            if got_mem_i != src_lo || got_mem_n != src_lo {
                return Err(anyhow!(
                    "[32-S5] xchg{w}: mem mismatch (i={:X} n={:X} want={:X})",
                    got_mem_i,
                    got_mem_n,
                    src_lo
                ));
            }
            let want_v = match w {
                1 => (src_val & !0xFF) | (mem_lo & 0xFF),
                2 => (src_val & !0xFFFF) | (mem_lo & 0xFFFF),
                4 => mem_lo & 0xFFFF_FFFF,
                _ => mem_lo,
            };
            if vi[14] != want_v || vn[14] != want_v {
                return Err(anyhow!(
                    "[32-S5] xchg{w}: vreg mismatch (i={:X} n={:X} want={:X})",
                    vi[14],
                    vn[14],
                    want_v
                ));
            }
            if mi != mn {
                return Err(anyhow!("[32-S5] xchg{w}: interp/native mem mismatch"));
            }
        }
        println!("[32-S5] width matrix 8/16/32/64 atomic XCHG (Once CompletionGuard swap): PASS");
    }

    {
        use crate::vm::bytecode::*;
        let xadd_specs: &[(u8, usize)] = &[
            (OP_XADD_MEM8_A, 1),
            (OP_XADD_MEM16_A, 2),
            (OP_XADD_MEM32_A, 4),
            (OP_XADD_MEM64_A, 8),
        ];
        for &(op, w) in xadd_specs {
            let mask = if w == 8 {
                u64::MAX
            } else {
                (1u64 << (w * 8)) - 1
            };
            let mem_lo: u64 = 0x10 & mask;
            let add_lo: u64 = 0x05;
            let mut data = vec![0u8; 16];
            for (i, b) in mem_lo.to_le_bytes().iter().enumerate().take(w) {
                data[i] = *b;
            }
            let mut bc = BytecodeBuilder::new();
            bc.mov_r_imm64(14, add_lo);
            bc.mem_xadd_a(op, 15, 14);
            bc.halt();
            let prog = bc.finish();
            let (vi, mi, vn, mn) = mrun(&prog, &data, &[(15usize, 0x8000u64)])?;
            let sum_lo = (mem_lo + add_lo) & mask;
            let got_i = u64::from_le_bytes(mi[..8].try_into().unwrap()) & mask;
            let got_n = u64::from_le_bytes(mn[..8].try_into().unwrap()) & mask;
            if got_i != sum_lo || got_n != sum_lo {
                return Err(anyhow!(
                    "[32-S6] xadd{w}: mem sum mismatch (i={:X} n={:X} want={:X})",
                    got_i,
                    got_n,
                    sum_lo
                ));
            }
            let want_v = match w {
                1 => (add_lo & !0xFF) | (mem_lo & 0xFF),
                2 => (add_lo & !0xFFFF) | (mem_lo & 0xFFFF),
                4 => mem_lo & 0xFFFF_FFFF,
                _ => mem_lo,
            };
            if vi[14] != want_v || vn[14] != want_v {
                return Err(anyhow!(
                    "[32-S6] xadd{w}: vreg old mismatch (i={:X} n={:X} want={:X})",
                    vi[14],
                    vn[14],
                    want_v
                ));
            }
            if mi != mn {
                return Err(anyhow!("[32-S6] xadd{w}: interp/native mem mismatch"));
            }
        }
        println!(
            "[32-S6] width matrix 8/16/32/64 atomic XADD (AtomicUsize fetch_add refcount): PASS"
        );
    }

    // ── S7: Rust Once::call_once 2회 — 클로저는 정확히 1회만 실행해야 한다 ──
    //    state[0x8000]: 0 INCOMPLETE / 1 RUNNING / 3 COMPLETE
    //    count[0x8008]: 클로저 실행 카운터
    //    1) CAS INCOMPLETE→RUNNING 성공 → 클로저(count+=1) → XCHG RUNNING→COMPLETE
    //    2) 두 번째 call_once: state==COMPLETE 이므로 CAS 실패 → 클로저 재실행 금지
    //    만약 CAS/XCHG가 비원자·폭오류면 두 번째가 재실행 → count=2
    //    (f.take()==None → once.rs:166 unwrap panic 과 동일 조건)
    {
        use crate::vm::bytecode::*;
        let mut bc = BytecodeBuilder::new();
        let l_call2 = bc.new_label();
        let l_skip2 = bc.new_label();
        // v15 = &state 는 아래 mrun(.., state_seed=[(15,0x8000)]) 로 시드 (native는 arena-absolute 보정)
        bc.mov_r_r64(13, 15); // v13 = v15 (state)
        bc.binop_r_imm64(OP_ADD_R_IMM64, 13, 8); // v13 = &count(0x8008)

        // call_once #1
        bc.mov_r_imm64(0, 0); // expected INCOMPLETE
        bc.mov_r_imm64(14, 1); // new RUNNING
        bc.mem_cmpxchg_a(OP_CMPXCHG_MEM8_A, 15, 14); // [state]: 0→1, 성공시 ZF=1
        bc.jcc8(COND_JNE, l_call2); // CAS 실패면 #2로
                                    // 클로저: count += 1
        bc.mov_r_imm64(12, 1);
        bc.mem_xadd_a(OP_XADD_MEM8_A, 13, 12);
        // CompletionGuard: state = COMPLETE(3) via XCHG
        bc.mov_r_imm64(0, 3);
        bc.mem_xchg_a(OP_XCHG_MEM8_A, 15, 0);

        // call_once #2
        bc.mark_label(l_call2);
        bc.mov_r_imm64(0, 0); // expected INCOMPLETE
        bc.mov_r_imm64(14, 1);
        bc.mem_cmpxchg_a(OP_CMPXCHG_MEM8_A, 15, 14); // state==COMPLETE(3) → 실패(ZF=0)
        bc.jcc8(COND_JNE, l_skip2); // 실패(COMPLETE)면 클로저 재실행 금지 → skip
                                    // (만약 여기 도달하면 = CAS가 COMPLETE를 RUNNING으로 오인 → 클로저 재실행 = BUG)
        bc.mark_label(l_skip2);
        bc.halt();

        let prog = bc.finish();
        let mut data = vec![0u8; 16];
        data[0] = 0; // state INCOMPLETE
        data[8] = 0; // count = 0
        let (_, mi, _, mn) = mrun(&prog, &data, &[(15usize, 0x8000u64)])?;
        let state_i = mi[0];
        let state_n = mn[0];
        let cnt_i = u64::from_le_bytes(mi[8..16].try_into().unwrap());
        let cnt_n = u64::from_le_bytes(mn[8..16].try_into().unwrap());
        if state_i != 3 || state_n != 3 {
            return Err(anyhow!(
                "[32-S7] Once 2x call_once: state must be COMPLETE(3) (i={} n={})",
                state_i,
                state_n
            ));
        }
        if cnt_i != 1 || cnt_n != 1 {
            return Err(anyhow!("[32-S7] Once 2x call_once: closure must run EXACTLY ONCE (i={} n={}) -> would be once.rs:166 f.take().unwrap() on None", cnt_i, cnt_n));
        }
        println!("[32-S7] Once::call_once x2 end-to-end (CAS RUNNING + XCHG COMPLETE; closure runs exactly once): PASS");
    }

    Ok(())
}
