// ==============================================================================
// BTG Pipeline - Pass 4: .btg Section Assembly (with Anti-Debug injection)
// ==============================================================================
// v2 변경: 섹션 버퍼를 고엔트로피 PRNG 필러(v1) 대신 0x00(저엔트로피)으로 초기화.
// .textb 섹션명과 안티디버그 주입은 유지한다.
//
// v3 변경: `crypto` 플래그 추가.
//   - crypto=true: 섹션 tail에 BOOT_AREA_RESERVE(0x4000) 예약 (부트 스텁/시드/런테이블용).
//     섹션 특성을 RWX(0xE0000020)로 올려 부트 스텁이 코드 영역을 in-place 복호화 가능하게 한다.
//     entry_block_id/entry_key를 ctx에 저장 (crypto::run에서 재사용).
//     tail 안티디버그는 부트 스텁에 통합되므로 생략한다.
//   - crypto=false: v2와 동일한 동작 (안티디버그 tail 배치 유지).
// ==============================================================================

use crate::dispatcher;
use crate::mba::MbaGenerator;
use crate::pe::builder::SectionData;
use crate::pipeline::PipelineContext;
use crate::util::MAX_PADDING_SIZE;
use anyhow::Result;

/// v3 암호화 부트 스텁 + 시드 + 런 테이블용 예약 공간 (섹션 tail)
// 부트 스텁/시드/런테이블/VM 모듈을 담는 섹션 tail 예약 영역.
// v29: 0x4000→0x5000 (XMM state 증가). v38(수정): 0x5000→0xC000 — 큰 타깃
// (sr_ko: 원본 .text 173KB → 문자열 런 437개, 런 테이블만 8+437*16≈7KB)의
// 실제 레이아웃(부트 스텁 + VM KSA/PRGA 모듈 + 패드 + 런테이블 + 시드)이
// 0x5000을 초과해 "Boot area layout overlap"이 났다. crypto.rs는 섹션을
// 실제 boot_end로 잘라내므로(truncate) reserve는 임시 할당 상한일 뿐, 최종
// 파일 크기는 늘지 않는다.
pub const BOOT_AREA_RESERVE: usize = 0x4000000; // v61: 0x120000→0x4000000 (64 MiB) — 대형 commercial 타깃
                                                  // (SNK-RAT hello.exe: 프로그램 VM 바이트코드 11.6MB + branch_map
                                                  //  ~1.16M ip_map 엔트리 x 16B ≈ 18MB) 에서 "Boot area layout
                                                  //  overlap" (runs_off≈0x1B57AC8≈28MB) 가 났다. crypto.rs 는
                                                  //  섹션을 실제 boot_end 로 잘라내므로 reserve 는 임시 할당
                                                  //  상한일 뿐, 최종 파일 크기는 늘지 않는다.
    //          program-VM bytecode가 ~310KB (200KB 타깃 기준, 이전 ~177KB)까지 커진다.
    //          crypto.rs truncates the section to actual boot_end, so final file size
    //          is unaffected.

/// Pass 4: 디스패처 셸코드, OEP Stub, 점프 테이블, 블록 바이트를 결합하여
/// `.btg` 섹션 바이트 버퍼를 조립한다.
///
/// `anti_debug`가 true이면 안티 디버깅 셸코드를 주입하고,
/// `needs_boot_stub`이 true이면 tail에 부트 스텁 영역을 예약한다.
/// v9: crypto가 false여도 IAT/메모리 하드닝/페이로드 재배치가 있으면 부트 스텁
/// (경량 — IAT 해석/복사/메모리 하드닝만)을 위한 영역을 예약한다.
pub fn run(ctx: &mut PipelineContext, anti_debug: bool, needs_boot_stub: bool, trace_blocks: bool) -> Result<()> {
    let layout = ctx.shuffled_layout.as_ref()
        .ok_or_else(|| anyhow::anyhow!("ShuffledLayout not yet built — run Pass 2 first"))?;
    let table_offset = ctx.table_offset;
    let first_block_offset = ctx.first_block_offset;
    let dispatcher_va = ctx.dispatcher_va;
    let dispatcher_rva = ctx.dispatcher_rva;
    let num_blocks = layout.shuffled_blocks.len();
    let block_ring = ctx.block_ring;

    // ── 섹션 버퍼 크기 계산 (FIX: 올바른 블록별 offset + 길이 사용) ──────────────
    // v13.4d: --block-ring 이면 섹션 tail(부트 스텁 앞/혹은 끝)에 RING_REGION 을 예약.
    // 디스패처가 그 VA 를 알아야 하므로, total_section_size 를 먼저 확정한 뒤
    // 디스패처를 생성한다 (기존엔 디스패처를 먼저 만들었음).
    let mut max_phys_offset = first_block_offset;
    for block in &layout.shuffled_blocks {
        let logical_id = block.id as usize;
        let off = layout.table_offsets[logical_id] as usize;
        let end = off + block.instructions.len();
        if end > max_phys_offset {
            max_phys_offset = end;
        }
    }

    // v8: 재암호화 시 점프 테이블 뒤에 블록 길이 테이블(num_blocks*4)이 붙는다.
    // v61: --m7은 상태 테이블(num_blocks*4)까지 추가한다 (점프 + 길이 + 상태).
    // v61(+custom-cipher): C1 상태(0x80) + S-box 상수(0x100) 예약 (first_block 직전).
    let c1_reserve = if ctx.m7 && ctx.custom_cipher { 0x180 } else { 0 };
    let required_table_end = table_offset
        + num_blocks * 4
        + if ctx.reencrypt { num_blocks * 4 } else { 0 }
        + if ctx.m7 { num_blocks * 4 } else { 0 }
        + c1_reserve;
    let min_section_size = max_phys_offset.max(required_table_end);
    let mut total_section_size = ((min_section_size + 0xFF) & !0xFF) + 0x100;

    // v3: 부트 스텁 예약 영역 추가 (crypto 또는 iat/mem 하드닝 시)
    if needs_boot_stub {
        total_section_size += BOOT_AREA_RESERVE;
        ctx.crypto_enabled = true;
        ctx.boot_entry_offset = (total_section_size - BOOT_AREA_RESERVE) as u32;
    }

    // ── v13.4d diag: ring-buffer tail 예약 ───────────────────────────────────────
    // 부트 스텁이 있으면 그 직전, 없으면 섹션 끝에 RING_REGION 을 잡는다.
    let ring_va: u64 = if block_ring {
        let ring_off = if needs_boot_stub {
            total_section_size - BOOT_AREA_RESERVE - dispatcher::RING_REGION
        } else {
            total_section_size
        };
        total_section_size += dispatcher::RING_REGION;
        if needs_boot_stub {
            // 부트 스텁이 ring 뒤로 밀린다 — OEP 진입 오프셋 재계산
            ctx.boot_entry_offset = (total_section_size - BOOT_AREA_RESERVE) as u32;
        }
        dispatcher_va + ring_off as u64
    } else {
        0
    };

    // ── 디스패처 셸코드 생성 ─────────────────────────────────────────────────────
    // v8(Phase 0.3): 재암호화 디스패처는 블록별 RC4 KSA/PRGA 서브루틴을 내장한다.
    // v13.4d diag: ring-buffer 는 표준 디스패처(build_dispatcher)에서만 지원한다.
    // 재암호화 디스패처는 핸들러가 빡빡해 안정성 리스크 — 경고 후 무시.
    // v61: --m7은 refcount-safe 실행 후 재암호화 디스패처를 쓴다.
    //      --m7 + --custom-cipher면 BTG-C1 per-block 디스패처를 쓴다.
    //      (C1 상태/sbox는 first_block_offset 직전 예약 영역에 배치)
    let (c1_state_va, c1_sbox_va) = if ctx.m7 && ctx.custom_cipher {
        (
            dispatcher_va + (first_block_offset - 0x180) as u64,
            dispatcher_va + (first_block_offset - 0x100) as u64,
        )
    } else {
        (0, 0)
    };
    let dispatcher_bytes = if ctx.m7 {
        if ctx.custom_cipher {
            dispatcher::build_dispatcher_m7_c1(
                dispatcher_va,
                table_offset,
                num_blocks,
                ctx.mba_constant,
                trace_blocks,
                c1_state_va,
                c1_sbox_va,
            )
        } else {
            dispatcher::build_dispatcher_m7(
                dispatcher_va,
                table_offset,
                num_blocks,
                ctx.mba_constant,
                trace_blocks,
            )
        }
    } else if ctx.reencrypt {
        if block_ring {
            println!("[!] --block-ring: reencrypt dispatcher is not instrumented (standard-dispatcher only); ignored for this build.");
        }
        dispatcher::build_dispatcher_reencrypt(
            dispatcher_va,
            table_offset,
            num_blocks,
            ctx.mba_constant,
            trace_blocks,
        )
    } else {
        dispatcher::build_dispatcher(
            dispatcher_va,
            table_offset,
            num_blocks,
            trace_blocks,
            ctx.mba_constant,
            block_ring,
            ring_va,
        )
    };
    dispatcher::validate_dispatcher(&dispatcher_bytes)?;

    println!(
        "[+] Dispatcher: table_offset=0x{:X}, shellcode_len={} bytes, available={} bytes, anti_debug={}, block_ring={}",
        table_offset,
        dispatcher_bytes.len(),
        table_offset.saturating_sub(0x20),
        anti_debug,
        block_ring
    );

    let disp_end = 0x20 + dispatcher_bytes.len();
    if disp_end > table_offset {
        return Err(anyhow::anyhow!(
            "Dispatcher shellcode ({} bytes) overflows into jump table at offset 0x{:X}! (max {} bytes)",
            dispatcher_bytes.len(), table_offset, table_offset - 0x20
        ).into());
    }
    if block_ring {
        println!(
            "[+] Diag ring-buffer: {} entries x4B @VA 0x{:X} (next-index u32 @0x{:X}), region [0x{:X}..0x{:X})",
            dispatcher::RING_ENTRIES,
            ring_va,
            ring_va + dispatcher::RING_ENTRIES as u64 * 4,
            ring_va,
            ring_va + dispatcher::RING_REGION as u64
        );
    }

    // ── 안티 디버깅 셸코드 생성 (옵션) ───────────────────────────────────────────
    // 부트 스텁이 설치되면 안티디버그는 부트 스텁 내부 블록으로 통합된다.
    // v10 FIX: 셸코드 길이는 고정(ANTI_DEBUG_SIZE)이므로 ad_offset을 먼저 계산하고,
    //           절대 VA(ad_va/dispatcher_va)를 넣어 정상 경로가 디스패처로
    //           점프하도록 생성한다. (이전: tail에 배치만 하고 실행 경로가 없었음)
    let (anti_debug_bytes, ad_offset) = if anti_debug && !needs_boot_stub {
        // v13.4d: --block-ring 을 켠 진단 빌드는 부트 스텁이 필요(needs_boot_stub)하므로
        // 이 분기에 오지 않는다. 혹시 오더라도 ring 영역과 겹치지 않게 막아둔다.
        if block_ring {
            println!("[!] Anti-Debug shellcode skipped: overlaps --block-ring ring region without a boot stub (use a boot-stub config).");
            (Vec::new(), 0)
        } else {
            let off = total_section_size.saturating_sub(dispatcher::antidebug::ANTI_DEBUG_SIZE + 16);
            let ad = dispatcher::antidebug::build_anti_debug_shellcode(
                dispatcher_va + off as u64,
                dispatcher_va + 0x20,
            );
            println!("[+] Anti-Debug: Generated {} bytes of anti-debugging shellcode.", ad.len());
            (ad, off)
        }
    } else {
        (Vec::new(), 0)
    };

    // v2 (low-entropy): 섹션 버퍼를 0x00으로 초기화한다.
    // v1의 고엔트로피 PRNG 필러는 오히려 "패킹 흔적"처럼 보였고,
    // 원본의 0xCC 대량 패딩도 패킹 지문이었다. 밀집 패킹(pass3)으로 블록 사이
    // 간격이 최소화되므로, 잔여 여백/테일은 0x00(저엔트로피)으로 채운다.
    // 실행되는 영역(OEP/디스패처/테이블/블록/안티디버그)은 아래에서 전부 덮어써진다.
    let mut btg_bytes = vec![0u8; total_section_size];

    // ── OEPStub (offset 0x00) ───────────────────────────────────────────────────
    let entry_block_id = resolve_entry_block_id(ctx)?;
    // v6: OEP 스텁은 (block_id, seed)를 push — 디스패처가 MBA 항등식으로 키 재도출
    let entry_seed = MbaGenerator::seed_for(ctx.mba_constant, entry_block_id as u32);

    // v3: entry 정보 저장 (crypto::run이 boot stub에 임베드)
    ctx.entry_block_id = entry_block_id;
    ctx.entry_seed = entry_seed;

    let mut oep_stub = Vec::new();
    if ctx.reencrypt {
        // v8(Phase 0.3): 디스패처 3-푸시 규약 [seed][target_id][current_id].
        // 첫 디스패치에는 직전 블록이 없으므로 current = 0xFFFFFFFF(센티널).
        oep_stub.extend_from_slice(&[0x68]);                       // push imm32 (current_id = sentinel)
        oep_stub.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        oep_stub.extend_from_slice(&[0x68]);                       // push imm32 (entry_block_id)
        oep_stub.extend_from_slice(&(entry_block_id as u32).to_le_bytes());
        oep_stub.extend_from_slice(&[0x68]);                       // push imm32 (entry_seed)
        oep_stub.extend_from_slice(&entry_seed.to_le_bytes());
        oep_stub.extend_from_slice(&[0xEB, 0x0F]);                 // jmp short +0x0F → 0x20
    } else {
        oep_stub.extend_from_slice(&[0x68]);                       // push imm32 (entry_block_id)
        oep_stub.extend_from_slice(&(entry_block_id as u32).to_le_bytes());
        oep_stub.extend_from_slice(&[0x68]);                       // push imm32 (entry_seed)
        oep_stub.extend_from_slice(&entry_seed.to_le_bytes());
        if !anti_debug_bytes.is_empty() {
            // v10 FIX: 안티디버그 셸코드 경로 — OEP → 셸코드(검사) → 디스패처(0x20).
            // jmp rel32: 점프 명령은 오프셋 10, next_ip=15, 타깃=ad_offset.
            let disp = (ad_offset as i64) - 15;
            oep_stub.extend_from_slice(&[0xE9]);
            oep_stub.extend_from_slice(&(disp as i32).to_le_bytes());
        } else {
            oep_stub.extend_from_slice(&[0xEB, 0x14]);             // jmp short +0x14 → 0x20
        }
    }

    btg_bytes[0..oep_stub.len()].copy_from_slice(&oep_stub);

    // ── CFG 스텁 (offset 0x18~0x1F) ─────────────────────────────────────────────
    btg_bytes[0x18..0x1C].copy_from_slice(&[0x01, 0x00, 0x00, 0x00]); // UNWIND_INFO
    btg_bytes[0x1D..0x1F].copy_from_slice(&[0xFF, 0xE0]);              // jmp rax
    btg_bytes[0x1F] = 0xC3;                                            // ret

    // ── Anti-Debug shellcode (섹션 끝 여유 영역에 배치) ──────────────────────────
    // v10: ad_offset는 위에서 OEP 스텁과 함께 계산 (고정 길이 셸코드).
    if !anti_debug_bytes.is_empty() {
        btg_bytes[ad_offset..ad_offset + anti_debug_bytes.len()]
            .copy_from_slice(&anti_debug_bytes);
        println!("[+] Anti-Debug: Placed at section offset 0x{:X}", ad_offset);
    }

    // ── Dispatcher (offset 0x20) ─────────────────────────────────────────────────
    btg_bytes[0x20..disp_end].copy_from_slice(&dispatcher_bytes);

    // ── Jump Table (offset table_offset) ─────────────────────────────────────────
    let layout = ctx.shuffled_layout.as_ref().unwrap();
    for (logical_id, &encrypted_entry) in layout.encrypted_table_entries.iter().enumerate() {
        let tbl_pos = table_offset + logical_id * 4;
        if tbl_pos + 4 <= btg_bytes.len() {
            btg_bytes[tbl_pos..tbl_pos + 4].copy_from_slice(&encrypted_entry.to_le_bytes());
        }
    }

    // ── v8(Phase 0.3): 블록 길이 테이블 (per-block MBA 키로 암호화) ────────────
    // 점프 테이블과 동일하게 **logical id**를 인덱스로 쓴다 (셔플 순서 아님).
    if ctx.reencrypt {
        let length_table_offset = table_offset + num_blocks * 4;
        let mut call_target_count = 0usize;
        for block in &layout.shuffled_blocks {
            let id = block.id as usize;
            let seed = MbaGenerator::seed_for(ctx.mba_constant, block.id);
            let key = MbaGenerator::compute_key(seed, block.id, ctx.mba_constant, 2);
            // v11 FIX: call-target 블록은 평문 유지 — 길이 테이블에 len_enc = key 를
            // 기록해 디스패처가 복호화한 길이 = 0 (센티널) → block_crypt가 생략된다.
            // (0xC0000096 call-into-ciphertext 크래시 수정)
            let len_enc = if ctx.call_target_block_ids.contains(&block.id) {
                call_target_count += 1;
                key
            } else {
                (block.instructions.len() as u32) ^ key
            };
            // v14: 디스패처 상태 머신 마커(0xFFFFFFFE = "복호화 중")
            // 충돌 검사 — 충돌하면 영구 spin 방지를 위해
            // 빌드 시점에 거부한다 (재빌드시 새 시드/셔플).
            if len_enc == 0xFFFF_FFFEu32 {
                return Err(anyhow::anyhow!(
                    "v14: block {} length entry 0xFFFFFFFE collides with dispatcher claim marker - rebuild (shuffle/seed re-randomizes)",
                    id
                ));
            }
            let tbl_pos = length_table_offset + id * 4;
            if tbl_pos + 4 <= btg_bytes.len() {
                btg_bytes[tbl_pos..tbl_pos + 4].copy_from_slice(&len_enc.to_le_bytes());
            }
        }
        println!(
            "[+] v8 Dispatcher Re-Encrypt: length table ({} entries, key-XORed) @0x{:X} ({} call-target plaintext sentinels)",
            num_blocks, length_table_offset, call_target_count
        );
    }

    // ── v61 (--m7): on-demand 상태 테이블 (num_blocks×4) ──────────────────────
    // 0xFFFFFFFF = 암호화 (복호화 필요), 0 = 복호화/미접근(또는 call-target 평문),
    // 그 외 k = 복호화 + k개 컨텍스트 실행 중 (refcount). 실행은 디스패처가 원자적
    // 상태 전이로 관리한다 — 파일에는 전부 0xFFFFFFFF(암호화) 또는 call-target 0.
    if ctx.m7 {
        let state_table_offset = table_offset + num_blocks * 8;
        let mut call_target_count = 0usize;
        for block in &layout.shuffled_blocks {
            let id = block.id as usize;
            let state: u32 = if ctx.call_target_block_ids.contains(&block.id) {
                call_target_count += 1;
                0 // call-target(평문) — 디스패처가 length 센티널로 상태 머신 스킵
            } else {
                0xFFFF_FFFF // 암호화 상태로 시작
            };
            let tbl_pos = state_table_offset + id * 4;
            if tbl_pos + 4 <= btg_bytes.len() {
                btg_bytes[tbl_pos..tbl_pos + 4].copy_from_slice(&state.to_le_bytes());
            }
        }
        println!(
            "[+] v61 M7: on-demand state table ({} entries: ENC/call-target) @0x{:X} ({} call-target plaintext)",
            num_blocks, state_table_offset, call_target_count
        );
    }

    // ── v61 (--custom-cipher + --m7): C1 S-box 상수 테이블 배치 ────────────────
    // [first_block_offset-0x180 .. first_block_offset-0x100) = C1 상태 버퍼(0x80,
    // 디스패처 C1Init이 런타임에 초기화), [..-0x100 .. first_block_offset) =
    // 256B S-box 상수 테이블 (패커가 기록 — 디스패처 blob이 c1_sbox_va로 참조).
    if ctx.m7 && ctx.custom_cipher {
        let sbox_off = first_block_offset - 0x100;
        let sbox = crate::crypto::nonlinear::sbox();
        if sbox_off + 0x100 <= btg_bytes.len() {
            btg_bytes[sbox_off..sbox_off + 0x100].copy_from_slice(&sbox);
        }
        // C1 상태 버퍼는 0으로 초기화 (디스패처 C1Init이 key/ctr/nonce/ks_off 기록)
        let state_off = first_block_offset - 0x180;
        if state_off + 0x80 <= btg_bytes.len() {
            btg_bytes[state_off..state_off + 0x80].fill(0);
        }
        println!(
            "[+] v61 M7-C1: C1 sbox @0x{:X} (256B), state @0x{:X} (0x80B) reserved before first_block 0x{:X}",
            sbox_off, state_off, first_block_offset
        );
    }

    // ── Trigger Blocks ───────────────────────────────────────────────────────────
    for (i, block) in layout.shuffled_blocks.iter().enumerate() {
        let logical_id = block.id as usize;
        let phys_offset = layout.table_offsets[logical_id] as usize;
        let encrypted_offset = layout.encrypted_table_entries[logical_id];
        let block_len = block.instructions.len();

        let ct_mark = if ctx.call_target_block_ids.contains(&block.id) {
            " | CALL-TARGET (plaintext)"
        } else {
            ""
        };
        println!(
            "    [Block {:02}] Logical ID: {} | Phys Offset: 0x{:04X} | Encrypted Entry: 0x{:08X} | Entries: {} | Len: {}{}",
            i, block.id, phys_offset, encrypted_offset, block.entries.len(), block_len, ct_mark
        );

        if phys_offset + block_len > btg_bytes.len() {
            return Err(anyhow::anyhow!(
                "Block {} at offset 0x{:X} + len {} exceeds section size 0x{:X}!",
                block.id, phys_offset, block_len, btg_bytes.len()
            ).into());
        }

        if i + 1 < layout.shuffled_blocks.len() {
            let next_id = layout.shuffled_blocks[i + 1].id;
            let next_phys = layout.table_offsets[next_id as usize] as usize;
            if phys_offset + block_len > next_phys {
                return Err(anyhow::anyhow!(
                    "Block {} (0x{:X}..0x{:X}) overflows into next block {} slot at 0x{:X}! block_len={}",
                    block.id, phys_offset, phys_offset + block_len, next_id, next_phys, block_len
                ).into());
            }
        }

        btg_bytes[phys_offset..phys_offset + block_len].copy_from_slice(&block.instructions);
        // ── ud2 (0x0F 0x0B) 은 그대로 둔다 — NOP 변환 금지 (v13.4c) ─────────────
        // `ud2`는 "절대 fall-through 하지 않는다"는 하드 트랩 계약이다. 이를 nop nop
        // (0x90 0x90)로 바꾸면 블록 shuffle 레이아웃에서 그 다음 블록으로 제어가
        // 흘러 들어가(엉뚱한 함수 진입) panic → 잘못된 OS unwind → 잘못된 RSP →
        // 0xC0000005 로 이어진다. ud2가 유효 경로로 도달하는 상황 자체가 별개 버그이지
        // 트랩을 지워서 고칠 일이 아니다. 도달 시 해당 명령에서 깨끗하게 fault 하도록
        // 원본 0x0F 0x0B 를 보존한다. (crypto.rs 의 전섹션 ud2 sweep 도 동일하게 제거)
    }

    // ── ud2 보존 확인 (v13.4c) ───────────────────────────────────────────────────
    // ud2는 더 이상 NOP으로 변환하지 않는다(위 주석 참조). 블록 shuffle로 인해
    // 블록 내 ud2는 해당 블록의 종단 트랩으로 그대로 유지된다. 여기서는 단순히
    // 블록 코드에 원본 ud2가 그대로 보존되었음을 집계해 로그로 남긴다 (변환 안 함).
    {
        let mut original_ud2 = 0usize;
        for block in &layout.shuffled_blocks {
            let n = block.instructions.len();
            let mut j = 0usize;
            while j + 1 < n {
                if block.instructions[j] == 0x0f && block.instructions[j + 1] == 0x0b {
                    original_ud2 += 1;
                    j += 2;
                } else {
                    j += 1;
                }
            }
        }
        if original_ud2 > 0 {
            println!("[+] Pass4: Preserved {} ud2 trap(s) verbatim across {} code blocks in .textb (no NOP conversion — fall-through safety).",
                original_ud2, layout.shuffled_blocks.len());
        }
    }

    // v3: crypto/부트 스텁일 때 섹션을 RWX로 (부트 스텁이 코드를 in-place 복호화/
    // 복사, 또는 IAT 슬롯을 기록)
    let characteristics = if needs_boot_stub { 0xE0000020u32 } else { 0x60000020u32 };

    ctx.btg_section_data = Some(SectionData {
        name: ".textb".to_string(), // decoy section name (was .btg)
        virtual_address: dispatcher_rva,
        virtual_size: btg_bytes.len() as u32,
        characteristics, // CODE | EXECUTE | READ (+ WRITE if crypto)
        bytes: btg_bytes,
    });

    println!(
        "[+] Pass 4 Complete: .btg section assembled ({} bytes, entry_block_id={}, OEP_RVA=0x{:X}, boot_stub={}).",
        total_section_size, entry_block_id, dispatcher_rva, needs_boot_stub
    );

    Ok(())
}

/// 원본 OEP VA로부터 대응하는 Trigger Block ID를 찾는다.
fn resolve_entry_block_id(ctx: &PipelineContext) -> Result<usize> {
    let target_ep_va = ctx.target_info.image_base + ctx.target_info.entry_point_rva as u64;
    let va_map = &ctx.va_to_trigger_id;

    if let Some(&id) = va_map.get(&target_ep_va) {
        println!("[INFO] Entry Block ID resolved to {} for OEP VA 0x{:X}", id, target_ep_va);
        return Ok(id as usize);
    }

    if let Some((&next_va, &next_id)) = va_map.range((target_ep_va + 1)..).next() {
        if next_va - target_ep_va <= MAX_PADDING_SIZE {
            println!("[INFO] Entry Block ID resolved to {} (next after padding) for OEP VA 0x{:X}", next_id, target_ep_va);
            return Ok(next_id as usize);
        }
    }

    if let Some((_, &id)) = va_map.range(..=target_ep_va).next_back() {
        eprintln!("[WARN] OEP VA 0x{:X} is inside block ID {}. Using that block.", target_ep_va, id);
        return Ok(id as usize);
    }

    eprintln!("[WARN] Could not find entry block for OEP VA 0x{:X}! Defaulting to block 0.", target_ep_va);
    Ok(0)
}
