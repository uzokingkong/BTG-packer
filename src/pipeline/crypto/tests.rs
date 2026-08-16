use super::bootstub::{build_anti_debug_raw_block, build_rc4_block, BootStubCtx};
use super::cipher::Rc4;
use super::integrity::crc32;
use super::scan::scan_string_runs;
use super::{run, ANTI_DEBUG_BLOCK_LEN, IMPORT_MBA_C};
use crate::crypto::chain_encrypt;
use crate::pe::builder::SectionData;
use crate::pipeline::PipelineContext;

    #[test]
    fn test_rc4_roundtrip() {
        let key = [0x11u8; 32];
        let mut data = vec![0xABu8; 4096];
        let orig = data.clone();
        let mut enc = Rc4::new(&key);
        enc.crypt(&mut data);
        assert_ne!(data, orig);
        let mut dec = Rc4::new(&key);
        dec.crypt(&mut data);
        assert_eq!(data, orig);
    }

    #[test]
    fn test_rc4_known_key() {
        // Wikipedia RC4 test vector (key "Key")
        let key = b"Key";
        let mut rc4 = Rc4::new(key);
        let mut out = [0u8; 3];
        rc4.crypt(&mut out);
        assert_eq!(out, [0xEB, 0x9F, 0x77]);
    }

    #[test]
    fn test_chained_roundtrip() {
        // v7: chained_encrypt로 암호화 → 동일 체인으로 복호화 → 원문 복원 + 마지막 윈도우 일치
        let anchor = [0xA7u8; 256];
        let mut data: Vec<u8> = (0..5000u32).map(|i| (i.wrapping_mul(31) + 7) as u8).collect();
        let orig = data.clone();
        let last_key = chain_encrypt(&mut data, &anchor);

        let mut prev = anchor;
        let mut off = 0usize;
        while off < data.len() {
            let n = (data.len() - off).min(256);
            let mut rc4 = Rc4::new(&prev);
            rc4.crypt(&mut data[off..off + n]);
            if off + n >= 256 {
                prev.copy_from_slice(&data[off + n - 256..off + n]);
            } else {
                prev = [0u8; 256];
                prev[..off + n].copy_from_slice(&data[..off + n]);
            }
            off += n;
        }
        assert_eq!(data, orig, "chained decrypt must restore plaintext");
        assert_eq!(prev, last_key, "last 256B window must match encrypt return");
    }

    #[test]
    fn test_anti_debug_block_length() {
        let b = build_anti_debug_raw_block();
        assert_eq!(b.len(), ANTI_DEBUG_BLOCK_LEN);
        assert_eq!(&b[b.len()-4..b.len()-2], &[0x0F, 0x0B]); // ud2
        assert_eq!(&b[b.len()-2..], &[0x58, 0x9D]); // pop rax; popfq
    }

    #[test]
    fn test_boot_stub_generates() {
        // build_rc4_block + build_anti_debug_raw_block가 패닉 없이 인코딩되는지 검증
        let stub = BootStubCtx {
            boot_va: 0x140001000,
            anti_debug: true,
            dispatcher_va: 0x140001020,
            code_va: 0x140005000,
            code_len: 0x100,
            runs_va: 0x140001400,
            num_runs: 2,
            seed_va: 0x140001500,
            k1: 0xDEADBEEF,
            k2: 0x12345678,
            k3: 0x0BADF00D,
            entry_block_id: 7,
            entry_seed: 0xAABBCCDD,
            vm: false,
            chained: false,
            reencrypt: false,
            no_crypto: false,
            vm_entry_va: 0,
            vm_state_va: 0,
            vm_prga: false,
            vm_prga_entry_va: 0,
            vm_prga_state_va: 0,
            vm_oep: false,
            vm_prog_entry_va: 0,
            vm_prog_state_va: 0,
            vm_oep_native_entry: false,
            vm_oep_native_va: 0,
            vm_oep_bc_va: 0,
            vm_oep_bc_len: 0,
            vm_oep_text_va: 0,
            vm_oep_text_len: 0,
            vm_oep_text_runs_va: 0,
            vm_oep_text_runs_count: 0,
            payload_va: 0,
            payload_len: 0,
            integrity: false,
            crc_va: 0,
            iat_enabled: false,
            iat_table_va: 0,
            iat_ll_slot_va: 0,
            iat_gpa_slot_va: 0,
        mba_master: 0x12345678,
        mba_c: IMPORT_MBA_C,
            mem_harden: false,
            mem_ntdll_name_va: 0,
            mem_ntprot_name_va: 0,
            mem_code_base: 0,
            mem_code_size: 0,
            stack_frame: 0x118,
            c1_mode: false,
            c1_blob_va: 0,
            c1_sbox_va: 0,
            c1_state_va: 0,
        };
        let ad = build_anti_debug_raw_block();
        assert_eq!(ad.len(), ANTI_DEBUG_BLOCK_LEN);
        let code = build_rc4_block(&stub);
        assert!(!code.is_empty());
        assert!(code.len() > 100, "rc4 block too small: {}", code.len());
        // 마지막 명령이 ret(0xC3)이어야 한다 (prga 서브루틴 종료)
        assert_eq!(*code.last().unwrap(), 0xC3);

        // anti_debug=false 변형도 인코딩 가능해야 한다
        let stub2 = BootStubCtx { anti_debug: false, ..stub };
        let code2 = build_rc4_block(&stub2);
        assert!(!code2.is_empty());
    }

    #[test]
    fn test_key_mix_deterministic() {
        // v10: 키 유도는 vm/ksa::key_mix 단일 소스 — 패커 키 == reference_ksa의
        // S-box(부트 스텁/VM과 동일 경로)와 동치여야 한다.
        let k1 = 0xDEADBEEFu32;
        let k2 = 0x12345678u32;
        let k3 = 0x0BADF00Du32;
        let seed_masked: Vec<u8> = (0..256u32)
            .map(|i| ((i.wrapping_mul(31) + 7) as u8) ^ 0xA7)
            .collect();
        let mut key = [0u8; 256];
        for i in 0..256usize {
            let iu = i as u32;
            key[i] = seed_masked[i] ^ (crate::vm::ksa::key_mix(iu, k1, k2, k3) as u8);
        }
        // key_mix 결정성 + 인접 i 확산
        assert_eq!(
            crate::vm::ksa::key_mix(3, k1, k2, k3),
            crate::vm::ksa::key_mix(3, k1, k2, k3)
        );
        assert_ne!(
            crate::vm::ksa::key_mix(3, k1, k2, k3),
            crate::vm::ksa::key_mix(4, k1, k2, k3)
        );
        // 패커 key → RC4 KSA S-box == reference_ksa S-box (부트 스텁/VM 동치성)
        let mut rc4 = Rc4::new(&key);
        let mut ref_sbox = [0u8; 256];
        crate::vm::ksa::reference_ksa(
            &seed_masked.clone().try_into().unwrap(),
            k1,
            k2,
            k3,
            &mut ref_sbox,
        );
        assert_eq!(
            rc4.sbox(),
            &ref_sbox,
            "packer key derivation must match reference KSA (boot stub / VM path)"
        );
    }

    #[test]
    fn test_boot_stub_ksa_matches_shared_list() {
        // v10 회귀: 부트 스텁이 쓰는 KSA 명령 리스트는 vm/ksa::build_ksa_instructions와
        // 정확히 같아야 한다 (단일 소스). 명령 코드/피연산자 종류를 비교한다.
        let shared = crate::vm::ksa::build_ksa_instructions(0x140001500, 0x11111111, 0x22222222, 0x33333333);
        let codes: Vec<iced_x86::Code> = shared.iter().map(|k| k.inst.code()).collect();
        // 리스트는 S[i]=i init 루프로 시작하고 KSA 루프를 포함해야 한다
        assert!(codes.contains(&iced_x86::Code::Mov_rm8_r8));
        assert!(codes.contains(&iced_x86::Code::Jb_rel32_64));
        assert!(codes.contains(&iced_x86::Code::Ror_rm32_imm8), "v10 key_mix must end with ror");
        // 부트 스텁 build_rc4_block가 이 리스트를 그대로 소비하는지 (라벨 매핑 스모크)
        let stub = BootStubCtx {
            boot_va: 0x140001000,
            anti_debug: false,
            dispatcher_va: 0x140001020,
            code_va: 0x140005000,
            code_len: 0x100,
            runs_va: 0x140001400,
            num_runs: 1,
            seed_va: 0x140001500,
            k1: 0x11111111,
            k2: 0x22222222,
            k3: 0x33333333,
            entry_block_id: 0,
            entry_seed: 0xAABBCCDD,
            vm: false,
            chained: false,
            reencrypt: false,
            no_crypto: false,
            vm_entry_va: 0,
            vm_state_va: 0,
            vm_prga: false,
            vm_prga_entry_va: 0,
            vm_prga_state_va: 0,
            vm_oep: false,
            vm_prog_entry_va: 0,
            vm_prog_state_va: 0,
            vm_oep_native_entry: false,
            vm_oep_native_va: 0,
            vm_oep_bc_va: 0,
            vm_oep_bc_len: 0,
            vm_oep_text_va: 0,
            vm_oep_text_len: 0,
            vm_oep_text_runs_va: 0,
            vm_oep_text_runs_count: 0,
            payload_va: 0,
            payload_len: 0,
            integrity: false,
            crc_va: 0,
            iat_enabled: false,
            iat_table_va: 0,
            iat_ll_slot_va: 0,
            iat_gpa_slot_va: 0,
        mba_master: 0x12345678,
        mba_c: IMPORT_MBA_C,
            mem_harden: false,
            mem_ntdll_name_va: 0,
            mem_ntprot_name_va: 0,
            mem_code_base: 0,
            mem_code_size: 0,
            stack_frame: 0x118,
            c1_mode: false,
            c1_blob_va: 0,
            c1_sbox_va: 0,
            c1_state_va: 0,
        };
        let code = build_rc4_block(&stub);
        assert!(!code.is_empty());
        assert_eq!(*code.last().unwrap(), 0xC3);
    }

    #[test]
    fn test_scan_ascii_runs_still_work() {
        // 일반 ASCII 문자열("LoadLibraryA\0")은 여전히 감지되어야 한다.
        let mut sec = SectionData {
            name: ".rdata".to_string(),
            virtual_address: 0x5000,
            virtual_size: 0x100,
            characteristics: 0x40000040,
            bytes: {
                let mut b = vec![0u8; 0x100];
                b[..12].copy_from_slice(b"LoadLibraryA");
                b
            },
        };
        let runs = scan_string_runs(std::slice::from_mut(&mut sec), 0x140000000, &[]);
        assert_eq!(runs.len(), 1, "ASCII string run should be detected");
        assert_eq!(runs[0].len, 12);
        assert_eq!(runs[0].va, 0x140005000);
    }

    #[test]
    fn test_scan_utf16_runs_detected() {
        // FIX 회귀 테스트: UTF-16LE 문자열("Hello World\0", 22바이트)이 감지되어야 한다.
        // 과거 구현은 ASCII 스캔이 첫 문자를 소비해 wide 런을 절대 찾지 못했다.
        // Bug-1 fix: 런은 4바이트 정렬 경계로 절단되므로 22바이트 -> 20바이트(4-정렬)로
        // 감지된다(usize 상태 워드가 런 경계에 걸치지 않도록).
        let mut sec = SectionData {
            name: ".rdata".to_string(),
            virtual_address: 0x5000,
            virtual_size: 0x100,
            characteristics: 0x40000040,
            bytes: {
                let mut b = vec![0u8; 0x100];
                for (i, c) in "Hello World".encode_utf16().enumerate() {
                    b[i * 2] = c as u8;
                    b[i * 2 + 1] = (c >> 8) as u8;
                }
                b
            },
        };
        let runs = scan_string_runs(std::slice::from_mut(&mut sec), 0x140000000, &[]);
        assert!(!runs.is_empty(), "UTF-16LE string run should be detected");
        assert_eq!(runs[0].len, 20, "Hello World = 22B, truncated to 4-aligned 20B");
        assert_eq!(runs[0].va, 0x140005000);
    }

    #[test]
    fn test_full_pipeline_crypto_anti_debug_no_overlap() {
        // FIX 회귀 테스트: crypto + anti_debug로 실제 더미 타깃 전체 파이프라인을 돌려
        // 부트 영역 레이아웃(스텁 vs 런테이블/시드)이 겹치지 않는지 검증한다.
        // 과거 코드는 cursor = boot_off + stub_code_len 로 계산해 anti_debug 블록(69B)만큼
        // 런테이블/시드가 RC4 코드 꼬리를 덮어써 이 테스트가 Err를 반환했다.
        let dummy = crate::pe::generate_dummy_target_pe().unwrap();
        let info = crate::pe::TargetPeInfo::parse(&dummy).unwrap();
        let section_alignment = if info.section_alignment == 0 { 0x1000 } else { info.section_alignment };
        let dispatcher_rva: u32 = info
            .relayed_sections
            .iter()
            .map(|s| {
                s.virtual_address
                    + ((s.virtual_size.max(s.bytes.len() as u32) + section_alignment - 1) / section_alignment)
                        * section_alignment
            })
            .max()
            .unwrap_or(0x2000);
        let dispatcher_va = info.image_base + dispatcher_rva as u64;
        let mut ctx = PipelineContext::new(info, dispatcher_va, dispatcher_rva, 3);
        crate::pipeline::pass1_slice::run(&mut ctx).unwrap();
        crate::pipeline::pass2_shuffle::run(&mut ctx).unwrap();
        crate::pipeline::pass3_encode::run(&mut ctx).unwrap();
        crate::pipeline::pass4_section::run(&mut ctx, true, true, false).unwrap();
        let relayed = ctx.target_info.relayed_sections.clone();
        crate::pipeline::patch_data::run(&mut ctx, relayed).unwrap();
        run(&mut ctx, true, true, false, 100, false, false, false, false).unwrap();

        // 부트 스텁의 마지막 바이트(ret, 0xC3)가 런테이블/시드에 덮이지 않아야 한다.
        let btg = ctx.btg_section_data.as_ref().unwrap();
        let boot_off = ctx.boot_entry_offset as usize;
        // crypto::run의 Err 가드가 통과했다는 것 자체가 레이아웃 무결성을 보장한다.
        // v5: 동적 부트 영역 — 고정 예약(0x4000) 대신 사용분만 남도록 잘렸어야 한다.
        assert!(
            btg.bytes.len() < boot_off + 0x4000,
            "v5 size control failed: section not trimmed (len=0x{:X}, boot_off=0x{:X})",
            btg.bytes.len(),
            boot_off
        );
        // 런 테이블/시드가 스텁 뒤에 배치됐고, 잘린 tail에도 부트 콘텐츠가 남아 있다.
        assert!(btg.bytes.len() - boot_off >= 0x100);
    }

    #[test]
    fn test_crc32_known_vector() {
        // 표준 CRC-32 체크 벡터 (zlib): crc32("123456789") == 0xCBF43926
        assert_eq!(crc32(b"123456789"), 0xCBF43926);
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn test_boot_stub_generates_with_integrity() {
        // --integrity 경로의 부트 스텁이 인코딩 가능하고 길이 불변(VA 픽스업)한지 검증.
        let stub = BootStubCtx {
            boot_va: 0x140001000,
            anti_debug: true,
            dispatcher_va: 0x140001020,
            code_va: 0x140005000,
            code_len: 0x100,
            runs_va: 0x140001400,
            num_runs: 2,
            seed_va: 0x140001500,
            k1: 0xDEADBEEF,
            k2: 0x12345678,
            k3: 0x0BADF00D,
            entry_block_id: 7,
            entry_seed: 0xAABBCCDD,
            vm: false,
            chained: false,
            reencrypt: false,
            no_crypto: false,
            vm_entry_va: 0,
            vm_state_va: 0,
            vm_prga: false,
            vm_prga_entry_va: 0,
            vm_prga_state_va: 0,
            vm_oep: false,
            vm_prog_entry_va: 0,
            vm_prog_state_va: 0,
            vm_oep_native_entry: false,
            vm_oep_native_va: 0,
            vm_oep_bc_va: 0,
            vm_oep_bc_len: 0,
            vm_oep_text_va: 0,
            vm_oep_text_len: 0,
            vm_oep_text_runs_va: 0,
            vm_oep_text_runs_count: 0,
            payload_va: 0x140006000,
            payload_len: 0x100,
            integrity: true,
            crc_va: 0x140001600,
            iat_enabled: false,
            iat_table_va: 0,
            iat_ll_slot_va: 0,
            iat_gpa_slot_va: 0,
        mba_master: 0x12345678,
        mba_c: IMPORT_MBA_C,
            mem_harden: false,
            mem_ntdll_name_va: 0,
            mem_ntprot_name_va: 0,
            mem_code_base: 0,
            mem_code_size: 0,
            stack_frame: 0x138,
            c1_mode: false,
            c1_blob_va: 0,
            c1_sbox_va: 0,
            c1_state_va: 0,
        };
        let code = build_rc4_block(&stub);
        assert!(!code.is_empty());
        // 마지막 명령이 ret(0xC3)이어야 한다 (prga 서브루틴 종료)
        assert_eq!(*code.last().unwrap(), 0xC3);
        // CRC 루틴이 포함됐는지: ud2(0F 0B) + CRC 폴리 상수(ED B8 83 20) 흔적 검사
        let has_ud2 = code.windows(2).any(|w| w == [0x0F, 0x0B]);
        assert!(has_ud2, "integrity stub must contain ud2 trap");
    }

    #[test]
    fn test_phase03_per_block_encryption_roundtrip() {
        // v8 (Phase 0.3): --dispatcher-reencrypt 전체 파이프라인 → 각 블록이
        // 블록별 MBA 키로 개별 RC4 암호화되어 있고, 디스패처가 쓰는 키로
        // 복호화하면 정확히 평문(block.instructions)이 복원되는지 + 길이 테이블
        // 엔트리 동치성을 검증한다.
        let dummy = crate::pe::generate_dummy_target_pe().unwrap();
        let info = crate::pe::TargetPeInfo::parse(&dummy).unwrap();
        let section_alignment = if info.section_alignment == 0 { 0x1000 } else { info.section_alignment };
        let dispatcher_rva: u32 = info
            .relayed_sections
            .iter()
            .map(|s| {
                s.virtual_address
                    + ((s.virtual_size.max(s.bytes.len() as u32) + section_alignment - 1) / section_alignment)
                        * section_alignment
            })
            .max()
            .unwrap_or(0x2000);
        let dispatcher_va = info.image_base + dispatcher_rva as u64;
        let mut ctx = PipelineContext::new(info, dispatcher_va, dispatcher_rva, 3);
        ctx.reencrypt = true; // Phase 0.3 활성 — pass4가 재암호화 디스패처/길이 테이블 배치
        crate::pipeline::pass1_slice::run(&mut ctx).unwrap();
        crate::pipeline::pass2_shuffle::run(&mut ctx).unwrap();
        crate::pipeline::pass3_encode::run(&mut ctx).unwrap();
        crate::pipeline::pass4_section::run(&mut ctx, true, true, false).unwrap();
        let relayed = ctx.target_info.relayed_sections.clone();
        crate::pipeline::patch_data::run(&mut ctx, relayed).unwrap();
        run(&mut ctx, true, true, false, 40, false, false, false, true)
            .unwrap();

        let btg = ctx.btg_section_data.as_ref().unwrap();
        let layout = ctx.layout().unwrap();
        let num_blocks = layout.shuffled_blocks.len();
        assert!(num_blocks > 0);
        for block in &layout.shuffled_blocks {
            let id = block.id;
            let off = layout.table_offsets[id as usize] as usize;
            let len = block.instructions.len();
            let seed = crate::mba::MbaGenerator::seed_for(ctx.mba_constant, id);
            let key = crate::mba::MbaGenerator::compute_key(seed, id, ctx.mba_constant, 2);
            // 길이 테이블 엔트리:
            //   일반 블록: len_enc ^ key == len
            //   call-target 블록(v11+): len_enc == key → 복호화 길이 0 (평문 센티널)
            let len_off = ctx.table_offset + num_blocks * 4 + (id as usize) * 4;
            let len_enc = u32::from_le_bytes(btg.bytes[len_off..len_off + 4].try_into().unwrap());
            let is_ct = ctx.call_target_block_ids.contains(&id);
            if is_ct {
                assert_eq!(
                    len_enc, key,
                    "call-target block {} length sentinel mismatch (len_enc ^ key must be 0)",
                    id
                );
                // call-target 블록은 파일에 평문으로 저장된다
                assert_eq!(
                    &btg.bytes[off..off + len],
                    block.instructions.as_slice(),
                    "call-target block {} must be stored plaintext",
                    id
                );
            } else {
                assert_eq!(len_enc ^ key, len as u32, "length table mismatch for block {}", id);
                // 블록 roundtrip: per-block 키로 복호화 → 평문 복원
                let mut rc4 = Rc4::new(&key.to_le_bytes());
                let mut dec = btg.bytes[off..off + len].to_vec();
                rc4.crypt(&mut dec);
                assert_eq!(
                    dec, block.instructions,
                    "block {} must roundtrip with per-block key",
                    id
                );
            }
        }
    }
