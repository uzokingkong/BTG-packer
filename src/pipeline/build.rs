// ==============================================================================
// BTG Pipeline - Build: PE Synthesis & Output
// ==============================================================================

use crate::dispatcher::{UNWIND_ALLOC8, dispatcher_unwind_codes};
use crate::pe::builder::{DataDirectory, PeMultiSectionBuilder, SectionData};
use crate::pe::parser::RuntimeFunction;
use crate::pipeline::PipelineContext;
use anyhow::Result;
use std::fs;
use std::path::Path;

/// 최종 PE 이진 파일을 합성하고 (선택적으로) 디스크에 기록한다.
///
/// 처리 순서:
/// 1. DataDirectory 정리 (Debug, Security, Relocations 제거)
/// 2. `.pdata` SEH 테이블 갱신 (.btg 커버리지는 디스패처 부트 영역만 타이트하게)
/// 3. `PeMultiSectionBuilder::build()` 호출
/// 4. `output_path`가 `Some`이면 파일 기록, `None`이면 바이트만 반환
///
/// 리뷰 지적 #29: library API(`pack::run_full`)가 호출자의 working directory에
/// 부수 파일을 만들지 않도록, 파일 기록을 호출자가 명시적으로 요청할 때만
/// 하게끔 `Option<&Path>` 로 받는다.
///
/// # 반환
/// 빌드된 PE 바이너리 바이트열.
pub fn run(ctx: &PipelineContext, output_path: Option<&Path>) -> Result<Vec<u8>> {
    ctx.layout()?;
    let btg_section = ctx
        .btg_section_data
        .clone()
        .ok_or_else(|| anyhow::anyhow!("btg_section_data not set — run Pass 4 first"))?;

    let dispatcher_rva = ctx.dispatcher_rva;
    // 디스패처/부트 스텁 영역 길이: [dispatcher .. dispatcher+first_block_offset)
    // 까지만이 실제 연속적인 "부트 함수"(고유 prologue + UNWIND_INFO). 그 뒤의
    // shuffled 블록 영역은 각기 다른 stack frame 의 무수한 블록이므로 단일
    // RUNTIME_FUNCTION 으로 커버하면 안 된다 (잘못된 unwind → 잘못된 RSP →
    // 0xC0000005). 브리지 진입 스텁(boot/dispatcher)만 최소 UNWIND_INFO 로 감싼다.
    let boot_area_len = ctx.first_block_offset as u32;
    // ── DataDirectory 정리 ────────────────────────────────────────────────────────
    let mut clean_data_dirs = ctx.target_info.data_directories.clone();
    // idx=4 Security, idx=5 .reloc, idx=6 Debug 제거
    for idx in &[4usize, 5, 6] {
        if clean_data_dirs.len() > *idx {
            clean_data_dirs[*idx] = DataDirectory { virtual_address: 0, size: 0 };
        }
    }
    // v4: --rsrc-register — 리소스 디렉터리를 재구성된 트리로 교체
    if ctx.rsrc_dir_rva > 0 && clean_data_dirs.len() > 2 {
        clean_data_dirs[2] = DataDirectory {
            virtual_address: ctx.rsrc_dir_rva,
            size: ctx.rsrc_dir_size,
        };
    }
    // v6: --iat-hide — import 디렉터리를 더미(LoadLibraryA/GetProcAddress)로 교체
    if ctx.iat_dir_rva > 0 && clean_data_dirs.len() > 1 {
        clean_data_dirs[1] = DataDirectory {
            virtual_address: ctx.iat_dir_rva,
            size: ctx.iat_dir_size,
        };
    }

    // ── DLL Characteristics: DYNAMIC_BASE(0x0040), HIGH_ENTROPY_VA(0x0020), GUARD_CF(0x4000) 제거 ──
    let clean_dll_characteristics = ctx.target_info.dll_characteristics & !(0x0020 | 0x0040 | 0x4000);

    // ── 패치된 섹션에서 .pdata SEH 테이블 재구성 ────────────────────────────────
    // 원본 `.text`는 TLS 콜백, VM native bridge, 그리고 entry_native 경로에서 계속
    // 실행된다. 따라서 원본 RUNTIME_FUNCTION 항목을 반드시 유지하고, 새 디스패처
    // 브리지 영역의 leaf 항목만 추가한다. `--keep-pdata`는 진단 호환성을
    // 위해 새 항목까지 추가하지 않는 완전 원본 유지 모드로 남긴다.
    //
    // 브리지 leaf가 커버하는 실제 코드는 [dispatcher+0x20 .. dispatcher+boot_area_len),
    // 즉 디스패처 본체(셔플 블록/부트 스텁은 커버하지 않는다 — 이들은 `.textb`의
    // 나머지처럼 원칙적으로 unwind 커버리지 밖이다). UNWIND_INFO는 하드코딩하지 않고
    // 실제 디스패처의 `pushfq`/`push r64` prologue를 역어셈블해 생성한다. (기존
    // `PUSH RBX + ALLOC 0x20` 하드코딩은 표준 디스패처의 pushfq/rax/rcx/r10/r11
    // prologue와 재암호화 디스패처의 16-푸시 prologue 어느 것과도 일치하지 않는 허상
    // 이었다 — 잘못된 unwind → 잘못된 RSP → 0xC0000005 경로의 원인이 될 수 있다.)
    let mut relayed_sections = ctx.patched_sections.clone();
    // 브리지 leaf 가 커버하는 디스패처 본체(.textb 섹션 오프셋 0x20)의 prologue 를
    // 디코드해 UNWIND_INFO 를 생성한다. `.textb` 는 patched_sections 에 없고
    // `btg_section_data` 에 있으므로 여기서 읽는다 (relayed_sections 에서 찾으면
    // bridge_unwind 가 None → 브리지 leaf 가 누락되는 회귀).
    let bridge_unwind: Option<(u8, Vec<(u8, u8)>)> = ctx
        .btg_section_data
        .as_ref()
        .map(|sec| {
            let end = (0x20 + boot_area_len as usize).min(sec.bytes.len());
            let disp = if end > 0x20 { &sec.bytes[0x20..end] } else { &[] };
            let (codes, prolog_len) = dispatcher_unwind_codes(disp);
            (prolog_len, codes.iter().map(|c| (c.offset, c.reg)).collect())
        });
    if ctx.keep_pdata {
        println!("[+] .pdata: KEPT original (--keep-pdata) — build.rs SEH rebuild skipped; original RUNTIME_FUNCTION table left verbatim");
    } else {
        update_pdata_seh(
            &mut relayed_sections,
            &mut clean_data_dirs,
            &ctx.target_info.original_pdata_entries,
            dispatcher_rva,
            boot_area_len,
            bridge_unwind.as_ref(),
        );
    }

    // ── PE 빌드 ───────────────────────────────────────────────────────────────────
    // v3: 암호화가 켜져 있으면 부트 스텁(boot stub)이 새 진입점이 된다.
    // ctx.boot_entry_offset = 부트 스텁의 섹션 내 오프셋 (0이면 기존 OEP = 섹션 시작)
    let entry_point_rva = dispatcher_rva + ctx.boot_entry_offset;

    let multi_builder = PeMultiSectionBuilder::new(
        ctx.target_info.image_base,
        entry_point_rva,
        ctx.target_info.subsystem,
        clean_dll_characteristics,
        ctx.target_info.stack_reserve,
        ctx.target_info.stack_commit,
        ctx.target_info.heap_reserve,
        ctx.target_info.heap_commit,
        ctx.target_info.file_alignment,
        ctx.target_info.section_alignment,
        clean_data_dirs,
        relayed_sections,
        btg_section,
        ctx.payload_section_data.clone(),
        ctx.target_info.original_headers_bytes.clone(),
    );

    let output_pe_bytes = multi_builder.build()?;

    if let Some(path) = output_path {
        fs::write(path, &output_pe_bytes)?;
        println!("==================================================================");
        println!("[SUCCESS] Synthesized Protected BTG PE Binary Written to: {}", path.display());
        println!("[INFO] Size of Output Protected Binary: {} bytes", output_pe_bytes.len());
        println!("[INFO] Protected Entry Point (OEP) RVA: 0x{:X}", entry_point_rva);
        println!("==================================================================");
    } else {
        println!("==================================================================");
        println!("[SUCCESS] Synthesized Protected BTG PE Binary (in-memory, {} bytes)", output_pe_bytes.len());
        println!("[INFO] Protected Entry Point (OEP) RVA: 0x{:X}", entry_point_rva);
        println!("==================================================================");
    }

    Ok(output_pe_bytes)
}

// ── x64 UNWIND_INFO / UNWIND_CODE 상수 (PE/COFF §5.8, Win64 ABI) ─────────────
/// UNWIND_INFO Version (낮은 3비트). 로더는 version==1 만 수용한다.
const UNWIND_VERSION: u8 = 1;
/// UWOP_PUSH_NONVOL — callee-saved 정수 레지스터를 스택에 push.
const UWOP_PUSH_NONVOL: u8 = 0;
/// UWOP_ALLOC_SMALL — 8..=128 바이트 소형 스택 할당 (OpInfo = (size/8)-1).
const UWOP_ALLOC_SMALL: u8 = 2;

/// SEH 브리지 디스패처 영역용 UNWIND_INFO 바이트 열을 생성한다.
///
/// UNWIND_CODE 는 하드코딩하지 않고, 디스패처의 **실제 prologue**(`pushfq`/
/// `push r64` 시퀀스)에서 `dispatcher_unwind_codes`가 뽑아낸 사양으로부터 만든다.
///  - 비휘발성 GPR push   → `UWOP_PUSH_NONVOL(reg)` (언와인드 시 레지스터 복원)
///  - pushfq/휘발성 push   → `UWOP_ALLOC_SMALL(8)` (RSP 정산만 — 복원 불필요)
/// 이렇게 하면 UNWIND_INFO 가 로더가 실제 실행하는 코드와 항상 일치한다.
///
/// 반환 구조 (DWORD 정렬, 로더 수용 조건 충족):
/// ```text
/// +0  Version(3) | Flags(5)      = 0x01 (v1, no handler)
/// +1  SizeOfProlog
/// +2  CountOfCodes               = codes.len()
/// +3  FrameRegister(4)|Offset(4) = 0
/// +4  UNWIND_CODE[0]  (CodeOffset, UnwindOp|OpInfo)
/// ... UNWIND_CODE[n-1]
/// +pad DWORD 경계
/// ```
fn build_bridge_unwind_info(size_of_prolog: u8, codes: &[(u8, u8)]) -> Vec<u8> {
    let mut info = Vec::with_capacity(4 + codes.len() * 2);
    // byte0: Version | Flags(0 = exception handler 없음)
    info.push((UNWIND_VERSION & 0x07) | 0);
    // byte1: SizeOfProlog
    info.push(size_of_prolog);
    // byte2: CountOfCodes
    info.push(codes.len() as u8);
    // byte3: FrameRegister=0, FrameRegisterOffset=0
    info.push(0);
    // UNWIND_CODE[...]: byte0 = CodeOffset, byte1 = (OpInfo << 4) | UnwindOp
    for &(off, reg) in codes {
        info.push(off);
        if reg == UNWIND_ALLOC8 {
            // 8바이트 스택 op (pushfq/휘발성 push) — UWOP_ALLOC_SMALL(8): OpInfo=0.
            info.push((0 << 4) | UWOP_ALLOC_SMALL);
        } else {
            // 비휘발성 GPR push — UWOP_PUSH_NONVOL(reg). reg 는 Win64 레지스터 번호.
            info.push(((reg & 0x0F) << 4) | UWOP_PUSH_NONVOL);
        }
    }
    // DWORD 정렬
    while info.len() % 4 != 0 {
        info.push(0);
    }
    info
}

/// `.pdata` SEH 테이블을 재구성한다 (v13.4c → P4: 브리지 UNWIND_INFO 생성).
///
/// 블록 shuffle 결과는 새 `.textb` 주소에 있으므로 원본 `.text`의 RUNTIME_FUNCTION
/// 범위와 겹치지 않는다. 원본 `.text` 자체도 그대로 보존되며 네이티브 경로에서
/// 실행되므로 기존 항목을 삭제하면 Rust panic/TLS teardown의 OS unwind가 깨진다.
/// 따라서:
///   1. 유효한 원본 항목을 주소 변경 없이 모두 보존한다.
///   2. **브리지 디스패처** 영역 [dispatcher+0x20 .. dispatcher+boot_area_len) 을
///      커버하는 RUNTIME_FUNCTION 하나를 추가하고, 그 UNWIND_INFO 는 실제
///      디스패처 prologue에서 유도한 UNWIND_CODE(헤더 + PUSH_NONVOL/ALLOC_SMALL)로
///      생성한다. 생성된 UNWIND_INFO 는 `.pdata` 섹션의 RUNTIME_FUNCTION 배열
///      직후에 DWORD 정렬로 이어붙인다. (예전처럼 `.btg` 전체를 하나의
///      RUNTIME_FUNCTION 로 등록하면 서로 다른 stack frame 을 가진 수천 블록을
///      하나의 UNWIND_INFO 로 처리하려다 잘못된 unwind 가 된다.)
///   3. 로더가 STATUS_INVALID_IMAGE_FORMAT 으로 거부하지 않도록 Exception
///      Directory(Idx 3) 크기는 RUNTIME_FUNCTION 배열 길이(12 바이트 배수)로
///      유지하고, UNWIND_INFO 는 배열 뒤에 두어 배열 파싱에 영향을 주지 않게 한다.
fn update_pdata_seh(
    relayed_sections: &mut Vec<SectionData>,
    clean_data_dirs: &mut Vec<DataDirectory>,
    original_pdata_entries: &[RuntimeFunction],
    dispatcher_rva: u32,
    boot_area_len: u32,
    bridge_unwind: Option<&(u8, Vec<(u8, u8)>)>,
) {
    if let Some(pdata_sec) = relayed_sections.iter_mut().find(|s| s.name == ".pdata") {
        // 원본 `.text`는 그대로 존재하고 네이티브 경로에서 실행되므로 전부 보존한다.
        let mut rf_list: Vec<RuntimeFunction> = original_pdata_entries
            .iter()
            .filter(|rf| {
                rf.begin_address > 0
                    && rf.end_address > rf.begin_address
            })
            .copied()
            .collect();

        // 브리지 디스패처 영역만 커버하는 타이트 leaf 추가 (.btg 전체가 아님).
        // 기존 엔트리와 Begin 이 충돌하지 않을 때만. UNWIND_INFO RVA 는 배열을
        // 직렬화한 뒤의 .pdata 내부 오프셋으로 아래에서 채운다. 디스패처 본체는
        // 섹션 오프셋 0x20 에 있으므로(섹션 시작 0x0 = OEP 스텁) begin 은 0x20.
        let bridge_begin = dispatcher_rva + 0x20;
        let mut added_bridge = false;
        let mut unwind_info: Vec<u8> = Vec::new();
        if let Some((prolog_len, codes)) = bridge_unwind {
            if !rf_list.iter().any(|rf| rf.begin_address == bridge_begin) {
                added_bridge = true;
                rf_list.push(RuntimeFunction {
                    begin_address: bridge_begin,
                    end_address: dispatcher_rva + boot_area_len,
                    unwind_info_address: 0, // 채워질 자리
                });
            }
            unwind_info = build_bridge_unwind_info(*prolog_len, codes);
        }

        rf_list.sort_by_key(|rf| rf.begin_address);
        rf_list.dedup_by_key(|rf| rf.begin_address);

        // RUNTIME_FUNCTION 배열 (12 바이트/엔트리). Exception Directory 크기로 쓴다.
        let array_len = rf_list.len() as u32 * 12;

        // UNWIND_INFO 를 배열 직후 .pdata 내부로 이어붙인다 (DWORD 정렬: 12|4).
        let unwind_rva = pdata_sec.virtual_address + array_len;

        // 브리지 엔트리의 UNWIND_INFO 주소를 채운다.
        for rf in rf_list.iter_mut() {
            if rf.begin_address == bridge_begin {
                rf.unwind_info_address = unwind_rva;
            }
        }

        let mut pdata_bytes = Vec::with_capacity(array_len as usize + unwind_info.len());
        for rf in &rf_list {
            pdata_bytes.extend_from_slice(&rf.begin_address.to_le_bytes());
            pdata_bytes.extend_from_slice(&rf.end_address.to_le_bytes());
            pdata_bytes.extend_from_slice(&rf.unwind_info_address.to_le_bytes());
        }
        pdata_bytes.extend_from_slice(&unwind_info);

        pdata_sec.bytes = pdata_bytes.clone();
        // Exception Directory 크기 = RUNTIME_FUNCTION 배열만 (로더가 size/12 로
        // 엔트리 수를 세므로 UNWIND_INFO 를 포함하면 오파싱 → STATUS_INVALID_IMAGE_FORMAT).
        pdata_sec.virtual_size = array_len;

        if clean_data_dirs.len() > 3 {
            clean_data_dirs[3] = DataDirectory {
                virtual_address: pdata_sec.virtual_address,
                size: array_len,
            };
            println!(
                "[+] Rebuilt SEH Table (.pdata): RVA 0x{:X}, {} entries (Size 0x{:X}) + bridge UNWIND_INFO @0x{:X} [original native entries preserved; bridge leaf 0x{:X}..0x{:X} added, prolog_len=0x{:X}, {} codes]",
                pdata_sec.virtual_address, rf_list.len(), array_len,
                unwind_rva, bridge_begin, dispatcher_rva + boot_area_len,
                bridge_unwind.map(|(l, _)| *l).unwrap_or(0),
                bridge_unwind.map(|(_, c)| c.len()).unwrap_or(0)
            );
            let _ = added_bridge;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dispatcher::{UNWIND_ALLOC8, build_dispatcher, build_dispatcher_reencrypt};

    #[test]
    fn pdata_rebuild_preserves_native_entries_and_adds_bridge_leaf() {
        let originals = vec![
            RuntimeFunction {
                begin_address: 0x1000,
                end_address: 0x1100,
                unwind_info_address: 0x3000,
            },
            RuntimeFunction {
                begin_address: 0x1200,
                end_address: 0x1300,
                unwind_info_address: 0x3010,
            },
        ];
        let mut sections = vec![SectionData {
            name: ".pdata".to_string(),
            virtual_address: 0x4000,
            virtual_size: 24,
            characteristics: 0x4000_0040,
            bytes: vec![0; 24],
        }];
        let mut directories = vec![
            DataDirectory {
                virtual_address: 0,
                size: 0,
            };
            16
        ];

        // 브리지 UNWIND_CODE: PUSH_NONVOL(RBX=3) @1 + ALLOC8 @0x0C (실제 디스패처
        // prologue를 모사하는 합성 코드).
        let bridge_unwind = (0x0Eu8, vec![(0x01u8, 0x03u8), (0x0Cu8, UNWIND_ALLOC8)]);
        update_pdata_seh(
            &mut sections,
            &mut directories,
            &originals,
            0x5000,
            0x80,
            Some(&bridge_unwind),
        );

        // 원본 2 + 브리지 1 = 3개 RUNTIME_FUNCTION (36 바이트) + UNWIND_INFO(8) = 44.
        assert_eq!(sections[0].bytes.len(), 44);
        // Exception Directory 크기는 배열만.
        assert_eq!(directories[3].virtual_address, 0x4000);
        assert_eq!(directories[3].size, 36);
        assert_eq!(sections[0].virtual_size, 36);

        let words: Vec<u32> = sections[0]
            .bytes[..36]
            .chunks_exact(4)
            .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
            .collect();
        // 브리지 엔트리 begin=0x5020(디스패처 = 섹션 0x0 + 0x20), end=0x5080,
        // unwind=0x4000+36=0x4024.
        assert_eq!(
            words,
            vec![
                0x1000, 0x1100, 0x3000,
                0x1200, 0x1300, 0x3010,
                0x5020, 0x5080, 0x4024,
            ]
        );
    }

    #[test]
    fn pdata_runtime_function_unwind_info_generated() {
        let originals = vec![RuntimeFunction {
            begin_address: 0x1000,
            end_address: 0x1010,
            unwind_info_address: 0x2000,
        }];
        let mut sections = vec![SectionData {
            name: ".pdata".to_string(),
            virtual_address: 0x4000,
            virtual_size: 12,
            characteristics: 0x4000_0040,
            bytes: vec![0; 12],
        }];
        let mut directories = vec![
            DataDirectory {
                virtual_address: 0,
                size: 0,
            };
            16
        ];

        // 표준 디스패처 prologue (pushfq; push rax; push rcx; push r10; push r11)를
        // 합성한 UNWIND_CODE — 전부 8바이트 스택 op (pushfq/휘발성 GPR).
        let bridge_unwind = (0x07u8, vec![
            (0x00u8, UNWIND_ALLOC8), // pushfq
            (0x01u8, UNWIND_ALLOC8), // push rax
            (0x02u8, UNWIND_ALLOC8), // push rcx
            (0x03u8, UNWIND_ALLOC8), // push r10
            (0x05u8, UNWIND_ALLOC8), // push r11
        ]);
        update_pdata_seh(
            &mut sections,
            &mut directories,
            &originals,
            0x5000,
            0x40,
            Some(&bridge_unwind),
        );

        // 배열 24 바이트(2 엔트리) + UNWIND_INFO (4 헤더 + 5*2 코드 = 14 → 16) = 40.
        assert_eq!(sections[0].bytes.len(), 40);
        let unwind_off = 24usize;
        let unwind = &sections[0].bytes[unwind_off..unwind_off + 16];

        // 헤더: Version=1, Flags=0.
        assert_eq!(unwind[0] & 0x07, UNWIND_VERSION);
        assert_eq!(unwind[0] & 0xF8, 0);
        // SizeOfProlog = 7 (5 push 명령의 총 길이).
        assert_eq!(unwind[1], 0x07);
        // CountOfCodes = 5.
        assert_eq!(unwind[2], 5);
        // FrameRegister/Offset = 0.
        assert_eq!(unwind[3], 0);

        // 모든 코드가 UWOP_ALLOC_SMALL(8) (OpInfo=0, op=ALLOC_SMALL=2) 이어야 한다.
        for i in 0..5 {
            let off = unwind[4 + i * 2];
            let opbyte = unwind[5 + i * 2];
            assert_eq!(opbyte & 0x0F, UWOP_ALLOC_SMALL, "code {i} op");
            assert_eq!(opbyte >> 4, 0, "code {i} alloc OpInfo (8B/8-1=0)");
            let _ = off;
        }
        assert_eq!(unwind[4], 0x00);
        assert_eq!(unwind[6], 0x01);
        assert_eq!(unwind[8], 0x02);
        assert_eq!(unwind[10], 0x03);
        assert_eq!(unwind[12], 0x05);
    }

    #[test]
    fn pdata_loader_field_structure_verified() {
        let originals = vec![RuntimeFunction {
            begin_address: 0x1000,
            end_address: 0x1010,
            unwind_info_address: 0x2000,
        }];
        let mut sections = vec![SectionData {
            name: ".pdata".to_string(),
            virtual_address: 0x4000,
            virtual_size: 12,
            characteristics: 0x4000_0040,
            bytes: vec![0; 12],
        }];
        let mut directories = vec![
            DataDirectory {
                virtual_address: 0,
                size: 0,
            };
            16
        ];

        let bridge_unwind = (0x07u8, vec![
            (0x00u8, UNWIND_ALLOC8),
            (0x01u8, UNWIND_ALLOC8),
            (0x02u8, UNWIND_ALLOC8),
            (0x03u8, UNWIND_ALLOC8),
            (0x05u8, UNWIND_ALLOC8),
        ]);
        update_pdata_seh(
            &mut sections,
            &mut directories,
            &originals,
            0x5000,
            0x40,
            Some(&bridge_unwind),
        );

        let pdata = &sections[0].bytes;
        let dir = directories[3];

        // 로더는 Exception Directory 크기가 12바이트(RUNTIME_FUNCTION)의 배수임을 요구.
        assert_eq!(dir.virtual_address, 0x4000);
        assert_eq!(dir.size % 12, 0);
        let num_entries = dir.size as usize / 12;
        assert_eq!(num_entries, 2);

        // 각 엔트리: Begin < End, UNWIND_INFO 가 4바이트 정렬.
        for i in 0..num_entries {
            let begin = u32::from_le_bytes(pdata[i * 12..i * 12 + 4].try_into().unwrap());
            let end = u32::from_le_bytes(pdata[i * 12 + 4..i * 12 + 8].try_into().unwrap());
            let unwind = u32::from_le_bytes(pdata[i * 12 + 8..i * 12 + 12].try_into().unwrap());
            assert!(begin < end, "entry {}: begin 0x{:X} < end 0x{:X}", i, begin, end);
            assert_eq!(unwind % 4, 0, "entry {}: unwind 0x{:X} not DWORD aligned", i, unwind);
        }

        // 브리지(우리가 추가한) 엔트리는 UNWIND_INFO 가 .pdata 섹션 내부(배열 뒤
        // DWORD 정렬 위치)를 가리켜야 한다. 원본 엔트리는 원본 .text/.rdata 의
        // UNWIND_INFO 를 가리키므로 .pdata 밖일 수 있다 (정상).
        let bridge = pdata
            .chunks_exact(12)
            .nth(num_entries - 1)
            .unwrap();
        let bridge_begin = u32::from_le_bytes(bridge[0..4].try_into().unwrap());
        assert_eq!(bridge_begin, 0x5020); // 디스패처 = dispatcher_rva + 0x20
        let bridge_unwind = u32::from_le_bytes(bridge[8..12].try_into().unwrap());
        assert_eq!(bridge_unwind, 0x4000 + 24); // .pdata 시작 + 배열(24) = UNWIND_INFO
        assert!(
            bridge_unwind >= 0x4000 && bridge_unwind < 0x4000 + pdata.len() as u32,
            "bridge unwind 0x{:X} outside .pdata",
            bridge_unwind
        );

        // 정렬: BeginAddress 오름차순이어야 로더가 이분 탐색 가능.
        let begins: Vec<u32> = (0..num_entries)
            .map(|i| u32::from_le_bytes(pdata[i * 12..i * 12 + 4].try_into().unwrap()))
            .collect();
        let mut sorted = begins.clone();
        sorted.sort_unstable();
        assert_eq!(begins, sorted);
    }

    #[test]
    fn build_bridge_unwind_info_layout() {
        // DWORD 정렬 + 헤더/코드 구조 검증 (PUSH_NONVOL + ALLOC8 혼합).
        let codes = vec![(0x01u8, 0x03u8), (0x0Cu8, UNWIND_ALLOC8)];
        let info = build_bridge_unwind_info(0x0E, &codes);
        assert_eq!(info.len() % 4, 0);
        assert_eq!(info.len(), 8);
        assert_eq!(info[0], 0x01);
        assert_eq!(info[1], 0x0E);
        assert_eq!(info[2], 2);
        assert_eq!(info[3], 0);
        assert_eq!(info[4], 0x01);
        assert_eq!(info[5], (0x03 << 4) | UWOP_PUSH_NONVOL); // PUSH_NONVOL RBX
        assert_eq!(info[6], 0x0C);
        assert_eq!(info[7], (0 << 4) | UWOP_ALLOC_SMALL); // ALLOC_SMALL(8)
    }

    /// 리뷰 지적 #28 검증: 생성된 UNWIND_INFO 가 **실제 디스패처 prologue와 정확히
    /// 일치**해야 한다 (형식 검증이 아니라 코드 대조).
    #[test]
    fn bridge_unwind_info_matches_real_dispatcher_prologue() {
        for (code, name) in [
            (build_dispatcher(0x140001000, 0x80, 16, false, 0xCAFEBABE, false, 0), "plain"),
            (build_dispatcher(0x140001000, 0x80, 16, true, 0xCAFEBABE, false, 0), "plain+trace"),
            (build_dispatcher_reencrypt(0x140001000, 0x600, 16, 0xCAFEBABE, false), "reencrypt"),
        ] {
            let (codes, prolog_len) = crate::dispatcher::dispatcher_unwind_codes(&code);
            let unwind = build_bridge_unwind_info(prolog_len, &codes.iter().map(|c| (c.offset, c.reg)).collect::<Vec<_>>());
            // 헤더
            assert_eq!(unwind[0] & 0x07, UNWIND_VERSION, "{name}");
            assert_eq!(unwind[1], prolog_len, "{name}: SizeOfProlog");
            assert_eq!(unwind[2] as usize, codes.len(), "{name}: CountOfCodes");
            assert_eq!(unwind[3], 0, "{name}: frame reg");
            // 코드가 prologue 길이를 초과하지 않는다
            for c in &codes {
                assert!((c.offset as u16) < prolog_len as u16, "{name}: code off {}", c.offset);
            }
            // DWORD 정렬
            assert_eq!(unwind.len() % 4, 0, "{name}");
            // 실제 디스패처 첫 바이트가 pushfq(0x9C)이면 첫 코드가 ALLOC8(flags) 이어야 한다
            if code[0] == 0x9C {
                assert_eq!(codes.first().unwrap().reg, UNWIND_ALLOC8, "{name}: pushfq");
                assert_eq!(codes.first().unwrap().offset, 0, "{name}: pushfq offset");
            }
        }
    }
}
