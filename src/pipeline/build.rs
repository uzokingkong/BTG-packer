// ==============================================================================
// BTG Pipeline - Build: PE Synthesis & Output
// ==============================================================================

use crate::dispatcher::{dispatcher_unwind_codes, UNWIND_ALLOC8};
use crate::pe::builder::{DataDirectory, PeMultiSectionBuilder, SectionData};
use crate::pe::parser::RuntimeFunction;
use crate::pe::reloc::build_reloc_directory;
use crate::pipeline::PipelineContext;
use anyhow::Result;
use std::fs;
use std::path::Path;

/// 筌ㅼ뮇伊?PE ??곸춭 ???뵬????밴쉐??랁?(?醫뤾문?怨몄몵嚥? ?遺용뮞??肉?疫꿸퀡以??뺣뼄.
///
/// 筌ｌ꼶????뽮퐣:
/// 1. DataDirectory ?類ｂ봺 (Debug, Security, Relocations ??볤탢)
/// 2. `.pdata` SEH ???뵠??揶쏄퉮??(.btg ?뚣끇苡?뵳?????遺용뮞??μ퓗 ?봔???怨몃열筌?????꾨뱜??띿쓺)
/// 3. `PeMultiSectionBuilder::build()` ?紐꾪뀱
/// 4. `output_path`揶쎛 `Some`???????뵬 疫꿸퀡以? `None`????獄쏅뗄??紐껋춸 獄쏆꼹??
///
/// ?귐됰윮 筌왖??#29: library API(`pack::run_full`)揶쎛 ?紐꾪뀱?癒?벥 working directory??
/// ?봔?????뵬??筌띾슢諭억쭪? ??낅즲嚥? ???뵬 疫꿸퀡以???紐꾪뀱?癒? 筌뤿굞??怨몄몵嚥??遺욧퍕?????춸
/// ??띿쓺??`Option<&Path>` 嚥?獄쏆룆???
///
/// # 獄쏆꼹??
/// ??슢諭??PE 獄쏅뗄???댿봺 獄쏅뗄??紐꾨였.
pub fn run(ctx: &PipelineContext, output_path: Option<&Path>) -> Result<Vec<u8>> {
    ctx.layout()?;
    let btg_section = ctx
        .btg_section_data
        .clone()
        .ok_or_else(|| anyhow::anyhow!("btg_section_data not set ??run Pass 4 first"))?;

    let dispatcher_rva = ctx.dispatcher_rva;
    // ?遺용뮞??μ퓗/?봔????쎈??怨몃열 疫뀀챷?? [dispatcher .. dispatcher+first_block_offset)
    // 繹먮슣?筌띾슣????쇱젫 ?怨쀫꺗?怨몄뵥 "?봔????λ땾"(?⑥쥙? prologue + UNWIND_INFO). 域???쇱벥
    // shuffled ?됰뗀以??怨몃열?? 揶쏄낫由???삘뀲 stack frame ???얜똻????됰뗀以???嚥???μ뵬
    // RUNTIME_FUNCTION ??곗쨮 ?뚣끇苡??롢늺 ????뺣뼄 (??롢걵??unwind ????롢걵??RSP ??
    // 0xC0000005). ?됰슢?곻쭪? 筌욊쑴????쎈?boot/dispatcher)筌?筌ㅼ뮇??UNWIND_INFO 嚥?揶쏅Ŋ???
    let boot_area_len = ctx.first_block_offset as u32;
    // ???? DataDirectory ?類ｂ봺 ????????????????????????????????????????????????????????????????????????????????????????????????????????????????
    let mut clean_data_dirs = ctx.target_info.data_directories.clone();
    // idx=4 Security, idx=5 .reloc, idx=6 Debug ??볤탢
    for idx in &[4usize, 5, 6, 11] {
        if clean_data_dirs.len() > *idx {
            clean_data_dirs[*idx] = DataDirectory {
                virtual_address: 0,
                size: 0,
            };
        }
    }
    // v4: --rsrc-register ???귐딅꺖???遺얠젂?怨뺚봺??????源낅쭆 ?紐꺿봺嚥??대Ŋ猿?
    if ctx.rsrc_dir_rva > 0 && clean_data_dirs.len() > 2 {
        clean_data_dirs[2] = DataDirectory {
            virtual_address: ctx.rsrc_dir_rva,
            size: ctx.rsrc_dir_size,
        };
    }
    // v6: --iat-hide ??import ?遺얠젂?怨뺚봺???遺?(LoadLibraryA/GetProcAddress)嚥??대Ŋ猿?
    if ctx.iat_dir_rva > 0 && clean_data_dirs.len() > 1 {
        clean_data_dirs[1] = DataDirectory {
            virtual_address: ctx.iat_dir_rva,
            size: ctx.iat_dir_size,
        };
    }

    // ???? DLL Characteristics: DYNAMIC_BASE(0x0040), HIGH_ENTROPY_VA(0x0020), GUARD_CF(0x4000) ??볤탢 ????
    // P0-⑦: relocation-aware 경로가 확정되기 전까지는 기존대로 ASLR/CFG 비트를 스트립한
    // 값을 쓰고, 아래에서 preserve_aslr_bits가 켜지면 원본 ASLR 비트를 복원한다.
    let clean_dll_characteristics =
        ctx.target_info.dll_characteristics & !(0x0020 | 0x0040 | 0x4000);

    // ???? ??ν뒄???諭??癒?퐣 .pdata SEH ???뵠???????????????????????????????????????????????????????????????????????
    // ?癒?궚 `.text`??TLS ?꾩뮆媛? VM native bridge, 域밸챶?곫?entry_native 野껋럥以?癒?퐣 ?④쑴??
    // ??쎈뻬??뺣뼄. ?怨뺤뵬???癒?궚 RUNTIME_FUNCTION ?????獄쏆꼶諭???醫???랁? ???遺용뮞??μ퓗
    // ?됰슢?곻쭪? ?怨몃열??leaf ???됵쭕??곕떽???뺣뼄. `--keep-pdata`??筌욊쑬???紐낆넎?源놁뱽
    // ?袁る퉸 ?????됪틦?? ?곕떽???? ??낅뮉 ?袁⑹읈 ?癒?궚 ?醫? 筌뤴뫀諭뜻에???ｋ┸??
    //
    // ?됰슢?곻쭪? leaf揶쎛 ?뚣끇苡??롫뮉 ??쇱젫 ?꾨뗀諭??[dispatcher+0x20 .. dispatcher+boot_area_len),
    // 筌??遺용뮞??μ퓗 癰귣챷猿??酉逾??됰뗀以??봔????쎈?? ?뚣끇苡??? ??낅뮉??????諭?? `.textb`??
    // ??롢돢筌왖筌ｌ꼶???癒?뒅?怨몄몵嚥?unwind ?뚣끇苡?뵳?? 獄쏅쉼???. UNWIND_INFO????롫굡?꾨뗀逾??? ??꾪?
    // ??쇱젫 ?遺용뮞??μ퓗??`pushfq`/`push r64` prologue????堉??덊닜????밴쉐??뺣뼄. (疫꿸퀣??
    // `PUSH RBX + ALLOC 0x20` ??롫굡?꾨뗀逾?? ??? ?遺용뮞??μ퓗??pushfq/rax/rcx/r10/r11
    // prologue?? ??釉?紐낆넅 ?遺용뮞??μ퓗??16-?紐꾨뻻 prologue ????野껉퍒?????깊뒄??? ??낅뮉 ??됯맒
    // ??곷???????롢걵??unwind ????롢걵??RSP ??0xC0000005 野껋럥以???癒?뵥????????덈뼄.)
    let mut relayed_sections = ctx.patched_sections.clone();
    // Pillar 1: Sanitize sensitive metadata, source paths, and PDB signatures from data sections
    let stripped = crate::pipeline::rdata_strip::RdataMetadataStripper::sanitize_sections(
        &mut relayed_sections,
        ctx.poly_vm_seed,
    );
    if stripped > 0 {
        println!(
            "[+] Stealth: Sanitized {} plaintext metadata/path references from PE sections",
            stripped
        );
    }

    // ?됰슢?곻쭪? leaf 揶쎛 ?뚣끇苡??롫뮉 ?遺용뮞??μ퓗 癰귣챷猿?.textb ?諭????쎈늄??0x20)??prologue ??
    // ?遺욱맜??쀫퉸 UNWIND_INFO ????밴쉐??뺣뼄. `.textb` ??patched_sections ????얩?
    // `btg_section_data` ????됱몵沃샕嚥???由????덈뮉??(relayed_sections ?癒?퐣 筌≪뼚?앾쭖?
    // bridge_unwind 揶쎛 None ???됰슢?곻쭪? leaf 揶쎛 ?袁⑥뵭??롫뮉 ???).
    let bridge_unwind: Option<(u8, Vec<(u8, u8)>)> = ctx.btg_section_data.as_ref().map(|sec| {
        let end = (0x20 + boot_area_len as usize).min(sec.bytes.len());
        let disp = if end > 0x20 {
            &sec.bytes[0x20..end]
        } else {
            &[]
        };
        let (codes, prolog_len) = dispatcher_unwind_codes(disp);
        (
            prolog_len,
            codes.iter().map(|c| (c.offset, c.reg)).collect(),
        )
    });
    // P4 (전체 SEH 가상화): whole-program VM 모듈 영역의 브리지 UNWIND_INFO.
    // Program VM은 부트 스텁이 tail-jmp로 진입하므로, VM 내부에서 예외가 나면
    // OS unwinder가 걷는 유일한 .textb 프레임이 **Program VM 엔트리 프레임**이다.
    // 여기에 정확한 엔트리 프로로그(sub rsp,0xA0 + 15 push) UNWIND_INFO를 등록해
    // 더미 핸들러(리프 프레임 가정)에 의존하지 않고 결정적으로 VM 밖으로 unwind
    // 하게 한다. 커버 범위 = [vm_prog_rva .. vm_prog_rva+vm_prog_total).
    let vm_prog_unwind: Option<Vec<u8>> = if ctx.vm_prog_rva > 0 && ctx.vm_prog_total > 0 {
        ctx.btg_section_data.as_ref().and_then(|sec| {
            let off = (ctx.vm_prog_rva as u64).saturating_sub(dispatcher_rva as u64) as usize;
            let end = (off + ctx.vm_prog_total as usize).min(sec.bytes.len());
            if end > off && off < sec.bytes.len() {
                let (ops, prolog_len) = vm_entry_unwind_ops(&sec.bytes[off..end]);
                if !ops.is_empty() {
                    println!(
                        "[+] P4 .pdata: Program-VM bridge UNWIND_INFO — covering 0x{:X}..0x{:X} ({}B), prolog_len=0x{:X}, {} code(s)",
                        ctx.vm_prog_rva,
                        ctx.vm_prog_rva + ctx.vm_prog_total,
                        ctx.vm_prog_total,
                        prolog_len,
                        ops.len()
                    );
                    Some(build_vm_entry_unwind_info(prolog_len, &ops))
                } else {
                    None
                }
            } else {
                None
            }
        })
    } else {
        None
    };
    if ctx.keep_pdata {
        println!("[+] .pdata: KEPT original (--keep-pdata) ??build.rs SEH rebuild skipped; original RUNTIME_FUNCTION table left verbatim");
    } else {
        update_pdata_seh(
            &mut relayed_sections,
            &mut clean_data_dirs,
            &ctx.target_info.original_pdata_entries,
            dispatcher_rva,
            boot_area_len,
            bridge_unwind.as_ref(),
            ctx.vm_prog_rva,
            ctx.vm_prog_total,
            vm_prog_unwind.as_ref().map(|v| v.as_slice()),
            ctx.vm_prog_native_bridge,
        );
    }

    // ???? PE ??슢諭???????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????
    // v3: ?酉€??遺? ?녹뮇議???됱몵筌??봔€????쎈€?boot stub)????筌욊쑴??癒?뵠 ??뺣뼄.
    // ctx.boot_entry_offset = ?봔€????쎈€???諭€??????쎈늄??(0??€??疫꿸퀣??OEP = ?諭€????뽰삂)
    let entry_point_rva = dispatcher_rva + ctx.boot_entry_offset;

    // ── P0-⑦ (T0-3): relocation-aware 출력 — 암호화 경로에서도 ASLR 보존 ──────────
    // 기존 코드는 `at_rest_encrypted=true`이면 .reloc 생성을 포기해 ASLR이 완전히
    // 비활성화됐다. T0-3 수정: 암호화된 영역 RVA만 encrypted_rva_ranges로 패스해
    // reloc.rs가 해당 슬롯을 skip하도록 한다. 이로써 부트 스텁 imm64(모듈
    // 엔트리 VA, 핸들러 테이블 VA 등)은 정상 reloc되는 반면, 암호문 영역은
    // 안전하게 제외된다.
    //
    // 암호화 단위:
    //   - 코드 블록 영역 (.textb first_block_offset .. first_block_offset+code_len)
    //   - .text at-rest 런 (암호화된 것만; 평문 유지 영역은 reloc OK)
    //   - 구체적으로 알 수 없는 범위는 보수적으로 코드 블록 전체를 포함함
    //   - 컈트르트는 항상 .textb 떠나 인접하지 않는 .btg 섬션 안에 있으므로
    //   코드 블록 RVA 범위로만 충분함.
    //
    // 로더가 부트 스텁 복호화 전에 .reloc을 적용하더라도 암호문 슬롯은 skip되어
    // 암호문이 다치지 않는다. 부트 스텁 imm64들(모듈 엔트리 VA 등)은 평문이라
    // reloc되어도 안전하다.
    // FIX(T0-3): boot stub/VM runtime is not ASLR-safe (hand-assembled preferred-base
    // absolute addresses), so the at-rest-encrypted (protected) path disables ASLR/
    // .reloc entirely. The no-crypto path installs no boot stub and no at-rest
    // ciphertext, so it keeps the relocation-aware output (ASLR preserved).
    let reloc_aware = !ctx.at_rest_encrypted;

    let mut preserve_aslr_bits = false;
    let mut reloc_section: Option<SectionData> = None;
    if reloc_aware {
        // 최종 섹션 배치를 builder 로직과 동일하게 계산한다.
        let sec_align = ctx.target_info.section_alignment;
        let align_sec = |v: u32| -> u32 {
            if sec_align == 0 {
                0x1000
            } else {
                (v + sec_align - 1) & !(sec_align - 1)
            }
        };
        let max_existing_va = relayed_sections
            .iter()
            .map(|s| {
                let sz = s.virtual_size.max(s.bytes.len() as u32);
                s.virtual_address + align_sec(sz)
            })
            .max()
            .unwrap_or(0x1000);
        let btg_va = if btg_section.virtual_address < max_existing_va {
            align_sec(max_existing_va)
        } else {
            btg_section.virtual_address
        };
        let btg_end =
            btg_va + align_sec(btg_section.virtual_size.max(btg_section.bytes.len() as u32));
        let payload_end = match &ctx.payload_section_data {
            Some(p) => {
                let p_va = align_sec(btg_end);
                p_va + align_sec(p.virtual_size.max(p.bytes.len() as u32))
            }
            None => btg_end,
        };

        // T0-3: 암호화된 RVA 범위를 파앙한다.
        // 코드 블록 영역: dispatcher_rva + first_block_offset .. + code_len
        // (crypto::run이 at_rest_encrypted=true로 기록한 경우에만 유효)
        // 단순한 보수 범위: .textb 코드 블록 영역 전체(first_block_offset에서
        // btg_section 끝까지). 실제 암호화 눁이가 code_len보다 작으면
        // 일부 평문이 남아도 안전: 위양성(false-skip)이 암호문-skip만 못하는
        // false-include보다 항상 안전하다 (reloc 빠지면 VM이 장로드되고,
        // reloc 두면 boot stub이 2회 체이닝 후 컴파일 복호화하므로 대부분
        // OK임).
        let mut encrypted_rva_ranges: Vec<(u32, u32)> = Vec::new();
        if ctx.at_rest_encrypted {
            // .textb 코드 블록 영역 (dispatcher부터 코드 끝까지)
            let code_block_rva = ctx.dispatcher_rva + ctx.first_block_offset as u32;
            let code_block_len =
                (btg_section.bytes.len() as u32).saturating_sub(ctx.first_block_offset as u32);
            if code_block_len > 0 {
                encrypted_rva_ranges.push((code_block_rva, code_block_len));
            }
            // .text 섹션 at-rest 런 (vm-oep 경로에서 암호화된 영역)
            // 소스: patched_sections 중 .text 섹션 전체를 보수적으로 포함
            // (at-rest 런 정보를 파이프라인에서 전달하지 않는 트레이드오프)
            if ctx.vm_oep {
                for sec in &relayed_sections {
                    if sec.name == ".text" {
                        // .text 셀션 전체를 알려진 범위로 포함
                        // (실제 at-rest 런 정보는 place.rs에서만 알므로
                        //  섹션 전체를 보수적 exclusion으로 등록)
                        let len = sec.bytes.len() as u32;
                        if len > 0 {
                            encrypted_rva_ranges.push((sec.virtual_address, len));
                        }
                        break;
                    }
                }
            }
            println!(
                "[+] T0-3 ASLR: at_rest_encrypted path — excluding {} encrypted range(s) from .reloc \
                 (code_block RVA=0x{:X}/{}B{}). \
                 Boot-stub imm64 slots (plaintext) will still get reloc entries.",
                encrypted_rva_ranges.len(),
                code_block_rva, code_block_len,
                if ctx.vm_oep { " + .text at-rest" } else { "" }
            );
        }

        let image_base = ctx.target_info.image_base;
        let size_of_image = payload_end;

        // 모든 최종 섹션 목록 (VA 확정본) — .reloc 자체는 제외하고 스캔.
        let mut final_sections: Vec<SectionData> = relayed_sections.clone();
        {
            let mut btg_final = btg_section.clone();
            btg_final.virtual_address = btg_va;
            final_sections.push(btg_final);
        }
        if let Some(p) = &ctx.payload_section_data {
            let mut pf = p.clone();
            pf.virtual_address = align_sec(btg_end);
            final_sections.push(pf);
        }

        let reloc = build_reloc_directory(
            &final_sections,
            image_base,
            size_of_image,
            &encrypted_rva_ranges,
        );

        if let Some(mut ro) = reloc {
            let reloc_va = align_sec(payload_end);
            ro.section.virtual_address = reloc_va;
            if clean_data_dirs.len() > 5 {
                clean_data_dirs[5] = DataDirectory {
                    virtual_address: reloc_va,
                    size: ro.directory.size,
                };
            }
            preserve_aslr_bits = true;
            // builder가 .reloc 섹션을 btg/payload 뒤에 배치하도록 전달한다
            // (relayed_sections에 추가하지 않음 — .textb 위치가 밀리면 안 됨).
            reloc_section = Some(ro.section);
            println!(
                    "[+] P0-⑦ relocation-aware: .reloc dir @0x{:X} ({}B, {} slot(s)) — DYNAMIC_BASE/HIGH_ENTROPY_VA preserved",
                    reloc_va, ro.directory.size, ro.directory.size / 2
                );
        } else {
            println!("[!] P0-⑦ relocation-aware: no image-relative pointers found in injected sections; ASLR bits kept stripped");
        }
    }

    let multi_builder = PeMultiSectionBuilder::new(
        ctx.target_info.image_base,
        entry_point_rva,
        ctx.target_info.subsystem,
        // P0-⑦: relocation-aware 경로는 원본 DLL characteristics(DYNAMIC_BASE/
        // HIGH_ENTROPY_VA 포함)를 그대로 넘겨 builder가 .reloc과 함께 보존한다.
        if preserve_aslr_bits {
            ctx.target_info.original_dll_characteristics
        } else {
            clean_dll_characteristics
        },
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
    // P0-⑦: relocation-aware 경로만 ASLR 비트 보존 (다른 경로는 기존 스트립 유지).
    let mut multi_builder = multi_builder;
    multi_builder.preserve_aslr_bits = preserve_aslr_bits;
    multi_builder.reloc_section = reloc_section;

    let output_pe_bytes = multi_builder.build()?;

    if let Some(path) = output_path {
        fs::write(path, &output_pe_bytes)?;
        println!("==================================================================");
        println!(
            "[SUCCESS] Synthesized Protected BTG PE Binary Written to: {}",
            path.display()
        );
        println!(
            "[INFO] Size of Output Protected Binary: {} bytes",
            output_pe_bytes.len()
        );
        println!(
            "[INFO] Protected Entry Point (OEP) RVA: 0x{:X}",
            entry_point_rva
        );
        println!("==================================================================");
    } else {
        println!("==================================================================");
        println!(
            "[SUCCESS] Synthesized Protected BTG PE Binary (in-memory, {} bytes)",
            output_pe_bytes.len()
        );
        println!(
            "[INFO] Protected Entry Point (OEP) RVA: 0x{:X}",
            entry_point_rva
        );
        println!("==================================================================");
    }

    Ok(output_pe_bytes)
}

// ???? x64 UNWIND_INFO / UNWIND_CODE ?怨몃땾 (PE/COFF 吏?.8, Win64 ABI) ??????????????????????????
/// UNWIND_INFO Version (??? 3??쑵??. 嚥≪뮆???version==1 筌???륁뒠??뺣뼄.
const UNWIND_VERSION: u8 = 1;
/// UWOP_PUSH_NONVOL ??callee-saved ?類ㅻ땾 ?????쎄숲????쎄문??push.
const UWOP_PUSH_NONVOL: u8 = 0;
/// UWOP_ALLOC_SMALL ??8..=128 獄쏅뗄?????곗굨 ??쎄문 ?醫딅뼣 (OpInfo = (size/8)-1).
const UWOP_ALLOC_SMALL: u8 = 2;
/// UWOP_ALLOC_LARGE ??allocs > 128 獄쏅뗄?? 2-byte (OpInfo=0) 遺좊┰ 4-byte
/// (OpInfo=1) frame size ??移댄??댁빞?.
const UWOP_ALLOC_LARGE: u8 = 1;

/// One stack-modifying op in the Program-VM entry prologue, in execution order.
enum VmEntryOp {
    /// `sub rsp, size` (0xA0 = XMM save area).
    Alloc(u32),
    /// `push r64` of a callee-saved GPR (UWOP_PUSH_NONVOL reg).
    PushNonVol(u8),
    /// `push r64` volatile / `pushfq` — only RSP accounting needed (8 bytes).
    PushAny,
}

/// Decode the leading prologue of the Program-VM module entry code (`sub rsp,
/// 0xA0; cld; movdqu [rsp+disp], xmm6..xmm15; push rax..r11, r15..r12`) and
/// return the stack-modifying ops in execution order (with byte offset) plus
/// the total prologue length in bytes. `movdqu`/`cld`/`nop`/`int3` are skipped
/// (no RSP change).
fn vm_entry_unwind_ops(code: &[u8]) -> (Vec<(u8, VmEntryOp)>, u8) {
    use iced_x86::{Code, Decoder, DecoderOptions, Register};
    let mut ops: Vec<(u8, VmEntryOp)> = Vec::new();
    let mut off = 0usize;
    let mut decoder = Decoder::with_ip(64, code, 0, DecoderOptions::NONE);
    loop {
        if off >= code.len() {
            break;
        }
        let inst = decoder.decode();
        if inst.is_invalid() {
            break;
        }
        let len = inst.len() as usize;
        if len == 0 || off + len > code.len() {
            break;
        }
        match inst.code() {
            Code::Sub_rm64_imm8 | Code::Sub_rm64_imm32
                if inst.op0_kind() == iced_x86::OpKind::Register
                    && inst.op0_register() == Register::RSP =>
            {
                let size = inst.immediate32() as i64;
                ops.push((off as u8, VmEntryOp::Alloc(size as u32)));
            }
            Code::Cld | Code::Int3 | Code::Nopd | Code::Nopw | Code::Nopq => {}
            // XMM save area stores (movdqu [rsp+disp], xmm) — no RSP change.
            Code::Movdqu_xmmm128_xmm
            | Code::Movdqu_xmm_xmmm128
            | Code::Movaps_xmmm128_xmm
            | Code::Movaps_xmm_xmmm128
            | Code::Movups_xmmm128_xmm
            | Code::Movups_xmm_xmmm128 => {}
            Code::Pushfq => {
                ops.push((off as u8, VmEntryOp::PushAny));
            }
            Code::Push_r64 => {
                let reg = inst.op0_register();
                let nonvol = matches!(
                    reg,
                    Register::RBX
                        | Register::RBP
                        | Register::RSI
                        | Register::RDI
                        | Register::R12
                        | Register::R13
                        | Register::R14
                        | Register::R15
                );
                ops.push((
                    off as u8,
                    if nonvol {
                        VmEntryOp::PushNonVol(reg.number() as u8)
                    } else {
                        VmEntryOp::PushAny
                    },
                ));
            }
            _ => break,
        }
        off += len;
    }
    (ops, off as u8)
}

/// Build a UNWIND_INFO (version 1, no handler, frame register 0) from
/// stack-modifying prologue ops. UNWIND_CODE entries are emitted in DESCENDING
/// CodeOffset order per the PE/COFF spec, so the OS unwinder's "apply codes with
/// offset <= current prologue offset" scan stays correct. ALLOC sizes > 0x80 use
/// UWOP_ALLOC_LARGE(0) + 2-byte frame size.
fn build_vm_entry_unwind_info(size_of_prolog: u8, ops: &[(u8, VmEntryOp)]) -> Vec<u8> {
    // Build UNWIND_CODE entries (CodeOffset, op byte, optional 2-byte frame size)
    // in execution order.
    let mut entries: Vec<(u8, Vec<u8>)> = Vec::new();
    for (off, op) in ops {
        let mut body = match op {
            VmEntryOp::Alloc(size) if *size > 0x80 => {
                let frame = (*size / 8) as u16;
                vec![
                    (0 << 4) | UWOP_ALLOC_LARGE,
                    (frame & 0xFF) as u8,
                    (frame >> 8) as u8,
                ]
            }
            VmEntryOp::Alloc(size) => {
                let sm = ((*size / 8).saturating_sub(1)) as u8;
                vec![(sm << 4) | UWOP_ALLOC_SMALL]
            }
            VmEntryOp::PushNonVol(reg) => vec![((*reg & 0x0F) << 4) | UWOP_PUSH_NONVOL],
            VmEntryOp::PushAny => vec![(0 << 4) | UWOP_ALLOC_SMALL],
        };
        let mut code = vec![*off];
        code.append(&mut body);
        entries.push((*off, code));
    }
    // Sort by CodeOffset DESCENDING per spec.
    entries.sort_by_key(|(off, _)| std::cmp::Reverse(*off));

    let mut info = Vec::with_capacity(4 + entries.len() * 4);
    info.push((UNWIND_VERSION & 0x07) | 0); // v1, no handler
    info.push(size_of_prolog);
    info.push(entries.len() as u8);
    info.push(0); // FrameRegister=0, FrameRegisterOffset=0
    for (_, code) in &entries {
        info.extend_from_slice(code);
    }
    while info.len() % 4 != 0 {
        info.push(0);
    }
    info
}

fn build_native_call_bridge_unwind_info() -> Vec<u8> {
    let code_off = 0x20u8;
    let mut info = vec![UNWIND_VERSION, code_off, 10, 0];
    info.extend_from_slice(&[code_off, UWOP_ALLOC_LARGE, 0x17, 0x00]);
    for reg in [5u8, 3, 6, 7, 15, 14, 13, 12] {
        info.extend_from_slice(&[code_off, (reg << 4) | UWOP_PUSH_NONVOL]);
    }
    while info.len() % 4 != 0 {
        info.push(0);
    }
    info
}

/// SEH ?됰슢?곻쭪? ?遺용뮞??μ퓗 ?怨몃열??UNWIND_INFO 獄쏅뗄?????곸뱽 ??밴쉐??뺣뼄.
///
/// UNWIND_CODE ????롫굡?꾨뗀逾??? ??꾪? ?遺용뮞??μ퓗??**??쇱젫 prologue**(`pushfq`/
/// `push r64` ??쀂????癒?퐣 `dispatcher_unwind_codes`揶쎛 筌믩쵐釉????堉??곗쨮?봔??筌띾슢諭??
///  - ??쑵?띈쳸?뽮쉐 GPR push   ??`UWOP_PUSH_NONVOL(reg)` (?紐??紐껊굡 ???????쎄숲 癰귣벊??
///  - pushfq/??롮뻣??push   ??`UWOP_ALLOC_SMALL(8)` (RSP ?類ㅺ텦筌???癰귣벊???븍뜇釉??
/// ???껃칰???롢늺 UNWIND_INFO 揶쎛 嚥≪뮆?묈첎? ??쇱젫 ??쎈뻬??롫뮉 ?꾨뗀諭?? ??湲???깊뒄??뺣뼄.
///
/// 獄쏆꼹???닌듼?(DWORD ?類ｌ졊, 嚥≪뮆????륁뒠 鈺곌퀗援??겸뫗??:
/// ```text
/// +0  Version(3) | Flags(5)      = 0x01 (v1, no handler)
/// +1  SizeOfProlog
/// +2  CountOfCodes               = codes.len()
/// +3  FrameRegister(4)|Offset(4) = 0
/// +4  UNWIND_CODE[0]  (CodeOffset, UnwindOp|OpInfo)
/// ... UNWIND_CODE[n-1]
/// +pad DWORD 野껋럡??
/// ```
fn build_bridge_unwind_info(size_of_prolog: u8, codes: &[(u8, u8)]) -> Vec<u8> {
    let mut info = Vec::with_capacity(4 + codes.len() * 2);
    // byte0: Version | Flags(0 = exception handler ??곸벉)
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
            // 8獄쏅뗄?????쎄문 op (pushfq/??롮뻣??push) ??UWOP_ALLOC_SMALL(8): OpInfo=0.
            info.push((0 << 4) | UWOP_ALLOC_SMALL);
        } else {
            // ??쑵?띈쳸?뽮쉐 GPR push ??UWOP_PUSH_NONVOL(reg). reg ??Win64 ?????쎄숲 甕곕뜇??
            info.push(((reg & 0x0F) << 4) | UWOP_PUSH_NONVOL);
        }
    }
    // DWORD ?類ｌ졊
    while info.len() % 4 != 0 {
        info.push(0);
    }
    info
}

/// `.pdata` SEH ???뵠?됰뗄??????源딅립??(v13.4c ??P4: ?됰슢?곻쭪? UNWIND_INFO ??밴쉐).
///
/// ?됰뗀以?shuffle 野껉퀗?????`.textb` 雅뚯눘?????됱몵沃샕嚥??癒?궚 `.text`??RUNTIME_FUNCTION
/// 甕곕뗄??? 野껊??귨쭪? ??낅뮉?? ?癒?궚 `.text` ?癒?퍥??域밸챶?嚥?癰귣똻???렽???쇱뵠?怨뺥닏 野껋럥以?癒?퐣
/// ??쎈뻬???嚥?疫꿸퀣????????????롢늺 Rust panic/TLS teardown??OS unwind揶쎛 繹먥뫁彛??
/// ?怨뺤뵬??
///   1. ?醫륁뒞???癒?궚 ?????雅뚯눘??癰궰野???곸뵠 筌뤴뫀紐?癰귣똻???뺣뼄.
///   2. **?됰슢?곻쭪? ?遺용뮞??μ퓗** ?怨몃열 [dispatcher+0x20 .. dispatcher+boot_area_len) ??
///      ?뚣끇苡??롫뮉 RUNTIME_FUNCTION ??롪돌???곕떽???랁? 域?UNWIND_INFO ????쇱젫
///      ?遺용뮞??μ퓗 prologue?癒?퐣 ?醫딅즲??UNWIND_CODE(??삳쐭 + PUSH_NONVOL/ALLOC_SMALL)嚥?
///      ??밴쉐??뺣뼄. ??밴쉐??UNWIND_INFO ??`.pdata` ?諭???RUNTIME_FUNCTION 獄쏄퀣肉?
///      筌욊낱???DWORD ?類ｌ졊嚥???곷선?븐늿??? (??됱읈筌ｌ꼶??`.btg` ?袁⑷퍥????롪돌??
///      RUNTIME_FUNCTION 嚥??源낆쨯??롢늺 ??뺤쨮 ??삘뀲 stack frame ??揶쎛筌???륁퓝 ?됰뗀以??
///      ??롪돌??UNWIND_INFO 嚥?筌ｌ꼶???롮젻????롢걵??unwind 揶쎛 ??뺣뼄.)
///   3. 嚥≪뮆?묈첎? STATUS_INVALID_IMAGE_FORMAT ??곗쨮 椰꾧퀡???? ??낅즲嚥?Exception
///      Directory(Idx 3) ??由??RUNTIME_FUNCTION 獄쏄퀣肉?疫뀀챷??12 獄쏅뗄???獄쏄퀣??嚥?
///      ?醫???랁? UNWIND_INFO ??獄쏄퀣肉???쇰퓠 ?癒?선 獄쏄퀣肉????뼓???怨밸샨??雅뚯눘? ??꾩쓺 ??뺣뼄.
fn update_pdata_seh(
    relayed_sections: &mut Vec<SectionData>,
    clean_data_dirs: &mut Vec<DataDirectory>,
    original_pdata_entries: &[RuntimeFunction],
    dispatcher_rva: u32,
    boot_area_len: u32,
    bridge_unwind: Option<&(u8, Vec<(u8, u8)>)>,
    vm_prog_rva: u32,
    vm_prog_total: u32,
    vm_prog_unwind: Option<&[u8]>,
    vm_native_bridge: Option<(u32, u32)>,
) {
    if let Some(pdata_sec) = relayed_sections.iter_mut().find(|s| s.name == ".pdata") {
        // ?癒?궚 `.text`??域밸챶?嚥?鈺곕똻???랁???쇱뵠?怨뺥닏 野껋럥以?癒?퐣 ??쎈뻬???嚥??袁? 癰귣똻???뺣뼄.
        let mut rf_list: Vec<RuntimeFunction> = original_pdata_entries
            .iter()
            .filter(|rf| rf.begin_address > 0 && rf.end_address > rf.begin_address)
            .copied()
            .collect();

        // ?됰슢?곻쭪? ?遺용뮞??μ퓗 ?怨몃열筌??뚣끇苡??롫뮉 ????꾨뱜 leaf ?곕떽? (.btg ?袁⑷퍥揶쎛 ?袁⑤뻷).
        // 疫꿸퀣???酉?껆뵳?? Begin ???겸뫖猷??? ??놁뱽 ???춸. UNWIND_INFO RVA ??獄쏄퀣肉??
        // 筌욊낮??酉釉???쇱벥 .pdata ??? ??쎈늄???몵嚥??袁⑥삋?癒?퐣 筌?쑴??? ?遺용뮞??μ퓗 癰귣챷猿??
        // ?諭????쎈늄??0x20 ????됱몵沃샕嚥??諭????뽰삂 0x0 = OEP ??쎈? begin ?? 0x20.
        let bridge_begin = dispatcher_rva + 0x20;
        let mut added_bridge = false;
        let mut unwind_info: Vec<u8> = Vec::new();
        if let Some((prolog_len, codes)) = bridge_unwind {
            if !rf_list.iter().any(|rf| rf.begin_address == bridge_begin) {
                added_bridge = true;
                rf_list.push(RuntimeFunction {
                    begin_address: bridge_begin,
                    end_address: dispatcher_rva + boot_area_len,
                    unwind_info_address: 0, // 筌?쑴?숋쭪??癒?봺
                });
            }
            unwind_info = build_bridge_unwind_info(*prolog_len, codes);
        }

        // P4 (전체 SEH 가상화): whole-program VM 모듈 전체를 한 RUNTIME_FUNCTION으로
        // 커버해, VM 내부에서 예외가 나면 OS unwinder가 더미 핸들러 대신 Program VM
        // 엔트리 UNWIND_INFO로 결정적으로 프레임을 걷게 한다. (VM 안의 모든 코드는
        // 하나의 엔트리 프레임 안에서 실행되므로 단일 UNWIND_INFO가 정확하다.)
        let mut vm_unwind: Vec<u8> = Vec::new();
        let mut native_bridge_unwind: Vec<u8> = Vec::new();
        let mut vm_begin = 0u32;
        let mut vm_end = 0u32;
        let mut native_bridge_begin = 0u32;
        let mut native_bridge_end = 0u32;
        if vm_prog_rva > 0 && vm_prog_total > 0 {
            vm_begin = vm_prog_rva;
            vm_end = vm_prog_rva.saturating_add(vm_prog_total);
            // FIX(commercial-vm-pdata): vm_entry_unwind_ops fails on commercial VM
            // (entry starts with JMP, not a push/sub-rsp prologue). Even when
            // vm_prog_unwind is None we must register a RUNTIME_FUNCTION covering
            // [vm_prog_rva..vm_prog_rva+vm_prog_total) so that
            // validate_function_ownership does not fall back to the original .pdata
            // entry (which is narrower) and report "extends beyond".
            if let Some(uwi) = vm_prog_unwind {
                vm_unwind = uwi.to_vec();
            } else {
                // Leaf / no unwind info — SEH inside the VM module will unwind to
                // the caller frame without prologue restoration. Acceptable for the
                // commercial self-decoding dispatcher (no non-volatile registers saved
                // before the JMP trampoline).
                println!(
                    "[+] P4 .pdata: Program-VM RUNTIME_FUNCTION (leaf/no-unwind-info) \
                     covering 0x{:X}..0x{:X} ({}B)",
                    vm_begin, vm_end, vm_prog_total
                );
            }
            if let Some((rel_begin, rel_end)) =
                vm_native_bridge.filter(|(s, e)| s < e && *e <= vm_prog_total)
            {
                native_bridge_begin = vm_begin + rel_begin;
                native_bridge_end = vm_begin + rel_end;
                native_bridge_unwind = build_native_call_bridge_unwind_info();
                for (begin, end) in [
                    (vm_begin, native_bridge_begin),
                    (native_bridge_begin, native_bridge_end),
                    (native_bridge_end, vm_end),
                ] {
                    if begin < end {
                        rf_list.push(RuntimeFunction {
                            begin_address: begin,
                            end_address: end,
                            unwind_info_address: 0,
                        });
                    }
                }
            } else if !rf_list.iter().any(|rf| rf.begin_address == vm_begin) {
                rf_list.push(RuntimeFunction {
                    begin_address: vm_begin,
                    end_address: vm_end,
                    unwind_info_address: 0, // patched below when vm_unwind is non-empty
                });
            }
        }

        rf_list.sort_by_key(|rf| rf.begin_address);
        rf_list.dedup_by_key(|rf| rf.begin_address);

        // RUNTIME_FUNCTION 獄쏄퀣肉?(12 獄쏅뗄????酉?껆뵳?. Exception Directory ??由경에?????
        let array_len = rf_list.len() as u32 * 12;

        // UNWIND_INFO ??獄쏄퀣肉?筌욊낱??.pdata ???嚥???곷선?븐늿???(DWORD ?類ｌ졊: 12|4).
        let mut unwind_rva = pdata_sec.virtual_address + array_len;
        let bridge_unwind_rva = unwind_rva;

        // ?됰슢?곻쭪? ?酉?껆뵳???UNWIND_INFO 雅뚯눘?쇘몴?筌?쑴???
        for rf in rf_list.iter_mut() {
            if rf.begin_address == bridge_begin {
                rf.unwind_info_address = bridge_unwind_rva;
            }
        }
        if vm_begin > 0 && !vm_unwind.is_empty() {
            let vm_unwind_rva = unwind_rva + unwind_info.len() as u32;
            for rf in rf_list.iter_mut() {
                if rf.begin_address == vm_begin || rf.begin_address == native_bridge_end {
                    rf.unwind_info_address = vm_unwind_rva;
                }
            }
        }
        if native_bridge_begin > 0 {
            let native_unwind_rva = unwind_rva + unwind_info.len() as u32 + vm_unwind.len() as u32;
            for rf in rf_list.iter_mut() {
                if rf.begin_address == native_bridge_begin {
                    rf.unwind_info_address = native_unwind_rva;
                }
            }
        }

        let mut pdata_bytes = Vec::with_capacity(
            array_len as usize + unwind_info.len() + vm_unwind.len() + native_bridge_unwind.len(),
        );
        for rf in &rf_list {
            pdata_bytes.extend_from_slice(&rf.begin_address.to_le_bytes());
            pdata_bytes.extend_from_slice(&rf.end_address.to_le_bytes());
            pdata_bytes.extend_from_slice(&rf.unwind_info_address.to_le_bytes());
        }
        pdata_bytes.extend_from_slice(&unwind_info);
        pdata_bytes.extend_from_slice(&vm_unwind);
        pdata_bytes.extend_from_slice(&native_bridge_unwind);

        pdata_sec.bytes = pdata_bytes.clone();
        // Exception Directory ??由?= RUNTIME_FUNCTION 獄쏄퀣肉댐쭕?(嚥≪뮆?묈첎? size/12 嚥?
        // ?酉?껆뵳???? ?紐?嚥?UNWIND_INFO ????釉??롢늺 ??쎈솁????STATUS_INVALID_IMAGE_FORMAT).
        pdata_sec.virtual_size = array_len;

        if clean_data_dirs.len() > 3 {
            clean_data_dirs[3] = DataDirectory {
                virtual_address: pdata_sec.virtual_address,
                size: array_len,
            };
            let mut msg = format!(
                "[+] Rebuilt SEH Table (.pdata): RVA 0x{:X}, {} entries (Size 0x{:X}) + bridge UNWIND_INFO @0x{:X} [original native entries preserved; bridge leaf 0x{:X}..0x{:X} added, prolog_len=0x{:X}, {} codes]",
                pdata_sec.virtual_address, rf_list.len(), array_len,
                bridge_unwind_rva, bridge_begin, dispatcher_rva + boot_area_len,
                bridge_unwind.map(|(l, _)| *l).unwrap_or(0),
                bridge_unwind.map(|(_, c)| c.len()).unwrap_or(0)
            );
            if vm_begin > 0 && !vm_unwind.is_empty() {
                msg.push_str(&format!(
                    " + Program-VM bridge @0x{:X}..0x{:X} (unwind @0x{:X}, {}B)",
                    vm_begin,
                    vm_end,
                    bridge_unwind_rva + unwind_info.len() as u32,
                    vm_unwind.len()
                ));
            }
            println!("{}", msg);
            let _ = added_bridge;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dispatcher::{build_dispatcher, build_dispatcher_reencrypt, UNWIND_ALLOC8};

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

        // ?됰슢?곻쭪? UNWIND_CODE: PUSH_NONVOL(RBX=3) @1 + ALLOC8 @0x0C (??쇱젫 ?遺용뮞??μ퓗
        // prologue??筌뤴뫁沅??롫뮉 ??밴쉐 ?꾨뗀諭?.
        let bridge_unwind = (0x0Eu8, vec![(0x01u8, 0x03u8), (0x0Cu8, UNWIND_ALLOC8)]);
        update_pdata_seh(
            &mut sections,
            &mut directories,
            &originals,
            0x5000,
            0x80,
            Some(&bridge_unwind),
            0,
            0,
            None,
            None,
        );

        // ?癒?궚 2 + ?됰슢?곻쭪? 1 = 3揶?RUNTIME_FUNCTION (36 獄쏅뗄??? + UNWIND_INFO(8) = 44.
        assert_eq!(sections[0].bytes.len(), 44);
        // Exception Directory ??由??獄쏄퀣肉댐쭕?
        assert_eq!(directories[3].virtual_address, 0x4000);
        assert_eq!(directories[3].size, 36);
        assert_eq!(sections[0].virtual_size, 36);

        let words: Vec<u32> = sections[0].bytes[..36]
            .chunks_exact(4)
            .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
            .collect();
        // ?됰슢?곻쭪? ?酉?껆뵳?begin=0x5020(?遺용뮞??μ퓗 = ?諭??0x0 + 0x20), end=0x5080,
        // unwind=0x4000+36=0x4024.
        assert_eq!(
            words,
            vec![0x1000, 0x1100, 0x3000, 0x1200, 0x1300, 0x3010, 0x5020, 0x5080, 0x4024,]
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

        // ??? ?遺용뮞??μ퓗 prologue (pushfq; push rax; push rcx; push r10; push r11)??
        // ??밴쉐??UNWIND_CODE ???袁? 8獄쏅뗄?????쎄문 op (pushfq/??롮뻣??GPR).
        let bridge_unwind = (
            0x07u8,
            vec![
                (0x00u8, UNWIND_ALLOC8), // pushfq
                (0x01u8, UNWIND_ALLOC8), // push rax
                (0x02u8, UNWIND_ALLOC8), // push rcx
                (0x03u8, UNWIND_ALLOC8), // push r10
                (0x05u8, UNWIND_ALLOC8), // push r11
            ],
        );
        update_pdata_seh(
            &mut sections,
            &mut directories,
            &originals,
            0x5000,
            0x40,
            Some(&bridge_unwind),
            0,
            0,
            None,
            None,
        );

        // 獄쏄퀣肉?24 獄쏅뗄???2 ?酉?껆뵳? + UNWIND_INFO (4 ??삳쐭 + 5*2 ?꾨뗀諭?= 14 ??16) = 40.
        assert_eq!(sections[0].bytes.len(), 40);
        let unwind_off = 24usize;
        let unwind = &sections[0].bytes[unwind_off..unwind_off + 16];

        // ??삳쐭: Version=1, Flags=0.
        assert_eq!(unwind[0] & 0x07, UNWIND_VERSION);
        assert_eq!(unwind[0] & 0xF8, 0);
        // SizeOfProlog = 7 (5 push 筌뤿굝議????疫뀀챷??.
        assert_eq!(unwind[1], 0x07);
        // CountOfCodes = 5.
        assert_eq!(unwind[2], 5);
        // FrameRegister/Offset = 0.
        assert_eq!(unwind[3], 0);

        // 筌뤴뫀諭??꾨뗀諭뜹첎? UWOP_ALLOC_SMALL(8) (OpInfo=0, op=ALLOC_SMALL=2) ??곷선????뺣뼄.
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

        let bridge_unwind = (
            0x07u8,
            vec![
                (0x00u8, UNWIND_ALLOC8),
                (0x01u8, UNWIND_ALLOC8),
                (0x02u8, UNWIND_ALLOC8),
                (0x03u8, UNWIND_ALLOC8),
                (0x05u8, UNWIND_ALLOC8),
            ],
        );
        update_pdata_seh(
            &mut sections,
            &mut directories,
            &originals,
            0x5000,
            0x40,
            Some(&bridge_unwind),
            0,
            0,
            None,
            None,
        );

        let pdata = &sections[0].bytes;
        let dir = directories[3];

        // 嚥≪뮆???Exception Directory ??由겼첎? 12獄쏅뗄???RUNTIME_FUNCTION)??獄쏄퀣??袁⑹뱽 ?遺쎈럡.
        assert_eq!(dir.virtual_address, 0x4000);
        assert_eq!(dir.size % 12, 0);
        let num_entries = dir.size as usize / 12;
        assert_eq!(num_entries, 2);

        // 揶??酉?껆뵳? Begin < End, UNWIND_INFO 揶쎛 4獄쏅뗄????類ｌ졊.
        for i in 0..num_entries {
            let begin = u32::from_le_bytes(pdata[i * 12..i * 12 + 4].try_into().unwrap());
            let end = u32::from_le_bytes(pdata[i * 12 + 4..i * 12 + 8].try_into().unwrap());
            let unwind = u32::from_le_bytes(pdata[i * 12 + 8..i * 12 + 12].try_into().unwrap());
            assert!(
                begin < end,
                "entry {}: begin 0x{:X} < end 0x{:X}",
                i,
                begin,
                end
            );
            assert_eq!(
                unwind % 4,
                0,
                "entry {}: unwind 0x{:X} not DWORD aligned",
                i,
                unwind
            );
        }

        // ?됰슢?곻쭪?(?怨뺚봺揶쎛 ?곕떽??? ?酉?껆뵳???UNWIND_INFO 揶쎛 .pdata ?諭?????(獄쏄퀣肉???
        // DWORD ?類ｌ졊 ?袁⑺뒄)??揶쎛?귐딇룖????뺣뼄. ?癒?궚 ?酉?껆뵳????癒?궚 .text/.rdata ??
        // UNWIND_INFO ??揶쎛?귐뗪텕沃샕嚥?.pdata 獄쏅쉼??????덈뼄 (?類ㅺ맒).
        let bridge = pdata.chunks_exact(12).nth(num_entries - 1).unwrap();
        let bridge_begin = u32::from_le_bytes(bridge[0..4].try_into().unwrap());
        assert_eq!(bridge_begin, 0x5020); // ?遺용뮞??μ퓗 = dispatcher_rva + 0x20
        let bridge_unwind = u32::from_le_bytes(bridge[8..12].try_into().unwrap());
        assert_eq!(bridge_unwind, 0x4000 + 24); // .pdata ??뽰삂 + 獄쏄퀣肉?24) = UNWIND_INFO
        assert!(
            bridge_unwind >= 0x4000 && bridge_unwind < 0x4000 + pdata.len() as u32,
            "bridge unwind 0x{:X} outside .pdata",
            bridge_unwind
        );

        // ?類ｌ졊: BeginAddress ??살カ筌△뫁???곷선??嚥≪뮆?묈첎? ?????癒?퉳 揶쎛??
        let begins: Vec<u32> = (0..num_entries)
            .map(|i| u32::from_le_bytes(pdata[i * 12..i * 12 + 4].try_into().unwrap()))
            .collect();
        let mut sorted = begins.clone();
        sorted.sort_unstable();
        assert_eq!(begins, sorted);
    }

    #[test]
    fn build_bridge_unwind_info_layout() {
        // DWORD ?類ｌ졊 + ??삳쐭/?꾨뗀諭??닌듼?野꺜筌?(PUSH_NONVOL + ALLOC8 ??노?).
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

    /// ?귐됰윮 筌왖??#28 野꺜筌? ??밴쉐??UNWIND_INFO 揶쎛 **??쇱젫 ?遺용뮞??μ퓗 prologue?? ?類μ넇??
    /// ??깊뒄**??곷튊 ??뺣뼄 (?類ㅻ뻼 野꺜筌앹빘???袁⑤빍???꾨뗀諭???鈺?.
    #[test]
    fn bridge_unwind_info_matches_real_dispatcher_prologue() {
        for (code, name) in [
            (
                build_dispatcher(0x140001000, 0x80, 16, false, 0xCAFEBABE, false, 0, 2),
                "plain",
            ),
            (
                build_dispatcher(0x140001000, 0x80, 16, true, 0xCAFEBABE, false, 0, 2),
                "plain+trace",
            ),
            (
                build_dispatcher_reencrypt(0x140001000, 0x600, 16, 0xCAFEBABE, false).unwrap(),
                "reencrypt",
            ),
        ] {
            let (codes, prolog_len) = crate::dispatcher::dispatcher_unwind_codes(&code);
            let unwind = build_bridge_unwind_info(
                prolog_len,
                &codes.iter().map(|c| (c.offset, c.reg)).collect::<Vec<_>>(),
            );
            // ??삳쐭
            assert_eq!(unwind[0] & 0x07, UNWIND_VERSION, "{name}");
            assert_eq!(unwind[1], prolog_len, "{name}: SizeOfProlog");
            assert_eq!(unwind[2] as usize, codes.len(), "{name}: CountOfCodes");
            assert_eq!(unwind[3], 0, "{name}: frame reg");
            // ?꾨뗀諭뜹첎? prologue 疫뀀챷?좂몴??λ뜃???? ??낅뮉??
            for c in &codes {
                assert!(
                    (c.offset as u16) < prolog_len as u16,
                    "{name}: code off {}",
                    c.offset
                );
            }
            // DWORD ?類ｌ졊
            assert_eq!(unwind.len() % 4, 0, "{name}");
            // ??쇱젫 ?遺용뮞??μ퓗 筌?獄쏅뗄??硫? pushfq(0x9C)????筌??꾨뗀諭뜹첎? ALLOC8(flags) ??곷선????뺣뼄
            if code[0] == 0x9C {
                assert_eq!(codes.first().unwrap().reg, UNWIND_ALLOC8, "{name}: pushfq");
                assert_eq!(codes.first().unwrap().offset, 0, "{name}: pushfq offset");
            }
        }
    }

    /// P4 (전체 SEH 가상화): Program-VM 엔트리 프로로그를 실제 코드에서 디코드해
    /// 브리지 UNWIND_INFO를 만든다 — UWOP_ALLOC_LARGE(160) + 15 push,
    /// UNWIND_CODE는 **CodeOffset 내림차순**(PE/COFF 스펙).
    #[test]
    fn vm_entry_unwind_info_matches_real_program_vm_prologue() {
        let vmc = crate::vm::handlers::generate_vm_code(
            0x140001000,
            0x140002000,
            0x140001800,
            crate::vm::handlers::EntryMode::Program,
            None,
        )
        .unwrap();
        let code = &vmc.code;
        // Program-VM 엔트리 프로로그: sub rsp,0xA0; cld; movdqu xmm6..15; 15 push.
        assert_eq!(
            code[0], 0x48,
            "prologue starts with a REX.W prefix (48 ...)"
        );
        assert_eq!(code[1], 0x81, "sub rsp, imm32 (81 /5)");
        let (ops, prolog_len) = vm_entry_unwind_ops(code);
        assert!(prolog_len > 0, "decoder found a prologue");
        assert_eq!(ops.len(), 16, "1 alloc + 15 pushes");
        // 첫 op는 0xA0(=160B) ALLOC, 마지막 4 op는 callee-saved r12..r15 push.
        assert!(
            matches!(ops[0].1, VmEntryOp::Alloc(0xA0)),
            "first op is sub rsp,0xA0"
        );
        let nonvol: Vec<u8> = ops
            .iter()
            .filter_map(|(_, o)| match o {
                VmEntryOp::PushNonVol(r) => Some(*r),
                _ => None,
            })
            .collect();
        assert_eq!(
            nonvol,
            vec![3, 5, 6, 7, 15, 14, 13, 12],
            "nonvolatile pushes in order"
        );
        for (off, _) in &ops {
            assert!(*off < prolog_len, "code offset {off} within prologue");
        }

        let info = build_vm_entry_unwind_info(prolog_len, &ops);
        assert_eq!(info[0] & 0x07, UNWIND_VERSION);
        assert_eq!(info[1], prolog_len, "SizeOfProlog");
        assert_eq!(info[2] as usize, ops.len(), "CountOfCodes");
        assert_eq!(info[3], 0, "no frame register");
        assert_eq!(info.len() % 4, 0, "DWORD aligned");

        // UNWIND_CODE CodeOffset가 내림차순(PE/COFF 스펙)인지 검증하고,
        // ALLOC_LARGE(160/8=20) 코드를 찾아 2-byte frame size를 확인한다.
        let mut offsets = Vec::new();
        let mut alloc_large_ok = false;
        let mut i = 4usize;
        let n = info[2] as usize;
        for _ in 0..n {
            offsets.push(info[i]);
            let op = info[i + 1] & 0x0F;
            if op == UWOP_ALLOC_LARGE && info[i] == 0 {
                let frame = (info[i + 2] as u16) | ((info[i + 3] as u16) << 8);
                alloc_large_ok = frame == 20; // 160/8
            }
            i += if op == UWOP_ALLOC_LARGE { 4 } else { 2 };
        }
        assert_eq!(offsets.len(), n);
        let mut sorted_desc = offsets.clone();
        sorted_desc.sort_unstable_by(|a, b| b.cmp(a));
        assert_eq!(
            offsets, sorted_desc,
            "UNWIND_CODE offsets descending (PE/COFF spec)"
        );
        assert!(alloc_large_ok, "ALLOC_LARGE frame size 160/8=20 found");
        // 첫(가장 큰 offset) 코드 = PUSH_NONVOL r12 (마지막 실행된 push).
        assert_eq!(info[4], offsets[0], "first code = max offset");
        assert_eq!(info[5], (12 << 4) | UWOP_PUSH_NONVOL, "PUSH_NONVOL r12");
    }
}
