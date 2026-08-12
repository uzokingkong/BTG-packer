// ==============================================================================
// BTG Pipeline - v6 IAT Hiding & Memory Hardening support
// ==============================================================================
//
// --iat-hide   : 원본 import 디렉터리/이름을 파일에서 제거하고, kernel32의
//                LoadLibraryA + GetProcAddress 2개만 남기는 "더미 import"를
//                설치한다. 나머지 모든 API는 부트 스텁이 실행 시점에
//                (LoadLibraryA/GetProcAddress를 통해) 리졸브 테이블을 따라
//                원본 IAT 슬롯에 채운다. 정적 분석 시 API 목록이 2개만 노출.
//
// --mem-harden : 복호화 완료 직후 부트 스텁이 ntdll!NtProtectVirtualMemory를
//                호출해 .textb를 RWX → RX(PAGE_EXECUTE_READ)로 전환한다.
//                메모리 덤프 후 패치/재기록을 차단 (fail-open — 해석 실패 시
//                보호 없이 계속 실행).
//
// 배치: 두 기능의 데이터(더미 import 블록, 리졸브 테이블, 문자열)는 crypto::run이
// 부트 영역 레이아웃을 확정한 뒤 .textb tail에 배치한다. 이 모듈은 그 데이터
// 블롭을 준비하고, 원본 import 흔적을 제거한다.
// ==============================================================================

use crate::pipeline::PipelineContext;
use anyhow::{Result, anyhow};
use goblin::pe::PE;
use std::collections::HashSet;

/// 원본 PE에서 추출한 import 1건.
#[derive(Debug, Clone)]
pub struct OriginalImport {
    /// DLL 이름 (예: "kernel32.dll")
    pub dll: String,
    /// FirstThunk(IAT) 슬롯 RVA — 부트 스텁이 해석 결과를 이 주소에 기록
    pub slot_rva: u32,
    /// hint/name 문자열 RVA (0이면 ordinal import)
    pub name_rva: u32,
    pub func: FuncRef,
}

#[derive(Debug, Clone)]
pub enum FuncRef {
    Name(String),
    Ordinal(u16),
}

/// goblin으로 원본 PE의 import 목록을 추출한다.
pub fn collect_from_pe(bytes: &[u8]) -> Result<Vec<OriginalImport>> {
    let pe = PE::parse(bytes).map_err(|e| anyhow!("collect imports: PE parse failed: {e}"))?;
    let mut out = Vec::new();
    for imp in &pe.imports {
        let func = match imp.name.as_ref() {
            n if n.starts_with("ORDINAL ") || n.is_empty() => FuncRef::Ordinal(imp.ordinal),
            n => FuncRef::Name(n.to_string()),
        };
        out.push(OriginalImport {
            dll: imp.dll.to_string(),
            slot_rva: imp.offset as u32, // goblin: FirstThunk 슬롯 RVA
            name_rva: imp.rva as u32,
            func,
        });
    }
    Ok(out)
}

// ──────────────────────────────────────────────────────────────────────────────
// 데이터 블롭 생성
// ──────────────────────────────────────────────────────────────────────────────

/// kernel32!LoadLibraryA / GetProcAddress만 남기는 더미 import 블록.
///
/// 내부 RVA는 모두 `base_rva`를 기준으로 절대값으로 기록된다 (PE 규격).
/// 레이아웃 (오프셋은 문자열 길이 기준 순차 계산):
/// ```text
/// 0x00  IMAGE_IMPORT_DESCRIPTOR (OFT=name array, Name="kernel32.dll", FT=iat)
/// 0x14  null descriptor (종료)
/// 0x28  "kernel32.dll\0"
/// 0x35  name array (u64 ×3 → hint/name RVA 2개 + NULL 종료)
/// 0x4D  hint/name "LoadLibraryA\0"
/// 0x5C  hint/name "GetProcAddress\0"
/// 0x70  IAT 슬롯 (u64 ×3 — hint/name RVA 체인 + NULL 종료; 로더가 주소로 덮어씀)
/// ```
///
/// FIX(v12): Windows 로더는 FirstThunk(IAT) 슬롯이 hint/name RVA 체인으로
/// 채워져 있을 때만 dummy import를 처리한다 (로더가 슬롯을 해석 주소로 덮어씀).
/// 기존 코드는 IAT를 0으로 비워 두어 로더가 import를 통째로 건너뛰었고, 그 결과
/// LoadLibraryA/GetProcAddress 슬롯이 채워지지 않아 부트 스텁의 IAT 복원이
/// 실행되지 않았다 → 첫 import 호출이 0x0으로 점프해 0xC0000005 크래시.
/// name array(OFT)에도 NULL 종료자를 추가 (체인 워크 오버런 방지).
pub fn build_dummy_import_block(base_rva: u32) -> (Vec<u8>, u32, u32, u32, u32) {
    // 모든 오프셋은 실제 바이트 길이를 기준으로 순차 계산 (하드코딩 금지)
    let name_off = 0x28usize; // descriptor(20) + null descriptor(20)
    let namearr_off = name_off + b"kernel32.dll\0".len();
    let mut cursor = namearr_off + 24; // name array (3×u64: RVA 2개 + NULL 종료)
    let ll_hn_off = cursor;
    cursor += 2 + b"LoadLibraryA\0".len(); // u16 hint + cstr
    let gpa_hn_off = cursor;
    cursor += 2 + b"GetProcAddress\0".len();
    let iat_off = (cursor + 7) & !7;
    let rva = |o: usize| base_rva + o as u32;

    let mut b = Vec::new();
    // descriptor (20B)
    b.extend_from_slice(&rva(namearr_off).to_le_bytes()); // OriginalFirstThunk
    b.extend_from_slice(&0u32.to_le_bytes());             // TimeDateStamp
    b.extend_from_slice(&0u32.to_le_bytes());             // ForwarderChain
    b.extend_from_slice(&rva(name_off).to_le_bytes());    // Name
    b.extend_from_slice(&rva(iat_off).to_le_bytes());     // FirstThunk
    // null descriptor (20B)
    b.extend_from_slice(&[0u8; 20]);
    debug_assert_eq!(b.len(), name_off);
    // dll name
    b.extend_from_slice(b"kernel32.dll\0");
    debug_assert_eq!(b.len(), namearr_off);
    // name array (OFT 체인 → hint/name RVA) — IMAGE_THUNK_DATA64: 엔트리당 u64(8B)
    b.extend_from_slice(&(rva(ll_hn_off) as u64).to_le_bytes());
    b.extend_from_slice(&(rva(gpa_hn_off) as u64).to_le_bytes());
    b.extend_from_slice(&0u64.to_le_bytes()); // OFT 체인 NULL 종료 (FIX v12)
    // hint/name entries (u16 hint + cstr)
    b.extend_from_slice(&0u16.to_le_bytes());
    b.extend_from_slice(b"LoadLibraryA\0");
    b.extend_from_slice(&0u16.to_le_bytes());
    b.extend_from_slice(b"GetProcAddress\0");
    while b.len() < iat_off {
        b.push(0);
    }
    // IAT 슬롯 3개 (FIX v12): hint/name RVA 체인으로 채운다 — Windows 로더는
    // IAT가 RVA 체인으로 채워져 있을 때만 import를 처리하고 슬롯을 해석 주소로
    // 덮어쓴다. 0으로 비워 두면 로더가 dummy import를 건너뛰어
    // LoadLibraryA/GetProcAddress가 해석되지 않는다 (0xC0000005 크래시).
    b.extend_from_slice(&(rva(ll_hn_off) as u64).to_le_bytes());
    b.extend_from_slice(&(rva(gpa_hn_off) as u64).to_le_bytes());
    b.extend_from_slice(&0u64.to_le_bytes()); // IAT 체인 NULL 종료

    (
        b,
        base_rva,               // desc RVA
        0x28,                   // desc size (descriptor 2개)
        rva(iat_off),           // LoadLibraryA 슬롯 RVA
        rva(iat_off + 8),       // GetProcAddress 슬롯 RVA
    )
}

/// 이름 문자열을 per-entry MBA 키로 XOR 암호화한다 (다층 1단계).
/// 키 = MBA::compute_key(master, entry_index, c, 2) — 패킹 시점과 부트 스텁
/// resolve 루프(RBX=entry index)가 같은 키를 유도한다. 이름마다 키가 달라
/// 단일 키스트림(예: 전역 RC4)으로 전부 풀 수 없다.
fn mba_xor(name: &[u8], entry_index: u32, master: u32, c: u32) -> Vec<u8> {
    let key = crate::mba::MbaGenerator::compute_key(master, entry_index, c, 2);
    name.iter()
        .enumerate()
        .map(|(i, &b)| b ^ ((key >> (8 * ((i as u32) & 3))) & 0xFF) as u8)
        .collect()
}

/// 부트 스텁이 처리하는 리졸브 테이블:
/// ```text
/// u32 dll_count
/// 각 dll:
///   u32 name_len, name bytes, 0x00 (NUL),
///   u32 func_count,
///   각 func: u64 slot_va, u32 name_len, name bytes, 0x00 (NUL)
/// ```
/// ordinal import는 name 대신 `name_len = 0xFFFF0000` 마커 + u16 ordinal + NUL.
///
/// FIX(v10): slot 항목은 **절대 VA**(image_base + slot_rva)여야 한다. 부트 스텁은
/// `mov [r12], rax`로 슬롯 주소에 해석 결과를 기록하는데, 이전 코드는 RVA를
/// 그대로 기록해 image_base(예: 0x140000000)가 0이 아닌 한 낮은 주소(미매핑)에
/// 기록 → --iat-hide 실행 시 해석된 API가 실제 IAT 슬롯에 들어가지 않았다.
/// (ASLR은 패커가 제거하므로 고정 image_base가 항상 유효하다.)
pub fn build_resolve_table(
    imports: &[OriginalImport],
    image_base: u64,
    mba_master: u32,
    mba_c: u32,
) -> Vec<u8> {
    // DLL 순서 보존 그룹핑
    let mut groups: Vec<(&str, Vec<&OriginalImport>)> = Vec::new();
    for imp in imports {
        if let Some(g) = groups.iter_mut().find(|(name, _)| *name == imp.dll.as_str()) {
            g.1.push(imp);
        } else {
            groups.push((&imp.dll, vec![imp]));
        }
    }

    let mut out = Vec::new();
    out.extend_from_slice(&(groups.len() as u32).to_le_bytes());
    // entry index — dll 이름 + 각 named func마다 1씩 증가 (부트 스텁 RBX와 동일 순서)
    let mut g = 0u32;
    for (dll, funcs) in &groups {
        // dll 이름 (g)
        out.extend_from_slice(&(dll.len() as u32).to_le_bytes());
        out.extend_from_slice(&mba_xor(dll.as_bytes(), g, mba_master, mba_c));
        out.push(0);
        g += 1;
        // 함수들
        out.extend_from_slice(&(funcs.len() as u32).to_le_bytes());
        for imp in funcs {
            // slot은 부트 스텁이 절대 VA로 기록하므로 image_base를 더한다.
            // (원본 IAT 슬롯 RVA는 릴레이 섹션에서 유지됨)
            out.extend_from_slice(&(image_base.wrapping_add(imp.slot_rva as u64)).to_le_bytes());
            match &imp.func {
                FuncRef::Name(n) => {
                    out.extend_from_slice(&(n.len() as u32).to_le_bytes());
                    out.extend_from_slice(&mba_xor(n.as_bytes(), g, mba_master, mba_c));
                    out.push(0);
                    g += 1;
                }
                FuncRef::Ordinal(o) => {
                    out.extend_from_slice(&0xFFFF_0000u32.to_le_bytes()); // ordinal 마커
                    out.extend_from_slice(&(*o as u16).to_le_bytes());
                    out.push(0);
                }
            }
        }
    }
    out
}

// ──────────────────────────────────────────────────────────────────────────────
// 원본 import 흔적 제거
// ──────────────────────────────────────────────────────────────────────────────

fn zero_rva_range(ctx: &mut PipelineContext, rva: u32, len: u32) {
    for sec in ctx.patched_sections.iter_mut() {
        if rva >= sec.virtual_address {
            let off = (rva - sec.virtual_address) as usize;
            let end = off + len as usize;
            if end <= sec.bytes.len() {
                sec.bytes[off..end].fill(0);
                return;
            }
        }
    }
}

/// 원본 import 디렉터리/이름/IAT 슬롯을 제로아웃하고, IAT 슬롯이 있는 섹션을
/// 쓰기 가능으로 바꾼다 (부트 스텁이 실행 시점에 슬롯을 채운다).
pub fn erase_original_imports(ctx: &mut PipelineContext) {
    // 원본 목록 스냅샷 (patched_sections 가변 대여 중 ctx를 다시 빌리지 않기 위해)
    let imports: Vec<OriginalImport> = ctx.original_imports.clone();
    let dd1 = ctx
        .target_info
        .data_directories
        .get(1)
        .copied()
        .unwrap_or(crate::pe::builder::DataDirectory { virtual_address: 0, size: 0 });

    // 1) import 디렉터리 영역 제로아웃 (DataDirectory[1]은 더미로 대체됨)
    if dd1.virtual_address != 0 && dd1.size != 0 {
        zero_rva_range(ctx, dd1.virtual_address, dd1.size);
    }

    // 2) hint/name 문자열 + IAT 슬롯 제로아웃, 슬롯 섹션 WRITE
    let mut writable = HashSet::new();
    for imp in &imports {
        if imp.name_rva != 0 {
            // hint(2B) + 이름 문자열 종료까지 제로아웃
            zero_rva_range(ctx, imp.name_rva.saturating_sub(2), 2);
            if let Some(sec) = ctx
                .patched_sections
                .iter()
                .find(|s| imp.name_rva >= s.virtual_address)
            {
                let off = (imp.name_rva - sec.virtual_address) as usize;
                if off < sec.bytes.len() {
                    let mut end = off;
                    while end < sec.bytes.len() && sec.bytes[end] != 0 {
                        end += 1;
                    }
                    let len = (end - off).min(0x1000) as u32;
                    zero_rva_range(ctx, imp.name_rva, len);
                }
            }
        }
        // IAT 슬롯 (8B)
        zero_rva_range(ctx, imp.slot_rva, 8);
        for (idx, sec) in ctx.patched_sections.iter().enumerate() {
            if imp.slot_rva >= sec.virtual_address
                && imp.slot_rva < sec.virtual_address.saturating_add(sec.virtual_size)
            {
                writable.insert(idx);
            }
        }
    }
    for idx in writable {
        ctx.patched_sections[idx].characteristics |= 0x8000_0000; // IMAGE_SCN_MEM_WRITE
    }
}

/// 메인 진입: 원본 import 흔적 제거 (더미 import/리졸브 테이블/문자열 배치는
/// crypto::run이 부트 영역에 수행).
pub fn run(ctx: &mut PipelineContext) -> Result<()> {
    if !ctx.iat_hide && !ctx.mem_harden {
        return Ok(());
    }
    if ctx.iat_hide {
        erase_original_imports(ctx);
        println!(
            "[+] v6 IAT Hiding: {} original imports erased; dummy import (LoadLibraryA/GetProcAddress) installed",
            ctx.original_imports.len()
        );
    }
    if ctx.mem_harden {
        println!("[+] v6 Memory Hardening: .textb will be switched RWX->RX after decryption");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dummy_import_block_layout() {
        // base_rva=0x3000으로 블록 생성 → 내부 RVA가 base를 반영하는지 검증
        let (b, dir_rva, dir_size, ll_slot, gpa_slot) = build_dummy_import_block(0x3000);
        eprintln!("DBG block hex 0x30..0x70: {}", b[0x30..0x70].iter().map(|x| format!("{:02X}", x)).collect::<Vec<_>>().join(" "));
        eprintln!("DBG len={} dir_rva={:#x} ll_slot={:#x} gpa_slot={:#x}", b.len(), dir_rva, ll_slot, gpa_slot);
        assert_eq!(dir_rva, 0x3000);
        assert_eq!(dir_size, 0x28);
        let u32at = |o: usize| u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
        assert_eq!(u32at(0), 0x3035);  // OriginalFirstThunk -> name array
        assert_eq!(u32at(12), 0x3028); // Name ("kernel32.dll")
        assert_eq!(u32at(16), 0x3070); // FirstThunk (IAT)
        assert_eq!(ll_slot, 0x3070);
        assert_eq!(gpa_slot, 0x3078);
        let s = String::from_utf8_lossy(&b[0x28..0x28 + 12]);
        assert_eq!(s, "kernel32.dll");
        // "LoadLibraryA" hint/name은 namearr(0x35)+24 = 0x4D에서 시작
        let s2 = String::from_utf8_lossy(&b[0x4D + 2..0x4D + 2 + 12]);
        assert_eq!(s2, "LoadLibraryA");
        // name array (OFT) 엔트리 2개 + NULL 종료
        assert_eq!(u64::from_le_bytes(b[0x35..0x3D].try_into().unwrap()), 0x304D);
        assert_eq!(u64::from_le_bytes(b[0x3D..0x45].try_into().unwrap()), 0x305C);
        assert_eq!(u64::from_le_bytes(b[0x45..0x4D].try_into().unwrap()), 0);
        // IAT: hint/name RVA 체인 + NULL 종료 (로더가 해석 주소로 덮어씀)
        assert_eq!(u64::from_le_bytes(b[0x70..0x78].try_into().unwrap()), 0x304D);
        assert_eq!(u64::from_le_bytes(b[0x78..0x80].try_into().unwrap()), 0x305C);
        assert_eq!(u64::from_le_bytes(b[0x80..0x88].try_into().unwrap()), 0);
    }

    #[test]
    fn test_resolve_table_format() {
        // v10: slot 항목은 image_base + RVA의 **절대 VA**여야 한다 (부트 스텁이
        // `mov [slot], rax`로 기록하므로). RVA를 그대로 쓰면 미매핑 주소에 기록된다.
        let image_base: u64 = 0x140000000;
        let imports = vec![
            OriginalImport { dll: "kernel32.dll".into(), slot_rva: 0x2028, name_rva: 0x2058, func: FuncRef::Name("ExitProcess".into()) },
            OriginalImport { dll: "kernel32.dll".into(), slot_rva: 0x2030, name_rva: 0x2068, func: FuncRef::Name("GetModuleHandleA".into()) },
            OriginalImport { dll: "user32.dll".into(), slot_rva: 0x2038, name_rva: 0x2078, func: FuncRef::Ordinal(5) },
        ];
        let t = build_resolve_table(&imports, image_base, 0, 0);
        assert_eq!(u32::from_le_bytes(t[0..4].try_into().unwrap()), 2); // dll_count
        // 1st dll: "kernel32.dll"(12)+NUL, func_count=2
        let p = 4usize;
        assert_eq!(u32::from_le_bytes(t[p..p + 4].try_into().unwrap()), 12);
        assert_eq!(&t[p + 4..p + 4 + 12], b"kernel32.dll");
        assert_eq!(t[p + 4 + 12], 0);
        let mut q = p + 4 + 12 + 1;
        assert_eq!(u32::from_le_bytes(t[q..q + 4].try_into().unwrap()), 2);
        q += 4;
        // func1: slot = 0x140000000 + 0x2028, "ExitProcess"(11)
        assert_eq!(u64::from_le_bytes(t[q..q + 8].try_into().unwrap()), 0x140002028);
        q += 8;
        assert_eq!(u32::from_le_bytes(t[q..q + 4].try_into().unwrap()), 11);
        assert_eq!(mba_xor(&t[q + 4..q + 4 + 11], 1, 0, 0).as_slice(), b"ExitProcess");
        q += 4 + 11 + 1;
        // func2: slot = 0x140000000 + 0x2030, "GetModuleHandleA"(17)
        assert_eq!(u64::from_le_bytes(t[q..q + 8].try_into().unwrap()), 0x140002030);
        q += 8;
        assert_eq!(u32::from_le_bytes(t[q..q + 4].try_into().unwrap()), 16);
        q += 4 + 16 + 1;
        // 2nd dll: "user32.dll"(10) + ordinal func
        assert_eq!(u32::from_le_bytes(t[q..q + 4].try_into().unwrap()), 10);
        assert_eq!(mba_xor(&t[q + 4..q + 4 + 10], 3, 0, 0).as_slice(), b"user32.dll");
        q += 4 + 10 + 1;
        assert_eq!(u32::from_le_bytes(t[q..q + 4].try_into().unwrap()), 1);
        q += 4;
        assert_eq!(u64::from_le_bytes(t[q..q + 8].try_into().unwrap()), 0x140002038);
        q += 8;
        assert_eq!(u32::from_le_bytes(t[q..q + 4].try_into().unwrap()), 0xFFFF_0000);
        assert_eq!(u16::from_le_bytes(t[q + 4..q + 6].try_into().unwrap()), 5);
        q += 4 + 2 + 1;
        assert_eq!(q, t.len(), "table fully consumed");
    }

    #[test]
    fn test_resolve_table_slots_are_absolute_vas() {
        // FIX 회귀: 모든 slot 항목이 image_base+RVA (절대 VA)이고, image_base가
        // 0이 아닌 한 어떤 항목도 원본 RVA와 같으면 안 된다.
        let image_base: u64 = 0x140000000;
        let imports = vec![
            OriginalImport { dll: "kernel32.dll".into(), slot_rva: 0x2028, name_rva: 0x2058, func: FuncRef::Name("ExitProcess".into()) },
            OriginalImport { dll: "user32.dll".into(), slot_rva: 0x2038, name_rva: 0x2078, func: FuncRef::Ordinal(5) },
        ];
        let t = build_resolve_table(&imports, image_base, 0, 0);
        // dll_count(4) + dll1(4+12+1+4) + func1(8+4+11+1) + dll2(4+10+1+4) + func2(8+4+2+1)
        let mut slots = Vec::new();
        let mut q = 4usize;
        for _ in 0..2 {
            let name_len = u32::from_le_bytes(t[q..q + 4].try_into().unwrap()) as usize;
            q += 4 + name_len + 1;
            let func_count = u32::from_le_bytes(t[q..q + 4].try_into().unwrap());
            q += 4;
            for _ in 0..func_count {
                let slot = u64::from_le_bytes(t[q..q + 8].try_into().unwrap());
                slots.push(slot);
                q += 8;
                let fname_len = u32::from_le_bytes(t[q..q + 4].try_into().unwrap());
                q += 4;
                q += if fname_len == 0xFFFF_0000 { 2 + 1 } else { fname_len as usize + 1 };
            }
        }
        assert_eq!(q, t.len());
        assert_eq!(slots, vec![0x140002028, 0x140002038]);
        for s in &slots {
            assert!(*s >= image_base, "slot must be an absolute VA");
            assert!(*s != (*s - image_base), "must differ from the bare RVA");
        }
    }

    #[test]
    fn test_collect_from_pe_import_test() {
        // import_test.exe (mingw): kernel32.dll!ExitProcess import 1건.
        // RVA는 컴파일러 레이아웃에 따라 달라지므로 고정값 대신 goblin 파서와
        // 교차 검증한다 — collect_from_pe가 goblin과 동일한 DLL/이름/슬롯을 보고하는지.
        // 픽스처는 리포지토리 tests/fixtures/ (안정) 또는 /tmp/import_test.exe.
        let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("tests/fixtures/import_test.exe");
        if !path.exists() {
            path = std::path::PathBuf::from("/tmp/import_test.exe");
        }
        let bytes = std::fs::read(&path).unwrap();
        let imports = collect_from_pe(&bytes).unwrap();
        assert!(!imports.is_empty(), "fixture must import at least one function");
        // goblin과 1:1 대조 (순서/개수/DLL/이름/슬롯 RVA)
        let pe = goblin::pe::PE::parse(&bytes).unwrap();
        assert_eq!(imports.len(), pe.imports.len());
        for (got, imp) in imports.iter().zip(pe.imports.iter()) {
            assert_eq!(got.dll, imp.dll);
            assert_eq!(got.slot_rva, imp.offset as u32, "IAT slot RVA must match goblin");
            match &got.func {
                FuncRef::Name(n) => assert_eq!(&imp.name, n),
                _ => panic!("fixture imports must be by name"),
            }
        }
        // KERNEL32!ExitProcess가 포함되어 있는지 확인 (DLL 이름은 대소문자 무시)
        assert!(imports
            .iter()
            .any(|i| i.dll.eq_ignore_ascii_case("kernel32.dll")
                && matches!(&i.func, FuncRef::Name(n) if n == "ExitProcess")));
    }
}
