// ==============================================================================
// BTG - Commercial-Grade VM: SDK Marker Signatures & Scanner
// ==============================================================================
// C/C++ 및 Rust 소스 코드의 `BTG_VM_START` / `BTG_VM_END` 인라인 어셈블리
// 서명 바이트를 PE 바이너리의 코드 섹션에서 고속 탐색한다.
//
// Marker Sig:
//   BTG_VM_START: [0xEB, 0x08, b'B', b'T', b'G', b'V', b'M', b'S', b'T', b'1'] (10 bytes: jmp +8 + signature)
//   BTG_VM_END:   [0xEB, 0x08, b'B', b'T', b'G', b'V', b'M', b'E', b'N', b'1'] (10 bytes: jmp +8 + signature)
// ==============================================================================

pub const SIG_VM_START: [u8; 10] = [0xEB, 0x08, b'B', b'T', b'G', b'V', b'M', b'S', b'T', b'1'];
pub const SIG_VM_END: [u8; 10] = [0xEB, 0x08, b'B', b'T', b'G', b'V', b'M', b'E', b'N', b'1'];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmMarkerRegion {
    pub start_offset: usize,
    pub end_offset: usize,
    pub length: usize,
}

pub struct MarkerScanner;

impl MarkerScanner {
    /// 바이트 슬라이스에서 모든 `(VM_START, VM_END)` 쌍의 오프셋 범위를 탐색
    pub fn scan_markers(code: &[u8]) -> Vec<VmMarkerRegion> {
        let mut regions = Vec::new();
        let mut i = 0;

        while i + SIG_VM_START.len() <= code.len() {
            if &code[i..i + SIG_VM_START.len()] == SIG_VM_START {
                let region_start = i + SIG_VM_START.len();
                // Find matching VM_END
                let mut j = region_start;
                let mut found_end = None;
                while j + SIG_VM_END.len() <= code.len() {
                    if &code[j..j + SIG_VM_END.len()] == SIG_VM_END {
                        found_end = Some(j);
                        break;
                    }
                    j += 1;
                }

                if let Some(region_end) = found_end {
                    regions.push(VmMarkerRegion {
                        start_offset: region_start,
                        end_offset: region_end,
                        length: region_end - region_start,
                    });
                    i = region_end + SIG_VM_END.len();
                    continue;
                }
            }
            i += 1;
        }

        regions
    }
}
