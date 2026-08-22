// ==============================================================================
// BTG - import/delay-import RVA range collection - split from patch_data.rs
// ==============================================================================
use crate::pe::builder::SectionData;

pub(crate) fn is_rva_range_protected(
    start_rva: u32,
    len: u32,
    protected_ranges: &[(u32, u32)],
) -> bool {
    let end_rva = start_rva.saturating_add(len);
    for &(p_start, p_end) in protected_ranges {
        if p_start >= end_rva {
            break;
        }
        if start_rva < p_end && end_rva > p_start {
            return true;
        }
    }
    false
}

/// PE 섹션 데이터에서 RVA 위치의 slice를 안전하게 취득한다.
pub(crate) fn rva_to_slice<'a>(sections: &'a [SectionData], rva: u32) -> Option<&'a [u8]> {
    for sec in sections {
        if rva >= sec.virtual_address {
            let offset = (rva - sec.virtual_address) as usize;
            if offset < sec.bytes.len() {
                return Some(&sec.bytes[offset..]);
            }
        }
    }
    None
}

/// RVA 위치의 null 종료 ASCII 문자열의 범위 `(start_rva, end_rva)`를 취득한다.
pub(crate) fn get_ascii_string_rva_range(sections: &[SectionData], rva: u32) -> Option<(u32, u32)> {
    if rva == 0 {
        return None;
    }
    let slice = rva_to_slice(sections, rva)?;
    let len = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    Some((rva, rva.saturating_add(len as u32 + 1)))
}

/// Import Directory (DataDirectory[1]) 내의 테이블, DLL 이름, INT/IAT, IMAGE_IMPORT_BY_NAME 영역을 수집한다.
pub(crate) fn collect_import_directory_ranges(
    sections: &[SectionData],
    import_rva: u32,
    import_size: u32,
    ranges: &mut Vec<(u32, u32)>,
) {
    if import_rva == 0 {
        return;
    }

    if import_size > 0 {
        ranges.push((import_rva, import_rva.saturating_add(import_size)));
    }

    let mut curr_rva = import_rva;
    loop {
        let slice = match rva_to_slice(sections, curr_rva) {
            Some(s) => s,
            None => break,
        };
        if slice.len() < 20 {
            break;
        }

        let orig_first_thunk = u32::from_le_bytes(slice[0..4].try_into().unwrap());
        let time_date_stamp = u32::from_le_bytes(slice[4..8].try_into().unwrap());
        let forwarder_chain = u32::from_le_bytes(slice[8..12].try_into().unwrap());
        let name_rva = u32::from_le_bytes(slice[12..16].try_into().unwrap());
        let first_thunk = u32::from_le_bytes(slice[16..20].try_into().unwrap());

        if orig_first_thunk == 0
            && time_date_stamp == 0
            && forwarder_chain == 0
            && name_rva == 0
            && first_thunk == 0
        {
            if import_size == 0 {
                ranges.push((import_rva, curr_rva.saturating_add(20)));
            }
            break;
        }

        // 1. DLL 이름 문자열 보호
        if name_rva > 0 {
            if let Some(range) = get_ascii_string_rva_range(sections, name_rva) {
                ranges.push(range);
            }
        }

        // 2. INT (OriginalFirstThunk) & IAT (FirstThunk) 테이블 및 IMAGE_IMPORT_BY_NAME 보호
        for &thunk_head_rva in &[orig_first_thunk, first_thunk] {
            if thunk_head_rva == 0 {
                continue;
            }
            let mut t_rva = thunk_head_rva;
            loop {
                let t_slice = match rva_to_slice(sections, t_rva) {
                    Some(s) => s,
                    None => break,
                };
                if t_slice.len() < 8 {
                    break;
                }
                let thunk_val = u64::from_le_bytes(t_slice[0..8].try_into().unwrap());
                if thunk_val == 0 {
                    ranges.push((thunk_head_rva, t_rva.saturating_add(8)));
                    break;
                }

                if (thunk_val & 0x8000_0000_0000_0000) == 0 {
                    let by_name_rva = thunk_val as u32;
                    if by_name_rva > 0 {
                        if let Some(slice) = rva_to_slice(sections, by_name_rva) {
                            if slice.len() >= 2 {
                                let name_slice = &slice[2..];
                                let name_len = name_slice
                                    .iter()
                                    .position(|&b| b == 0)
                                    .unwrap_or(name_slice.len());
                                ranges.push((
                                    by_name_rva,
                                    by_name_rva.saturating_add(2 + name_len as u32 + 1),
                                ));
                            }
                        }
                    }
                }

                t_rva = match t_rva.checked_add(8) {
                    Some(val) => val,
                    None => break,
                };
            }
        }

        curr_rva = match curr_rva.checked_add(20) {
            Some(val) => val,
            None => break,
        };
    }
}

/// Delay Load Import Directory (DataDirectory[13]) 내의 영역을 수집한다.
pub(crate) fn collect_delay_import_directory_ranges(
    sections: &[SectionData],
    delay_rva: u32,
    delay_size: u32,
    ranges: &mut Vec<(u32, u32)>,
) {
    if delay_rva == 0 {
        return;
    }
    if delay_size > 0 {
        ranges.push((delay_rva, delay_rva.saturating_add(delay_size)));
    }

    let mut curr_rva = delay_rva;
    loop {
        let slice = match rva_to_slice(sections, curr_rva) {
            Some(s) => s,
            None => break,
        };
        if slice.len() < 32 {
            break;
        }

        let dll_name_rva = u32::from_le_bytes(slice[4..8].try_into().unwrap());
        let iat_rva = u32::from_le_bytes(slice[12..16].try_into().unwrap());
        let int_rva = u32::from_le_bytes(slice[16..20].try_into().unwrap());

        if dll_name_rva == 0 && iat_rva == 0 && int_rva == 0 {
            break;
        }

        if dll_name_rva > 0 {
            if let Some(range) = get_ascii_string_rva_range(sections, dll_name_rva) {
                ranges.push(range);
            }
        }

        for &thunk_head_rva in &[int_rva, iat_rva] {
            if thunk_head_rva == 0 {
                continue;
            }
            let mut t_rva = thunk_head_rva;
            loop {
                let t_slice = match rva_to_slice(sections, t_rva) {
                    Some(s) => s,
                    None => break,
                };
                if t_slice.len() < 8 {
                    break;
                }
                let thunk_val = u64::from_le_bytes(t_slice[0..8].try_into().unwrap());
                if thunk_val == 0 {
                    ranges.push((thunk_head_rva, t_rva.saturating_add(8)));
                    break;
                }
                if (thunk_val & 0x8000_0000_0000_0000) == 0 {
                    let by_name_rva = thunk_val as u32;
                    if by_name_rva > 0 {
                        if let Some(slice) = rva_to_slice(sections, by_name_rva) {
                            if slice.len() >= 2 {
                                let name_slice = &slice[2..];
                                let name_len = name_slice
                                    .iter()
                                    .position(|&b| b == 0)
                                    .unwrap_or(name_slice.len());
                                ranges.push((
                                    by_name_rva,
                                    by_name_rva.saturating_add(2 + name_len as u32 + 1),
                                ));
                            }
                        }
                    }
                }
                t_rva = match t_rva.checked_add(8) {
                    Some(val) => val,
                    None => break,
                };
            }
        }

        curr_rva = match curr_rva.checked_add(32) {
            Some(val) => val,
            None => break,
        };
    }
}
