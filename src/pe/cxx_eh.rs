//! Bounds-checked parser for the RVA-based MSVC x64 C++ EH3 metadata graph.

use crate::pe::builder::SectionData;
use std::collections::BTreeSet;

const EH_MAGIC_NUMBER3: u32 = 0x1993_0522;
const MAX_RECORDS: u32 = 1 << 16;

fn read<'a>(sections: &'a [SectionData], rva: u32, len: usize) -> Option<&'a [u8]> {
    sections.iter().find_map(|section| {
        let offset = rva.checked_sub(section.virtual_address)? as usize;
        let end = offset.checked_add(len)?;
        section.bytes.get(offset..end)
    })
}

fn u32_at(sections: &[SectionData], rva: u32) -> Option<u32> {
    Some(u32::from_le_bytes(read(sections, rva, 4)?.try_into().ok()?))
}

fn i32_at(sections: &[SectionData], rva: u32) -> Option<i32> {
    Some(i32::from_le_bytes(read(sections, rva, 4)?.try_into().ok()?))
}

/// Returns the exact RVA locations of executable RVA fields reachable from
/// inline `FuncInfo` records referenced by UNWIND_INFO handler trailers.
pub fn collect_code_rva_slots(
    language_data_roots: impl IntoIterator<Item = u32>,
    sections: &[SectionData],
) -> BTreeSet<u32> {
    let mut slots = BTreeSet::new();
    for language_data_rva in language_data_roots {
        let root = if u32_at(sections, language_data_rva) == Some(EH_MAGIC_NUMBER3) {
            language_data_rva
        } else {
            let Some(candidate) = u32_at(sections, language_data_rva) else {
                continue;
            };
            if u32_at(sections, candidate) != Some(EH_MAGIC_NUMBER3) {
                continue;
            }
            candidate
        };
        if read(sections, root, 40).is_none() {
            continue;
        }
        let Some(max_state) = i32_at(sections, root.saturating_add(4)) else {
            continue;
        };
        let unwind_count = if max_state < 0 {
            0
        } else {
            (max_state as u32).saturating_add(1)
        };
        let Some(unwind_map) = u32_at(sections, root.saturating_add(8)) else {
            continue;
        };
        let Some(try_count) = u32_at(sections, root.saturating_add(12)) else {
            continue;
        };
        let Some(try_map) = u32_at(sections, root.saturating_add(16)) else {
            continue;
        };
        let Some(ip_count) = u32_at(sections, root.saturating_add(20)) else {
            continue;
        };
        let Some(ip_map) = u32_at(sections, root.saturating_add(24)) else {
            continue;
        };
        if unwind_count > MAX_RECORDS || try_count > MAX_RECORDS || ip_count > MAX_RECORDS {
            continue;
        }
        for index in 0..unwind_count {
            let Some(entry) = unwind_map.checked_add(index.saturating_mul(8)) else {
                break;
            };
            if read(sections, entry, 8).is_none() {
                break;
            }
            slots.insert(entry + 4); // UnwindMapEntry::action
        }
        for index in 0..ip_count {
            let Some(entry) = ip_map.checked_add(index.saturating_mul(8)) else {
                break;
            };
            if read(sections, entry, 8).is_none() {
                break;
            }
            slots.insert(entry); // IPtoStateMapEntry::Ip
        }
        for index in 0..try_count {
            let Some(entry) = try_map.checked_add(index.saturating_mul(20)) else {
                break;
            };
            let Some(catches) = u32_at(sections, entry.saturating_add(12)) else {
                break;
            };
            let Some(handlers) = u32_at(sections, entry.saturating_add(16)) else {
                break;
            };
            if catches > MAX_RECORDS {
                break;
            }
            for handler_index in 0..catches {
                let Some(handler) = handlers.checked_add(handler_index.saturating_mul(20)) else {
                    break;
                };
                if read(sections, handler, 20).is_none() {
                    break;
                }
                slots.insert(handler + 12); // HandlerType::addressOfHandler
            }
        }
    }
    slots
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn follows_indirect_func_info_and_collects_exact_code_fields() {
        let mut bytes = vec![0u8; 0x100];
        let mut put = |rva: u32, value: u32| {
            let offset = (rva - 0x1000) as usize;
            bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        };
        put(0x1000, 0x1040); // language data -> FuncInfo RVA
        put(0x1040, EH_MAGIC_NUMBER3);
        put(0x1044, 0); // maxState => one unwind-map entry
        put(0x1048, 0x1080);
        put(0x104C, 1); // one try block
        put(0x1050, 0x1090);
        put(0x1054, 1); // one IP-to-state entry
        put(0x1058, 0x10D0);
        put(0x1084, 0x2000); // UnwindMapEntry::action
        put(0x109C, 1); // TryBlockMapEntry::nCatches
        put(0x10A0, 0x10B0); // handler array
        put(0x10BC, 0x2010); // HandlerType::addressOfHandler
        put(0x10D0, 0x2020); // IPtoStateMapEntry::Ip
        let sections = [SectionData {
            name: ".rdata".into(),
            virtual_address: 0x1000,
            virtual_size: bytes.len() as u32,
            characteristics: 0x4000_0040,
            bytes,
        }];
        assert_eq!(
            collect_code_rva_slots([0x1000], &sections),
            BTreeSet::from([0x1084, 0x10BC, 0x10D0])
        );
    }
}
