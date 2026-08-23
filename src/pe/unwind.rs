//! Typed, bounds-checked parser for the Windows x64 exception directory.
//!
//! Addresses in these structures are image-relative (RVAs), as they are in the
//! PE exception directory.  The parser intentionally does not interpret the
//! operation-specific extra `UNWIND_CODE` slots; it preserves every two-byte
//! slot so consumers can decode operations without losing the original layout.

use std::fmt;

pub const UNW_FLAG_EHANDLER: u8 = 0x01;
pub const UNW_FLAG_UHANDLER: u8 = 0x02;
pub const UNW_FLAG_CHAININFO: u8 = 0x04;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeFunction {
    pub begin_address: u32,
    pub end_address: u32,
    pub unwind_info_address: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnwindCode {
    pub code_offset: u8,
    pub unwind_operation: u8,
    pub operation_info: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnwindTrailer {
    None,
    Handler { handler_rva: u32 },
    Chain(RuntimeFunction),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnwindInfo {
    pub version: u8,
    /// Unshifted `UNW_FLAG_*` bits.
    pub flags: u8,
    pub prolog_size: u8,
    pub frame_register: u8,
    pub frame_offset: u8,
    pub codes: Vec<UnwindCode>,
    pub trailer: UnwindTrailer,
}

#[derive(Debug, Clone, Copy)]
pub struct RvaSection<'a> {
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub bytes: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnwindError {
    TruncatedExceptionDirectory {
        length: usize,
    },
    InvalidRuntimeFunction {
        index: usize,
        begin: u32,
        end: u32,
    },
    RvaNotMapped(u32),
    TruncatedUnwindInfo {
        rva: u32,
        needed: usize,
        available: usize,
    },
    InvalidVersion {
        rva: u32,
        version: u8,
    },
    ConflictingTrailerFlags {
        rva: u32,
        flags: u8,
    },
    ChainCycle {
        rva: u32,
    },
    ChainDepthExceeded {
        max_depth: usize,
    },
}

impl fmt::Display for UnwindError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for UnwindError {}

/// Parse the x64 exception directory (`.pdata`) into typed records.
///
/// Fully-zero records and an all-zero alignment tail are accepted as padding.
pub fn parse_runtime_functions(bytes: &[u8]) -> Result<Vec<RuntimeFunction>, UnwindError> {
    let record_bytes = bytes.len() / 12 * 12;
    if bytes[record_bytes..].iter().any(|&b| b != 0) {
        return Err(UnwindError::TruncatedExceptionDirectory {
            length: bytes.len(),
        });
    }

    let mut result = Vec::new();
    for (index, record) in bytes[..record_bytes].chunks_exact(12).enumerate() {
        let function = parse_runtime_function(record);
        if function.begin_address == 0
            && function.end_address == 0
            && function.unwind_info_address == 0
        {
            continue;
        }
        if function.begin_address == 0 || function.end_address <= function.begin_address {
            return Err(UnwindError::InvalidRuntimeFunction {
                index,
                begin: function.begin_address,
                end: function.end_address,
            });
        }
        result.push(function);
    }
    result.sort_by_key(|function| function.begin_address);
    Ok(result)
}

/// Locate and parse one `UNWIND_INFO` structure by RVA.
pub fn parse_unwind_info(
    unwind_rva: u32,
    sections: &[RvaSection<'_>],
) -> Result<UnwindInfo, UnwindError> {
    let bytes = locate_rva(unwind_rva, sections)?;
    require(unwind_rva, bytes, 4)?;

    let version = bytes[0] & 0x07;
    let flags = bytes[0] >> 3;
    if version == 0 || version > 2 {
        return Err(UnwindError::InvalidVersion {
            rva: unwind_rva,
            version,
        });
    }
    let has_handler = flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER) != 0;
    let has_chain = flags & UNW_FLAG_CHAININFO != 0;
    if has_handler && has_chain {
        return Err(UnwindError::ConflictingTrailerFlags {
            rva: unwind_rva,
            flags,
        });
    }

    let count = bytes[2] as usize;
    let codes_end = 4usize
        .checked_add(
            count
                .checked_mul(2)
                .ok_or(UnwindError::TruncatedUnwindInfo {
                    rva: unwind_rva,
                    needed: usize::MAX,
                    available: bytes.len(),
                })?,
        )
        .ok_or(UnwindError::TruncatedUnwindInfo {
            rva: unwind_rva,
            needed: usize::MAX,
            available: bytes.len(),
        })?;
    require(unwind_rva, bytes, codes_end)?;

    let mut codes = Vec::with_capacity(count);
    for slot in bytes[4..codes_end].chunks_exact(2) {
        codes.push(UnwindCode {
            code_offset: slot[0],
            unwind_operation: slot[1] & 0x0f,
            operation_info: slot[1] >> 4,
        });
    }

    // The optional trailer follows an even number of two-byte code slots.
    let trailer_offset = 4 + ((count + 1) & !1) * 2;
    let trailer = if has_chain {
        require(unwind_rva, bytes, trailer_offset + 12)?;
        UnwindTrailer::Chain(parse_runtime_function(
            &bytes[trailer_offset..trailer_offset + 12],
        ))
    } else if has_handler {
        require(unwind_rva, bytes, trailer_offset + 4)?;
        UnwindTrailer::Handler {
            handler_rva: read_u32(&bytes[trailer_offset..trailer_offset + 4]),
        }
    } else {
        UnwindTrailer::None
    };

    Ok(UnwindInfo {
        version,
        flags,
        prolog_size: bytes[1],
        frame_register: bytes[3] & 0x0f,
        frame_offset: bytes[3] >> 4,
        codes,
        trailer,
    })
}

/// Parse an unwind record and follow every `UNW_FLAG_CHAININFO` link.
/// The first element is `unwind_rva`; subsequent elements are its parents.
pub fn parse_unwind_chain(
    unwind_rva: u32,
    sections: &[RvaSection<'_>],
    max_depth: usize,
) -> Result<Vec<(u32, UnwindInfo)>, UnwindError> {
    let mut result = Vec::new();
    let mut current = unwind_rva;
    for _ in 0..max_depth {
        if result.iter().any(|(rva, _)| *rva == current) {
            return Err(UnwindError::ChainCycle { rva: current });
        }
        let info = parse_unwind_info(current, sections)?;
        let next = match info.trailer {
            UnwindTrailer::Chain(parent) => Some(parent.unwind_info_address),
            _ => None,
        };
        result.push((current, info));
        match next {
            Some(rva) => current = rva,
            None => return Ok(result),
        }
    }
    Err(UnwindError::ChainDepthExceeded { max_depth })
}

fn locate_rva<'a>(rva: u32, sections: &'a [RvaSection<'a>]) -> Result<&'a [u8], UnwindError> {
    for section in sections {
        let span = section
            .virtual_size
            .max(section.bytes.len().min(u32::MAX as usize) as u32);
        if rva >= section.virtual_address && rva - section.virtual_address < span {
            let offset = (rva - section.virtual_address) as usize;
            return section
                .bytes
                .get(offset..)
                .ok_or(UnwindError::TruncatedUnwindInfo {
                    rva,
                    needed: 1,
                    available: 0,
                });
        }
    }
    Err(UnwindError::RvaNotMapped(rva))
}

fn require(rva: u32, bytes: &[u8], needed: usize) -> Result<(), UnwindError> {
    if bytes.len() < needed {
        Err(UnwindError::TruncatedUnwindInfo {
            rva,
            needed,
            available: bytes.len(),
        })
    } else {
        Ok(())
    }
}

fn parse_runtime_function(bytes: &[u8]) -> RuntimeFunction {
    RuntimeFunction {
        begin_address: read_u32(&bytes[0..4]),
        end_address: read_u32(&bytes[4..8]),
        unwind_info_address: read_u32(&bytes[8..12]),
    }
}

fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pdata_is_compatible_with_legacy_parser_and_sorted() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0x3000u32.to_le_bytes());
        bytes.extend_from_slice(&0x3040u32.to_le_bytes());
        bytes.extend_from_slice(&0x5010u32.to_le_bytes());
        bytes.extend_from_slice(&0x1000u32.to_le_bytes());
        bytes.extend_from_slice(&0x1020u32.to_le_bytes());
        bytes.extend_from_slice(&0x5000u32.to_le_bytes());
        bytes.extend_from_slice(&[0; 12]);
        let parsed = parse_runtime_functions(&bytes).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].begin_address, 0x1000);
        assert_eq!(parsed[1].unwind_info_address, 0x5010);
    }

    #[test]
    fn handler_follows_odd_code_count_padding() {
        let bytes = [
            (UNW_FLAG_EHANDLER << 3) | 1,
            5,
            1,
            0x35, // header
            4,
            0x32, // one code slot
            0,
            0, // alignment slot
            0x78,
            0x56,
            0x34,
            0x12, // handler RVA
        ];
        let sections = [RvaSection {
            virtual_address: 0x5000,
            virtual_size: bytes.len() as u32,
            bytes: &bytes,
        }];
        let info = parse_unwind_info(0x5000, &sections).unwrap();
        assert_eq!(info.frame_register, 5);
        assert_eq!(info.frame_offset, 3);
        assert_eq!(
            info.codes[0],
            UnwindCode {
                code_offset: 4,
                unwind_operation: 2,
                operation_info: 3
            }
        );
        assert_eq!(
            info.trailer,
            UnwindTrailer::Handler {
                handler_rva: 0x12345678
            }
        );
    }

    #[test]
    fn chain_is_a_runtime_function_at_aligned_trailer() {
        let mut bytes = vec![(UNW_FLAG_CHAININFO << 3) | 1, 7, 2, 0];
        bytes.extend_from_slice(&[7, 0x30, 2, 0x01]);
        bytes.extend_from_slice(&0x1100u32.to_le_bytes());
        bytes.extend_from_slice(&0x1200u32.to_le_bytes());
        bytes.extend_from_slice(&0x5100u32.to_le_bytes());
        let sections = [RvaSection {
            virtual_address: 0x5000,
            virtual_size: bytes.len() as u32,
            bytes: &bytes,
        }];
        let info = parse_unwind_info(0x5000, &sections).unwrap();
        assert_eq!(
            info.trailer,
            UnwindTrailer::Chain(RuntimeFunction {
                begin_address: 0x1100,
                end_address: 0x1200,
                unwind_info_address: 0x5100,
            })
        );
    }

    #[test]
    fn rejects_truncated_handler_and_conflicting_flags() {
        let truncated = [(UNW_FLAG_UHANDLER << 3) | 1, 0, 0, 0];
        let sections = [RvaSection {
            virtual_address: 0x6000,
            virtual_size: 4,
            bytes: &truncated,
        }];
        assert!(matches!(
            parse_unwind_info(0x6000, &sections),
            Err(UnwindError::TruncatedUnwindInfo { .. })
        ));

        let conflict = [((UNW_FLAG_EHANDLER | UNW_FLAG_CHAININFO) << 3) | 1, 0, 0, 0];
        let sections = [RvaSection {
            virtual_address: 0x7000,
            virtual_size: 4,
            bytes: &conflict,
        }];
        assert!(matches!(
            parse_unwind_info(0x7000, &sections),
            Err(UnwindError::ConflictingTrailerFlags { .. })
        ));
    }

    #[test]
    fn follows_chain_to_parent_handler() {
        let mut bytes = vec![(UNW_FLAG_CHAININFO << 3) | 1, 0, 0, 0];
        bytes.extend_from_slice(&0x1100u32.to_le_bytes());
        bytes.extend_from_slice(&0x1200u32.to_le_bytes());
        bytes.extend_from_slice(&0x5010u32.to_le_bytes());
        bytes.extend_from_slice(&[(UNW_FLAG_UHANDLER << 3) | 1, 0, 0, 0]);
        bytes.extend_from_slice(&0x87654321u32.to_le_bytes());
        let sections = [RvaSection {
            virtual_address: 0x5000,
            virtual_size: bytes.len() as u32,
            bytes: &bytes,
        }];
        let chain = parse_unwind_chain(0x5000, &sections, 8).unwrap();
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[1].0, 0x5010);
        assert_eq!(
            chain[1].1.trailer,
            UnwindTrailer::Handler {
                handler_rva: 0x87654321
            }
        );
    }
}
