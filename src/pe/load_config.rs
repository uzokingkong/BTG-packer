//! Typed, bounds-checked parser for `IMAGE_LOAD_CONFIG_DIRECTORY64`.
//!
//! Load-config pointers are virtual addresses (not RVAs).  This module converts
//! them to image-relative ranges only after checking the complete object/table
//! lies inside the mapped image.  It intentionally does not dereference file
//! bytes: callers may use the validated RVAs with their own RVA mapper.

use core::fmt;

const MIN_SIZE: usize = 0x60; // through SecurityCookie
const CFG_SIZE: usize = 0x94; // through GuardFlags
const EH_CONT_SIZE: usize = 0x118; // through GuardEHContinuationCount

/// GuardFlags bits describing extra bytes following each CFG function RVA.
pub const IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK: u32 = 0xF000_0000;
pub const IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT: u32 = 28;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImageRange {
    pub rva: u32,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadConfigError {
    Truncated {
        needed: usize,
        available: usize,
    },
    DeclaredSizeTooSmall(u32),
    DeclaredSizeExceedsDirectory {
        declared: u32,
        available: usize,
    },
    AddressBelowImage {
        field: &'static str,
        va: u64,
    },
    RangeOutsideImage {
        field: &'static str,
        rva: u64,
        size: u64,
    },
    CountWithoutTable {
        field: &'static str,
        count: u64,
    },
    SizeOverflow {
        field: &'static str,
        count: u64,
        entry_size: u64,
    },
}

impl fmt::Display for LoadConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid PE32+ load-config: {self:?}")
    }
}

impl std::error::Error for LoadConfigError {}

/// Executable/code-bearing pointers consumed by Windows mitigations.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LoadConfigCodePointers {
    pub guard_cf_check: Option<u32>,
    pub guard_cf_dispatch: Option<u32>,
    pub guard_rf_failure_routine: Option<u32>,
    pub guard_rf_failure_routine_function: Option<u32>,
    pub guard_rf_verify_stack_pointer: Option<u32>,
    pub guard_xfg_check: Option<u32>,
    pub guard_xfg_dispatch: Option<u32>,
    pub guard_xfg_table_dispatch: Option<u32>,
    pub cast_guard_failure_mode: Option<u32>,
    pub guard_memcpy: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadConfig64 {
    pub size: u32,
    pub security_cookie: Option<u32>,
    pub guard_cf_function_table: Option<ImageRange>,
    pub guard_cf_function_count: u64,
    pub guard_cf_entry_size: u8,
    pub guard_eh_continuation_table: Option<ImageRange>,
    pub guard_eh_continuation_count: u64,
    pub guard_flags: u32,
    pub code: LoadConfigCodePointers,
}

impl LoadConfig64 {
    /// Parse a PE32+ load-config directory from its file-backed bytes.
    ///
    /// `directory` must contain the whole data-directory extent; `image_base`
    /// and `size_of_image` describe the mapped image used to validate all VAs.
    pub fn parse(
        directory: &[u8],
        image_base: u64,
        size_of_image: u32,
    ) -> Result<Self, LoadConfigError> {
        if directory.len() < 4 {
            return Err(LoadConfigError::Truncated {
                needed: 4,
                available: directory.len(),
            });
        }
        let size = u32_at(directory, 0) as usize;
        if size < MIN_SIZE {
            return Err(LoadConfigError::DeclaredSizeTooSmall(size as u32));
        }
        if size > directory.len() {
            return Err(LoadConfigError::DeclaredSizeExceedsDirectory {
                declared: size as u32,
                available: directory.len(),
            });
        }
        let data = &directory[..size];
        let cookie_va = u64_at(data, 0x58);
        let security_cookie =
            optional_object_rva("SecurityCookie", cookie_va, 8, image_base, size_of_image)?;

        let mut result = Self {
            size: size as u32,
            security_cookie,
            guard_cf_function_table: None,
            guard_cf_function_count: 0,
            guard_cf_entry_size: 4,
            guard_eh_continuation_table: None,
            guard_eh_continuation_count: 0,
            guard_flags: 0,
            code: LoadConfigCodePointers::default(),
        };

        if size >= CFG_SIZE {
            result.guard_flags = u32_at(data, 0x90);
            let extra = ((result.guard_flags & IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK)
                >> IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT) as u8;
            result.guard_cf_entry_size = 4 + extra;
            result.guard_cf_function_count = u64_at(data, 0x88);
            result.guard_cf_function_table = optional_table(
                "GuardCFFunctionTable",
                u64_at(data, 0x80),
                result.guard_cf_function_count,
                result.guard_cf_entry_size as u64,
                image_base,
                size_of_image,
            )?;
            result.code.guard_cf_check = optional_object_rva(
                "GuardCFCheckFunctionPointer",
                u64_at(data, 0x70),
                8,
                image_base,
                size_of_image,
            )?;
            result.code.guard_cf_dispatch = optional_object_rva(
                "GuardCFDispatchFunctionPointer",
                u64_at(data, 0x78),
                8,
                image_base,
                size_of_image,
            )?;
        }

        // Later SDK revisions are parsed only when the declared structure size
        // reaches the corresponding field. This keeps old, valid structures valid.
        result.code.guard_rf_failure_routine = ptr_if_present(
            data,
            0xD0,
            "GuardRFFailureRoutine",
            image_base,
            size_of_image,
        )?;
        result.code.guard_rf_failure_routine_function = ptr_if_present(
            data,
            0xD8,
            "GuardRFFailureRoutineFunctionPointer",
            image_base,
            size_of_image,
        )?;
        result.code.guard_rf_verify_stack_pointer = ptr_if_present(
            data,
            0xE8,
            "GuardRFVerifyStackPointerFunctionPointer",
            image_base,
            size_of_image,
        )?;

        if size >= EH_CONT_SIZE {
            result.guard_eh_continuation_count = u64_at(data, 0x110);
            result.guard_eh_continuation_table = optional_table(
                "GuardEHContinuationTable",
                u64_at(data, 0x108),
                result.guard_eh_continuation_count,
                4,
                image_base,
                size_of_image,
            )?;
        }
        result.code.guard_xfg_check = ptr_if_present(
            data,
            0x118,
            "GuardXFGCheckFunctionPointer",
            image_base,
            size_of_image,
        )?;
        result.code.guard_xfg_dispatch = ptr_if_present(
            data,
            0x120,
            "GuardXFGDispatchFunctionPointer",
            image_base,
            size_of_image,
        )?;
        result.code.guard_xfg_table_dispatch = ptr_if_present(
            data,
            0x128,
            "GuardXFGTableDispatchFunctionPointer",
            image_base,
            size_of_image,
        )?;
        result.code.cast_guard_failure_mode = ptr_if_present(
            data,
            0x130,
            "CastGuardOsDeterminedFailureMode",
            image_base,
            size_of_image,
        )?;
        result.code.guard_memcpy = ptr_if_present(
            data,
            0x138,
            "GuardMemcpyFunctionPointer",
            image_base,
            size_of_image,
        )?;
        Ok(result)
    }
}

fn u32_at(data: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(data[off..off + 4].try_into().unwrap())
}
fn u64_at(data: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(data[off..off + 8].try_into().unwrap())
}
fn ptr_if_present(
    data: &[u8],
    off: usize,
    field: &'static str,
    base: u64,
    image_size: u32,
) -> Result<Option<u32>, LoadConfigError> {
    if data.len() < off + 8 {
        return Ok(None);
    }
    optional_object_rva(field, u64_at(data, off), 8, base, image_size)
}
fn optional_object_rva(
    field: &'static str,
    va: u64,
    object_size: u64,
    base: u64,
    image_size: u32,
) -> Result<Option<u32>, LoadConfigError> {
    if va == 0 {
        return Ok(None);
    }
    let rva = va
        .checked_sub(base)
        .ok_or(LoadConfigError::AddressBelowImage { field, va })?;
    validate_range(field, rva, object_size, image_size).map(|range| Some(range.rva))
}
fn optional_table(
    field: &'static str,
    va: u64,
    count: u64,
    entry_size: u64,
    base: u64,
    image_size: u32,
) -> Result<Option<ImageRange>, LoadConfigError> {
    if va == 0 {
        return if count == 0 {
            Ok(None)
        } else {
            Err(LoadConfigError::CountWithoutTable { field, count })
        };
    }
    let rva = va
        .checked_sub(base)
        .ok_or(LoadConfigError::AddressBelowImage { field, va })?;
    let bytes = count
        .checked_mul(entry_size)
        .ok_or(LoadConfigError::SizeOverflow {
            field,
            count,
            entry_size,
        })?;
    validate_range(field, rva, bytes, image_size).map(Some)
}
fn validate_range(
    field: &'static str,
    rva: u64,
    size: u64,
    image_size: u32,
) -> Result<ImageRange, LoadConfigError> {
    let end = rva
        .checked_add(size)
        .ok_or(LoadConfigError::RangeOutsideImage { field, rva, size })?;
    if rva > image_size as u64 || end > image_size as u64 {
        return Err(LoadConfigError::RangeOutsideImage { field, rva, size });
    }
    Ok(ImageRange {
        rva: rva as u32,
        size,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    const BASE: u64 = 0x1400_0000_0;
    fn put32(b: &mut [u8], o: usize, v: u32) {
        b[o..o + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn put64(b: &mut [u8], o: usize, v: u64) {
        b[o..o + 8].copy_from_slice(&v.to_le_bytes());
    }
    fn config(size: usize) -> Vec<u8> {
        let mut b = vec![0; size];
        put32(&mut b, 0, size as u32);
        b
    }

    #[test]
    fn parses_cookie_cfg_eh_and_code_pointers() {
        let mut b = config(0x140);
        put64(&mut b, 0x58, BASE + 0x2000);
        put64(&mut b, 0x70, BASE + 0x3000);
        put64(&mut b, 0x78, BASE + 0x3010);
        put64(&mut b, 0x80, BASE + 0x4000);
        put64(&mut b, 0x88, 3);
        put32(&mut b, 0x90, 2 << 28); // 4-byte RVA + 2 metadata bytes
        put64(&mut b, 0x108, BASE + 0x5000);
        put64(&mut b, 0x110, 2);
        put64(&mut b, 0x118, BASE + 0x6000);
        put64(&mut b, 0x138, BASE + 0x7000);
        let p = LoadConfig64::parse(&b, BASE, 0x10_000).unwrap();
        assert_eq!(p.security_cookie, Some(0x2000));
        assert_eq!(p.guard_cf_entry_size, 6);
        assert_eq!(
            p.guard_cf_function_table,
            Some(ImageRange {
                rva: 0x4000,
                size: 18
            })
        );
        assert_eq!(
            p.guard_eh_continuation_table,
            Some(ImageRange {
                rva: 0x5000,
                size: 8
            })
        );
        assert_eq!(p.code.guard_xfg_check, Some(0x6000));
        assert_eq!(p.code.guard_memcpy, Some(0x7000));
    }

    #[test]
    fn rejects_truncation_and_declared_size_mismatch() {
        assert!(matches!(
            LoadConfig64::parse(&[0; 3], BASE, 0x1000),
            Err(LoadConfigError::Truncated { .. })
        ));
        let mut b = config(MIN_SIZE);
        put32(&mut b, 0, (MIN_SIZE + 1) as u32);
        assert!(matches!(
            LoadConfig64::parse(&b, BASE, 0x1000),
            Err(LoadConfigError::DeclaredSizeExceedsDirectory { .. })
        ));
    }

    #[test]
    fn rejects_table_past_image_and_count_without_pointer() {
        let mut b = config(CFG_SIZE);
        put64(&mut b, 0x80, BASE + 0x0ff8);
        put64(&mut b, 0x88, 3);
        assert!(matches!(
            LoadConfig64::parse(&b, BASE, 0x1000),
            Err(LoadConfigError::RangeOutsideImage {
                field: "GuardCFFunctionTable",
                ..
            })
        ));
        put64(&mut b, 0x80, 0);
        assert!(matches!(
            LoadConfig64::parse(&b, BASE, 0x1000),
            Err(LoadConfigError::CountWithoutTable { .. })
        ));
    }

    #[test]
    fn rejects_va_below_image_and_cookie_at_end() {
        let mut b = config(MIN_SIZE);
        put64(&mut b, 0x58, BASE - 1);
        assert!(matches!(
            LoadConfig64::parse(&b, BASE, 0x1000),
            Err(LoadConfigError::AddressBelowImage { .. })
        ));
        put64(&mut b, 0x58, BASE + 0xffc);
        assert!(matches!(
            LoadConfig64::parse(&b, BASE, 0x1000),
            Err(LoadConfigError::RangeOutsideImage {
                field: "SecurityCookie",
                ..
            })
        ));
    }

    #[test]
    fn accepts_legacy_cookie_only_structure() {
        let mut b = config(MIN_SIZE);
        put64(&mut b, 0x58, BASE + 0x100);
        let p = LoadConfig64::parse(&b, BASE, 0x1000).unwrap();
        assert_eq!(p.security_cookie, Some(0x100));
        assert_eq!(p.guard_cf_function_table, None);
    }
}
