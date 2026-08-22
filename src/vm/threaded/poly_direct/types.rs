use crate::vm::risc::RiscOp;
use anyhow::{anyhow, Result};

/// Build-time description of an unresolved branch that must enter another
/// independently built commercial VM module instead of native code.
#[derive(Debug, Clone)]
pub struct NativeCrossFamilyRoute {
    pub target_va: u64,
    pub target_entry_va: u64,
    pub target_state_va: u64,
    pub target_byte_offset: u64,
    pub target_layout: crate::vm::threaded::VmRuntimeLayout,
    pub tail_jump_resume_offset: Option<u64>,
}

/// P2 (G3): 폭별 ALU 네이티브 핸들러 종류 (Add/SubWithBorrow/Inc/Dec/Not).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WidthAluOp {
    Add,
    Sub,
    Adc,
    Sbb,
    Inc,
    Dec,
    Not,
}

/// R4: SSE/FPU 스칼라 unary 변환 핸들러 종류 (IntToFloat/FloatToInt/FloatToFloat).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FloatCvtMode {
    IntToFloat,
    FloatToInt,
    FloatToFloat,
}

/// P3 (G1): assembled self-decoding dispatcher pieces (machine code + tables).
pub struct SelfDecodingParts {
    pub code: Vec<u8>,
    /// Machine-code byte range of the VM→native call bridge. Exceptions whose
    /// return RIP lands here require the bridge's private stack allocation in
    /// addition to the module-entry nonvolatile saves.
    pub native_bridge_range: Option<(usize, usize)>,
    /// Language-specific x64 unwind handler which re-encrypts and releases
    /// call-scoped lifetime objects owned by the unwinding OS thread.
    pub lifetime_cleanup_handler_offset: Option<usize>,
    /// 256 x u64 handler table (decrypted opcode byte -> handler VA).
    pub table: Vec<u64>,
    /// P6-1: handler 테이블 마스터 키 (시드 유래). P6-3 부터 단일 XOR 상수가 아니라
    /// per-opcode 파생 키 `key(op) = (op*C1) ^ (op<<17) ^ master` 의 마스터로 쓰인다
    /// (dispatch 가 opcode byte 로 파생 키를 다시 계산해 `table[op] ^ key(op)` 로
    /// 복호화). 마스터 K 자체는 평문 상수로 코드에 없고 MBA(a,b)로 런타임 유도된다 —
    /// 평문 테이블/덤프로부터 opcode↔handler 매핑 복원을 막는다.
    pub table_key: u64,
    /// P6-3: 테이블 무결성 셀프체크 값 (빌드 시 암호화된 256 항목 checksum). 엔트리
    /// 스텁이 매 VM 진입마다 재계산해 비교하며, 변조/복원된 테이블은 ud2로 실패한다.
    pub table_checksum: u64,
    /// Family-specific traversal grammar used by the entry integrity anchor.
    pub table_integrity_topology: super::checksum::TableIntegrityTopology,
    /// 256 x u8 operand-offset table (operand-encoding -> state offset).
    pub offs_tab: Vec<u16>,
    /// 256 x u8 operand-kind table (0=reg/temp/vsp/flags, 1=imm, 2=none).
    pub flags_tab: Vec<u8>,
    /// 256 x u8 cond-code table (decrypted cond byte -> canonical COND_* code, 0xFF invalid).
    pub cond_codes: Vec<u8>,
    /// Branch-resolution table (u32 count + count x (encoded target, encoded byte offset)),
    /// embedded at `layout.branch_map_off` relative to `table_va`. The VirtualBranch handler scans it
    /// to map a target (source-IP via ip_map, or direct micro-op index) to a bytecode
    /// byte offset for the rolling-key re-sync.
    pub branch_map: Vec<u8>,
    /// Build-only validation/decode keys mirrored by immediates in generated code.
    pub branch_target_key: u64,
    pub branch_offset_key: u64,
    /// Per-build relative placement of every metadata table used by `code`.
    pub layout: crate::vm::table_layout::TableLayout,
    /// State-buffer ABI consumed by every generated handler and bridge.
    pub runtime_layout: crate::vm::threaded::VmRuntimeLayout,
    /// Actual build-selected dispatch control-flow topology.
    pub dispatcher_plan: crate::vm::dispatch_perm::DispatcherPlan,
    /// P2-9 native chunk descriptor lookup grammar selected for this build.
    pub chunk_lookup_topology: crate::vm::chunk_crypto::ChunkLookupTopology,
}

impl SelfDecodingParts {
    /// Production build gate for the native commercial runtime.  This checks
    /// structural invariants that otherwise turn generator drift into a packed
    /// executable which crashes only after launch.
    pub fn validate(&self, code_base: u64, bytecode_len: usize) -> Result<()> {
        use super::checksum::{per_op_key, table_checksum_with_topology};

        if self.code.is_empty() {
            return Err(anyhow!("commercial VM emitted empty code"));
        }
        if self.table.len() != 256
            || self.offs_tab.len() != 256
            || self.flags_tab.len() != 256
            || self.cond_codes.len() != 256
        {
            return Err(anyhow!(
                "commercial VM metadata cardinality drift: table={} offs={} flags={} cond={}",
                self.table.len(),
                self.offs_tab.len(),
                self.flags_tab.len(),
                self.cond_codes.len()
            ));
        }
        if table_checksum_with_topology(&self.table, self.table_integrity_topology)
            != self.table_checksum
        {
            return Err(anyhow!("commercial VM handler-table checksum mismatch"));
        }

        let code_end = code_base
            .checked_add(self.code.len() as u64)
            .ok_or_else(|| anyhow!("commercial VM code address overflow"))?;
        for (op, encrypted) in self.table.iter().copied().enumerate() {
            let target = encrypted ^ per_op_key(self.table_key, op as u8);
            if !(code_base..code_end).contains(&target) {
                return Err(anyhow!(
                    "commercial VM handler {op:#04x} resolves outside code: {target:#x} not in {code_base:#x}..{code_end:#x}"
                ));
            }
        }

        let l = self.layout;
        if l.handler_table_off
            .checked_add(2048)
            .is_none_or(|v| v > l.operand_offs_off)
            || l.operand_offs_off
                .checked_add(512)
                .is_none_or(|v| v > l.operand_flags_off)
            || l.operand_flags_off
                .checked_add(256)
                .is_none_or(|v| v > l.cond_codes_off)
            || l.cond_codes_off
                .checked_add(256)
                .is_none_or(|v| v > l.branch_map_off)
        {
            return Err(anyhow!("commercial VM metadata layout overlaps"));
        }

        if self.branch_map.len() < 4 {
            return Err(anyhow!("commercial VM branch map is truncated"));
        }
        for (raw, (&offset, &kind)) in self.offs_tab.iter().zip(&self.flags_tab).enumerate() {
            if kind == super::K_REG
                && (offset as usize % 8 != 0
                    || offset as usize + 8 > self.runtime_layout.total_size)
            {
                return Err(anyhow!(
                    "commercial VM operand {raw:#04x} has invalid split-state offset {offset:#x}"
                ));
            }
        }
        let count = u32::from_le_bytes(self.branch_map[0..4].try_into().unwrap()) as usize;
        let expected = 4usize
            .checked_add(
                count
                    .checked_mul(16)
                    .ok_or_else(|| anyhow!("branch-map count overflow"))?,
            )
            .ok_or_else(|| anyhow!("branch-map size overflow"))?;
        if self.branch_map.len() != expected {
            return Err(anyhow!(
                "commercial VM branch-map length mismatch: count={count} len={} expected={expected}",
                self.branch_map.len()
            ));
        }
        for i in 0..count {
            let p = 4 + i * 16 + 8;
            let target_p = 4 + i * 16;
            let encoded_target =
                u64::from_le_bytes(self.branch_map[target_p..target_p + 8].try_into().unwrap());
            let encoded_offset = u64::from_le_bytes(self.branch_map[p..p + 8].try_into().unwrap());
            let _target = encoded_target ^ self.branch_target_key;
            let offset = encoded_offset ^ self.branch_offset_key;
            if offset as usize >= bytecode_len {
                return Err(anyhow!(
                    "commercial VM branch-map entry {i} has out-of-range bytecode offset {offset:#x} (len={bytecode_len:#x})"
                ));
            }
        }
        Ok(())
    }
}
