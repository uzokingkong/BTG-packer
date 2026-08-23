use super::codegen_util::{C1, C4};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TableIntegrityTopology {
    ForwardSingle,
    ReverseSingle,
    ForwardPair,
    ReversePair,
}

impl TableIntegrityTopology {
    pub fn for_family(family: crate::vm::poly::VmArchitectureFamily) -> Self {
        use crate::vm::poly::VmArchitectureFamily::*;
        match family {
            Stack => Self::ForwardSingle,
            Register => Self::ReverseSingle,
            MixedRisc => Self::ForwardPair,
            FusedCisc => Self::ReversePair,
        }
    }
}

/// P6-3: opcode byte 별 파생 테이블 키 — `key(op) = (op*C1) ^ (op<<17) ^ C4 ^ master`.
/// dispatch loop 가 이 파생식을 재현해 `table[op] ^ key(op)` 로 handler VA 를
/// 복호화한다. 단일 XOR 상수(master)로는 256개 항목을 일괄 복호화할 수 없다 —
/// 항목마다 opcode byte 에 의존하는 서로 다른 키를 쓴다 (Themida식 테이블
/// 재구성 방지). C4 상수를 섞어 opcode 0 의 키도 master 와 같아지지 않게 한다
/// (master 단독 XOR 로 특정 항목이 복호화되는 것을 방지). master 는 MBA(a,b)로
/// 런타임 유도되므로 평문 상수로 노출되지 않는다.
pub(crate) fn per_op_key(master: u64, op: u8) -> u64 {
    (op as u64).wrapping_mul(C1) ^ ((op as u64) << 17) ^ C4 ^ master
}

/// P6-3: 암호화된 256개 handler 테이블 항목의 무결성 checksum.
/// 엔트리 스텁이 매 VM 진입마다 재계산해 빌드 시 값(`parts.table_checksum`)과
/// 비교한다 — 테이블이 패치/복원되면 ud2로 즉시 실패 (anti-tamper / 복원 감지).
pub(crate) fn table_checksum(table: &[u64]) -> u64 {
    table_checksum_with_topology(table, TableIntegrityTopology::ForwardSingle)
}

pub(crate) fn table_checksum_with_topology(table: &[u64], topology: TableIntegrityTopology) -> u64 {
    fn fold<'a>(values: impl Iterator<Item = &'a u64>) -> u64 {
        let mut h: u64 = 0x811C9DC5;
        for &v in values {
            h = h.wrapping_add(v).wrapping_mul(0x0100_0000_01B3);
            h ^= h >> 33;
            h = h.wrapping_mul(0xFF51_AFD7_ED55_8CCD);
        }
        h
    }
    match topology {
        TableIntegrityTopology::ForwardSingle | TableIntegrityTopology::ForwardPair => {
            fold(table.iter())
        }
        TableIntegrityTopology::ReverseSingle | TableIntegrityTopology::ReversePair => {
            fold(table.iter().rev())
        }
    }
}
