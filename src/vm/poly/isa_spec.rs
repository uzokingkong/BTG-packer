// ==============================================================================
// BTG - Commercial-Grade VM: Randomized Virtual ISA Specification
// ==============================================================================
// 빌드마다 고유한 64비트 시드를 기반으로 새로운 가상 CPU ISA를 합성한다.
// Opcode 번호, 피연산자 순서/인코딩, 레지스터 인덱스 순열이 빌드마다 달라져
// 정적 시그니처 분석 및 자동 디컴파일 도구를 완전히 무력화한다.
// ==============================================================================

use crate::vm::risc::RiscOp;
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct VirtualIsaSpec {
    pub seed: u64,
    /// 12개 RiscOp에 매핑되는 무작위 1바이트 Opcode
    pub opcode_map: HashMap<RiscOp, u8>,
    pub reverse_opcode_map: HashMap<u8, RiscOp>,
    /// 피연산자 XOR 마스크
    pub operand_mask: u64,
    /// 가상 레지스터 인덱스 순열 (0~15)
    pub register_permutation: [u8; 16],
    pub reverse_reg_permutation: [u8; 16],
}

impl VirtualIsaSpec {
    pub fn from_seed(seed: u64) -> Self {
        let mut rng = StdRng::seed_from_u64(seed);

        // 1. Generate unique random opcodes for all RiscOps
        let ops = [
            RiscOp::Nor,
            RiscOp::AddWithCarry,
            RiscOp::ShiftRight,
            RiscOp::ShiftLeft,
            RiscOp::VirtualPush,
            RiscOp::VirtualPop,
            RiscOp::MemoryRead { width: 8 },
            RiscOp::MemoryWrite { width: 8 },
            RiscOp::NativeCallBridge,
            RiscOp::SetFlag,
            RiscOp::Halt,
        ];

        let mut used_bytes = std::collections::HashSet::new();
        let mut opcode_map = HashMap::new();
        let mut reverse_opcode_map = HashMap::new();

        for op in ops {
            loop {
                let b = rng.gen::<u8>();
                if !used_bytes.contains(&b) {
                    used_bytes.insert(b);
                    opcode_map.insert(op, b);
                    reverse_opcode_map.insert(b, op);
                    break;
                }
            }
        }

        // 2. Generate random register permutations
        let mut reg_perm: Vec<u8> = (0..16).collect();
        // Fisher-Yates shuffle
        for i in (1..16).rev() {
            let j = rng.gen_range(0..=i);
            reg_perm.swap(i, j);
        }

        let mut register_permutation = [0u8; 16];
        let mut reverse_reg_permutation = [0u8; 16];
        for (i, &v) in reg_perm.iter().enumerate() {
            register_permutation[i] = v;
            reverse_reg_permutation[v as usize] = i as u8;
        }

        let operand_mask = rng.gen::<u64>() | 0x0101010101010101;

        Self {
            seed,
            opcode_map,
            reverse_opcode_map,
            operand_mask,
            register_permutation,
            reverse_reg_permutation,
        }
    }

    #[inline]
    pub fn encode_reg(&self, reg_idx: u8) -> u8 {
        self.register_permutation[(reg_idx & 0x0F) as usize]
    }

    #[inline]
    pub fn decode_reg(&self, enc_reg: u8) -> u8 {
        self.reverse_reg_permutation[(enc_reg & 0x0F) as usize]
    }
}
