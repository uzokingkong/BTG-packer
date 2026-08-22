// ==============================================================================
// BTG - Commercial-Grade VM: Randomized Virtual ISA Specification
// ==============================================================================
// 빌드마다 고유한 64비트 시드를 기반으로 새로운 가상 CPU ISA를 합성한다.
// Opcode 번호, 피연산자 순서/인코딩, 레지스터 인덱스 순열이 빌드마다 달라져
// 정적 시그니처 분석 및 자동 디컴파일 도구를 완전히 무력화한다.
// ==============================================================================

use super::architecture_family::{family_isa_seed, VmArchitectureFamily, VmFamilyProfile};
use crate::vm::risc::{BranchCondition, RiscOp};
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct VirtualIsaSpec {
    pub seed: u64,
    /// Architecture family is part of the ISA identity, not merely metadata.
    /// Its domain separator changes every generated opcode/register/condition map.
    pub family: VmArchitectureFamily,
    pub family_profile: VmFamilyProfile,
    /// 전체 도달 가능한 RiscOp 집합에 매핑되는 무작위 1바이트 Opcode.
    /// 메모리 폭(MemoryRead/MemoryWrite)은 폭별로 서로 다른 Opcode를 갖고,
    /// VirtualBranch 는 조건과 무관한 단일 Opcode 를 갖는다(조건은 `branch_cond_map`).
    pub opcode_map: HashMap<RiscOp, u8>,
    pub reverse_opcode_map: HashMap<u8, RiscOp>,
    /// VirtualBranch 조건 부호화 맵 (모든 BranchCondition, CounterZero 폭 포함).
    pub branch_cond_map: HashMap<BranchCondition, u8>,
    pub reverse_branch_cond_map: HashMap<u8, BranchCondition>,
    /// 피연산자 XOR 마스크
    pub operand_mask: u64,
    /// 가상 레지스터 인덱스 순열 (0~15)
    pub register_permutation: [u8; 16],
    pub reverse_reg_permutation: [u8; 16],
}

/// 메모리 접근 폭 (1, 2, 4, 8 바이트).
const MEMORY_WIDTHS: [u8; 4] = [1, 2, 4, 8];
/// 카운터 기반 분기 폭 (Jcxz=2, Jecxz=4, Jrcxz=8).
const COUNTER_WIDTHS: [u8; 3] = [2, 4, 8];

impl VirtualIsaSpec {
    /// Family-local compact-immediate marker order for widths 1/2/4/8.
    /// All markers stay in the otherwise-unused scalar descriptor range.
    pub fn immediate_markers(&self) -> [u8; 4] {
        match self.family {
            VmArchitectureFamily::Stack => [0x01, 0x02, 0x03, 0x04],
            VmArchitectureFamily::Register => [0x03, 0x01, 0x04, 0x02],
            VmArchitectureFamily::MixedRisc => [0x04, 0x03, 0x02, 0x01],
            VmArchitectureFamily::FusedCisc => [0x02, 0x04, 0x01, 0x03],
        }
    }

    pub fn signed_immediate_markers(&self) -> [u8; 4] {
        self.immediate_markers().map(|marker| marker + 4)
    }

    pub fn immediate_width_for_value(value: u64) -> usize {
        if value <= u8::MAX as u64 {
            1
        } else if value <= u16::MAX as u64 {
            2
        } else if value <= u32::MAX as u64 {
            4
        } else {
            8
        }
    }

    pub fn immediate_marker(&self, width: usize) -> u8 {
        let index = match width {
            1 => 0,
            2 => 1,
            4 => 2,
            8 => 3,
            _ => unreachable!(),
        };
        self.immediate_markers()[index]
    }

    pub fn signed_immediate_width_for_value(value: u64) -> Option<usize> {
        let signed = value as i64;
        if signed == signed as i8 as i64 {
            Some(1)
        } else if signed == signed as i16 as i64 {
            Some(2)
        } else if signed == signed as i32 as i64 {
            Some(4)
        } else {
            None
        }
    }

    /// Returns marker, payload width and whether decode must sign-extend.
    pub fn immediate_encoding(&self, value: u64) -> (u8, usize, bool) {
        let unsigned_width = Self::immediate_width_for_value(value);
        if let Some(signed_width) = Self::signed_immediate_width_for_value(value) {
            if signed_width < unsigned_width {
                let index = match signed_width {
                    1 => 0,
                    2 => 1,
                    4 => 2,
                    _ => unreachable!(),
                };
                return (self.signed_immediate_markers()[index], signed_width, true);
            }
        }
        (self.immediate_marker(unsigned_width), unsigned_width, false)
    }

    pub fn immediate_width(&self, marker: u8) -> Option<usize> {
        self.immediate_markers()
            .iter()
            .position(|&candidate| candidate == marker)
            .map(|index| [1, 2, 4, 8][index])
            .or_else(|| {
                self.signed_immediate_markers()
                    .iter()
                    .position(|&candidate| candidate == marker)
                    .map(|index| [1, 2, 4, 8][index])
            })
    }

    pub fn is_signed_immediate_marker(&self, marker: u8) -> bool {
        self.signed_immediate_markers().contains(&marker)
    }

    pub fn decode_immediate_payload(&self, marker: u8, payload: u64) -> u64 {
        let width = self.immediate_width(marker).unwrap_or(8);
        let bits = width * 8;
        let decoded = payload
            ^ if width == 8 {
                self.operand_mask
            } else {
                self.operand_mask & ((1u64 << bits) - 1)
            };
        if self.is_signed_immediate_marker(marker) && width < 8 {
            (((decoded << (64 - bits)) as i64) >> (64 - bits)) as u64
        } else {
            decoded
        }
    }

    pub fn is_immediate_marker(&self, marker: u8) -> bool {
        self.immediate_width(marker).is_some()
    }

    /// Physical order of the three operand descriptor bytes. The returned
    /// values are logical slots: 0=dst, 1=src1, 2=src2.
    pub fn operand_order(&self) -> [usize; 3] {
        match self.family {
            VmArchitectureFamily::Stack => [0, 1, 2],
            VmArchitectureFamily::Register => [1, 2, 0],
            VmArchitectureFamily::MixedRisc => [2, 0, 1],
            VmArchitectureFamily::FusedCisc => [1, 0, 2],
        }
    }

    pub fn branch_target_key(&self) -> u64 {
        self.operand_mask.rotate_left(11) ^ self.family_profile.isa_domain ^ 0xB7E1_5162_8AED_2A6B
    }

    /// Family-local representation of an absolute branch instruction index.
    pub fn encode_branch_target(&self, target: u64) -> u64 {
        let key = self.branch_target_key();
        match self.family {
            VmArchitectureFamily::Stack => target,
            VmArchitectureFamily::Register => target.rotate_left(17) ^ key,
            VmArchitectureFamily::MixedRisc => target.swap_bytes() ^ key,
            VmArchitectureFamily::FusedCisc => target.wrapping_add(key).rotate_left(29),
        }
    }

    pub fn decode_branch_target(&self, encoded: u64) -> u64 {
        let key = self.branch_target_key();
        match self.family {
            VmArchitectureFamily::Stack => encoded,
            VmArchitectureFamily::Register => (encoded ^ key).rotate_right(17),
            VmArchitectureFamily::MixedRisc => (encoded ^ key).swap_bytes(),
            VmArchitectureFamily::FusedCisc => encoded.rotate_right(29).wrapping_sub(key),
        }
    }

    pub fn from_seed(seed: u64) -> Self {
        Self::from_seed_and_family(seed, VmArchitectureFamily::for_build(seed))
    }

    pub fn from_seed_and_family(seed: u64, family: VmArchitectureFamily) -> Self {
        let mut rng = StdRng::seed_from_u64(family_isa_seed(seed, family));

        // 1. Generate unique random opcodes for the ENTIRE reachable RiscOp set.
        //    기존 11개 매핑(Nor/AddWithCarry/ShiftRight/ShiftLeft/VirtualPush/
        //    VirtualPop/MemoryRead{8}/MemoryWrite{8}/NativeCallBridge/SetFlag/Halt)
        //    은 그대로 유지하고, 누락된 ArithmeticShiftRight · VirtualBranch ·
        //    MemoryRead/Write{1,2,4} 를 폭별로 추가해 전체 집합을 커버한다.
        let mut ops: Vec<RiscOp> = Vec::new();
        ops.push(RiscOp::Nor);
        ops.push(RiscOp::AddWithCarry);
        ops.push(RiscOp::ShiftRight);
        ops.push(RiscOp::ArithmeticShiftRight);
        for w in [1u8, 2, 4, 8] {
            ops.push(RiscOp::RotateLeft { width: w });
        }
        ops.push(RiscOp::ShiftLeft);
        ops.push(RiscOp::VirtualPush);
        ops.push(RiscOp::VirtualPop);
        // 메모리 폭별로 서로 다른 Opcode (1, 2, 4, 8)
        for w in MEMORY_WIDTHS {
            ops.push(RiscOp::MemoryRead { width: w });
        }
        for w in MEMORY_WIDTHS {
            ops.push(RiscOp::MemoryWrite { width: w });
        }
        // VirtualBranch: 조건은 별도 부호화 — Opcode 는 단일 항목.
        ops.push(RiscOp::VirtualBranch {
            cond: BranchCondition::Always,
        });
        ops.push(RiscOp::NativeCallBridge);
        ops.push(RiscOp::SetFlag);
        ops.push(RiscOp::Halt);
        ops.push(RiscOp::Trap);
        ops.push(RiscOp::VirtualRet);
        ops.push(RiscOp::Mov);
        // P2: 정수/비트/제어 복합 연산 — 부호/폭/모드별로 별도 Opcode.
        // (signed/width/mode 는 variant 에 Bake — 각각 유일 Opcode.)
        for signed in [false, true] {
            for w in [1u8, 2, 4, 8] {
                ops.push(RiscOp::Multiply { signed, width: w });
            }
        }
        for signed in [false, true] {
            for w in [2u8, 4, 8] {
                ops.push(RiscOp::MultiplyLow { signed, width: w });
            }
        }
        for signed in [false, true] {
            for w in [1u8, 2, 4, 8] {
                ops.push(RiscOp::Divide { signed, width: w });
            }
        }
        for w in [4u8, 8] {
            ops.push(RiscOp::BSwap { width: w });
        }
        ops.push(RiscOp::BitScanForward);
        ops.push(RiscOp::BitScanReverse);
        for w in [2u8, 4, 8] {
            ops.push(RiscOp::CountTrailingZeros { width: w });
        }
        for w in [2u8, 4, 8] {
            ops.push(RiscOp::CountLeadingZeros { width: w });
        }
        ops.push(RiscOp::PopCount);
        // Setcc/ConditionalMove — 조건은 branch_cond_map 으로 별도 부호화, 단일 Opcode.
        ops.push(RiscOp::Setcc {
            cond: BranchCondition::Always,
        });
        ops.push(RiscOp::ConditionalMove {
            cond: BranchCondition::Always,
        });
        for w in [1u8, 2, 4, 8] {
            ops.push(RiscOp::CompareExchange { width: w });
            ops.push(RiscOp::AtomicExchange { width: w });
            ops.push(RiscOp::AtomicAdd { width: w });
        }
        // P0-1: x86 정확 플래그 전용 산술 op (ADD/SUB borrow-CF, INC/DEC CF 보존, NOT 무변경).
        for w in [1u8, 2, 4, 8] {
            ops.push(RiscOp::Add { width: w });
            ops.push(RiscOp::SubWithBorrow { width: w });
            ops.push(RiscOp::Adc { width: w });
            ops.push(RiscOp::Sbb { width: w });
            ops.push(RiscOp::Inc { width: w });
            ops.push(RiscOp::Dec { width: w });
            ops.push(RiscOp::Not { width: w });
        }
        // P1: legacy 128-bit packed SSE. Width/lane metadata is part of the
        // opcode identity so native dispatch cannot confuse differently sized
        // lane operations after opcode randomization.
        ops.push(RiscOp::PackedMove);
        for (elem_width, lanes) in [(1u8, 16u8), (2, 8), (4, 4), (8, 2)] {
            ops.push(RiscOp::PackedAdd { elem_width, lanes });
            ops.push(RiscOp::PackedSub { elem_width, lanes });
            ops.push(RiscOp::PackedCmpEq { elem_width, lanes });
            ops.push(RiscOp::PackedCmpGt { elem_width, lanes });
        }
        ops.push(RiscOp::PackedXor);
        ops.push(RiscOp::PackedAnd);
        ops.push(RiscOp::PackedOr);
        ops.push(RiscOp::PackedAndNot);
        for elem_width in [1u8, 2, 4, 8] {
            ops.push(RiscOp::PackedUnpack {
                elem_width,
                high: false,
            });
            ops.push(RiscOp::PackedUnpack {
                elem_width,
                high: true,
            });
        }
        ops.push(RiscOp::PackedShiftRightQ);
        ops.push(RiscOp::PackedShuffle { low_words: false });
        ops.push(RiscOp::PackedShuffle { low_words: true });
        for width in [2u8, 4, 8] {
            ops.push(RiscOp::DoubleShiftLeft { width });
        }
        for width in [4u8, 8] {
            for modify in [0u8, 1, 2] {
                ops.push(RiscOp::BitTest {
                    width,
                    modify,
                    memory: false,
                });
                ops.push(RiscOp::BitTest {
                    width,
                    modify,
                    memory: true,
                });
            }
        }
        ops.push(RiscOp::PackedMovMaskBytes);
        ops.push(RiscOp::PackedMovMaskPs);
        ops.push(RiscOp::PackedInsertWord);
        ops.push(RiscOp::CpuId);
        ops.push(RiscOp::XGetBv);
        ops.push(RiscOp::ReadSegmentBase { gs: false });
        ops.push(RiscOp::ReadSegmentBase { gs: true });
        // R4: SSE/FPU 스칼라 — FloatAdd/Sub/Mul/Div{4,8} + IntToFloat/FloatToInt/
        // FloatToFloat (모든 reachable src/dst_bits·truncate 조합). 이전에는 isa_spec
        // 미포함 → `is_encodable`=false → `--vm-commercial`이 FP 포함 함수를 통째로
        // 네이티브 유지했다. 여기서 폴리 인코딩 가능하게 만들어 `eval_state`(참조)와
        // 폴리 인터프리터·네이티브 self-decoding 러너가 동치 실행하도록 한다.
        for w in [4u8, 8] {
            ops.push(RiscOp::FloatAdd { width: w });
            ops.push(RiscOp::FloatSub { width: w });
            ops.push(RiscOp::FloatMul { width: w });
            ops.push(RiscOp::FloatDiv { width: w });
        }
        for sb in [4u8, 8] {
            for db in [4u8, 8] {
                ops.push(RiscOp::IntToFloat {
                    src_bits: sb,
                    dst_bits: db,
                });
                ops.push(RiscOp::FloatToFloat {
                    src_bits: sb,
                    dst_bits: db,
                });
                for t in [false, true] {
                    ops.push(RiscOp::FloatToInt {
                        src_bits: sb,
                        dst_bits: db,
                        truncate: t,
                    });
                }
            }
        }
        // F1: 네이티브 브릿지 FP 리턴 힌트 (0=정수/무시, 4=f32, 8=f64).
        ops.push(RiscOp::SetNativeFpReturn { width: 0 });
        ops.push(RiscOp::SetNativeFpReturn { width: 4 });
        ops.push(RiscOp::SetNativeFpReturn { width: 8 });

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

        // 1b. Generate unique random bytes for every BranchCondition.
        //     VirtualBranch 의 조건은 Opcode 와 분리되어 `branch_cond_map`으로
        //     부호화한다 — Always..NotParity 전 19종 + CounterZero 폭(2/4/8) 3종.
        let mut conds: Vec<BranchCondition> = vec![
            BranchCondition::Always,
            BranchCondition::Zero,
            BranchCondition::NotZero,
            BranchCondition::Carry,
            BranchCondition::NotCarry,
            BranchCondition::Sign,
            BranchCondition::NotSign,
            BranchCondition::Overflow,
            BranchCondition::NotOverflow,
            BranchCondition::Greater,
            BranchCondition::Less,
            BranchCondition::GreaterOrEqual,
            BranchCondition::LessOrEqual,
            BranchCondition::Above,
            BranchCondition::AboveOrEqual,
            BranchCondition::Below,
            BranchCondition::BelowOrEqual,
            BranchCondition::Parity,
            BranchCondition::NotParity,
        ];
        for w in COUNTER_WIDTHS {
            conds.push(BranchCondition::CounterZero(w));
        }

        let mut used_cond_bytes = std::collections::HashSet::new();
        let mut branch_cond_map = HashMap::new();
        let mut reverse_branch_cond_map = HashMap::new();
        for cond in conds {
            loop {
                let b = rng.gen::<u8>();
                if !used_cond_bytes.contains(&b) {
                    used_cond_bytes.insert(b);
                    branch_cond_map.insert(cond, b);
                    reverse_branch_cond_map.insert(b, cond);
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
            family,
            family_profile: family.profile(),
            opcode_map,
            reverse_opcode_map,
            branch_cond_map,
            reverse_branch_cond_map,
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

    /// VirtualBranch 조건 부호화 — 모든 BranchCondition(포함 CounterZero 폭)을 1바이트로.
    #[inline]
    pub fn encode_cond(&self, cond: BranchCondition) -> u8 {
        self.branch_cond_map[&cond]
    }

    /// VirtualBranch 조건 복호화 — 알 수 없는 바이트면 `None`.
    #[inline]
    pub fn decode_cond(&self, byte: u8) -> Option<BranchCondition> {
        self.reverse_branch_cond_map.get(&byte).copied()
    }

    /// Opcode 조회 — VirtualBranch/Setcc/ConditionalMove 는 조건과 무관한 단일
    /// Opcode 를 공유하므로 어떤 조건이든 canonical(Always) 항목으로 정규화해 찾는다.
    #[inline]
    pub fn opcode_for(&self, op: RiscOp) -> Option<u8> {
        let canonical = match op {
            RiscOp::VirtualBranch { .. } => RiscOp::VirtualBranch {
                cond: BranchCondition::Always,
            },
            RiscOp::Setcc { .. } => RiscOp::Setcc {
                cond: BranchCondition::Always,
            },
            RiscOp::ConditionalMove { .. } => RiscOp::ConditionalMove {
                cond: BranchCondition::Always,
            },
            other => other,
        };
        self.opcode_map.get(&canonical).copied()
    }

    /// 폴리 인코딩 가능한 opcode 인지 — **시드 무관** (opcode 바이트는 시드 의존이지만
    /// opcode **집합**은 고정이다). `opcode_for`와 동일하게 VirtualBranch/Setcc/
    /// ConditionalMove 조건은 canonicalize 한다.
    ///
    /// 상용(`--vm-commercial`) 리프트가 RISC 로는 lift 되지만 폴리 ISA 에 없는
    /// op(Float 스칼라 등)를 조기 감지해 해당 함수를 네이티브로 유지하는 데 쓴다.
    /// (폴리 인터프리터/네이티브 러너가 Float 를 아직 실행하지 않으므로, 인코딩만
    /// 추가하면 참조와 불일치 — 제외가 올바른 경로.)
    pub fn is_encodable(op: RiscOp) -> bool {
        use std::sync::OnceLock;
        static SPEC: OnceLock<VirtualIsaSpec> = OnceLock::new();
        SPEC.get_or_init(|| VirtualIsaSpec::from_seed(0))
            .opcode_for(op)
            .is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opcode_map_covers_entire_reachable_set() {
        let spec = VirtualIsaSpec::from_seed(0xDEADBEEF_CAFE_1234);

        // 메모리 폭별 별도 Opcode 존재
        for w in MEMORY_WIDTHS {
            let rd = spec.opcode_for(RiscOp::MemoryRead { width: w });
            let wr = spec.opcode_for(RiscOp::MemoryWrite { width: w });
            assert!(rd.is_some(), "MemoryRead{{{w}}} must be mapped");
            assert!(wr.is_some(), "MemoryWrite{{{w}}} must be mapped");
        }

        // 산술 시프트 · 브랜치 · 네이티브 콜 브리지 존재
        assert!(spec.opcode_for(RiscOp::ArithmeticShiftRight).is_some());
        assert!(spec
            .opcode_for(RiscOp::VirtualBranch {
                cond: BranchCondition::Always
            })
            .is_some());
        assert!(spec.opcode_for(RiscOp::NativeCallBridge).is_some());

        // 메모리 폭별 Opcode 가 서로 다르고, VirtualBranch 조건과 무관하게 일관됨
        let mut mem_opcodes = std::collections::HashSet::new();
        for w in MEMORY_WIDTHS {
            let rd = spec.opcode_for(RiscOp::MemoryRead { width: w }).unwrap();
            let wr = spec.opcode_for(RiscOp::MemoryWrite { width: w }).unwrap();
            assert!(mem_opcodes.insert(rd), "MemoryRead opcode collision");
            assert!(mem_opcodes.insert(wr), "MemoryWrite opcode collision");
        }
        let vb1 = spec
            .opcode_for(RiscOp::VirtualBranch {
                cond: BranchCondition::Always,
            })
            .unwrap();
        let vb2 = spec
            .opcode_for(RiscOp::VirtualBranch {
                cond: BranchCondition::Zero,
            })
            .unwrap();
        assert_eq!(vb1, vb2, "VirtualBranch cond must share one opcode");
    }

    #[test]
    fn test_opcode_bytes_unique_no_collisions() {
        let spec = VirtualIsaSpec::from_seed(0x1234_5678_9ABC_DEF0);
        // forward + reverse map consistency, 전부 유일한 바이트
        assert_eq!(spec.opcode_map.len(), spec.reverse_opcode_map.len());
        let mut bytes: Vec<u8> = spec.opcode_map.values().copied().collect();
        bytes.sort_unstable();
        bytes.dedup();
        assert_eq!(bytes.len(), spec.opcode_map.len(), "opcode collision!");
        for (op, &b) in &spec.opcode_map {
            assert_eq!(spec.reverse_opcode_map.get(&b), Some(op));
        }
    }

    #[test]
    fn test_branch_condition_encode_decode_all() {
        let spec = VirtualIsaSpec::from_seed(0x0FF1CE);

        // 모든 조건 (CounterZero 폭 2/4/8 포함) 이 부호화/복호화 가능하고 유일해야 한다.
        let mut conds: Vec<BranchCondition> = vec![
            BranchCondition::Always,
            BranchCondition::Zero,
            BranchCondition::NotZero,
            BranchCondition::Carry,
            BranchCondition::NotCarry,
            BranchCondition::Sign,
            BranchCondition::NotSign,
            BranchCondition::Overflow,
            BranchCondition::NotOverflow,
            BranchCondition::Greater,
            BranchCondition::Less,
            BranchCondition::GreaterOrEqual,
            BranchCondition::LessOrEqual,
            BranchCondition::Above,
            BranchCondition::AboveOrEqual,
            BranchCondition::Below,
            BranchCondition::BelowOrEqual,
            BranchCondition::Parity,
            BranchCondition::NotParity,
        ];
        for w in COUNTER_WIDTHS {
            conds.push(BranchCondition::CounterZero(w));
        }

        let mut enc_bytes = std::collections::HashSet::new();
        for cond in &conds {
            let b = spec.encode_cond(*cond);
            assert!(enc_bytes.insert(b), "branch cond collision for {cond:?}");
            assert_eq!(spec.decode_cond(b), Some(*cond), "cond roundtrip {cond:?}");
        }
        assert_eq!(enc_bytes.len(), spec.branch_cond_map.len());
        assert_eq!(spec.decode_cond(0xFF), None, "unknown cond must be None");
    }

    #[test]
    fn test_polymorphic_isa_diversity_still_holds() {
        let s1 = VirtualIsaSpec::from_seed(0x1111222233334444);
        let s2 = VirtualIsaSpec::from_seed(0xAAAABBBBCCCCDDDD);
        assert_ne!(s1.register_permutation, s2.register_permutation);
        assert_ne!(s1.operand_mask, s2.operand_mask);
        assert_ne!(s1.opcode_map, s2.opcode_map);
    }
}
