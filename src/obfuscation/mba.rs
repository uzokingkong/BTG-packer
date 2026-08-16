// ==============================================================================
// BTG - Advanced MBA (Mixed Boolean-Arithmetic) Obfuscation Engine
// ==============================================================================
// 상용 난독화 수준의 MBA 다항식 생성 및 x86-64 코드 생성.
//
// MBA 핵심 아이디어:
//   단순한 정수 연산(x + y, x ^ y 등)을 부울 연산(AND, OR, XOR, NOT)과
//   산술 연산(ADD, SUB, IMUL, SHL, ROR)의 조합으로 변환하여,
//   정적 분석(디스어셈블러, 심볼릭 실행)을 방해한다.
//
// 수학적 동등성 보장:
//   모든 MBA 표현식은 원본 값과 수학적으로 동일함을 assert로 검증한다.
// ==============================================================================

use std::collections::HashMap;
use iced_x86::{BlockEncoder, BlockEncoderOptions, Code, Instruction, InstructionBlock, Register};
use rand::Rng;

#[derive(Debug, Clone)]
pub struct MbaPolynomial {
    pub terms: Vec<MbaTerm>,
    pub variables: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct MbaTerm {
    pub coefficient: u32,
    pub operations: Vec<BooleanOp>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BooleanOp {
    And,
    Or,
    Xor,
    Not,
    Nand,
    Nor,
    Xnor,
    AndNot,  // (a & ~b)
    OrNot,   // (a | ~b)
}

impl MbaPolynomial {
    /// 주어진 값에 대한 MBA 다항식을 생성한다.
    /// complexity가 높을수록 더 많은 항과 연산을 사용한다.
    ///
    /// v10 구조 재설계 (이전 버전의 약점):
    ///   - 노이즈가 **완전히 동일한 항 쌍**(x ^ x = 0)이라 최적화기가 즉시
    ///     소거 가능했다 → 임의 v에 대해 **비동일 항족**이 대수적으로 상쇄되는
    ///     구조로 교체:
    ///       A: (a&v) ^ (a&~v) ^ a          = 0   (모든 v)
    ///       E: (a|v) ^ (a|~v) ^ ~a          = 0   (모든 v)
    ///       F: ~(a&v) ^ (a&~v) ^ ~a         = 0   (모든 v)
    ///       G: ~(a|v) ^ (a|~v) ^ a          = 0   (모든 v)
    ///     → 소거하려면 2차 MBA 항등식을 알아야 하므로 단순 중복 제거로는
    ///     안 지워진다. (동일 쌍과 달리 어떤 항도 단독으로 0이 아니다)
    ///   - 값 항을 XOR-분할(value = (value^t)^v ^ (t)^v)로 감춘다.
    ///   - 정합성 검증은 debug 뿐 아니라 릴리스에서도 다수 임의 var_val에 대해
    ///     수행한다. (이전: debug_assert + var_val=~value 단일 벡터만 검사 —
    ///     그 외 var_val에서는 중간/고급 레벨이 아예 틀린 값을 냈다)
    pub fn generate(value: u32, complexity: usize) -> Self {
        let mut polynomial = MbaPolynomial {
            terms: Vec::new(),
            variables: vec![
                "x".to_string(),
                "y".to_string(),
                "z".to_string(),
            ],
        };

        match complexity {
            1 => polynomial.generate_basic(value),
            2 => polynomial.generate_intermediate(value),
            _ => polynomial.generate_advanced(value),
        }

        // 수학적 동등성 검증 (릴리스 포함, 다중 임의 var_val)
        polynomial.verify_equivalence(value);

        polynomial
    }

    /// M8 (v36): **폴리모픽 MBA** — 동일한 `value`를 나타내는 `n_variants`개의
    /// 서로 다른(바이트코드가 상이한) 등가 다항식을 생성한다. 각 variant는
    /// 랜덤 상쇄족/XOR-분할을 새로 뽑아 만들어 정적 시그니처가 빌드마다 다르고,
    /// 개별 variant는 릴리스에서도 등가성 검증된다. 동일한 value에 대해 매번
    /// 같은 코드가 나오는 단일 다항식 생성과 달리, 폴리모픽 변이를 제공한다.
    pub fn generate_polymorphic(
        value: u32,
        complexity: usize,
        n_variants: usize,
    ) -> crate::error::Result<Vec<MbaPolynomial>> {
        let mut out = Vec::with_capacity(n_variants);
        let mut seen: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
        let mut guard = 0;
        while out.len() < n_variants && guard < n_variants * 8 {
            guard += 1;
            let p = Self::generate(value, complexity);
            let code = p.to_x86_64_code()?; // 코드생성 실패는 오류로 전파 (조용한 폴백 금지)
            if seen.insert(code) {
                out.push(p);
            }
        }
        Ok(out)
    }

    /// Level 1 (Basic): 값 상수 + 상쇄족 1개
    fn generate_basic(&mut self, value: u32) {
        let mut rng = rand::thread_rng();
        self.terms.push(MbaTerm {
            coefficient: value,
            operations: vec![],
        });
        let a: u32 = rng.gen::<u32>() | 1;
        self.push_cancel_family(rng.gen_range(0..3), a);
    }

    /// Level 2 (Intermediate): XOR-분할 값 항 + 상쇄족 2~3개
    fn generate_intermediate(&mut self, value: u32) {
        let mut rng = rand::thread_rng();
        let t: u32 = rng.gen::<u32>();
        self.terms.push(MbaTerm {
            coefficient: value ^ t,
            operations: vec![BooleanOp::Xor],
        });
        self.terms.push(MbaTerm {
            coefficient: t,
            operations: vec![BooleanOp::Xor],
        });
        for _ in 0..rng.gen_range(2..=3) {
            let a: u32 = rng.gen::<u32>() | 1;
            self.push_cancel_family(rng.gen_range(0..3), a);
        }
    }

    /// Level 3 (Advanced): op-체인 값 항 + 상쇄족 4~6개
    /// 값 항의 [Xor, Not, Not] 체인은 (c^v) 후 Not 2회(항등) — 정적 분석 시
    /// 단순 상수로 보이지 않는다.
    fn generate_advanced(&mut self, value: u32) {
        let mut rng = rand::thread_rng();
        let t: u32 = rng.gen::<u32>();
        self.terms.push(MbaTerm {
            coefficient: value ^ t,
            operations: vec![BooleanOp::Xor, BooleanOp::Not, BooleanOp::Not],
        });
        self.terms.push(MbaTerm {
            coefficient: t,
            operations: vec![BooleanOp::Xor],
        });
        for _ in 0..rng.gen_range(4..=6) {
            let a: u32 = rng.gen::<u32>() | 1;
            self.push_cancel_family(rng.gen_range(0..3), a);
        }
    }

    /// 임의 v에 대해 XOR 합이 0이 되는 **비동일** 상쇄 항족을 추가한다.
    /// (v10: 동일 쌍 노이즈 제거 — 항등식을 모르면 소거 불가. 각 항족은
    /// 서로 다른 op 시그니처를 갖고, bare-v 항을 쓰지 않아 항족 간 중복이 없다)
    fn push_cancel_family(&mut self, kind: u8, a: u32) {
        match kind {
            // A: (a&v) ^ (a&~v) ^ a = 0
            0 => {
                self.terms.push(MbaTerm { coefficient: a, operations: vec![BooleanOp::And] });
                self.terms.push(MbaTerm { coefficient: a, operations: vec![BooleanOp::AndNot] });
                self.terms.push(MbaTerm { coefficient: a, operations: vec![] });
            }
            // E: (a|v) ^ (a|~v) ^ ~a = 0
            1 => {
                self.terms.push(MbaTerm { coefficient: a, operations: vec![BooleanOp::Or] });
                self.terms.push(MbaTerm { coefficient: a, operations: vec![BooleanOp::OrNot] });
                self.terms.push(MbaTerm { coefficient: !a, operations: vec![] });
            }
            // F: ~(a&v) ^ (a&~v) ^ ~a = 0   (NAND 경유)
            2 => {
                self.terms.push(MbaTerm { coefficient: a, operations: vec![BooleanOp::Nand] });
                self.terms.push(MbaTerm { coefficient: a, operations: vec![BooleanOp::AndNot] });
                self.terms.push(MbaTerm { coefficient: !a, operations: vec![] });
            }
            // G: ~(a|v) ^ (a|~v) ^ a = 0   (NOR 경유)
            _ => {
                self.terms.push(MbaTerm { coefficient: a, operations: vec![BooleanOp::Nor] });
                self.terms.push(MbaTerm { coefficient: a, operations: vec![BooleanOp::OrNot] });
                self.terms.push(MbaTerm { coefficient: a, operations: vec![] });
            }
        }
    }

    /// MBA 다항식을 평가하여 원본 값을 복원한다.
    /// 모든 항의 결과를 XOR로 누적한다 (XOR은 교환법칙/결합법칙 성립).
    /// var_val = x ^ (y + z) — v10부터 **임의 var_val에 대해** value를 반환한다.
    pub fn evaluate(&self, variables: &HashMap<String, u32>) -> u32 {
        let var_val = if let Some(&x) = variables.get("x") {
            let var_y = variables.get("y").copied().unwrap_or(0);
            let var_z = variables.get("z").copied().unwrap_or(0);
            x ^ var_y.wrapping_add(var_z)
        } else {
            0xFFFFFFFF
        };

        let mut result = 0u32;
        for term in &self.terms {
            let mut val = term.coefficient;
            for op in &term.operations {
                val = Self::apply_op(*op, val, var_val);
            }
            result ^= val;
        }
        result
    }

    fn apply_op(op: BooleanOp, a: u32, b: u32) -> u32 {
        match op {
            BooleanOp::And => a & b,
            BooleanOp::Or => a | b,
            BooleanOp::Xor => a ^ b,
            BooleanOp::Not => !a,
            BooleanOp::Nand => !(a & b),
            BooleanOp::Nor => !(a | b),
            BooleanOp::Xnor => !(a ^ b),
            BooleanOp::AndNot => a & !b,
            BooleanOp::OrNot => a | !b,
        }
    }

    /// 수학적 동등성 검증: **32개 임의 var_val 조합**에 대해 evaluate 결과가
    /// 원본 value와 일치하는지 확인한다. v10: debug_assert(릴리스 무검사) +
    /// 단일 벡터를 제거하고 릴리스에서도 항상 검증한다.
    fn verify_equivalence(&self, value: u32) {
        let mut rng = rand::thread_rng();
        for _ in 0..32 {
            let x: u32 = rng.gen();
            let y: u32 = rng.gen();
            let z: u32 = rng.gen();
            let mut vars = HashMap::new();
            vars.insert("x".to_string(), x);
            vars.insert("y".to_string(), y);
            vars.insert("z".to_string(), z);
            let result = self.evaluate(&vars);
            assert_eq!(
                result, value,
                "MBA equivalence violated: expected 0x{:08X}, got 0x{:08X} (x=0x{:08X}, y=0x{:08X}, z=0x{:08X})",
                value, result, x, y, z
            );
        }
    }


}

mod codegen;
#[cfg(test)]
mod tests;
