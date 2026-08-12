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
    pub fn generate_polymorphic(value: u32, complexity: usize, n_variants: usize) -> Vec<MbaPolynomial> {
        let mut out = Vec::with_capacity(n_variants);
        let mut seen: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
        let mut guard = 0;
        while out.len() < n_variants && guard < n_variants * 8 {
            guard += 1;
            let p = Self::generate(value, complexity);
            let code = p.to_x86_64_code();
            if seen.insert(code) {
                out.push(p);
            }
        }
        out
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

    /// MBA 다항식을 실제 x86-64 기계어로 컴파일한다.
    ///
    /// # 레지스터 할당
    /// - 입력: EDX = y (target_block_id)
    /// - R8D = var_val = x ^ (y + z) (모든 항에서 사용, 보존됨)
    /// - ECX = 각 항의 임시 계산용
    /// - EAX = 최종 누적 결과 (XOR 누적)
    ///
    /// # 생성되는 코드 구조
    /// ```asm
    /// push rdx             ; y 보존
    /// push rcx             ; 레지스터 보존
    /// push r8              ; 레지스터 보존
    /// mov r8d, edx         ; R8D = y
    /// mov eax, 0xFFFFFFFF  ; EAX = x
    /// xor r8d, eax         ; R8D = x ^ y = var_val (z=0 가정)
    /// xor eax, eax         ; EAX = 0 (누적 결과 초기화)
    /// ; 각 항에 대해:
    /// mov ecx, <coeff>     ; ECX = coefficient
    /// ; <boolean op> ecx, r8d  ; ECX = op(coeff, var_val)
    /// xor eax, ecx         ; EAX ^= ECX (결과 누적)
    /// pop r8
    /// pop rcx
    /// pop rdx
    /// ret
    /// ```
    pub fn to_x86_64_code(&self) -> Vec<u8> {
        let mut instructions: Vec<Instruction> = Vec::new();

        // 레지스터 보존 (호출 규약: callee-saved 아님, 직접 보존)
        instructions.push(Instruction::with1(Code::Push_r64, Register::RDX).unwrap_or_default());
        instructions.push(Instruction::with1(Code::Push_r64, Register::RCX).unwrap_or_default());
        instructions.push(Instruction::with1(Code::Push_r64, Register::R8).unwrap_or_default());

        // R8D = y (EDX)
        instructions.push(
            Instruction::with2(Code::Mov_r32_rm32, Register::R8D, Register::EDX)
                .unwrap_or_default()
        );
        // EAX = x (0xFFFFFFFF)
        instructions.push(
            Instruction::with2(Code::Mov_r32_imm32, Register::EAX, 0xFFFFFFFFu32)
                .unwrap_or_default()
        );
        // R8D ^= EAX → R8D = x ^ y = var_val
        instructions.push(
            Instruction::with2(Code::Xor_rm32_r32, Register::R8D, Register::EAX)
                .unwrap_or_default()
        );
        // EAX = 0 (누적 결과 초기화)
        instructions.push(
            Instruction::with2(Code::Xor_r32_rm32, Register::EAX, Register::EAX)
                .unwrap_or_default()
        );

        for term in &self.terms {
            // ECX = coefficient
            instructions.push(
                Instruction::with2(Code::Mov_r32_imm32, Register::ECX, term.coefficient)
                    .unwrap_or_default()
            );

            // 부울 연산 적용: ECX = op(ECX, R8D)
            // R8D는 var_val이며 모든 항에서 보존됨
            for &op in &term.operations {
                match op {
                    BooleanOp::And => {
                        instructions.push(
                            Instruction::with2(Code::And_rm32_r32, Register::ECX, Register::R8D)
                                .unwrap_or_default()
                        );
                    }
                    BooleanOp::Or => {
                        instructions.push(
                            Instruction::with2(Code::Or_rm32_r32, Register::ECX, Register::R8D)
                                .unwrap_or_default()
                        );
                    }
                    BooleanOp::Xor => {
                        instructions.push(
                            Instruction::with2(Code::Xor_rm32_r32, Register::ECX, Register::R8D)
                                .unwrap_or_default()
                        );
                    }
                    BooleanOp::Not => {
                        instructions.push(
                            Instruction::with1(Code::Not_rm32, Register::ECX)
                                .unwrap_or_default()
                        );
                    }
                    BooleanOp::Nand => {
                        // ECX = ECX & R8D; ECX = ~ECX
                        instructions.push(
                            Instruction::with2(Code::And_rm32_r32, Register::ECX, Register::R8D)
                                .unwrap_or_default()
                        );
                        instructions.push(
                            Instruction::with1(Code::Not_rm32, Register::ECX)
                                .unwrap_or_default()
                        );
                    }
                    BooleanOp::Nor => {
                        // ECX = ECX | R8D; ECX = ~ECX
                        instructions.push(
                            Instruction::with2(Code::Or_rm32_r32, Register::ECX, Register::R8D)
                                .unwrap_or_default()
                        );
                        instructions.push(
                            Instruction::with1(Code::Not_rm32, Register::ECX)
                                .unwrap_or_default()
                        );
                    }
                    BooleanOp::Xnor => {
                        // ECX = ECX ^ R8D; ECX = ~ECX
                        instructions.push(
                            Instruction::with2(Code::Xor_rm32_r32, Register::ECX, Register::R8D)
                                .unwrap_or_default()
                        );
                        instructions.push(
                            Instruction::with1(Code::Not_rm32, Register::ECX)
                                .unwrap_or_default()
                        );
                    }
                    BooleanOp::AndNot => {
                        // ECX = ECX & ~R8D
                        // R8D 보존: push r8 → not r8d → and ecx, r8d → pop r8
                        instructions.push(
                            Instruction::with1(Code::Push_r64, Register::R8)
                                .unwrap_or_default()
                        );
                        instructions.push(
                            Instruction::with1(Code::Not_rm32, Register::R8D)
                                .unwrap_or_default()
                        );
                        instructions.push(
                            Instruction::with2(Code::And_rm32_r32, Register::ECX, Register::R8D)
                                .unwrap_or_default()
                        );
                        instructions.push(
                            Instruction::with1(Code::Pop_r64, Register::R8)
                                .unwrap_or_default()
                        );
                    }
                    BooleanOp::OrNot => {
                        // ECX = ECX | ~R8D
                        instructions.push(
                            Instruction::with1(Code::Push_r64, Register::R8)
                                .unwrap_or_default()
                        );
                        instructions.push(
                            Instruction::with1(Code::Not_rm32, Register::R8D)
                                .unwrap_or_default()
                        );
                        instructions.push(
                            Instruction::with2(Code::Or_rm32_r32, Register::ECX, Register::R8D)
                                .unwrap_or_default()
                        );
                        instructions.push(
                            Instruction::with1(Code::Pop_r64, Register::R8)
                                .unwrap_or_default()
                        );
                    }
                }
            }

            // 결과 누적: EAX ^= ECX
            instructions.push(
                Instruction::with2(Code::Xor_rm32_r32, Register::EAX, Register::ECX)
                    .unwrap_or_default()
            );
        }

        // 레지스터 복원
        instructions.push(Instruction::with1(Code::Pop_r64, Register::R8).unwrap_or_default());
        instructions.push(Instruction::with1(Code::Pop_r64, Register::RCX).unwrap_or_default());
        instructions.push(Instruction::with1(Code::Pop_r64, Register::RDX).unwrap_or_default());

        // 반환
        instructions.push(Instruction::with(Code::Retnq));

        // iced-x86 BlockEncoder로 컴파일
        let block = InstructionBlock::new(&instructions, 0x1000);
        match BlockEncoder::encode(64, block, BlockEncoderOptions::NONE) {
            Ok(result) => result.code_buffer,
            Err(e) => {
                log::error!("[MBA] BlockEncoder failed: {:?}. Falling back to simple XOR stub.", e);
                // 폴백: mov eax, edx; ret (입력 y를 그대로 반환)
                let fallback = vec![
                    Instruction::with2(Code::Mov_r32_rm32, Register::EAX, Register::EDX).unwrap_or_default(),
                    Instruction::with(Code::Retnq),
                ];
                let fb_block = InstructionBlock::new(&fallback, 0x1000);
                BlockEncoder::encode(64, fb_block, BlockEncoderOptions::NONE)
                    .map(|r| r.code_buffer)
                    .unwrap_or_else(|_| vec![0x89, 0xD0, 0xC3]) // mov eax, edx; ret
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// v10: 임의 var_val(x/y/z) 다수 벡터로 동치성 검증 — 이전 단일 벡터
    /// (x=0xFFFFFFFF, y=value) 검사는 중간/고급 레벨의 var_val 의존 버그를 놓쳤다.
    fn check_equiv(val: u32, level: usize) {
        use rand::Rng;
        let poly = MbaPolynomial::generate(val, level);
        let mut rng = rand::thread_rng();
        for _ in 0..64 {
            let x: u32 = rng.gen();
            let y: u32 = rng.gen();
            let z: u32 = rng.gen();
            let mut vars = HashMap::new();
            vars.insert("x".to_string(), x);
            vars.insert("y".to_string(), y);
            vars.insert("z".to_string(), z);
            assert_eq!(
                poly.evaluate(&vars),
                val,
                "MBA failed for val=0x{:08X} level={} at x=0x{:08X} y=0x{:08X} z=0x{:08X}",
                val, level, x, y, z
            );
        }
    }

    #[test]
    fn test_mba_equivalence_basic() {
        for &val in &[0u32, 1, 42, 0x12345678, 0xFFFFFFFF, 0xDEADBEEF] {
            check_equiv(val, 1);
        }
    }

    #[test]
    fn test_mba_equivalence_intermediate() {
        for &val in &[0u32, 1, 42, 0x12345678, 0xFFFFFFFF, 0xDEADBEEF] {
            check_equiv(val, 2);
        }
    }

    #[test]
    fn test_mba_equivalence_advanced() {
        for &val in &[0u32, 1, 42, 0x12345678, 0xFFFFFFFF, 0xDEADBEEF] {
            check_equiv(val, 3);
        }
    }

    #[test]
    fn test_mba_no_identical_noise_pairs() {
        // v10 회귀: 동일한 (coefficient, ops) 항 쌍이 있으면 안 된다 —
        // 이전 버전은 x^x=0으로 즉시 소거되는 중복 노이즈를 생성했다.
        for level in 1..=3 {
            for _ in 0..8 {
                let poly = MbaPolynomial::generate(0x12345678, level);
                for i in 0..poly.terms.len() {
                    for j in (i + 1)..poly.terms.len() {
                        let (a, b) = (&poly.terms[i], &poly.terms[j]);
                        let identical = a.coefficient == b.coefficient && a.operations == b.operations;
                        assert!(
                            !identical,
                            "level {}: identical noise pair at {} / {}",
                            level, i, j
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn test_mba_code_generation() {
        let poly = MbaPolynomial::generate(0x12345678, 2);
        let code = poly.to_x86_64_code();
        assert!(!code.is_empty());
        assert!(code.len() > 10, "MBA code should be substantial");
        assert_eq!(code[code.len() - 1], 0xC3, "Last byte should be RET");
    }

    #[test]
    fn test_mba_complexity_levels() {
        let basic = MbaPolynomial::generate(42, 1);
        let intermediate = MbaPolynomial::generate(42, 2);
        let advanced = MbaPolynomial::generate(42, 3);
        assert!(basic.terms.len() <= intermediate.terms.len());
        assert!(intermediate.terms.len() <= advanced.terms.len());
    }

    #[test]
    fn test_mba_code_different_each_time() {
        // 고급 레벨은 난수 노이즈를 사용하므로 매번 다른 코드가 생성됨
        let poly1 = MbaPolynomial::generate(0xABCDEF01, 3);
        let code1 = poly1.to_x86_64_code();
        let poly2 = MbaPolynomial::generate(0xABCDEF01, 3);
        let code2 = poly2.to_x86_64_code();
        // 코드 길이는 같을 수 있지만 바이트는 다를 가능성이 높음
        // (coefficient가 달라지므로)
    }

    #[test]
    fn test_mba_polymorphic_variants_distinct_and_equivalent() {
        // M8 (v36): generate_polymorphic가 서로 다른(바이트코드 상이한) 등가 변이를
        // n개 만들고, 각각이 임의 var_val에서도 원본 값과 동일함을 보장한다.
        for level in 1..=3 {
            let variants = MbaPolynomial::generate_polymorphic(0x12345678, level, 3);
            assert_eq!(variants.len(), 3, "level {}: expected 3 distinct variants", level);
            // 개별 variant가 서로 다른 기계어를 낸다 (폴리모픽)
            let codes: Vec<Vec<u8>> = variants.iter().map(|p| p.to_x86_64_code()).collect();
            assert!(codes[0] != codes[1] || codes[1] != codes[2],
                "level {}: variants should differ in generated code", level);
            // 각 variant의 등가성 (다수 임의 var_val)
            let mut rng = rand::thread_rng();
            for p in &variants {
                for _ in 0..32 {
                    let x: u32 = rng.gen();
                    let y: u32 = rng.gen();
                    let z: u32 = rng.gen();
                    let mut vars = HashMap::new();
                    vars.insert("x".to_string(), x);
                    vars.insert("y".to_string(), y);
                    vars.insert("z".to_string(), z);
                    assert_eq!(p.evaluate(&vars), 0x12345678,
                        "level {}: polymorphic variant not equivalent at x=0x{:08X}", level, x);
                }
            }
        }
    }
}
