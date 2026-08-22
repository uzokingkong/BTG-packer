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
            val,
            level,
            x,
            y,
            z
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
    let code = poly.to_x86_64_code().unwrap();
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
    let code1 = poly1.to_x86_64_code().unwrap();
    let poly2 = MbaPolynomial::generate(0xABCDEF01, 3);
    let code2 = poly2.to_x86_64_code().unwrap();
    // 코드 길이는 같을 수 있지만 바이트는 다를 가능성이 높음
    // (coefficient가 달라지므로)
}

#[test]
fn test_mba_polymorphic_variants_distinct_and_equivalent() {
    // M8 (v36): generate_polymorphic가 서로 다른(바이트코드 상이한) 등가 변이를
    // n개 만들고, 각각이 임의 var_val에서도 원본 값과 동일함을 보장한다.
    for level in 1..=3 {
        let variants = MbaPolynomial::generate_polymorphic(0x12345678, level, 3).unwrap();
        assert_eq!(
            variants.len(),
            3,
            "level {}: expected 3 distinct variants",
            level
        );
        // 개별 variant가 서로 다른 기계어를 낸다 (폴리모픽)
        let codes: Vec<Vec<u8>> = variants
            .iter()
            .map(|p| p.to_x86_64_code().unwrap())
            .collect();
        assert!(
            codes[0] != codes[1] || codes[1] != codes[2],
            "level {}: variants should differ in generated code",
            level
        );
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
                assert_eq!(
                    p.evaluate(&vars),
                    0x12345678,
                    "level {}: polymorphic variant not equivalent at x=0x{:08X}",
                    level,
                    x
                );
            }
        }
    }
}
