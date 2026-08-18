// ==============================================================================
// BTG (Bidirectional Trigger Graph) - Dispatcher shellcode validation
// ==============================================================================
// 상용 기준 검증 강화 (Notes_260817 리뷰 #3 반영):
//   1. 전체 명령이 정상 디코드 (기존)
//   2. **모든 직접 분기(rel32) 타깃 유효성** — 타깃 0(미패치 placeholder) 거부,
//      디스패처 영역 밖 타깃은 절대 주소만 허용(≥0x10000).
//   3. **영역 내 분기 타깃이 명령 경계와 일치** (중간 진입 = 인코딩 결함).
//   4. **무조건 자기 자신 루프(`jmp self`) 거부** (M7의 claim spin은 조건부라 허용).
//   5. **call/ret 쌍**: 모든 in-region `call` 타깃 서브루틴이 유한 단계 안에
//      `ret`에 도달 (BlockCrypt/KSA/PRGA/C1Init/gen_block 종단 검증). 루프가 있는
//      서브루틴(PRGA `jmp loop`)은 DFS로 양쪽 분기 모두 탐색해 해결.
//   6. 최소한 하나의 `ret`(반환 경로) 존재. (표준 디스패처는 분기가 없는
//      직선형이므로 "분기 필수"는 적용하지 않는다.)
//
// 상용 1-3 (Notes #3 확장):
//   7. **stack-delta 검증** — 각 분기 지점(명령 경계) 간 RSP 변화를 고정점
//      워크리스트로 추적. (a) 어떤 명령도 서로 다른 두 RSP delta로 도달하면
//      안 됨(분기 병합 지점 스택 불일치), (b) 모든 종단 `ret`은 동일한 RSP
//      delta(= 소비 스택 슬롯, 1..8 slots)로 도달해야 함. 스택 불균형 인코딩
//      결함을 조기에 잡는다.
//   8. **RIP-relative 오프셋 검증** — 모든 RIP-relative 메모리 피연산자가 실제
//      테이블/영역을 가리키는지 (0 = 미패치 placeholder 거부, 절대 VA ≥ 0x10000
//      또는 디스패처/테이블 영역 내). `validate_dispatcher_with_base`에서
//      실제 dispatcher_va를 알고 있을 때 수행.
//   9. **간접 분기/점프 테이블 타깃 검증** — (a) in-region `call` 서브루틴이
//      ret로 복귀(기존 5), (b) 점프 테이블 인덱스 접근(`[rax + idx*4]`)이
//      num_blocks 바운드 체크(`cmp idx, num_blocks; cmovae`) 아래에 있는지,
//      (c) `ret`/간접 `jmp r/m` 타깃이 0(미패치)이 아닌지.
// ==============================================================================

use iced_x86::{Code, Decoder, DecoderOptions, FlowControl, Instruction, OpKind, Register};

/// 검증 베이스 (rel32 분기는 position-independent — 실제 런타임 base와 무관).
const VALIDATE_BASE: u64 = 0x2000;

/// 특정 IP에서 명령 1개 디코드 (영역 경계 안일 때만).
fn decode_one(bytes: &[u8], ip: u64) -> Option<Instruction> {
    let base = VALIDATE_BASE;
    if ip < base || ip >= base + bytes.len() as u64 {
        return None;
    }
    let local = (ip - base) as usize;
    let mut decoder = Decoder::with_ip(64, &bytes[local..], ip, DecoderOptions::NONE);
    if !decoder.can_decode() {
        return None;
    }
    let inst = decoder.decode();
    if inst.is_invalid() {
        return None;
    }
    Some(inst)
}

/// call 서브루틴이 `ret`까지 도달하는지 DFS 탐색.
/// - `Return`         → 성공.
/// - `UnconditionalBranch` → 타깃 push.
/// - `ConditionalBranch`   → fall-through + taken 양쪽 push (루프는 visited로 차단).
/// - `Call`           → fall-through만 (중첩 call은 별도 검증 — 여기선 본체로 내려가지 않음).
/// - 기타             → fall-through.
/// 영역 밖 타깃은 push하지 않는다 (외부 절대 주소는 서브루틴 내부가 아님).
fn call_reaches_ret(bytes: &[u8], entry_va: u64) -> bool {
    let mut visited = std::collections::HashSet::new();
    let mut stack: Vec<u64> = vec![entry_va];
    while let Some(ip) = stack.pop() {
        if !visited.insert(ip) {
            continue;
        }
        let Some(inst) = decode_one(bytes, ip) else {
            continue;
        };
        let len = inst.len() as u64;
        match inst.flow_control() {
            FlowControl::Return => return true,
            FlowControl::UnconditionalBranch => {
                stack.push(inst.near_branch_target());
            }
            FlowControl::ConditionalBranch => {
                stack.push(ip + len);
                stack.push(inst.near_branch_target());
            }
            FlowControl::Call => {
                stack.push(ip + len); // 중첩 call 본체는 별도 call 검증에서 다룸
            }
            _ => {
                stack.push(ip + len);
            }
        }
    }
    false
}

// ──────────────────────────────────────────────────────────────────────────────
// 상용 1-3: stack-delta / RIP-relative / 간접 분기·점프 테이블 검증
// ──────────────────────────────────────────────────────────────────────────────

/// 명령 하나의 스택(RSP) 바이트 변화량(상대 delta).
/// - push r64 / pushfq / push imm : -8
/// - pop r64 / popfq              : +8
/// - sub rsp, imm                 : -imm
/// - add rsp, imm                 : +imm
/// - lea rsp, [rsp + disp]        : +disp
/// - call                         : 0 (호출 측은 ret가 상쇄 — callee 내부는 별도 추적)
/// - ret                          : +8 (반환 주소 pop; 종단으로 처리)
fn inst_rsp_delta(inst: &Instruction) -> i64 {
    match inst.code() {
        Code::Push_r64 | Code::Pushfq | Code::Push_rm64 | Code::Push_imm16 => -8,
        Code::Pop_r64 | Code::Popfq => 8,
        Code::Sub_rm64_imm32 => {
            if inst.op0_register() == Register::RSP {
                -(inst.immediate32() as i64)
            } else {
                0
            }
        }
        Code::Add_rm64_imm32 => {
            if inst.op0_register() == Register::RSP {
                inst.immediate32() as i64
            } else {
                0
            }
        }
        Code::Lea_r64_m if inst.op0_register() == Register::RSP => inst.memory_displacement64() as i64,
        Code::Retnq | Code::Retnq_imm16 => 8,
        _ => 0,
    }
}

/// 명령이 스택을 바꾸는지 (워크리스트에서 재진입 판별용).
fn is_stack_modifying(inst: &Instruction) -> bool {
    inst_rsp_delta(inst) != 0
}

/// 디스패처 전체의 stack-delta 고정점 분석.
///
/// 각 명령 시작 주소에 도달하는 RSP delta(진입 RSP 대비, push면 감소)를
/// 워크리스트로 계산한다. `call`은 callee+ret가 상쇄하므로 fall-through에
/// delta 변화 없음으로 모델링한다(중첩 call의 내부 스택은 call_reaches_ret가
/// 종단만 보장 — 이 분석은 **분기 지점 간 RSP 변화의 일관성**을 검증).
///
/// 실패 조건:
///   - 어떤 명령이 두 개의 다른 RSP delta로 도달 → 분기 병합 지점 스택 불일치.
///   - 종단 `ret`의 delta가 전부 같지 않음, 또는 0 초과가 아님(스택 미복원).
///
/// 성공 시 종단 `ret`의 RSP delta(소비된 스택 바이트)를 반환한다.
fn validate_stack_delta(bytes: &[u8]) -> crate::error::Result<i64> {
    let base = VALIDATE_BASE;
    // (address) -> (RSP delta) — 처음 도달한 delta로 초기화, 불일치 시 에러.
    let mut delta: std::collections::HashMap<u64, i64> = std::collections::HashMap::new();
    let mut work: Vec<u64> = vec![base];
    delta.insert(base, 0);
    let mut term_deltas: Vec<i64> = Vec::new();

    let mut guard = 0usize;
    while let Some(ip) = work.pop() {
        guard += 1;
        if guard > 2_000_000 {
            return Err(anyhow::anyhow!(
                "Dispatcher stack-delta fixpoint did not converge (loop guard)"
            )
            .into());
        }
        let Some(inst) = decode_one(bytes, ip) else { continue };
        let len = inst.len() as u64;
        let d = *delta.get(&ip).unwrap_or(&0);
        // 종단: ret (영역 내에서 서브루틴이 아닌 최종 반환은 delta 동일해야 함)
        if inst.flow_control() == FlowControl::Return {
            term_deltas.push(d);
            continue;
        }
        let eff = inst_rsp_delta(&inst);
        let next_d = d + eff;
        // call은 callee(ret)가 push한 반환 주소를 상쇄 → fall-through delta 불변.
        // 단, call 자체는 스택을 바꾸므로 여기서는 다음 명령이 동일 delta로 시작.
        let push_next = |next: u64, nd: i64, work: &mut Vec<u64>,
                         delta: &mut std::collections::HashMap<u64, i64>,
                         guard_ip: u64| -> crate::error::Result<()> {
            if next < base || next >= base + bytes.len() as u64 {
                return Ok(());
            }
            match delta.get(&next) {
                Some(prev) if *prev != nd => {
                    return Err(anyhow::anyhow!(
                        "Dispatcher stack-delta inconsistent at 0x{:X}: reached with RSP delta {} (from 0x{:X}) vs earlier {}",
                        next, nd, guard_ip, prev
                    )
                    .into());
                }
                Some(_) => {}
                None => {
                    delta.insert(next, nd);
                    work.push(next);
                }
            }
            Ok(())
        };

        match inst.flow_control() {
            FlowControl::UnconditionalBranch => {
                push_next(inst.near_branch_target(), next_d, &mut work, &mut delta, ip)?;
            }
            FlowControl::ConditionalBranch => {
                push_next(ip + len, next_d, &mut work, &mut delta, ip)?;
                push_next(inst.near_branch_target(), next_d, &mut work, &mut delta, ip)?;
            }
            FlowControl::Call => {
                // call: fall-through는 delta 불변 (callee+ret 상쇄)
                push_next(ip + len, d, &mut work, &mut delta, ip)?;
            }
            FlowControl::IndirectBranch | FlowControl::IndirectCall => {
                // 간접 분기/호출은 타깃을 정적으로 모를 수 있음 — 단, 이 분석은
                // linear/직접 흐름만 추적하므로 fall-through만 취급 (간접 타깃
                // 검증은 별도 함수에서 수행). 이 명령이 스택을 바꾸지 않았다면
                // 다음 명령은 동일 delta로 시작.
                let _ = is_stack_modifying(&inst);
                push_next(ip + len, next_d, &mut work, &mut delta, ip)?;
            }
            _ => {
                push_next(ip + len, next_d, &mut work, &mut delta, ip)?;
            }
        }
    }

    if term_deltas.is_empty() {
        return Err(anyhow::anyhow!("Dispatcher has no terminating ret for stack-delta").into());
    }
    let first = term_deltas[0];
    if term_deltas.iter().any(|&t| t != first) {
        return Err(anyhow::anyhow!(
            "Dispatcher terminating rets have inconsistent RSP delta (all must consume the same stack): {:?}",
            term_deltas
        )
        .into());
    }
    if first <= 0 {
        return Err(anyhow::anyhow!(
            "Dispatcher terminating ret reached with non-positive RSP delta {} (stack not restored)",
            first
        )
        .into());
    }
    if first > 8 * 8 {
        return Err(anyhow::anyhow!(
            "Dispatcher terminating ret consumed implausibly deep stack ({} bytes)",
            first
        )
        .into());
    }
    Ok(first)
}

/// 모든 명령의 메모리 피연산자 중 RIP-relative 것들의 타깃을 검증한다.
/// `memory_displacement64()`는 ip가 설정된 디코더에서 RIP-relative의 **절대**
/// 타깃(= ip+len+disp)을 반환한다(기존 reencrypt RIP 테스트가 이미 이 의미로
/// 사용). RIP-relative disp는 **절대 VA**로 인코딩되므로 실제 dispatcher 코드
/// 베이스 `code_base_va`(디스패처 코드 시작 = dispatcher_va + 0x20)에서 디코드해
/// 타깃을 얻어야 한다. `region`이 주어지면 그 영역(예: .btg 섹션) 안 또는 절대
/// VA ≥ 0x10000만 허용한다. region이 None이면 절대 VA ≥ 0x10000과 0이 아님만
/// 검증한다.
fn validate_rip_relative(
    bytes: &[u8],
    code_base_va: u64,
    region: Option<(u64, u64)>,
) -> crate::error::Result<()> {
    let mut decoder = Decoder::with_ip(64, bytes, code_base_va, DecoderOptions::NONE);
    while decoder.can_decode() {
        let inst = decoder.decode();
        if inst.is_invalid() {
            break;
        }
        if inst.memory_base() != Register::RIP {
            continue;
        }
        let target = inst.memory_displacement64();
        if target == 0 {
            return Err(anyhow::anyhow!(
                "Dispatcher RIP-relative operand resolves to 0 (unpatched table placeholder) @0x{:X}",
                decoder.ip().wrapping_sub(inst.len() as u64)
            )
            .into());
        }
        let ok = if let Some((lo, hi)) = region {
            (target >= lo && target < hi) || target >= 0x10000
        } else {
            target >= 0x10000
        };
        if !ok {
            return Err(anyhow::anyhow!(
                "Dispatcher RIP-relative operand target 0x{:X} does not point to a real table/region (region {:?})",
                target, region
            )
            .into());
        }
    }
    Ok(())
}

/// 점프 테이블 인덱스가 num_blocks로 바운드 체크되어 있는지 확인한다.
/// 디스패처는 `cmp idx, num_blocks; mov ecx, 0; cmovae idx, rcx` 패턴으로
/// OOB 인덱스를 0으로 클램프한다. 해당 패턴이 없으면 인덱싱 접근이 범위 밖을
/// 읽을 수 있어 간접 분기(점프 테이블) 타깃이 잘못될 수 있다.
fn has_table_bounds_check(bytes: &[u8], num_blocks: usize) -> bool {
    let base = VALIDATE_BASE;
    let mut decoder = Decoder::with_ip(64, bytes, base, DecoderOptions::NONE);
    let mut insts: Vec<Instruction> = Vec::new();
    while decoder.can_decode() {
        let inst = decoder.decode();
        if inst.is_invalid() {
            break;
        }
        insts.push(inst);
    }
    // cmp reg, num_blocks ... cmovae reg, (r)cx 패턴 탐색
    for i in 0..insts.len() {
        let inst = &insts[i];
        let is_cmp_nb = matches!(inst.code(), Code::Cmp_rm64_imm32 | Code::Cmp_rm32_imm32)
            && inst.immediate32() as usize == num_blocks
            && num_blocks <= 0x7FFF_FFFF;
        if !is_cmp_nb {
            continue;
        }
        // 뒤 3개 명령 안에서 cmovae (같은 대상 레지스터) 탐색
        for j in (i + 1)..insts.len().min(i + 4) {
            let jinst = &insts[j];
            if matches!(jinst.code(), Code::Cmovae_r64_rm64 | Code::Cmovae_r32_rm32) {
                return true;
            }
            // 다른 cmp/분기 전에 cmovae가 없으면 이 cmp는 바운드 체크가 아님
            if matches!(jinst.code(), Code::Cmp_rm64_imm32 | Code::Cmp_rm32_imm32) {
                break;
            }
        }
    }
    false
}

/// 간접 분기(점프 테이블) 타깃 검증.
/// - in-region call 서브루틴이 ret로 복귀 (call_reaches_ret 재사용)
/// - ret / 간접 jmp/call 타깃 0 거부 (간접 메모리/레지스터 연산의 disp가 0이면 미패치)
/// - num_blocks > 0이면 점프 테이블 인덱스 바운드 체크 존재 여부
fn validate_indirect_targets(bytes: &[u8], num_blocks: usize) -> crate::error::Result<()> {
    let base = VALIDATE_BASE;
    let mut decoder = Decoder::with_ip(64, bytes, base, DecoderOptions::NONE);
    let mut indirect_branches = 0usize;
    while decoder.can_decode() {
        let inst = decoder.decode();
        if inst.is_invalid() {
            break;
        }
        let fc = inst.flow_control();
        // 간접 분기/호출: 연산자(메모리/레지스터) 기반 — disp 0이면 미패치 placeholder
        if matches!(fc, FlowControl::IndirectBranch | FlowControl::IndirectCall) {
            indirect_branches += 1;
            // 간접 분기/호출의 타깃은 레지스터 또는 메모리 피연산자.
            let op0 = inst.op0_kind();
            let is_mem = op0 == OpKind::Memory;
            let is_reg = op0 == OpKind::Register;
            if !is_mem && !is_reg {
                return Err(anyhow::anyhow!(
                    "Dispatcher indirect branch has no register/memory target operand @0x{:X}",
                    decoder.ip().wrapping_sub(inst.len() as u64)
                )
                .into());
            }
            // [rip+disp] 형태: disp==0 → 미패치
            if is_mem && inst.memory_base() == Register::RIP && inst.memory_displacement64() == 0 {
                return Err(anyhow::anyhow!(
                    "Dispatcher indirect branch has unpatched RIP target 0 @0x{:X}",
                    decoder.ip().wrapping_sub(inst.len() as u64)
                )
                .into());
            }
        }
        // in-region call: 서브루틴이 ret로 복귀
        if fc == FlowControl::Call {
            let t = inst.near_branch_target();
            if t >= base && t < base + bytes.len() as u64 {
                if !call_reaches_ret(bytes, t) {
                    return Err(anyhow::anyhow!(
                        "Dispatcher indirect-target: call target 0x{:X} does not reach ret",
                        t
                    )
                    .into());
                }
            }
        }
    }
    // 점프 테이블 바운드 체크 (간접 분기/인덱스 접근이 있을 때)
    if num_blocks > 0 && indirect_branches > 0 && !has_table_bounds_check(bytes, num_blocks) {
        return Err(anyhow::anyhow!(
            "Dispatcher has {} indirect branch(es) but no `cmp idx, {}; cmovae` table bounds check",
            indirect_branches, num_blocks
        )
        .into());
    }
    Ok(())
}

/// 디스패처 바이트열의 상용급 구조 검증 (VA 불요).
///
/// 기본 구조 검증(1-6) + stack-delta(7) + 간접 분기/점프 테이블(9). RIP-relative
/// 절대 타깃(8)은 실제 dispatcher_va를 알아야 하므로 `validate_dispatcher_with_base`
/// 를 호출해야 함께 수행된다.
pub fn validate_dispatcher(bytes: &[u8]) -> crate::error::Result<()> {
    if bytes.is_empty() {
        return Err(anyhow::anyhow!("Dispatcher bytes are empty.").into());
    }

    let base = VALIDATE_BASE;
    let mut decoder = Decoder::with_ip(64, bytes, base, DecoderOptions::NONE);
    let mut valid_insts = 0;
    let mut found_ret = false;
    // 명령 시작 주소 집합 (영역 내 분기 타깃이 경계와 일치하는지 검사용)
    let mut inst_addrs: Vec<u64> = Vec::new();
    // (타깃 VA, 무조건 자기루프 여부, call 여부)
    let mut branch_targets: Vec<(u64, bool, bool)> = Vec::new();

    while decoder.can_decode() {
        let inst = decoder.decode();
        if inst.is_invalid() {
            return Err(anyhow::anyhow!(
                "Found invalid instruction at dispatcher offset 0x{:X}",
                (decoder.ip() - base).saturating_sub(inst.len() as u64)
            )
            .into());
        }
        let ip = decoder.ip() - inst.len() as u64;
        inst_addrs.push(ip);
        valid_insts += 1;

        match inst.flow_control() {
            FlowControl::Return => found_ret = true,
            FlowControl::UnconditionalBranch
            | FlowControl::ConditionalBranch
            | FlowControl::Call => {
                let t = inst.near_branch_target();
                let self_loop =
                    matches!(inst.flow_control(), FlowControl::UnconditionalBranch) && t == ip;
                let is_call = inst.flow_control() == FlowControl::Call;
                branch_targets.push((t, self_loop, is_call));
            }
            _ => {}
        }
    }

    if valid_insts == 0 {
        return Err(anyhow::anyhow!("No valid instructions decoded in dispatcher.").into());
    }

    // ── 1. 분기 타깃 유효성 + 명령 경계 정합 + 무조건 self-loop ────────────────
    for &(t, self_loop, _) in &branch_targets {
        if self_loop {
            return Err(anyhow::anyhow!(
                "Dispatcher has an unconditional self-loop at offset 0x{:X} (encoder/label bug)",
                t.wrapping_sub(base)
            )
            .into());
        }
        if t == 0 {
            return Err(anyhow::anyhow!(
                "Dispatcher has an unpatched placeholder branch target 0 (label not resolved)"
            )
            .into());
        }
        let off = t.wrapping_sub(base);
        if off >= bytes.len() as u64 {
            // 영역 밖: 절대(외부) 타깃만 허용 — VM 모듈/외부 루틴 호출 등.
            if t < 0x10000 {
                return Err(anyhow::anyhow!(
                    "Dispatcher branch target 0x{:X} is outside the region and implausible",
                    t
                )
                .into());
            }
        } else if !inst_addrs.contains(&t) {
            return Err(anyhow::anyhow!(
                "Dispatcher branch target 0x{:X} lands in the middle of an instruction",
                t
            )
            .into());
        }
    }

    // ── 2. call/ret 쌍: in-region call 타깃 서브루틴이 ret에 도달해야 한다 ─────
    for &(t, _, is_call) in &branch_targets {
        if is_call && t >= base && t < base + bytes.len() as u64 {
            if !call_reaches_ret(bytes, t) {
                return Err(anyhow::anyhow!(
                    "Dispatcher call target 0x{:X} does not reach a ret within bounded steps",
                    t
                )
                .into());
            }
        }
    }

    // ── 3. 반환 경로 존재 ──────────────────────────────────────────────────────
    if !found_ret {
        return Err(anyhow::anyhow!("Dispatcher does not contain a ret (return path missing)!" ).into());
    }

    // ── 7. stack-delta: 분기 지점 간 RSP 변화 일관성 ────────────────────────────
    let term_delta = validate_stack_delta(bytes)?;
    let _ = term_delta;

    // ── 9. 간접 분기/점프 테이블 타깃 검증 (num_blocks 모름 → 바운드 체크는
    //      with_base에서 수행) ──────────────────────────────────────────────
    validate_indirect_targets(bytes, 0)?;

    Ok(())
}

/// dispatcher_va / 테이블 레이아웃을 아는 상태에서의 확장 검증.
///
/// `validate_dispatcher`(1-7, 9 구조 검증)에 더해:
///   - **RIP-relative 오프셋(8)** — 실제 dispatcher 영역/테이블을 가리키는지.
///     `memory_displacement64()`가 반환하는 절대 타깃이 `.btg` 섹션
///     [dispatcher_va, dispatcher_va + region_len) 또는 절대 VA ≥ 0x10000
///     안에 있어야 한다.
///   - **점프 테이블 인덱스 바운드 체크(9)** — num_blocks가 주어졌을 때
///     `cmp idx, num_blocks; cmovae` 클램프 존재 확인.
///
/// `region_len` = .btg 섹션의 총 길이(dispatcher_va에서부터). 모르면 0을 주면
/// RIP-relative는 절대 VA ≥ 0x10000만 검증한다.
pub fn validate_dispatcher_with_base(
    bytes: &[u8],
    dispatcher_va: u64,
    region_len: usize,
    num_blocks: usize,
) -> crate::error::Result<()> {
    // 1-7, 9 기본 구조 + stack-delta + 간접(바운드 체크 제외) 검증
    validate_dispatcher(bytes)?;

    // ── 8. RIP-relative 오프셋 검증 ───────────────────────────────────────────
    // 디스패처 코드는 dispatcher_va + 0x20에서 시작 (build.rs의 disp_base_va).
    // RIP-relative disp는 절대 VA로 인코딩되므로 실제 코드 베이스에서 디코드해
    // 타깃을 얻는다.
    let code_base_va = dispatcher_va + 0x20;
    let region = if region_len > 0 {
        Some((dispatcher_va, dispatcher_va.saturating_add(region_len as u64)))
    } else {
        None
    };
    validate_rip_relative(bytes, code_base_va, region)?;

    // ── 9. 점프 테이블 인덱스 바운드 체크 ──────────────────────────────────────
    if num_blocks > 0 {
        let mut decoder = Decoder::with_ip(64, bytes, VALIDATE_BASE, DecoderOptions::NONE);
        let mut has_indexed_table = false;
        while decoder.can_decode() {
            let inst = decoder.decode();
            if inst.is_invalid() {
                break;
            }
            // [rax + idx*4] 형태의 인덱스 접근 탐지 (점프/길이/상태 테이블)
            if inst.op_count() > 0 {
                for op_idx in 0..inst.op_count() {
                    if inst.op_kind(op_idx) == OpKind::Memory {
                        let idx = inst.memory_index();
                        let scale = inst.memory_index_scale();
                        let base_r = inst.memory_base();
                        // base(테이블 시작) + index*4|8: 점프 테이블 룩업
                        if base_r != Register::None && idx != Register::None && (scale == 4 || scale == 8) {
                            has_indexed_table = true;
                        }
                    }
                }
            }
        }
        if has_indexed_table && !has_table_bounds_check(bytes, num_blocks) {
            return Err(anyhow::anyhow!(
                "Dispatcher uses a scaled jump-table index but has no `cmp idx, {}; cmovae` bounds clamp",
                num_blocks
            )
            .into());
        }
    }

    Ok(())
}
