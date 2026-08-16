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
// ==============================================================================

use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction};

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

/// 디스패처 바이트열의 상용급 구조 검증.
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
        return Err(anyhow::anyhow!("Dispatcher does not contain a ret (return path missing)!").into());
    }

    Ok(())
}
