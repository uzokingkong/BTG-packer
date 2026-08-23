// ==============================================================================
// Boot-stub block encoding: measure instruction IPs, resolve branch labels, encode.
// ==============================================================================

use super::bootstub::{BootStubCtx, Label};
use super::ANTI_DEBUG_BLOCK_LEN;
use iced_x86::{BlockEncoder, BlockEncoderOptions, Instruction, InstructionBlock};

fn measure_inst(inst: &Instruction, ip: u64, opts: u32) -> usize {
    let arr = [*inst];
    let block = InstructionBlock::new(&arr, ip);
    match BlockEncoder::encode(64, block, opts) {
        Ok(res) => res.code_buffer.len(),
        Err(_) => {
            // fallback: iced가 측정에 실패하면 명령어 자체 len() 사용
            if inst.len() > 0 {
                inst.len()
            } else {
                5
            }
        }
    }
}

/// import 이름을 per-entry MBA 키로 un-XOR한다 (패커 mba_xor와 동일 키 유도).
/// 키 = MBA::compute_key(mba_master, rbx(=entry index), mba_c, 2); r8을 진행 ptr로
/// 사용하고 이름 ptr(name_reg)은 보존한다. 길이는 ECX. r11d를 키 임시로 사용.

/// 분기 코드 여부 (with_branch로 재생성 가능한 near-branch만)
fn is_branch_code(code: iced_x86::Code) -> bool {
    matches!(
        code,
        iced_x86::Code::Jb_rel32_64
            | iced_x86::Code::Je_rel32_64
            | iced_x86::Code::Jne_rel32_64
            | iced_x86::Code::Jae_rel32_64
            | iced_x86::Code::Jmp_rel32_64
            | iced_x86::Code::Call_rel32_64
    )
}

pub(crate) fn encode_rc4_block(
    seq: &mut Vec<(Instruction, Option<Label>)>,
    stub: &BootStubCtx,
) -> anyhow::Result<Vec<u8>> {
    // 모든 경로에서 분기 최적화(rel8 축소)를 끄고 측정/최종 인코딩을 일치시킨다.
    // (rel8로 측정했다가 최종 레이아웃에서 rel32로 늘어나면 길이 검증이 깨진다.
    //  v6: IAT/mem 블록의 근거리 `je`가 rel8로 축소돼 4바이트 불일치를 일으켰음)
    let enc_opts = BlockEncoderOptions::DONT_FIX_BRANCHES;

    // ── 2. IP 배치 (각 명령을 개별 인코딩해 정확한 길이 측정) ──────────────────
    // anti-debug 블록은 고정 길이이며 rc4 코드는 그 뒤에서 시작한다.
    let rc4_start_va = stub.boot_va
        + if stub.anti_debug {
            ANTI_DEBUG_BLOCK_LEN as u64
        } else {
            0
        };
    let mut ip = rc4_start_va;
    let mut label_ips: std::collections::HashMap<Label, u64> = std::collections::HashMap::new();

    for (inst, lbl) in seq.iter() {
        // 측정 시 분기 타깃은 자기 자신 IP로 설정 (rel32라 길이 불변)
        let mut m = *inst;
        if lbl.is_some() && is_branch_code(inst.code()) {
            m = Instruction::with_branch(inst.code(), ip)
                .map_err(|e| anyhow::anyhow!("boot stub branch re-measure failed: {e}"))?;
        }
        let len = measure_inst(&m, ip, enc_opts);
        if let Some(l) = lbl {
            // 분기 명령어는 타깃 정의가 아니라 참조이므로 label_ips를 덮어쓰면 안 된다.
            if !is_branch_code(inst.code()) {
                label_ips.insert(*l, ip);
            }
        }
        ip += len as u64;
    }

    // ── 3. 분기 타깃 확정 + 전체 인코딩 ───────────────────────────────────────
    for (inst, lbl) in seq.iter_mut() {
        if let Some(l) = lbl {
            if is_branch_code(inst.code()) {
                let target = label_ips.get(&l).copied().ok_or_else(|| {
                    anyhow::anyhow!("boot stub label {:?} referenced but never defined", l)
                })?;
                *inst = Instruction::with_branch(inst.code(), target)
                    .map_err(|e| anyhow::anyhow!("boot stub branch target fix failed: {e}"))?;
            }
        }
    }

    let insts: Vec<Instruction> = seq.iter().map(|(i, _)| *i).collect();
    let block = InstructionBlock::new(&insts, rc4_start_va);
    let enc = BlockEncoder::encode(64, block, enc_opts)
        .map_err(|e| anyhow::anyhow!("boot stub BlockEncoder failed: {e}"))?;
    let code = enc.code_buffer;
    let expected = (ip - rc4_start_va) as usize;
    if code.len() != expected {
        anyhow::bail!(
            "boot stub length mismatch: measured {} vs encoded {}",
            expected,
            code.len()
        );
    }
    Ok(code)
}
