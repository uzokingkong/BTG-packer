use super::registry::*;

pub fn disassemble(code: &[u8]) -> String {
    let mut out = String::new();
    let mut ip = 0usize;
    while ip < code.len() {
        let start = ip;
        let op = code[ip];
        ip += 1;
        let mut line = format!("{:04X}: ", start);
        match op {
            OP_MOV_R_IMM32 => {
                let r = code[ip];
                let imm = u32::from_le_bytes(code[ip + 1..ip + 5].try_into().unwrap());
                ip += 5;
                line += &format!("mov v{}, 0x{:X}", r, imm);
            }
            OP_MOV_R_IMM64 => {
                let r = code[ip];
                let imm = u64::from_le_bytes(code[ip + 1..ip + 9].try_into().unwrap());
                ip += 9;
                line += &format!("mov v{}, 0x{:X}", r, imm);
            }
            OP_MOV_R_R => {
                line += &format!("mov v{}, v{}", code[ip], code[ip + 1]);
                ip += 2;
            }
            OP_XOR_R_R => {
                line += &format!("xor v{}, v{}", code[ip], code[ip + 1]);
                ip += 2;
            }
            OP_ADD_R_R => {
                line += &format!("add v{}, v{}", code[ip], code[ip + 1]);
                ip += 2;
            }
            OP_IMUL_R_R => {
                line += &format!("imul v{}, v{}", code[ip], code[ip + 1]);
                ip += 2;
            }
            OP_SUB_R_R => {
                line += &format!("sub v{}, v{}", code[ip], code[ip + 1]);
                ip += 2;
            }
            OP_AND_R_R => {
                line += &format!("and v{}, v{}", code[ip], code[ip + 1]);
                ip += 2;
            }
            OP_AND_R_IMM32 | OP_XOR_R_IMM32 | OP_ADD_R_IMM32 => {
                let r = code[ip];
                let imm = u32::from_le_bytes(code[ip + 1..ip + 5].try_into().unwrap());
                ip += 5;
                let m = match op {
                    OP_AND_R_IMM32 => "and",
                    OP_XOR_R_IMM32 => "xor",
                    _ => "add",
                };
                line += &format!("{} v{}, 0x{:X}", m, r, imm);
            }
            OP_ROL_R_IMM8 | OP_ROR_R_IMM8 => {
                line += &format!("{} v{}, {}", if op == OP_ROL_R_IMM8 { "rol" } else { "ror" }, code[ip], code[ip + 1]);
                ip += 2;
            }
            OP_INC_R => {
                line += &format!("inc v{}", code[ip]);
                ip += 1;
            }
            OP_DEC_R => {
                line += &format!("dec v{}", code[ip]);
                ip += 1;
            }
            OP_CMP_R_IMM32 => {
                let r = code[ip];
                let imm = u32::from_le_bytes(code[ip + 1..ip + 5].try_into().unwrap());
                ip += 5;
                line += &format!("cmp v{}, 0x{:X}", r, imm);
            }
            OP_MOVZX_R_MEM8 => {
                line += &format!("movzx v{}, mem[{}][v{}]", code[ip], code[ip + 1], code[ip + 2]);
                ip += 3;
            }
            OP_MOV_MEM8_R => {
                line += &format!("mov mem[{}][v{}], v{}", code[ip], code[ip + 1], code[ip + 2]);
                ip += 3;
            }
            OP_JMP8 => {
                let rel = code[ip] as i8;
                ip += 1;
                line += &format!("jmp {:+} (-> {:04X})", rel, (ip as i64 + rel as i64) as usize);
            }
            OP_JB8 => {
                let rel = code[ip] as i8;
                ip += 1;
                line += &format!("jb {:+} (-> {:04X})", rel, (ip as i64 + rel as i64) as usize);
            }
            OP_JCC8 => {
                let cond = code[ip];
                let rel = code[ip + 1] as i8;
                ip += 2;
                let name = match cond {
                    COND_JE => "je", COND_JNE => "jne", COND_JB => "jb", COND_JAE => "jae",
                    COND_JG => "jg", COND_JGE => "jge", COND_JL => "jl", COND_JLE => "jle",
                    COND_JS => "js", COND_JNS => "jns", COND_JO => "jo", COND_JNO => "jno",
                    COND_JP => "jp", COND_JNP => "jnp", COND_JA => "ja", COND_JBE => "jbe", _ => "j??",
                };
                line += &format!("{} {:+} (-> {:04X})", name, rel, (ip as i64 + rel as i64) as usize);
            }
            OP_HALT => line += "halt",
            OP_CLD => line += "cld",
            OP_STD => line += "std",
            // ── M2 disassembly ──────────────────────────────────────────────
            OP_MOV_R_R64 => {
                line += &format!("mov r64 v{}, v{}", code[ip], code[ip + 1]);
                ip += 2;
            }
            OP_ADD_R_R64 | OP_SUB_R_R64 | OP_XOR_R_R64 | OP_AND_R_R64 | OP_IMUL_R_R64 => {
                let m = match op {
                    OP_ADD_R_R64 => "add64", OP_SUB_R_R64 => "sub64", OP_XOR_R_R64 => "xor64",
                    OP_AND_R_R64 => "and64", _ => "imul64",
                };
                line += &format!("{} v{}, v{}", m, code[ip], code[ip + 1]);
                ip += 2;
            }
            OP_ADD_R_IMM64 | OP_XOR_R_IMM64 | OP_AND_R_IMM64 => {
                let r = code[ip];
                let imm = u32::from_le_bytes(code[ip + 1..ip + 5].try_into().unwrap());
                ip += 5;
                let m = match op { OP_ADD_R_IMM64 => "add64", OP_XOR_R_IMM64 => "xor64", _ => "and64" };
                line += &format!("{} v{}, 0x{:X}", m, r, imm);
            }
            OP_SHL_R_IMM8 | OP_SHR_R_IMM8 | OP_SAR_R_IMM8 => {
                let r = code[ip];
                let n = code[ip + 1];
                ip += 2;
                let m = match op { OP_SHL_R_IMM8 => "shl", OP_SHR_R_IMM8 => "shr", _ => "sar" };
                line += &format!("{} v{}, {}", m, r, n);
            }
            OP_SHL_R_CL | OP_SHR_R_CL | OP_SAR_R_CL => {
                let r = code[ip];
                ip += 1;
                let m = match op { OP_SHL_R_CL => "shl", OP_SHR_R_CL => "shr", _ => "sar" };
                line += &format!("{} v{}, cl", m, r);
            }
            OP_TEST_R_R32 => {
                line += &format!("test v{}, v{}", code[ip], code[ip + 1]);
                ip += 2;
            }
            OP_TEST_R_IMM32 => {
                let r = code[ip];
                let imm = u32::from_le_bytes(code[ip + 1..ip + 5].try_into().unwrap());
                ip += 5;
                line += &format!("test v{}, 0x{:X}", r, imm);
            }
            OP_MOVZX_R_MEM16 | OP_MOVZX_R_MEM32 | OP_MOVSX_R_MEM8 | OP_MOVSX_R_MEM16 | OP_MOV_R_MEM64 => {
                let (m, w) = match op {
                    OP_MOVZX_R_MEM16 => ("movzx", 16), OP_MOVZX_R_MEM32 => ("movzx", 32),
                    OP_MOVSX_R_MEM8 => ("movsx", 8), OP_MOVSX_R_MEM16 => ("movsx", 16), _ => ("mov", 64),
                };
                line += &format!("{} v{}, mem[{}][v{}] (u{})", m, code[ip], code[ip + 1], code[ip + 2], w);
                ip += 3;
            }
            OP_MOV_MEM16_R | OP_MOV_MEM32_R | OP_MOV_MEM64_R => {
                let w = match op { OP_MOV_MEM16_R => 16, OP_MOV_MEM32_R => 32, _ => 64 };
                line += &format!("mov mem[{}][v{}], v{} (u{})", code[ip], code[ip + 1], code[ip + 2], w);
                ip += 3;
            }
            // ── M3 disassembly ──────────────────────────────────────────────
            OP_PUSH_R => {
                line += &format!("push v{}", code[ip]);
                ip += 1;
            }
            OP_POP_R => {
                line += &format!("pop v{}", code[ip]);
                ip += 1;
            }
            OP_CALL8 => {
                let rel = code[ip] as i8;
                ip += 1;
                line += &format!("call {:+} (-> {:04X})", rel, (ip as i64 + rel as i64) as usize);
            }
            OP_RET => line += "ret",
            // ── M2 follow-up: addressing modes (v24) ───────────────────────
            OP_LEA => {
                let dst = code[ip];
                let base = code[ip + 1];
                let idx = code[ip + 2];
                let sc = code[ip + 3];
                let disp = i32::from_le_bytes(code[ip + 4..ip + 8].try_into().unwrap());
                ip += 8;
                line += &format!("lea v{}, v{} + {}v{} + 0x{:X}", dst, base, 1i32 << sc, if idx == ADDR_NO_INDEX { 0 } else { idx }, disp);
            }
            OP_SET_RIP => {
                let rip = u64::from_le_bytes(code[ip..ip + 8].try_into().unwrap());
                ip += 8;
                line += &format!("set_rip 0x{:X}", rip);
            }
            OP_LEA_RIP => {
                let dst = code[ip];
                let rel = i32::from_le_bytes(code[ip + 1..ip + 5].try_into().unwrap());
                ip += 5;
                line += &format!("lea_rip v{}, 0x{:X}", dst, rel);
            }
            // ── v43: gs:/fs: 세그먼트(PEB/TEB) ───────────────────────────────
            OP_LEA_GS => {
                let dst = code[ip];
                let disp = i32::from_le_bytes(code[ip + 1..ip + 5].try_into().unwrap());
                ip += 5;
                line += &format!("lea_gs v{}, 0x{:X}", dst, disp);
            }
            OP_MOVZX_R_MEM8_A | OP_MOVZX_R_MEM16_A | OP_MOVZX_R_MEM32_A | OP_MOVSX_R_MEM8_A | OP_MOVSX_R_MEM16_A | OP_MOV_R_MEM64_A => {
                let (m, w) = match op {
                    OP_MOVZX_R_MEM8_A => ("movzx", 8), OP_MOVZX_R_MEM16_A => ("movzx", 16),
                    OP_MOVZX_R_MEM32_A => ("movzx", 32), OP_MOVSX_R_MEM8_A => ("movsx", 8),
                    OP_MOVSX_R_MEM16_A => ("movsx", 16), _ => ("mov", 64),
                };
                line += &format!("{} v{}, [v{}] (u{})", m, code[ip], code[ip + 1], w);
                ip += 2;
            }
            OP_MOV_MEM8_A | OP_MOV_MEM16_A | OP_MOV_MEM32_A | OP_MOV_MEM64_A => {
                let w = match op { OP_MOV_MEM8_A => 8, OP_MOV_MEM16_A => 16, OP_MOV_MEM32_A => 32, _ => 64 };
                line += &format!("mov [v{}], v{} (u{})", code[ip], code[ip + 1], w);
                ip += 2;
            }
            OP_NATIVE_CALL => {
                line += &format!("native_call v{}", code[ip]);
                ip += 1;
            }
            // ── A-2 보강 (v25) ──────────────────────────────────────────────
            OP_OR_R_R | OP_OR_R_R64 => {
                let m = if op == OP_OR_R_R { "or" } else { "or64" };
                line += &format!("{} v{}, v{}", m, code[ip], code[ip + 1]);
                ip += 2;
            }
            OP_OR_R_IMM32 | OP_OR_R_IMM64 => {
                let r = code[ip];
                let imm = u32::from_le_bytes(code[ip + 1..ip + 5].try_into().unwrap());
                ip += 5;
                let m = if op == OP_OR_R_IMM32 { "or" } else { "or64" };
                line += &format!("{} v{}, 0x{:X}", m, r, imm);
            }
            OP_NEG_R | OP_NEG_R64 => {
                line += &format!("{} v{}", if op == OP_NEG_R { "neg" } else { "neg64" }, code[ip]);
                ip += 1;
            }
            OP_NOT_R | OP_NOT_R64 => {
                line += &format!("{} v{}", if op == OP_NOT_R { "not" } else { "not64" }, code[ip]);
                ip += 1;
            }
            OP_SHL64_R_IMM8 | OP_SHR64_R_IMM8 | OP_SAR64_R_IMM8 => {
                let r = code[ip];
                let n = code[ip + 1];
                ip += 2;
                let m = match op { OP_SHL64_R_IMM8 => "shl64", OP_SHR64_R_IMM8 => "shr64", _ => "sar64" };
                line += &format!("{} v{}, {}", m, r, n);
            }
            OP_SHL64_R_CL | OP_SHR64_R_CL | OP_SAR64_R_CL => {
                let r = code[ip];
                ip += 1;
                let m = match op { OP_SHL64_R_CL => "shl64", OP_SHR64_R_CL => "shr64", _ => "sar64" };
                line += &format!("{} v{}, cl", m, r);
            }
            OP_JMP32 => {
                let rel = i32::from_le_bytes(code[ip..ip+4].try_into().unwrap());
                ip += 4;
                line += &format!("jmp32 {:+} (-> {:08X})", rel, (ip as i64 + rel as i64) as usize);
            }
            OP_JCC32 => {
                let cond = code[ip];
                let rel = i32::from_le_bytes(code[ip+1..ip+5].try_into().unwrap());
                ip += 5;
                let name = match cond {
                    COND_JE => "je", COND_JNE => "jne", COND_JB => "jb", COND_JAE => "jae",
                    COND_JG => "jg", COND_JGE => "jge", COND_JL => "jl", COND_JLE => "jle",
                    COND_JS => "js", COND_JNS => "jns", COND_JO => "jo", COND_JNO => "jno",
                    COND_JP => "jp", COND_JNP => "jnp", COND_JA => "ja", COND_JBE => "jbe", _ => "j??",
                };
                line += &format!("{}32 {:+} (-> {:08X})", name, rel, (ip as i64 + rel as i64) as usize);
            }
            OP_CALL32 => {
                let rel = i32::from_le_bytes(code[ip..ip+4].try_into().unwrap());
                ip += 4;
                line += &format!("call32 {:+} (-> {:08X})", rel, (ip as i64 + rel as i64) as usize);
            }
            OP_NOP => line += "nop",
            OP_MOVSD_XMM_MEM => { line += &format!("movsd xmm{}, [v{}]", code[ip], code[ip+1]); ip += 2; }
            OP_MOVSD_MEM_XMM => { line += &format!("movsd [v{}], xmm{}", code[ip], code[ip+1]); ip += 2; }
            OP_MOVUPS_XMM_MEM => { line += &format!("movups xmm{}, [v{}]", code[ip], code[ip+1]); ip += 2; }
            OP_MOVUPS_MEM_XMM => { line += &format!("movups [v{}], xmm{}", code[ip], code[ip+1]); ip += 2; }
            OP_UNPCKLPD_XMM => { line += &format!("unpcklpd xmm{}, xmm{}", code[ip], code[ip+1]); ip += 2; }
            OP_UNPCKLPS_XMM => { line += &format!("unpcklps xmm{}, xmm{}", code[ip], code[ip+1]); ip += 2; }
            OP_XORPS_XMM => { line += &format!("xorps xmm{}, xmm{}", code[ip], code[ip+1]); ip += 2; }
            OP_PSHUFLW_XMM => { line += &format!("pshuflw xmm{}, xmm{}, 0x{:02X}", code[ip], code[ip+1], code[ip+2]); ip += 3; }
            OP_PSHUFHW_XMM => { line += &format!("pshufhw xmm{}, xmm{}, 0x{:02X}", code[ip], code[ip+1], code[ip+2]); ip += 3; }
            OP_PSHUFD_XMM => { line += &format!("pshufd xmm{}, xmm{}, 0x{:02X}", code[ip], code[ip+1], code[ip+2]); ip += 3; }
            OP_BSR_R32 | OP_BSR_R64 | OP_BSF_R32 | OP_BSF_R64 => {
                let m = match op { OP_BSR_R32 => "bsr32", OP_BSR_R64 => "bsr64", OP_BSF_R32 => "bsf32", _ => "bsf64" };
                line += &format!("{} v{}, v{}", m, code[ip], code[ip+1]); ip += 2;
            }
            OP_MOVQ_XMM_GPR => { line += &format!("movq v{}, xmm{}", code[ip], code[ip+1]); ip += 2; }
            OP_MOVQ_GPR_XMM => { line += &format!("movq xmm{}, v{}", code[ip], code[ip+1]); ip += 2; }
            OP_PSRLQ_XMM_IMM8 => { line += &format!("psrlq xmm{}, 0x{:02X}", code[ip], code[ip+1]); ip += 2; }
            OP_PSLLQ_XMM_IMM8 => { line += &format!("psllq xmm{}, 0x{:02X}", code[ip], code[ip+1]); ip += 2; }
            // ── v54: SSE/FPU (Group A) ──────────────────────────────────────
            OP_ADDSS_XMM | OP_ADDSD_XMM | OP_SUBSS_XMM | OP_SUBSD_XMM
            | OP_MULSS_XMM | OP_MULSD_XMM | OP_DIVSS_XMM | OP_DIVSD_XMM => {
                let m = match op {
                    OP_ADDSS_XMM => "addss", OP_ADDSD_XMM => "addsd",
                    OP_SUBSS_XMM => "subss", OP_SUBSD_XMM => "subsd",
                    OP_MULSS_XMM => "mulss", OP_MULSD_XMM => "mulsd",
                    OP_DIVSS_XMM => "divss", _ => "divsd",
                };
                line += &format!("{} xmm{}, xmm{}", m, code[ip], code[ip+1]); ip += 2;
            }
            OP_PAND_XMM | OP_POR_XMM | OP_PANDN_XMM => {
                let m = match op { OP_PAND_XMM => "pand", OP_POR_XMM => "por", _ => "pandn" };
                line += &format!("{} xmm{}, xmm{}", m, code[ip], code[ip+1]); ip += 2;
            }
            OP_CVTSI2SD_XMM | OP_CVTSI2SS_XMM => {
                let m = if op == OP_CVTSI2SD_XMM { "cvtsi2sd" } else { "cvtsi2ss" };
                line += &format!("{} xmm{}, v{}", m, code[ip], code[ip+1]); ip += 2;
            }
            OP_CVTSS2SD_XMM | OP_CVTSD2SS_XMM => {
                let m = if op == OP_CVTSS2SD_XMM { "cvtss2sd" } else { "cvtsd2ss" };
                line += &format!("{} xmm{}, xmm{}", m, code[ip], code[ip+1]); ip += 2;
            }
            OP_CVTTSS2SI | OP_CVTTSD2SI | OP_CVTSS2SI | OP_CVTSD2SI => {
                let m = match op {
                    OP_CVTTSS2SI => "cvttss2si", OP_CVTTSD2SI => "cvttsd2si",
                    OP_CVTSS2SI => "cvtss2si", _ => "cvtsd2si",
                };
                line += &format!("{} v{}, xmm{}", m, code[ip], code[ip+1]); ip += 2;
            }
            OP_PEXTRD_XMM => { line += &format!("pextrd v{}, xmm{}, 0x{:02X}", code[ip], code[ip+1], code[ip+2]); ip += 3; }
            OP_PINSRD_XMM => { line += &format!("pinsrd xmm{}, v{}, 0x{:02X}", code[ip], code[ip+1], code[ip+2]); ip += 3; }
            OP_LOCK_INC_MEM8_A | OP_LOCK_INC_MEM16_A | OP_LOCK_INC_MEM32_A | OP_LOCK_INC_MEM64_A => {
                let w = match op { OP_LOCK_INC_MEM8_A => 8, OP_LOCK_INC_MEM16_A => 16, OP_LOCK_INC_MEM32_A => 32, _ => 64 };
                line += &format!("lock inc{} [v{}]", w, code[ip]); ip += 1;
            }
            OP_LOCK_DEC_MEM8_A | OP_LOCK_DEC_MEM16_A | OP_LOCK_DEC_MEM32_A | OP_LOCK_DEC_MEM64_A => {
                let w = match op { OP_LOCK_DEC_MEM8_A => 8, OP_LOCK_DEC_MEM16_A => 16, OP_LOCK_DEC_MEM32_A => 32, _ => 64 };
                line += &format!("lock dec{} [v{}]", w, code[ip]); ip += 1;
            }
            // ── v31: multiply/divide + BSWAP ──────────────────────────────
            OP_MUL_R_R32 | OP_MUL_R_R64 => {
                let w = if op == OP_MUL_R_R32 { "mul32" } else { "mul64" };
                line += &format!("{} v{}", w, code[ip]); ip += 1;
            }
            OP_IMUL1_R_R32 | OP_IMUL1_R_R64 => {
                let w = if op == OP_IMUL1_R_R32 { "imul32" } else { "imul64" };
                line += &format!("{} v{}", w, code[ip]); ip += 1;
            }
            OP_DIV_R_R32 | OP_DIV_R_R64 => {
                let w = if op == OP_DIV_R_R32 { "div32" } else { "div64" };
                line += &format!("{} v{}", w, code[ip]); ip += 1;
            }
            OP_IDIV_R_R32 | OP_IDIV_R_R64 => {
                let w = if op == OP_IDIV_R_R32 { "idiv32" } else { "idiv64" };
                line += &format!("{} v{}", w, code[ip]); ip += 1;
            }
            OP_BSWAP_R32 | OP_BSWAP_R64 => {
                let w = if op == OP_BSWAP_R32 { "bswap32" } else { "bswap64" };
                line += &format!("{} v{}", w, code[ip]); ip += 1;
            }
            // ── v33: 8/16-bit 1-op multiply/divide ──────────────────────────
            OP_MUL_R_R8 | OP_MUL_R_R16 => {
                let w = if op == OP_MUL_R_R8 { "mul8" } else { "mul16" };
                line += &format!("{} v{}", w, code[ip]); ip += 1;
            }
            OP_IMUL1_R_R8 | OP_IMUL1_R_R16 => {
                let w = if op == OP_IMUL1_R_R8 { "imul8" } else { "imul16" };
                line += &format!("{} v{}", w, code[ip]); ip += 1;
            }
            OP_DIV_R_R8 | OP_DIV_R_R16 => {
                let w = if op == OP_DIV_R_R8 { "div8" } else { "div16" };
                line += &format!("{} v{}", w, code[ip]); ip += 1;
            }
            OP_IDIV_R_R8 | OP_IDIV_R_R16 => {
                let w = if op == OP_IDIV_R_R8 { "idiv8" } else { "idiv16" };
                line += &format!("{} v{}", w, code[ip]); ip += 1;
            }
            _ => {
                line += &format!("?? op=0x{:02X}", op);
                break;
            }
        }
        out.push_str(&line);
        out.push('\n');
    }
    out
}

