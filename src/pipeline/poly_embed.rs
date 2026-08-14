// ==============================================================================
// BTG - Commercial-Grade VM: T1-3 Polymorphic VM Stub Embedding
// ==============================================================================
// `SelectiveVmPass` lifts SDK-marker regions to RISC, encodes them to a rolling-key
// polymorphic bytecode, and stores the results in `PipelineContext.poly_vm_regions`.
// Until now that data was *preserved but never planted* — the output PE carried no
// trace of the VM. This module closes that gap (T1-3 "섹션 심기 + 트램펄린 패치"):
//
//   * `emit_poly_vm_section` builds a new `.btgvm` PE section that physically embeds:
//       1. a native VM entry stub (Win64 callee-saved save + ABI setup + tail dispatch),
//       2. a 256 x u64 native handler table (opcode -> handler VA),
//       3. the direct-threaded native handler code (DirectThreadedNativeRunner),
//       4. a region descriptor table (region_va, seed, bytecode offset/length, lifted ops),
//       5. the concatenated polymorphic bytecodes + a zeroed VM state buffer.
//   * `patch_marker_trampolines` replaces each marker region's start in `.text` with a
//     `jmp` to the VM entry stub, so a marker-instrumented target's protected region
//     is redirected into the VM module at runtime.
//
// NOTE on runtime scope: the rolling-key *native interpreter* that actually consumes
// the polymorphic bytecode stream is the separate T1-4 item. This T1-3 deliverable is
// the data-path embedding — the bytecode/seed/handler module now physically lives in
// the output PE (previously it was computed and dropped), and the trampoline redirect
// is in place. Execution correctness of the encrypted stream is wired next.
// ==============================================================================

use crate::pe::builder::SectionData;
use crate::pipeline::selective_vm::PolyVmRegion;
use crate::vm::threaded::{DirectTailEmitter, DirectThreadedNativeRunner};
use anyhow::{anyhow, Result};
use iced_x86::{Code, Instruction, Register};

/// `.btgvm` section magic (LE "BTVM").
pub const VM_SECTION_MAGIC: u32 = 0x4D_56_54_42;
pub const VM_SECTION_VERSION: u32 = 1;

// ── Fixed offsets within the .btgvm section (relative to section VA) ─────────
pub const OFF_ENTRY_STUB: usize = 0x0000;   // native entry stub
pub const OFF_HEADER: usize = 0x400;        // 16-byte header (clear of entry stub)
pub const OFF_HANDLER_TABLE: usize = 0x0800; // 256 x u64
pub const OFF_REGION_TABLE: usize = 0x1000; // N x 32 bytes
pub const OFF_HANDLER_CODE: usize = 0x2000; // direct-threaded handler bodies
pub const REGION_DESC_SIZE: usize = 32;

/// Region descriptor (fixed 32 bytes, LE).
/// Layout: [region_va u64][seed u64][bytecode_off u32][bytecode_len u32][lifted_ops u32][reserved u32]
#[derive(Debug, Clone)]
pub struct RegionDesc {
    pub region_va: u64,
    pub seed: u64,
    pub bytecode_off: u32,
    pub bytecode_len: u32,
    pub lifted_ops: u32,
}

impl RegionDesc {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(REGION_DESC_SIZE);
        b.extend_from_slice(&self.region_va.to_le_bytes());
        b.extend_from_slice(&self.seed.to_le_bytes());
        b.extend_from_slice(&self.bytecode_off.to_le_bytes());
        b.extend_from_slice(&self.bytecode_len.to_le_bytes());
        b.extend_from_slice(&self.lifted_ops.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes()); // reserved
        b
    }
}

/// The result of planting the VM stub: the `.btgvm` section plus the VAs the
/// trampoline patch needs.
#[derive(Debug, Clone)]
pub struct PolyVmEmbed {
    pub section: SectionData,
    /// Absolute VA of the VM entry stub (offset 0 of the section).
    pub entry_va: u64,
    /// Absolute VA of the native handler table.
    pub table_va: u64,
    /// Absolute VA of the first region's bytecode blob.
    pub first_bytecode_va: u64,
    /// Absolute VA of the zeroed VM state buffer.
    pub state_va: u64,
}

/// Build the `.btgvm` section payload for the given regions and placement.
///
/// `section_rva` is the RVA the caller has reserved for this new section;
/// `image_base` is the target image base. Handler/table/bytecode absolute VAs are
/// derived from `image_base + section_rva` so the embedded stub is self-consistent.
pub fn emit_poly_vm_section(
    regions: &[PolyVmRegion],
    image_base: u64,
    section_rva: u32,
    _section_alignment: u32,
) -> Result<PolyVmEmbed> {
    if regions.is_empty() {
        return Err(anyhow!("emit_poly_vm_section: no poly VM regions to embed"));
    }
    let section_va = image_base + section_rva as u64;

    // Build handler code + table.
    let handler_base_va = section_va + OFF_HANDLER_CODE as u64;
    let handlers = DirectThreadedNativeRunner::build_all_handlers(handler_base_va)?;
    let table_va = section_va + OFF_HANDLER_TABLE as u64;

    let mut handler_code = Vec::new();
    for (_name, _va, code) in &handlers {
        handler_code.extend_from_slice(code);
    }

    // State buffer after handler code (aligned).
    let state_off = align_up(OFF_HANDLER_CODE + handler_code.len(), 16);
    let state_va = section_va + state_off as u64;

    // Bytecode blobs after the state buffer (aligned).
    let mut bc_cursor = align_up(state_off + 0x100, 16);
    let mut region_descs: Vec<RegionDesc> = Vec::with_capacity(regions.len());
    let mut first_bytecode_va = 0u64;
    for (i, r) in regions.iter().enumerate() {
        let off = bc_cursor as u32;
        region_descs.push(RegionDesc {
            region_va: r.region_va,
            seed: r.seed,
            bytecode_off: off,
            bytecode_len: r.bytecode.len() as u32,
            lifted_ops: r.lifted_ops as u32,
        });
        if i == 0 {
            first_bytecode_va = section_va + off as u64;
        }
        bc_cursor = align_up(bc_cursor + r.bytecode.len(), 16);
    }

    let total = align_up(bc_cursor, 0x1000);
    let mut buf = vec![0u8; total];

    // Header (16 bytes at OFF_HEADER): magic, version, num_regions, reserved.
    let hdr = OFF_HEADER;
    buf[hdr..hdr + 4].copy_from_slice(&VM_SECTION_MAGIC.to_le_bytes());
    buf[hdr + 4..hdr + 8].copy_from_slice(&VM_SECTION_VERSION.to_le_bytes());
    buf[hdr + 8..hdr + 12].copy_from_slice(&(regions.len() as u32).to_le_bytes());
    buf[hdr + 12..hdr + 16].copy_from_slice(&0u32.to_le_bytes());

    // Entry stub (offset 0x00).
    {
        let mut es = Vec::new();
        for r in [Register::R12, Register::R13, Register::R14, Register::R15] {
            es.push(Instruction::with1(Code::Push_r64, r).map_err(|e| anyhow!("{e}"))?);
        }
        es.push(Instruction::with2(Code::Mov_r64_imm64, Register::R12, first_bytecode_va).map_err(|e| anyhow!("{e}"))?);
        es.push(Instruction::with2(Code::Mov_r64_imm64, Register::R13, state_va).map_err(|e| anyhow!("{e}"))?);
        let seed_key = regions[0].seed as u8;
        es.push(Instruction::with2(Code::Mov_r64_imm64, Register::R14, seed_key as u64).map_err(|e| anyhow!("{e}"))?);
        es.push(Instruction::with2(Code::Mov_r64_imm64, Register::R15, table_va).map_err(|e| anyhow!("{e}"))?);
        es.push(Instruction::with2(Code::Mov_r64_imm64, Register::RDX, state_va).map_err(|e| anyhow!("{e}"))?);
        DirectTailEmitter::emit_tail_dispatch(&mut es)?;
        let bytes = DirectTailEmitter::assemble(es, section_va)?;
        let n = bytes.len().min(OFF_HANDLER_TABLE - OFF_ENTRY_STUB);
        buf[OFF_ENTRY_STUB..OFF_ENTRY_STUB + n].copy_from_slice(&bytes[..n]);
    }

    // Handler table (256 x u64) at OFF_HANDLER_TABLE.
    {
        let entry_va = section_va + OFF_ENTRY_STUB as u64;
        // Known handlers occupy opcode slots 0..handlers.len().
        for (i, (_name, va, _code)) in handlers.iter().enumerate() {
            let e = i * 8;
            if OFF_HANDLER_TABLE + e + 8 <= buf.len() {
                buf[OFF_HANDLER_TABLE + e..OFF_HANDLER_TABLE + e + 8].copy_from_slice(&va.to_le_bytes());
            }
        }
        // Unused slots -> entry stub (safe landing).
        for i in handlers.len()..256 {
            let e = i * 8;
            if OFF_HANDLER_TABLE + e + 8 <= buf.len() {
                buf[OFF_HANDLER_TABLE + e..OFF_HANDLER_TABLE + e + 8].copy_from_slice(&entry_va.to_le_bytes());
            }
        }
    }

    // Region descriptor table at OFF_REGION_TABLE.
    for (i, d) in region_descs.iter().enumerate() {
        let off = OFF_REGION_TABLE + i * REGION_DESC_SIZE;
        if off + REGION_DESC_SIZE <= buf.len() {
            buf[off..off + REGION_DESC_SIZE].copy_from_slice(&d.to_bytes());
        }
    }

    // Handler code at OFF_HANDLER_CODE.
    buf[OFF_HANDLER_CODE..OFF_HANDLER_CODE + handler_code.len()].copy_from_slice(&handler_code);

    // Bytecode blobs (same cursor as region_descs recorded).
    let mut cursor = align_up(state_off + 0x100, 16);
    for r in regions.iter() {
        let off = align_up(cursor, 16);
        if off + r.bytecode.len() <= buf.len() {
            buf[off..off + r.bytecode.len()].copy_from_slice(&r.bytecode);
        }
        cursor = off + r.bytecode.len();
    }

    let section = SectionData {
        name: ".btgvm".to_string(),
        virtual_address: section_rva,
        virtual_size: total as u32,
        characteristics: 0xE000_0020, // CODE | EXECUTE | READ | WRITE
        bytes: buf,
    };

    Ok(PolyVmEmbed {
        entry_va: section_va,
        table_va,
        first_bytecode_va,
        state_va,
        section,
    })
}

/// Patch each marker region's start in `.text` with a `jmp` to the VM entry stub.
///
/// `text_section` is the (mutated) `.text` SectionData from `ctx.patched_sections`.
/// For each region, the 5 bytes at `start_offset` are replaced with `E9 rel32`
/// targeting `embed.entry_va`. Returns the number of trampolines written.
pub fn patch_marker_trampolines(
    regions: &[PolyVmRegion],
    text_section: &mut SectionData,
    image_base: u64,
    text_rva: u32,
    entry_va: u64,
) -> Result<usize> {
    let mut written = 0usize;
    for r in regions {
        let src_va = image_base + text_rva as u64 + r.start_offset as u64;
        // rel32 = target - (src + 5)
        let rel = entry_va.wrapping_sub(src_va.wrapping_add(5));
        let off = r.start_offset;
        if off + 5 <= text_section.bytes.len() {
            text_section.bytes[off] = 0xE9;
            text_section.bytes[off + 1..off + 5].copy_from_slice(&(rel as u32).to_le_bytes());
            written += 1;
        } else {
            return Err(anyhow!(
                "trampoline patch: region at offset 0x{:X} does not fit 5-byte jmp in .text (len {})",
                off,
                text_section.bytes.len()
            ));
        }
    }
    Ok(written)
}

fn align_up(v: usize, a: usize) -> usize {
    (v + a - 1) & !(a - 1)
}

/// High-level pipeline integration: embed the `.btgvm` module into the finished
/// `.textb` section (append to its tail — `.textb` is RWX) and patch the marker
/// trampolines in `.text`.
///
/// Returns `None` when there are no poly VM regions (no SDK markers / `--vm` off),
/// in which case the output is byte-identical to before. Otherwise the `.btgvm`
/// module is appended to the `.textb` tail and the entry VA is recorded.
pub fn embed_poly_vm_into_pipeline(ctx: &mut crate::pipeline::PipelineContext) -> Result<Option<u64>> {
    let regions = &ctx.poly_vm_regions;
    if regions.is_empty() {
        return Ok(None);
    }
    let btg = ctx
        .btg_section_data
        .as_mut()
        .ok_or_else(|| anyhow!("poly_embed: btg_section_data not set"))?;

    // Append the module at the current tail of .textb.
    let section_rva = btg.virtual_address.saturating_add(btg.bytes.len() as u32);
    let section_alignment = ctx.target_info.section_alignment.max(0x1000);
    let embed = emit_poly_vm_section(regions, ctx.target_info.image_base, section_rva, section_alignment)?;
    let entry_va = embed.entry_va;

    // Append the module bytes to the .textb section.
    let tail = btg.bytes.len();
    let grow = align_up(embed.section.bytes.len(), 0x10);
    btg.bytes.resize(tail + grow, 0);
    btg.bytes[tail..tail + embed.section.bytes.len()].copy_from_slice(&embed.section.bytes);
    btg.virtual_size = btg.bytes.len() as u32;

    // Patch marker trampolines in the `.text` section of patched_sections.
    let text_rva = ctx.target_info.text_rva;
    let image_base = ctx.target_info.image_base;
    let n_tramp = if let Some(text) = ctx.patched_sections.iter_mut().find(|s| {
        s.name == ".text"
            || (text_rva >= s.virtual_address
                && text_rva < s.virtual_address + s.virtual_size.max(s.bytes.len() as u32))
    }) {
        patch_marker_trampolines(regions, text, image_base, text_rva, entry_va)?
    } else {
        0
    };

    println!(
        "[+] T1-3 Poly VM embed: .btgvm module ({} regions, {}B) appended to .textb tail @RVA 0x{:X}; VM entry VA 0x{:X}; {} marker trampoline(s) patched",
        regions.len(),
        embed.section.bytes.len(),
        section_rva,
        entry_va,
        n_tramp
    );

    // Keep the generated module around for validation/debugging.
    ctx.poly_vm_section = Some(embed.section);
    ctx.poly_vm_entry_va = entry_va;
    Ok(Some(entry_va))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sdk::{SIG_VM_END, SIG_VM_START};
    use crate::vm::poly::PolymorphicEncoder;
    use crate::vm::risc::{MicroInstr, MicroOperand, RiscDesynthesizer, RiscOp, RiscProgram};
    use iced_x86::{Decoder, DecoderOptions};

    fn make_region(region_va: u64, seed: u64, lifted_ops: usize) -> PolyVmRegion {
        let mut d = RiscDesynthesizer::new();
        d.emit_add(MicroOperand::VReg(0), MicroOperand::Imm64(0x200), MicroOperand::Imm64(0));
        d.emit_add(MicroOperand::VReg(1), MicroOperand::Imm64(5), MicroOperand::Imm64(0));
        d.emit_xor(MicroOperand::VReg(0), MicroOperand::VReg(0), MicroOperand::Imm64(0x55));
        d.instrs.push(MicroInstr::new(RiscOp::Halt));
        let prog = RiscProgram::new(d.instrs);
        let mut enc = PolymorphicEncoder::new(seed);
        let bytecode = enc.encode(&prog).unwrap();
        PolyVmRegion {
            start_offset: 0x40,
            end_offset: 0x60,
            lifted_ops: lifted_ops.max(prog.instrs.len()),
            bytecode,
            seed,
            region_va,
        }
    }

    #[test]
    fn test_emit_poly_vm_section_layout() {
        let regions = vec![
            make_region(0x140001100, 0x1111222233334444, 4),
            make_region(0x140001160, 0xAAAABBBBCCCCDDDD, 4),
        ];
        let embed = emit_poly_vm_section(&regions, 0x140000000, 0x7000, 0x1000).unwrap();

        assert_eq!(embed.section.name, ".btgvm");
        assert_eq!(embed.section.virtual_address, 0x7000);
        assert_eq!(
            u32::from_le_bytes(embed.section.bytes[OFF_HEADER..OFF_HEADER + 4].try_into().unwrap()),
            VM_SECTION_MAGIC
        );
        assert_eq!(
            u32::from_le_bytes(embed.section.bytes[OFF_HEADER + 8..OFF_HEADER + 12].try_into().unwrap()),
            2
        );
        assert_eq!(embed.section.bytes[OFF_ENTRY_STUB], 0x41);
        assert!(embed.section.bytes.len() > OFF_HANDLER_TABLE + 256 * 8);
        let code = &embed.section.bytes[OFF_HANDLER_CODE..OFF_HANDLER_CODE + 32];
        assert!(code.iter().any(|&b| b != 0));

        let d0 = RegionDesc {
            region_va: u64::from_le_bytes(
                embed.section.bytes[OFF_REGION_TABLE..OFF_REGION_TABLE + 8].try_into().unwrap(),
            ),
            seed: u64::from_le_bytes(
                embed.section.bytes[OFF_REGION_TABLE + 8..OFF_REGION_TABLE + 16].try_into().unwrap(),
            ),
            bytecode_off: u32::from_le_bytes(
                embed.section.bytes[OFF_REGION_TABLE + 16..OFF_REGION_TABLE + 20].try_into().unwrap(),
            ),
            bytecode_len: u32::from_le_bytes(
                embed.section.bytes[OFF_REGION_TABLE + 20..OFF_REGION_TABLE + 24].try_into().unwrap(),
            ),
            lifted_ops: 0,
        };
        assert_eq!(d0.region_va, 0x140001100);
        assert_eq!(d0.seed, 0x1111222233334444);
        assert_eq!(d0.bytecode_len, regions[0].bytecode.len() as u32);
        let blob = &embed.section.bytes[d0.bytecode_off as usize..d0.bytecode_off as usize + d0.bytecode_len as usize];
        assert_eq!(blob, regions[0].bytecode.as_slice());

        let mut dec = Decoder::with_ip(64, &embed.section.bytes[OFF_ENTRY_STUB..OFF_ENTRY_STUB + 16], embed.entry_va, DecoderOptions::NONE);
        assert!(dec.can_decode());
    }

    #[test]
    fn test_patch_marker_trampoline_emits_jmp_to_entry() {
        let mut text = Vec::new();
        text.extend_from_slice(&[0x90, 0x90]);
        text.extend_from_slice(&SIG_VM_START);
        text.extend_from_slice(&[0x48, 0xFF, 0xC0, 0xC3]); // inc rax; ret
        text.extend_from_slice(&SIG_VM_END);
        text.extend_from_slice(&[0x90]);

        let regions = vec![PolyVmRegion {
            start_offset: 2 + SIG_VM_START.len(),
            end_offset: 2 + SIG_VM_START.len() + 4,
            lifted_ops: 2,
            bytecode: vec![0x11, 0x22, 0x33],
            seed: 42,
            region_va: 0x140001010,
        }];

        let mut sec = SectionData {
            name: ".text".to_string(),
            virtual_address: 0x1000,
            virtual_size: text.len() as u32,
            characteristics: 0x6000_0020,
            bytes: text.clone(),
        };
        let entry_va = 0x140007000;
        let n = patch_marker_trampolines(&regions, &mut sec, 0x140000000, 0x1000, entry_va).unwrap();
        assert_eq!(n, 1);

        let off = regions[0].start_offset;
        assert_eq!(sec.bytes[off], 0xE9);
        let rel = i32::from_le_bytes(sec.bytes[off + 1..off + 5].try_into().unwrap());
        let src = 0x140000000u64 + 0x1000 + off as u64;
        let target = (src as i64 + 5 + rel as i64) as u64;
        assert_eq!(target, entry_va);
    }
}
