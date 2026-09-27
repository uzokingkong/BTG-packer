#!/usr/bin/env python3
from pathlib import Path

ROOT = Path.cwd()
BUILDER = ROOT / "src/vm/threaded/poly_direct/builder.rs"
VMBUILD = ROOT / "src/pipeline/crypto/place/vm_build.rs"

def to_lf(s):
    return s.replace("\r\n", "\n").replace("\r", "\n")

def edit(path, replacements):
    if not path.exists():
        raise SystemExit(f"missing file: {path}")
    raw = path.read_bytes()
    text = raw.decode("utf-8")
    crlf = "\r\n" in text
    text_lf = to_lf(text)
    original_lf = text_lf

    for label, old, new in replacements:
        old = to_lf(old)
        new = to_lf(new)
        count = text_lf.count(old)
        if count == 0 and new in text_lf:
            print(f"[already applied] {label}")
            continue
        if count != 1:
            raise SystemExit(f"{path}: anchor '{label}' expected once, found {count}")
        text_lf = text_lf.replace(old, new, 1)
        print(f"[patched] {label}")

    if text_lf != original_lf:
        backup = path.with_suffix(path.suffix + ".btgfix.bak")
        if not backup.exists():
            backup.write_bytes(raw)
        out = text_lf.replace("\n", "\r\n") if crlf else text_lf
        path.write_bytes(out.encode("utf-8"))

builder_repls = [
("nonvolatile pointer table",
"""const STATE_CROSS_FAMILY_VOLATILE_PTRS: [(usize, i64); 6] = [
    (1, 0x5020),  // RCX
    (2, 0x5028),  // RDX
    (8, 0x5030),  // R8
    (9, 0x5038),  // R9
    (10, 0x5040), // R10
    (11, 0x5048), // R11
];
const STATE_CROSS_FAMILY_FLAGS_PTR: i64 = 0x5050;""",
"""const STATE_CROSS_FAMILY_VOLATILE_PTRS: [(usize, i64); 6] = [
    (1, 0x5020),  // RCX
    (2, 0x5028),  // RDX
    (8, 0x5030),  // R8
    (9, 0x5038),  // R9
    (10, 0x5040), // R10
    (11, 0x5048), // R11
];
// A generated-family transition is an internal VM boundary rather than an
// ordinary Win64 ABI call. Keep authoritative child-state pointers for the
// guest registers which are native-nonvolatile so tail-jumps and nested family
// routes can publish their final architectural values back to the parent.
const STATE_CROSS_FAMILY_NONVOLATILE_PTRS: [(usize, i64); 9] = [
    (3, 0x50C0),  // RBX
    (4, 0x50C8),  // RSP
    (5, 0x50D0),  // RBP
    (6, 0x50D8),  // RSI
    (7, 0x50E0),  // RDI
    (12, 0x50E8), // R12
    (13, 0x50F0), // R13
    (14, 0x50F8), // R14
    (15, 0x5100), // R15
];
const STATE_CROSS_FAMILY_FLAGS_PTR: i64 = 0x5050;"""),
("route child-state pointer arm",
"""            for (index, return_ptr_off) in std::iter::once((0, STATE_CROSS_FAMILY_RETURN_PTR))
                .chain(STATE_CROSS_FAMILY_VOLATILE_PTRS)
            {""",
"""            for (index, return_ptr_off) in std::iter::once((0, STATE_CROSS_FAMILY_RETURN_PTR))
                .chain(STATE_CROSS_FAMILY_VOLATILE_PTRS)
                .chain(STATE_CROSS_FAMILY_NONVOLATILE_PTRS)
            {"""),
("nonvolatile child-state sync-back",
"""            // Generated children publish architectural flags through their
            // state. Physical RFLAGS at HALT belongs to the dispatcher.""",
"""            // Generated children can return through a tail-jump/nested family
            // route, so native ABI nonvolatile preservation is not sufficient
            // to reconstruct the parent VM state. If route setup armed one of
            // these child-state pointers, sync the authoritative child guest
            // value back and clear the transient pointer.
            for (index, ptr_off) in STATE_CROSS_FAMILY_NONVOLATILE_PTRS {
                b.push(
                    Instruction::with2(
                        Code::Mov_r64_rm64,
                        Register::RDI,
                        MemoryOperand::with_base_displ_size(Register::RBX, ptr_off, 8),
                    )
                    .unwrap(),
                );
                b.push(
                    Instruction::with2(Code::Test_rm64_r64, Register::RDI, Register::RDI)
                        .unwrap(),
                );
                let skip = 0xC200_0000usize + index;
                b.br(Code::Je_rel32_64, skip);
                b.push(
                    Instruction::with2(
                        Code::Mov_r64_rm64,
                        Register::RAX,
                        MemoryOperand::with_base(Register::RDI),
                    )
                    .unwrap(),
                );
                b.push(
                    Instruction::with2(
                        Code::Mov_rm64_imm32,
                        MemoryOperand::with_base_displ_size(Register::RBX, ptr_off, 8),
                        0,
                    )
                    .unwrap(),
                );
                b.push(
                    Instruction::with2(
                        Code::Mov_rm64_r64,
                        MemoryOperand::with_base_displ_size(
                            Register::RBX,
                            state_disp(REGS_OFF + index as i32 * 8) as i64,
                            8,
                        ),
                        Register::RAX,
                    )
                    .unwrap(),
                );
                let synced = b.len();
                for &mut (_, ref mut target) in b.branches.iter_mut() {
                    if *target == skip {
                        *target = synced;
                    }
                }
            }
            // Generated children publish architectural flags through their
            // state. Physical RFLAGS at HALT belongs to the dispatcher.""")
]

vmbuild_repls = [
("fresh callback clears nonvolatile child pointers",
"""        0x5080,
        0x5088,
        0x5098,
    ] {""",
"""        0x5080,
        0x5088,
        0x5098,
        // generated-child authoritative nonvolatile guest-state pointers
        0x50C0,
        0x50C8,
        0x50D0,
        0x50D8,
        0x50E0,
        0x50E8,
        0x50F0,
        0x50F8,
        0x5100,
    ] {""")
]

edit(BUILDER, builder_repls)
edit(VMBUILD, vmbuild_repls)
print("BTG cross-family state fix applied.")
