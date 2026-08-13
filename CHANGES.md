# v54 — Phase 2.1 Group A: SSE/FPU opcodes + string-op x86-exactness fix

## Changes
- `src/vm/bytecode/registry.rs` — 21 new SSE/FPU opcodes (0x97..0xAB):
  scalar FP ADDSS/ADDSD/SUBSS/SUBSD/MULSS/MULSD/DIVSS/DIVSD, packed logic
  PAND/POR/PANDN, CVTSI2SD/CVTSI2SS, CVTSS2SD/CVTSD2SS,
  CVTTSS2SI/CVTTSD2SI (trunc) / CVTSS2SI/CVTSD2SI (round-to-nearest-even),
  PEXTRD/PINSRD. NUM_OPS 0x97 -> 0xAC (171 opcodes).
- `src/vm/handlers/sse_arith.rs` — native x86-64 handlers (state-XMM file
  addressing; scalar-FP ops preserve dst upper bytes, conversions zero them;
  no status-flag capture, matching the interpreter).
- `src/vm/interp/xmm.rs` — interpreter arms for all 21 opcodes (incl. the
  round-ties-to-even helper for CVTSS2SI/CVTSD2SI and the x86 "integer
  indefinite" 0x8000_0000 value for NaN/out-of-range converts).
- `src/vm/lifter/sse.rs` — lift_sse_fp / lift_sse_logic / lift_cvt /
  lift_pext_pins (+ width-exact m32/m64 scalar loads via a GPR so ADDSS xmm,
  m32 never over-reads). `lifter/mod.rs` routes the new arms; PAND/POR/PANDN
  are lifted correctly now (the legacy catch-all SSE arm emitted UNPCKLPD for
  them), and PXOR is bit-identical-mapped to XORPS.
- `src/vm/lifter/string.rs` — REP SCAS/CMPS lowering made x86-exact: the
  terminating iteration consumes the count and advances the pointer(s) like
  hardware (ZF decision captured via SETcc before bookeeping, final compare
  flags re-generated on exit), compare direction fixed to
  SCAS = acc - [rdi] / CMPS = [rsi] - [rdi], and all pointer bumps use LEA
  (no flag clobber). Non-REP MOVS/STOS/LODS single forms likewise bump via
  LEA so plain string ops write no rflags.
- `src/vm/self_test/` — [38] A-1 SSE/FPU group test (sse_fpu.rs: interp ==
  native == expected, incl. lift smoke test); [36] SCAS/CMPS expectations
  updated to the x86-exact model (+ exit-ZF asserts); [21] Part B/C decode
  REP-prefixed bytes (rep movsd/repe cmpsd regression from v52 fixed);
  [15] negative-diagnostic probe retargeted from ADDSS (now supported) to
  SQRTSS.
- `docs/coverage.md`, `docs/milestones.md` — P2-1 group work marked done.

## Verification
- `cargo build --release`: OK (warnings only, pre-existing).
- `cargo test`: 73 passed / 0 failed.
- `--vm-test`: [1]..[38] ALL PASS (incl. [30] registry sync over 171 opcodes).

---

# v13.4e — two-stack VM model (separate bytecode return-IP stack from the architectural RSP)

## Root cause (per message.txt audit, applied to the v13.4e src)
The program VM conflated the VM bytecode return IP with the program's observed return address:
CALL8/CALL32 pushed the bytecode IP (`r9+disp`) onto the architectural stack `[v4]` (RSP), and RET
popped it back into `r9`. That put a bytecode address where the program / native bridge expects a
real x86 return VA, corrupting the runtime stack. The fix separates them: the bytecode return IP goes
on a dedicated VM stack (`STATE_CALL_SP`/`STATE_PTR_CALL_STACK`), and `[v4]` carries the original
x86 return VA.

## Changes
- `src/vm/interp.rs` — CALL8/CALL32 push the bytecode return IP to the VM return-IP stack; RET /
  RET_IMM16 pop it for control flow and advance v4 (RSP) past the caller's return VA. STATE_SIZE
  stays small (0x258); the dedicated call-stack buffer is allocated outside it (program VM only).
- `src/vm/handlers.rs` — OP_CALL8/CALL32/RET/RET_IMM16 rewritten to the two-stack model.
- `src/vm/lifter.rs` — each internal CALL now emits a push of the original x86 return VA to [v4]
  before the call.
- `src/pipeline/crypto.rs` — boot stub initializes the program VM return-IP stack and reserves
  CALL_STACK_SIZE in the layout.
- `src/vm/self_test.rs` — M3/M4/[16]/[17]/[18]/[19]/[21]/[23]/[24]/[26] updated to the two-stack
  model.

## Verification
- `cargo build --release`: OK.
- `--vm-test`: [1]..[34] ALL PASS (incl. M3 call/ret, M4, M6 whole-CFG, exit teardown, ABI).
- Pack `--vm-oep` on rust_packer_test.exe: `[SUCCESS] Synthesized Protected BTG PE Binary Written
  to: packed.exe`; 181 ud2 preserved; 5833 Once/panic runtime blocks excluded; `entry_native=true`.

## Still open
- `packed.exe` runs the program correctly but panics at exit `once.rs:166` then AV 0xC0000005.
  `packed_novm.exe` (no `--vm-oep`) exits 0; `--keep-pdata` does not fix it. Because `entry_native=
  true`, the boot stub jumps to the native OEP and the Program VM never dispatches for this target,
  so the exit panic is a native boot-stub/OEP artifact rather than the VM RSP model. Next step:
  debug the entry_native boot-stub RSP/register handoff to native OEP.

---

# v13.4d — remove the last ud2->NOP neutralization (pass3_encode.rs)

## The bug my v13.4c missed
v13.4c removed the ud2->NOP conversion from `crypto.rs` (whole-.textb sweep) and from
`pass4_section.rs` (per-block), but a THIRD, earlier ud2->NOP neutralization still
lived in **`src/pipeline/pass3_encode.rs`** (added as "v13.5 FIX"). Pass 3 runs
BEFORE Pass 4, so by the time Pass 4 "preserved" ud2, they were already gone — the
pipeline was:

    Pass1 -> Pass2 shuffle -> Pass3 [ud2->NOP] -> Pass4 -> patch_data -> crypto -> build

That is why the packed output still showed 0 ud2 and could still fall through into
the wrong (shuffled) block at exit/cleanup time (once.rs:166 panic -> 0xC0000005).

## Fix
Removed the ud2->NOP block in `pass3_encode.rs`. ud2 (0x0F 0x0B) is now left verbatim
in `block.instructions` at every stage. Because Pass 4 copies `block.instructions`
verbatim into .textb, the written bytes and the Phase 0.3 validation source stay
identical, so the reencrypt "plaintext/roundtrip mismatch" that the v13.5 comment
worried about does NOT recur (ud2 is preserved on both sides).

## Verification (pack run on rustbtg_test.exe, --full, Linux packer)
- `Pass4: Preserved 195 ud2 trap(s) verbatim across 6088 code blocks in .textb (no
  NOP conversion ...)`  — ud2 count is now NON-ZERO (was 0 after old Pass-3 sweep).
- `[VALIDATE] OK Phase 0.3: 6088 blocks individually encrypted, length table
  verified (per-block keys, 2846 call-target plaintext)` — reencrypt validation OK
  with ud2 preserved.
- `[+] Rebuilt SEH Table (.pdata): RVA 0x1F000, 1 entries [text-shuffled entries
  dropped; dispatcher boot leaf 135168..0x2D100 only]`.
- `[SUCCESS] Synthesized Protected BTG PE Binary` + all post-build VALIDATE checks
  passed.
- `cargo build --release` clean; `--vm-test` ALL CHECKS PASSED.

## Still open (unchanged from v13.4c)
- Runtime execution of a packed target on Windows (FINAL-then-exit check) must be
  re-validated on a Windows host; this VM has no wine/Windows toolchain.
- Block-shuffled code still has no per-block unwind info (only the tight dispatcher
  boot leaf is registered). This is the explicitly-documented remaining .pdata gap.

---

# v13.4c — ud2 preservation + correct .pdata (block-shuffled fall-through / unwind fix)

## Root cause (per the message.txt audit — confirmed against source)
The packed 0xC0000005 was the tail of one connected corruption chain:

- `crypto.rs` swept the **entire** .textb code area converting every `0F 0B` (ud2) to
  `90 90` (nop nop). pass4_section.rs additionally did a per-block ud2->nop patch.
  ud2 is a *guaranteed* trap; converting it to NOP **enables fall-through** into the
  next (shuffled, unrelated) block. `call X; ud2; <next fn>` became
  `call X; nop; nop; <next fn>` — control slid into the wrong function.
- `patch_data.rs` remapped each .pdata Begin/End RVA to relocated block addresses
  independently. After global block shuffle the function is non-contiguous, so
  [new_begin, new_end) covered many unrelated blocks.
- `build.rs` registered the **whole .btg** as a single RUNTIME_FUNCTION
  [dispatcher .. dispatcher+total_section_size) with ONE unwind_info, claiming
  thousands of different stack frames are one unwindable function.

Combined: wrong control flow -> panic -> OS unwinder follows bogus .pdata/leaf ->
wrong UNWIND_INFO -> wrong RSP -> 0xC0000005.

## Fixes
1. `crypto.rs` — **removed** the whole-section ud2->nop sweep. ud2 is left as a real
   trap (no fall-through). A reachable ud2 is a separate bug, not a reason to erase
   the trap.
2. `pass4_section.rs` — **removed** the per-block ud2->nop neutralization and its
   aggregate report; now only counts and preserves ud2 verbatim.
3. `patch_data.rs` — **removed** the .pdata Begin/End relocation. Block-shuffled
   functions cannot be represented by a single RUNTIME_FUNCTION; remapping produced
   bogus ranges. The .pdata section is left untouched here.
4. `build.rs` — `update_pdata_seh` now rebuilds .pdata cleanly:
   - drops original entries that point into the shuffled `.text` range;
   - keeps original entries outside `.text` (still-valid untouched functions);
   - adds ONE tight leaf covering only the dispatcher/boot area
     [dispatcher .. dispatcher+first_block_offset) with its own UNWIND_INFO —
     **no more whole-.btg catch-all**.

## Verification
- `cargo build --release`: OK (this crate compiles; runtime Windows validation is
  outside this VM — see Still open).
- Log lines changed: `[+] Pass4: Preserved N ud2 trap(s) ... (no NOP conversion ...)`,
  `[+] Rebuilt SEH Table (.pdata): ... [text-shuffled entries dropped; dispatcher
  boot leaf ... only]`, `[+] .pdata: skipped Begin/End relocation ...`.

## Still open
- Runtime execution of a packed target must be re-validated on Windows
  (this environment has no Windows toolchain / target binaries to run the packer
  end-to-end). The `.text` `.pdata` entries for functions that still run from the
  decoy .text are deliberately dropped for safety; if a target depends on unwinding
  a non-relocated .text function, its entry can be re-added on a per-target basis.

---

# v13.4b — Program-VM single-stack fix (vreg4-as-RSP for CALL/RET/PUSH/POP)
# v13.4b — Program-VM single-stack fix (vreg4-as-RSP for CALL/RET/PUSH/POP)

## Root cause (the STATE_SP "init = 0" red flag, confirmed)
The program VM used TWO independent stack mechanisms that diverge and collide:

- `vreg[4]` (= RSP) — the real stack pointer. Used for `[rsp+disp]` data addressing
  and for the native-call bridge's stack-argument forwarding.
- `STATE_SP` + `STATE_PTR_STACK` — a SEPARATE "logical call stack" used only by
  OP_PUSH_R / OP_POP_R / OP_CALL8 / OP_CALL32 / OP_RET / OP_RET_IMM16.

The boot stub set `STATE_PTR_STACK = OS entry RSP` and `STATE_SP = 0`. When the
lifted OEP/CRT code runs `sub rsp, X` (frame allocation), only `vreg[4]` moves down;
`STATE_SP` stays anchored at the entry RSP. So CALL32/RET push return addresses at
`[entry_RSP-8, -16, …]`, which lands INSIDE the frame region `[entry_RSP-X, entry_RSP)`
that `vreg[4]` addresses → the VM's return-address stack and the program's own
frame/locals/stack-args overwrite each other → corrupted call/ret flow, garbage args,
and the downstream once.rs:166 teardown crash. (Exactly the `STATE_SP init = 0`
hazard the user's audit flagged.)

## Fix
Unify on the single x86 stack: all six stack opcodes now use `vreg[4]` (RSP) as the
stack pointer — the same pointer the lifted `[rsp+disp]` ops and the native-call
bridge use. `sub rsp`/`push`/`call`/`ret` now all move the same RSP, matching real x86.

- `src/vm/handlers.rs` — OP_PUSH_R/OP_POP_R/OP_CALL8/OP_CALL32/OP_RET/OP_RET_IMM16
  rewritten to read/write the RSP state slot `m(r8, 0x20)` instead of
  `STATE_SP`/`STATE_PTR_STACK`. Push/call store to `[RSP-8]` directly.
- `src/vm/interp.rs` — `sp_of`/`set_sp` now operate on vreg4; stack ops address
  `[vreg4]` directly (no `STATE_PTR_STACK + STATE_SP` base/offset).
- `src/vm/self_test.rs` — M3/M4/M6/whole-CFG/native-program tests now seed vreg4 as
  the stack pointer (and skip vreg4 in the interp-vs-native vreg comparison, since
  interp holds a mem-offset and native an absolute VA). No register is used as scratch.
- `src/pipeline/crypto.rs` — removed the now-dead `STATE_SP=0` / `STATE_PTR_STACK=RSP`
  boot-stub writes and updated the `[VM-OEP-DIAG]` note (STATE_SP/PTR_STACK unused;
  stack pointer = vreg4).

## Verification
- `cargo build --release`: OK.
- `--vm-test`: [1]..[34] ALL PASS (42 PASS lines), including M3 stack/call/ret,
  M4 lift, M6 whole-CFG, M6 native program exec, [32] exit teardown, [33] bridge ABI.

## Still open (documented, not changed here)
- A `native_call` bridge to a **noreturn** callee (ExitProcess / a non-returning CRT
  entry) still leaves the VM infra in r12-r15, so an exit-time Rust teardown
  (once.rs:166) can read polluted callee-saved regs. The clean-native-OEP path already
  avoids the entry-bridge case; calling ExitProcess from inside the program-VM remains
  a separate noreturn-bridge concern.
- `entry_native` (OEP virtualized vs clean-native-OEP) is target-dependent; read the
  `[VM-OEP-DIAG] entry_native` line in the pack log to know which route a given target
  takes.

---

# btg-packer once.rs:166 exit-panic fix (LOCK memory-RMW atomicity)

## Root cause
`src/vm/lifter.rs::lift_incdec()` lowered a `lock`-prefixed memory INC/DEC to a
NON-ATOMIC load->modify->store (there is no atomic memory INC/DEC opcode; only
register-only OP_INC_R/OP_DEC_R). In --vm-oep the Rust runtime teardown's
refcount/shared-state blocks (e.g. `lock dec [rax]`) were lifted this way,
corrupting the state so `Once::call_once` re-ran its closure and hit
`f.take().unwrap()` on None -> once.rs:166 panic, then a broken unwind -> stack
overflow.

The block-exclusion net `block_has_lock_atomic_on_global` only recognized
RIP-relative / absolute operands, so register-base `lock dec [rax]` slipped
through and stayed VM.

## Changes (this zip)
- `src/vm/text_lift.rs`
  - New `block_has_lock_memory_rmw(bb)`: catches ANY `lock`-prefixed memory
    operand regardless of addressing mode (register-base included).
  - Wired it into `lift_program_cfg`'s excluded-block set.
  - `detect_panic_unwind_ranges`: additionally quarantines the WHOLE .pdata
    function whenever it contains a lock-prefixed memory RMW, so refcount/
    teardown functions are not split native<->VM.
- `src/vm/lifter.rs`
  - `lift_incdec` now hard-errors on `lock` + memory INC/DEC (must remain
    native / atomic RMW) so any future gap surfaces instead of silently
    mis-compiling.

## Verification
- `cargo build --release`: OK.
- `--vm-test` (VM self-tests incl. [32] exit teardown, [33] bridge ABI): ALL PASS.
- Re-pack of a Rust test PE with `--vm-oep --map --sym-map`:
  excluded blocks 5550 -> 5553 (the 3 lock-RMW blocks now caught).
  Scanned the output `.map`: **0 VM blocks** contain a lock-memory RMW
  (37/37 lock-mem-RMW blocks are native).
- Expected on your target: after repacking, `0x140003163`, `0x140003295`,
  `0x1400034CC` flip from `vm` to `native` in the `.sym`, and exit no longer
  panics.

# v13.4a — VM handler/lifter/interpreter audit fixes (SBB carry, XADD/CMPXCHG flags)

Deep audit of the VM handler/lifter/interpreter consistency found bugs the
self-test did not cover. All are fixed and locked in by new self-test `[34]`.

## Changes (this zip)
- `src/vm/lifter.rs` — `lift_sbb`
  - **P0 fix**: real x86 `sbb dst,src = dst - src - CF_in` (carry BEFORE the
    instruction). The old code did `sub dst,src` first and branched on that
    sub's OWN borrow, so it read the wrong CF and returned a result one too
    small whenever `borrow(dst-src) != CF_in` (e.g. `sbb reg,reg` borrow
    propagation, `sbb rax,0` after a carry). Now reads the INCOMING CF via a
    `jcc` before any subtract (same pattern as `lift_adc`), then subtracts the
    borrow in the CF==1 branch.
  - Memory-destination SBB now errors loudly (was silently operating on the
    base register instead of `[mem]`).
- `src/vm/flags.rs` — new `add_flags_width(a,b,width)` (8/16/32-bit ADD flags).
- `src/vm/interp.rs`
  - **P1 fix**: XADD 8/16-bit now computes width-correct ADD flags via
    `add_flags_width` (the native `lock xadd [addr],al/ax` sets CF/SF/OF/AF
    from the 8/16-bit boundary, not bit 31), so interp == native for XADD 8/16.
  - **P1 fix**: CMPXCHG now preserves the non-ZF flags (mirrors the native
    handler, which captures only ZF); previously it wiped them to `set_flags(F_ZF)`
    / `set_flags(0)`.
- `src/vm/handlers.rs` — removed a duplicate `mov r11,[state+STATE_SP]` in the
  OP_RET_IMM16 handler (copy-paste residue; functionally harmless).
- `src/vm/self_test.rs` — new `run_carry_flag_fix_test` ([34]): SBB incoming-CF
  matrix (CF_in 0/1 × dst≷src), XADD 8/16 width flags, CMPXCHG flag preservation.

## Verification
- `cargo build --release`: OK.
- `--vm-test`: [1]..[33] unchanged + new [34] ALL PASS.
- Reproducer (`examples/audit_vm.rs`, removed after verification): SBB 4/4 cases
  corrected, XADD8/16 flags corrected, CMPXCHG CF preserved.

## Known limitation (not changed in this zip — requires width-aware native handlers)
- 8/16-bit CMP/TEST/SHIFT/INC/DEC flag semantics are still computed from the
  32-bit lowering (SF/OF/AF/CF at bit-31/bit-31 rather than the 8/16-bit
  boundary). Fixing this robustly needs dedicated width-aware flag ops; left
  for a follow-up to avoid destabilising the green handler table.
