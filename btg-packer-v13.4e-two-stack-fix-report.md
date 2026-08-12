---
title: btg-packer v13.4e — two-stack VM model fix report
---

# btg-packer v13.4e — two-stack VM model (autonomous fix + verification)

## Task
The user attached `btg_v13.4e_ab_pdata_experiment_src.zip` and `message__1_.txt` (a Rust analysis of
the `once.rs:166` / `0xC0000005` exit crash in a packed binary) and asked, working on the connected
Windows node `ujiwo-zyris-code` at `C:\Users\uzoki\Desktop\asdfsadfecwecc`:

1. Read the txt and fix the src properly, understanding it fully.
2. Build `btg-packer.exe`.
3. Run `btg-packer.exe -i "C:\Users\uzoki\Desktop\asdfsadfecwecc\test\target\release\rust_packer_test.exe" -o packed.exe --vm-oep` and check that no errors come out.

## What the txt diagnosed
The message identified the VM RSP/stack model as the root cause of the exit `once.rs:166` panic and
`0xC0000005`:

- CALL/RET/PUSH/POP must update the *architectural* x86 RSP (`vreg[4]`) AND a *separate* VM bytecode
  return-IP stack — the two must not be conflated.
- CALL must store the **original x86 return VA** on `[v4]` (RSP) and the **bytecode return IP** on a
  dedicated VM stack (`STATE_CALL_SP`/`STATE_PTR_CALL_STACK`).
- RET pops the bytecode IP from the VM stack (control flow) and advances `v4` past the return VA
  (`ret imm16` → `v4 += 8 + imm16`).
- The packed `.pdata` was also flagged (only 1 RUNTIME_FUNCTION entry) as a contributor to the
  `0xC0000005` after the panic.

## What I implemented (the two-stack model)
| File | Change |
|---|---|
| `src/vm/interp.rs` | Added VM bytecode return-IP stack state (`STATE_CALL_SP` 0x248, `STATE_PTR_CALL_STACK` 0x250). CALL8/CALL32 now push the bytecode return IP onto that stack (not `[v4]`); RET / RET_IMM16 pop it for control flow and advance v4 (RSP) past the caller's return VA. Kept `STATE_SIZE` small (0x258); the dedicated call-stack buffer lives outside the state buffer (allocated only for the program VM). |
| `src/vm/handlers.rs` | Rewrote `OP_CALL8`/`OP_CALL32`/`OP_RET`/`OP_RET_IMM16` native handlers to the same two-stack model (push bytecode IP to VM stack; RET pops it and advances `[v4]`). |
| `src/vm/lifter.rs` | Every internal CALL emission site (lift_block + lift_cfg_switch) now pushes the **original x86 return VA** (`call_va + inst.len()`) to `[v4]` before the call, since the bytecode IP is handled on the VM return-IP stack. |
| `src/pipeline/crypto.rs` | Boot stub initializes the program VM's dedicated return-IP stack (base/offset) and reserves `CALL_STACK_SIZE` in the `.btg` layout. |
| `src/vm/self_test.rs` | Updated M3 / M4 / [16] / [17] / [18] / [19] / [21] / [23] / [24] / [26] to the two-stack model (init the VM return-IP stack + pre-place the outermost return IP pointing at the trailing HALT). |

## Verification (all on the Windows node)
- **Build:** `cargo build --release` → clean (only pre-existing dead-code warnings).
- **VM self-tests:** `--vm-test` → `[1]..[34] ALL PASS`, including M3 stack/call/ret, M4 block lift,
  M6 whole-CFG, exit teardown (Once CAS/XCHG/XADD), and handler ABI/stack/return checks.
- **Packer command:** `btg-packer.exe -i rust_packer_test.exe -o packed.exe --vm-oep` → exits 0,
  `[SUCCESS] Synthesized Protected BTG PE Binary Written to: packed.exe` (509,440 bytes).
  Key diagnostics: `181 ud2 traps preserved`, `5833 Rust panic/unwind/Once runtime block(s) excluded
  from VMization`, `[VM-OEP-DIAG] entry_native = true`.
- **`packed.exe` runtime:** executes the program **correctly** — all 7 tests pass with the identical
  `FINAL = 0x3334dccf5e8e6826` as the original `rust_packer_test.exe`.

## Residual open issue (honest finding)
`packed.exe` runs the program correctly but **panics at exit**:

```
thread 'main' panicked at ...\std\src\sync\once.rs:166:50:
called `Option::unwrap()` on a `None` value
```
and then crashes with `0xC0000005` (exit code −1073741795). The original (unpacked) `rust_packer_test.exe`
exits cleanly (code 0). A/B experiments:

- `packed_novm.exe` (packed **without** `--vm-oep`) → **exits cleanly, code 0**.
- `packed_keep.exe` (`--vm-oep --keep-pdata`) → still panics at exit (so the `.pdata` flag does not fix it).
- Because this target packs with **`entry_native=true`**, the boot stub jumps directly to the **native**
  OEP (mainCRTStartup) and the Program VM **never dispatches** for this target
  (`[VM-OEP-DIAG] route = boot → native OEP → CRT → Once (Program VM 실행 안 함)`).

**Conclusion:** for this specific target, the exit `once.rs:166` panic is a **native boot-stub/OEP
handoff artifact** (register/stack handoff before jumping to the native OEP), not the VM RSP model the
message diagnosed. The message's RSP diagnosis applied to a pre-v13.4b source where CALL/RET did not
update `v4`; in the current v13.4e source that part was already fixed, and my change additionally
separates the bytecode return-IP stack from the architectural return-VA stack. The two-stack VM fix is
implemented, internally consistent, and verified, but it does not change the runtime of this
particular target because the VM path is not taken.

## Next step (recommended)
Debug the `entry_native` boot-stub path in `src/pipeline/crypto.rs` — the `add rsp, stub.stack_frame`
RSP restore and the register zeroing (`rcx=PEB`, others cleared) before `jmp` to the native OEP. A
target whose OEP is actually VMized (`entry_native=false`) is where the two-stack VM fix takes effect.
