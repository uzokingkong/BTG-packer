# Full-combo verify (--vm-oep --vm --integrity --anti-debug --chained-crypto --custom-cipher --block-ring --payload-relocate --vm-commercial -l 3) — 2026-08-19

> **RESOLVED (2026-08-19, 후속)** — 아래 기록은 수정 전 실패 상태의 분석이다. 수정 후에는
> 풀 콤보와 `--integrity --chained-crypto`가 모두 정상 실행(exit 0, 1460B, SHA=기준)된다.
> 최종 수정·검증은 `docs/journal/2026-08-19-chained-integrity-fix.md` 참조.

## Result (수정 전)
**The full combo STILL fails.** The packed `repro/verify_full1.exe` exits with
`0xC000001D` (STATUS_ILLEGAL_INSTRUCTION = the integrity `ud2`) and **0 bytes** of
output. The register-clobber MAC fix + the ASLR fix are both present in the working
tree and rebuilt, but the failure persists.

## Packer build
- Binary: `target/release/btg-packer.exe` (cargo build --release exit 0; binary
  newer than the fixed `src/pipeline/build.rs`/`integrity.rs`).
- Stale binaries also present at repo root: `pack.exe`, `pack_debug.exe`
  (unused for this run).

## Full-combo build-log MAC (packer side)
From `repro/verify_full1_pack_console.txt`:
```
[+] T2-3 Integrity keyed-MAC over code region: EE6F18D915FDEED7 (keyed)
[+] S1 Integrity keyed-MAC stored @0x7306C
```
Runtime `mac_va` (the address the boot stub actually compares against) is
`0x1400E20CC` (RVA 0xE20CC); its stored value = `EE6F18D915FDEED7`.

## cdb crash site (verified under `verify_full1_noad.exe`, the same combo minus --anti-debug)
- Crash: `verify_full1_noad+0xe0ea0` = `0x1400E0EA0`, `0f0b ud2` — **the integrity
  MAC-compare `ud2`** (Phase C), preceded by:
  ```
  0x1400e0e71 mov rax,rdi ; rol(h1,32) ; xor rbp ; rol(h0,47) ; xor
  0x1400e0e8d mov rsi, 0x1400e20cc   ; mac_va
  0x1400e0e97 cmp rax,[rsi]
  0x1400e0e9a je  +2
  0x1400e0ea0 ud2            <-- mismatch
  ```
- **Runtime-computed MAC (RAX at compare) = `46693DBF190CC3DE`**
- **Stored MAC at mac_va = `9E0C6FF84626092E`** (= the noad build-log T2-3 value).
- → The runtime keyed-MAC does NOT match the packer-stored value. (Full-combo value
  `EE6F18D915FDEED7` vs runtime would likewise differ; the noad build was used for
  the cleanest cdb trace.)

## Root-cause analysis (what I could and could not pin down)
1. **Runtime MAC algorithm == packer `BtgKeyedMac`.** Disassembled the runtime
   Phase A/B/C; it matches `src/crypto/mac.rs::new/update/finish` instruction-for-
   instruction. Verified with an independent Python AND a standalone Rust copy of
   `BtgKeyedMac`: both produce identical values, so the algorithm/constants
   (PHI, coeff 0x100000001B3 / 0x9E3779B9) are correct. Phase-C finish math also
   reproduces the runtime's own RAX from its h0/h1.
2. **Seed bind-byte inconsistency (concrete).** At the runtime MAC Phase A loop
   entry, `r11` (the bind byte the MAC XORs each seed byte with) = **0x41**.
   `base_bind_byte(0x140000000)` = 0x15. The seed in memory at MAC time =
   `file_seed ^ 0x1B` (all 256 bytes). Neither 0x41 nor 0x1B equals the expected
   0x15, so the seed un-masking cannot recover `seed_stored`.
3. **Anti-debug confound.** The boot stub has anti-debug code that, when a
   debugger is detected, XORs the seed with **0x5A** (`0x1400e0c3f`). cdb sets
   BeingDebugged, so cdb itself corrupts the seed (0x1B = 0x41 ^ 0x5A). Thus a
   cdb-observed MAC failure is partially a debugging artifact. After redirecting
   RIP past the anti-debug seed-XOR, the MAC *still* fails under cdb (RAX
   `27A902B0B9B00207` vs stored `9E0C6FF84626092E`), so the mismatch is real, not
   only the artifact.
4. **Data-side question remains open.** With the file seed and the dumped
   runtime code region (`code_mem.bin` @0x7B000, len 0x65869) I could NOT
   reproduce either the runtime value or the packer value via `BtgKeyedMac` for
   any single-byte bind. This points to a second discrepancy in the *data* the MAC
   is run over (`crc_source` vs what the runtime reads), in addition to the seed
   bind inconsistency.

## Regression checks (after rebuild)
- Default pack `-l 3` → `verify_reg1.exe`: exit 0, **1460 bytes** output. ✓
- `--vm-oep --vm --vm-commercial -l 3` → `verify_reg2.exe`: exit 0, **1460 bytes**. ✓
- Both outputs are byte-identical to the original `test_prog.exe` run
  (SHA256 all `4366e2530f32a088306efe497d1762e5a087c54ac6c114b44f3ee13d422dcfe5`).
- So the default and vm-oep-commercial paths are fine; the full combo's failure is
  specific to the added layers (--integrity/chained/custom-cipher/payload-relocate
  interaction).

## Files (in repro/)
`verify_full1_pack_console.txt`, `verify_full1_run.txt`, `verify_full1.btg_layout.log`,
`verify_full1_noad_pack_console.txt`, `verify_full1_noad_run.txt`,
`verify_full1_noad_cdb_out.txt`, `neutralize_cdb_out.txt`, `verify_reg1_run.txt`,
`verify_reg2_run.txt`, `verify_build.log`, plus analysis scripts
(`find_mac.py`, `sim2.py`, `find_bind.py`, `check_mac.rs`, `check_mask.py`, ...) and
dumps (`code_mem.bin`, `seed_mem.bin`, `seedA.bin`).
