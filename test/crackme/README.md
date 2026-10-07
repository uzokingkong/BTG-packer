# BTG VaultBreaker — crackme challenge game

A small Win32 **keygen-me** built to be packed by `btg-packer` and solved for fun.

## Two run modes (one validation core)

| Mode | How to launch | Behavior |
| --- | --- | --- |
| Game | double-click / no args | Win32 GUI. Three vault locks; type the key that hashes to each stage target to advance. Clear all three to breach the vault. |
| Headless | `crackme.exe --headless` | Deterministic console battery over a fixed key set; prints each hash and verdict, prints `cleared=3/3`, exits `0`. |

`--verify-output` in the packer diffs the original vs packed image by running each
with `--headless` and comparing exit code + stdout + stderr, so the headless path
must stay finite and deterministic. The GUI shell is native; only the validation
core is a clean VM-lift target.

## Solution keys (the game is solvable)

| Stage | Key | Target hash |
| --- | --- | --- |
| 1 | `BTG-2024-ALPHA` | `0x906666DB` |
| 2 | `V4ULT-BR34K3R` | `0x993713FD` |
| 3 | `0xC0FFEE-GAME` | `0x1F2B28BA` |

Targets were produced by the reference oracle for the shipped keys.

## Build (MSVC, console subsystem)

```powershell
cl /O2 /EHsc /std:c++17 vaultbreaker.cpp /Fe:crackme.exe /link user32.lib gdi32.lib
```

## Pack (Program-VM)

```powershell
btg-packer.exe --input crackme.exe --output crackme.packed.exe `
  --vm --vm-oep --vm-commercial --allow-partial-vm `
  --verify-output --verify-timeout-secs 60 `
  --map --sym-map --debug --log-file crackme-pack.log --seed 3134984190
```

CI: [`.github/workflows/crackme-pack.yml`](../../.github/workflows/crackme-pack.yml)
builds, packs, runs on `windows-latest`, and uploads logs + crash dumps as the
`crackme-pack-evidence` artifact.
