<#
.SYNOPSIS
  BTG codegen closed loop (Priority 5), runnable locally on Windows.

  coverage -> op-registry drift gate -> codegen (live-registry validated)
  -> semantic differential (silicon oracle) -> feature-on re-coverage
  -> coverage diff.

  Mirrors the steps gated in .github/workflows/ci.yml so the same loop can be
  reproduced on a dev box. Run from the repo root:  pwsh tools/btg_codegen/closed_loop.ps1
#>
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Set-Location $root

Write-Host "== 1. baseline coverage (feature off) =="
cargo run --release --locked --bin vm-coverage -- --out-dir coverage

Write-Host "== 2. RiscOp registry drift gate =="
$live = (cargo run --release --locked --bin btg-op-registry | Out-String)
$committed = (Get-Content tools/btg_codegen/op_registry.json -Raw)
if (($live -replace '\s','') -ne ($committed -replace '\s','')) {
  throw "op_registry.json drifted; regenerate: cargo run --bin btg-op-registry > tools/btg_codegen/op_registry.json"
}

Write-Host "== 3. codegen gap report (validated against the live registry) =="
cargo run --release --manifest-path tools/btg_codegen/Cargo.toml -- `
  --coverage coverage/vm_coverage.json `
  --out-dir tools/btg_codegen/generated `
  --op-registry tools/btg_codegen/op_registry.json --strict

Write-Host "== 4. semantic differential (silicon oracle) + generator tests =="
cargo test --release --locked --lib vm::risc::oracle
cargo test --release --manifest-path tools/btg_codegen/Cargo.toml

Write-Host "== 5. feature-on re-coverage + coverage diff =="
cargo run --release --locked --features codegen_fallback --bin vm-coverage -- --out-dir coverage-fallback
$b = (Get-Content coverage/vm_coverage.json -Raw | ConvertFrom-Json).summary
$f = (Get-Content coverage-fallback/vm_coverage.json -Raw | ConvertFrom-Json).summary
$du = $b.unsupported - $f.unsupported
Write-Host ("UNSUPPORTED  off={0}  on={1}  delta=-{2}" -f $b.unsupported, $f.unsupported, $du)
if ($f.unsupported -gt $b.unsupported) {
  throw "codegen fallback increased unsupported ($($b.unsupported) -> $($f.unsupported))"
}
Write-Host "closed loop OK"
