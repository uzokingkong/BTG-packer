//! Emit the live RiscOp registry as JSON.
//!
//! The codegen generator (tools/btg_codegen) must validate its lowering
//! templates against the RiscOps the core VM actually implements. Historically
//! it carried a hand-copied `KNOWN_RISC_OPS` const that silently drifted from
//! `src/vm/risc/op_registry.rs`. This binary is the single source of truth: it
//! prints every `RiscOpKind`'s stable name straight from `RiscOpKind::ALL`, so
//! CI can regenerate the generator's snapshot and fail on any drift.
//!
//! Usage: `cargo run --bin btg-op-registry` > tools/btg_codegen/op_registry.json

use btg_packer::vm::risc::op_registry::RiscOpKind;

fn main() {
    let names: Vec<&'static str> = RiscOpKind::ALL.iter().map(|k| k.stable_name()).collect();
    // Minimal, stable JSON: a version tag and the sorted-by-declaration list.
    // Pretty-printed by hand (no serde dep needed for a flat string array).
    let mut out = String::from("{\n  \"schema\": \"btg-op-registry-v1\",\n  \"count\": ");
    out.push_str(&names.len().to_string());
    out.push_str(",\n  \"ops\": [\n");
    for (i, n) in names.iter().enumerate() {
        out.push_str("    \"");
        out.push_str(n);
        out.push('"');
        if i + 1 != names.len() {
            out.push(',');
        }
        out.push('\n');
    }
    out.push_str("  ]\n}\n");
    print!("{out}");
}
