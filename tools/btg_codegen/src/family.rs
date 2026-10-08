//! Instruction family classifier.
//!
//! The classifier maps an iced-x86 `Code`/mnemonic record onto a coarse family.
//! Families drive the semantic rule engine: a family tells us *which kind of
//! lowering strategy is even plausible* before we look at a concrete rule.
//!
//! Classification uses only the metadata the coverage DB already carries
//! (mnemonic string, encoding, CPUID feature flags). It never claims to know an
//! instruction's exact semantics — that is the rule engine's job, and for many
//! families the honest answer is "manual semantics required".

use crate::coverage::CoverageRecord;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Family {
    /// Integer ALU: ADD/SUB/ADC/SBB/AND/OR/XOR/NOT/NEG/CMP/TEST/INC/DEC.
    IntegerAlu,
    /// MOV / MOVZX / MOVSX / MOVSXD / XCHG(reg) / LEA.
    DataMove,
    /// Shifts and rotates: SHL/SHR/SAR/ROL/ROR/RCL/RCR/SHLD/SHRD.
    ShiftRotate,
    /// Bit ops: BT/BTS/BTR/BTC/BSF/BSR/POPCNT/LZCNT/TZCNT/BSWAP.
    BitManip,
    /// BMI1/BMI2: ANDN/BEXTR/BLSI/BLSR/BZHI/PDEP/PEXT/MULX/RORX/SARX/SHLX/SHRX.
    Bmi,
    /// MUL/IMUL/DIV/IDIV.
    MulDiv,
    /// Jcc/JMP/CALL/RET/LOOP/Jrcxz and SETcc/CMOVcc.
    ControlFlow,
    /// Stack: PUSH/POP/PUSHF/POPF/ENTER/LEAVE.
    Stack,
    /// Locked / atomic RMW: XADD/CMPXCHG/CMPXCHG8B/CMPXCHG16B/XCHG(mem).
    Atomic,
    /// String ops: MOVS/STOS/LODS/SCAS/CMPS (+REP prefixes).
    StringOp,
    /// Sign/zero conversions: CBW/CWDE/CDQE/CWD/CDQ/CQO.
    Convert,
    /// Scalar + packed SSE/SSE2 integer and the legacy MMX set.
    SsePackedInt,
    /// SSE/SSE2 float (scalar + packed): ADDPS/ADDSS/MULPD/...
    SseFloat,
    /// AVX/AVX2 (VEX-encoded) vector ops.
    AvxVex,
    /// AVX-512 / APX style (EVEX-encoded): masking, zeroing, broadcast, 512-bit.
    Avx512Evex,
    /// AMX tile ops: LDTILECFG/TILELOADD/TDPBF16PS/...
    Amx,
    /// Crypto: AES-NI, PCLMULQDQ, SHA, GFNI.
    Crypto,
    /// Hardware RNG: RDRAND/RDSEED.
    Random,
    /// x87 FPU.
    X87,
    /// State save/restore & misc heavyweight: XSAVE/XRSTOR/FXSAVE/XSAVEC/...
    StateSave,
    /// Privileged / system / ring-0 / IO.
    SystemPrivileged,
    /// No-ops and fences: NOP/PAUSE/*FENCE/ENDBR/HINT.
    NopFence,
    /// Anything the classifier cannot place.
    Unknown,
}

impl Family {
    pub fn as_str(self) -> &'static str {
        match self {
            Family::IntegerAlu => "IntegerAlu",
            Family::DataMove => "DataMove",
            Family::ShiftRotate => "ShiftRotate",
            Family::BitManip => "BitManip",
            Family::Bmi => "Bmi",
            Family::MulDiv => "MulDiv",
            Family::ControlFlow => "ControlFlow",
            Family::Stack => "Stack",
            Family::Atomic => "Atomic",
            Family::StringOp => "StringOp",
            Family::Convert => "Convert",
            Family::SsePackedInt => "SsePackedInt",
            Family::SseFloat => "SseFloat",
            Family::AvxVex => "AvxVex",
            Family::Avx512Evex => "Avx512Evex",
            Family::Amx => "Amx",
            Family::Crypto => "Crypto",
            Family::Random => "Random",
            Family::X87 => "X87",
            Family::StateSave => "StateSave",
            Family::SystemPrivileged => "SystemPrivileged",
            Family::NopFence => "NopFence",
            Family::Unknown => "Unknown",
        }
    }
}

fn has_feature(rec: &CoverageRecord, needle: &str) -> bool {
    rec.cpuid_features
        .iter()
        .any(|f| f.to_ascii_uppercase().contains(needle))
}

fn is_evex(rec: &CoverageRecord) -> bool {
    rec.encoding.eq_ignore_ascii_case("EVEX")
}

fn is_vex(rec: &CoverageRecord) -> bool {
    rec.encoding.eq_ignore_ascii_case("VEX")
}

/// Classify a record into a family.
///
/// Order matters: encoding-based buckets (EVEX/AMX/crypto) are checked before
/// the mnemonic-prefix heuristics so that, for example, `VADDPS` under EVEX is
/// routed to `Avx512Evex` rather than `SseFloat`.
pub fn classify(rec: &CoverageRecord) -> Family {
    let m = rec.mnemonic.to_ascii_uppercase();

    // ── NOP / fences / control-flow-guard hints (semantics: none / trivial) ──
    if m == "NOP" || m == "PAUSE" || m.ends_with("FENCE") || m.starts_with("ENDBR") || m == "HINT_NOP"
    {
        return Family::NopFence;
    }

    // ── AMX (tile) ──────────────────────────────────────────────────────────
    if has_feature(rec, "AMX") || m.starts_with("TILE") || m.starts_with("TDP") || m == "LDTILECFG"
        || m == "STTILECFG"
    {
        return Family::Amx;
    }

    // ── Crypto accelerators ─────────────────────────────────────────────────
    if has_feature(rec, "AES")
        || has_feature(rec, "SHA")
        || has_feature(rec, "GFNI")
        || has_feature(rec, "PCLMULQDQ")
        || m.starts_with("AES")
        || m.starts_with("SHA")
        || m.starts_with("VAES")
        || m.contains("PCLMUL")
    {
        return Family::Crypto;
    }

    // ── Hardware RNG ─────────────────────────────────────────────────────────
    if m == "RDRAND" || m == "RDSEED" {
        return Family::Random;
    }

    // ── Heavyweight state save/restore ───────────────────────────────────────
    if m.starts_with("XSAVE") || m.starts_with("XRSTOR") || m.starts_with("FXSAVE")
        || m.starts_with("FXRSTOR")
    {
        return Family::StateSave;
    }

    // ── BMI1 / BMI2 (VEX-encoded but scalar GPR; must precede the VEX bucket) ─
    if has_feature(rec, "BMI")
        || matches!(
            m.as_str(),
            "ANDN" | "BEXTR" | "BLSI" | "BLSMSK" | "BLSR" | "BZHI" | "PDEP" | "PEXT" | "MULX"
                | "RORX" | "SARX" | "SHLX" | "SHRX"
        )
    {
        return Family::Bmi;
    }

    // ── AVX-512 / EVEX ───────────────────────────────────────────────────────
    if is_evex(rec) || has_feature(rec, "AVX512") {
        return Family::Avx512Evex;
    }

    // ── AVX / AVX2 (VEX) ─────────────────────────────────────────────────────
    if is_vex(rec) || has_feature(rec, "AVX") {
        return Family::AvxVex;
    }

    // ── x87 FPU ──────────────────────────────────────────────────────────────
    if has_feature(rec, "X87")
        || matches!(
            m.as_str(),
            "FADD" | "FADDP" | "FSUB" | "FSUBP" | "FMUL" | "FMULP" | "FDIV" | "FDIVP" | "FLD"
                | "FST" | "FSTP" | "FILD" | "FIST" | "FISTP" | "FCOM" | "FCOMP" | "FCOMPP"
                | "FUCOM" | "FUCOMP" | "FUCOMPP" | "FCHS" | "FABS" | "FSQRT" | "FLDZ" | "FLD1"
                | "FXCH" | "FNOP" | "FINIT" | "FNINIT" | "FWAIT" | "FLDCW" | "FNSTCW" | "FNSTSW"
                | "FSCALE" | "FPREM" | "FPREM1" | "FRNDINT" | "FSIN" | "FCOS" | "FPTAN" | "FPATAN"
        )
    {
        return Family::X87;
    }

    // ── Privileged / system / IO ─────────────────────────────────────────────
    if rec.privileged
        || matches!(
            m.as_str(),
            "IN" | "OUT" | "INS" | "OUTS" | "HLT" | "LGDT" | "LIDT" | "LLDT" | "LTR" | "SGDT"
                | "SIDT" | "SLDT" | "STR" | "LMSW" | "SMSW" | "INVD" | "WBINVD" | "INVLPG"
                | "RDMSR" | "WRMSR" | "RDPMC" | "RDTSC" | "RDTSCP" | "SWAPGS" | "SYSENTER"
                | "SYSEXIT" | "SYSCALL" | "SYSRET" | "IRET" | "IRETD" | "IRETQ" | "CLI" | "STI"
                | "CLTS" | "WRPKRU" | "RDPKRU"
        )
    {
        return Family::SystemPrivileged;
    }

    // ── Atomics / locked RMW ─────────────────────────────────────────────────
    if matches!(
        m.as_str(),
        "XADD" | "CMPXCHG" | "CMPXCHG8B" | "CMPXCHG16B"
    ) {
        return Family::Atomic;
    }

    // ── String ops ───────────────────────────────────────────────────────────
    if matches!(
        m.as_str(),
        "MOVS" | "MOVSB" | "MOVSW" | "MOVSD" | "MOVSQ" | "STOS" | "STOSB" | "STOSW" | "STOSD"
            | "STOSQ" | "LODS" | "LODSB" | "LODSW" | "LODSD" | "LODSQ" | "SCAS" | "SCASB"
            | "SCASW" | "SCASD" | "SCASQ" | "CMPS" | "CMPSB" | "CMPSW" | "CMPSD" | "CMPSQ"
    ) {
        return Family::StringOp;
    }

    // ── Sign/zero width conversions ──────────────────────────────────────────
    if matches!(
        m.as_str(),
        "CBW" | "CWDE" | "CDQE" | "CWD" | "CDQ" | "CQO"
    ) {
        return Family::Convert;
    }

    // ── Stack ────────────────────────────────────────────────────────────────
    if matches!(
        m.as_str(),
        "PUSH" | "POP" | "PUSHF" | "PUSHFQ" | "POPF" | "POPFQ" | "ENTER" | "LEAVE" | "PUSHA"
            | "PUSHAD" | "POPA" | "POPAD"
    ) {
        return Family::Stack;
    }

    // ── Control flow ─────────────────────────────────────────────────────────
    if m.starts_with('J')
        || m == "CALL"
        || m == "RET"
        || m == "RETF"
        || m == "LOOP"
        || m == "LOOPE"
        || m == "LOOPNE"
        || m.starts_with("SET")
        || m.starts_with("CMOV")
    {
        return Family::ControlFlow;
    }

    // NOTE: the scalar integer families below use EXACT full-mnemonic matches
    // and are checked BEFORE the broad SSE `starts_with('P')` heuristic, so
    // e.g. POPCNT resolves to BitManip rather than being swallowed as a packed
    // op. SSE mnemonics (PADDD, MULPS, ...) never exact-match a scalar name.

    // ── Shift / rotate ───────────────────────────────────────────────────────
    if matches!(
        m.as_str(),
        "SHL" | "SHR" | "SAR" | "SAL" | "ROL" | "ROR" | "RCL" | "RCR" | "SHLD" | "SHRD"
    ) {
        return Family::ShiftRotate;
    }

    // ── Bit manipulation ─────────────────────────────────────────────────────
    if matches!(
        m.as_str(),
        "BT" | "BTS" | "BTR" | "BTC" | "BSF" | "BSR" | "POPCNT" | "LZCNT" | "TZCNT" | "BSWAP"
    ) {
        return Family::BitManip;
    }

    // ── Multiply / divide ────────────────────────────────────────────────────
    if matches!(m.as_str(), "MUL" | "IMUL" | "DIV" | "IDIV") {
        return Family::MulDiv;
    }

    // ── Integer ALU ──────────────────────────────────────────────────────────
    if matches!(
        m.as_str(),
        "ADD" | "SUB" | "ADC" | "SBB" | "AND" | "OR" | "XOR" | "NOT" | "NEG" | "CMP" | "TEST"
            | "INC" | "DEC"
    ) {
        return Family::IntegerAlu;
    }

    // ── SSE/SSE2 packed integer + MMX ────────────────────────────────────────
    if m.starts_with('P')
        || m.starts_with("MOVDQ")
        || m.starts_with("MOVQ")
        || m.starts_with("MOVD")
        || has_feature(rec, "MMX")
    {
        return Family::SsePackedInt;
    }

    // ── SSE float ────────────────────────────────────────────────────────────
    if (m.ends_with("PS") || m.ends_with("PD") || m.ends_with("SS") || m.ends_with("SD"))
        && (has_feature(rec, "SSE") || m.starts_with("ADD") || m.starts_with("SUB")
            || m.starts_with("MUL") || m.starts_with("DIV") || m.starts_with("MOV"))
    {
        return Family::SseFloat;
    }

    // ── Data move (checked late: MOV is a prefix of many SSE mnemonics) ──────
    if matches!(
        m.as_str(),
        "MOV" | "MOVZX" | "MOVSX" | "MOVSXD" | "XCHG" | "LEA"
    ) {
        return Family::DataMove;
    }

    Family::Unknown
}
