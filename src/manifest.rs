// ==============================================================================
// BTG Packer - Build manifest (commercial-readiness-plan 3-2).
//
// A BuildManifest records everything needed to reproduce / triage a build:
//   * the packer version, a deterministic build_id, and the optional --seed,
//   * the VM ISA version and the crypto engine version actually used,
//   * the effective feature flags,
//   * SHA-256 of the input PE and of the output PE.
//
// It is written next to the output PE as `<output>.btgmanifest` and echoed to the
// pack log. Hashes are computed with the dependency-free SHA-256 in this module
// so no hashing crate is added to Cargo.toml.
//
// build_id is derived deterministically from (seed, input_hash) so two builds of
// the same input + seed + config produce the *same* build_id — that is what lets
// a customer support ticket (a build_id) pin down the exact build that crashed.
// ==============================================================================

use std::io;
use std::path::Path;

/// VM ISA version this packer emits (roadmap v31 — full ISA milestone line).
pub const VM_VERSION: u32 = 31;
/// Composite VM crypto engine version (BTG-C1 default, v62).
/// v63 (T3-1 Phase B): --crypto-mode chacha20 추가.
pub const CRYPTO_VERSION: u32 = 63;

/// A fully-qualified description of one pack run.
#[derive(Debug, Clone)]
pub struct BuildManifest {
    /// Packer binary version (`CARGO_PKG_VERSION` = "1.0.0").
    pub version: String,
    /// Deterministic build identifier: `BTG-<seed:016X>-<input_hash[..8]>`.
    pub build_id: String,
    /// The `--seed` used (None = entropy-seeded RNG).
    pub seed_id: Option<u64>,
    /// VM ISA version (see [`VM_VERSION`]).
    pub vm_version: u32,
    /// Crypto engine version (see [`CRYPTO_VERSION`]).
    pub crypto_version: u32,
    /// Effective feature flags (ordered, CSV in `render`).
    pub feature_flags: Vec<String>,
    /// v63/P3-2: effective crypto primitive (`rc4`/`c1`/`chacha20`) used by the
    /// boot stub at-rest decryption (readccc.md §6.1 capability manifest).
    pub crypto_mode: String,
    /// v63/P3-2: at-rest encryption was applied to the code region and/or data runs.
    pub at_rest_encryption: bool,
    /// v63/P3-2: ASLR (relocation-aware output) preserved. at-rest encryption
    /// disables it (loader relocation would corrupt ciphertext) — record the
    /// trade-off so the artifact states its guarantees.
    pub aslr_preserved: bool,
    /// v63/P3-2: integrity (CRC32 + keyed-MAC) active.
    pub integrity: bool,
    /// v63/P3-2: effective crypto coverage (%).
    pub crypto_coverage: u32,
    /// readccc §4.5: anti-debug 탐지 실패 정책 (`trap`/`hang`/`warn`).
    pub anti_debug_policy: String,
    /// readccc §4.4: W^X 메모리 계약 — 실행 코드가 어떤 권한 라이프사이클을
    /// 갖는지 기록한다. 값 (쉼표 구분):
    ///   `rwx-at-rest`   : `.textb`가 파일에서 RWX로 매핑 (in-place 부트 복호화)
    ///   `rx-after-verify`: `--mem-harden` — 복호화+무결성 검증 후 RX 전환
    ///   `code-data-split`: `--payload-relocate` — 암호화 페이로드는 비실행
    ///                      `.vdata`(데이터)에, 실행 스텁은 `.textb`에 분리
    pub wx_contract: String,
    /// SHA-256 (hex) of the input PE bytes.
    pub input_hash: String,
    /// SHA-256 (hex) of the output PE bytes.
    pub output_hash: String,
}

impl BuildManifest {
    /// Construct a manifest from raw inputs, deriving `build_id` and `version`.
    pub fn new(
        seed: Option<u64>,
        feature_flags: Vec<String>,
        input_hash: String,
        output_hash: String,
    ) -> Self {
        let build_id = format!(
            "BTG-{:016X}-{}",
            seed.unwrap_or(0),
            &input_hash[..input_hash.len().min(8)]
        );
        Self {
            version: env!("CARGO_PKG_VERSION").to_string(),
            build_id,
            seed_id: seed,
            vm_version: VM_VERSION,
            crypto_version: CRYPTO_VERSION,
            feature_flags,
            crypto_mode: "c1".to_string(),
            at_rest_encryption: false,
            aslr_preserved: true,
            integrity: false,
            crypto_coverage: 0,
            anti_debug_policy: "trap".to_string(),
            wx_contract: "rwx-at-rest".to_string(),
            input_hash,
            output_hash,
        }
    }

    /// P3-2/readccc §6.1: record effective protection capabilities so the
    /// artifact self-describes its guarantees (crypto primitive, at-rest,
    /// ASLR trade-off, integrity, coverage).
    pub fn with_capabilities(
        mut self,
        crypto_mode: &str,
        at_rest_encryption: bool,
        aslr_preserved: bool,
        integrity: bool,
        crypto_coverage: u32,
        anti_debug_policy: &str,
        wx_contract: &str,
    ) -> Self {
        self.crypto_mode = crypto_mode.to_string();
        self.at_rest_encryption = at_rest_encryption;
        self.aslr_preserved = aslr_preserved;
        self.integrity = integrity;
        self.crypto_coverage = crypto_coverage;
        self.anti_debug_policy = anti_debug_policy.to_string();
        self.wx_contract = wx_contract.to_string();
        self
    }

    /// Render as `key = value` lines (one per field), CSV for feature_flags.
    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("version = {}\n", self.version));
        out.push_str(&format!("build_id = {}\n", self.build_id));
        out.push_str(&format!(
            "seed_id = {}\n",
            self.seed_id.map(|s| format!("0x{:016X}", s)).unwrap_or_else(|| "none".to_string())
        ));
        out.push_str(&format!("vm_version = {}\n", self.vm_version));
        out.push_str(&format!("crypto_version = {}\n", self.crypto_version));
        out.push_str(&format!("input_hash = {}\n", self.input_hash));
        out.push_str(&format!("output_hash = {}\n", self.output_hash));
        out.push_str(&format!("feature_flags = {}\n", self.feature_flags.join(",")));
        out.push_str(&format!("crypto_mode = {}\n", self.crypto_mode));
        out.push_str(&format!("at_rest_encryption = {}\n", self.at_rest_encryption));
        out.push_str(&format!("aslr_preserved = {}\n", self.aslr_preserved));
        out.push_str(&format!("integrity = {}\n", self.integrity));
        out.push_str(&format!("crypto_coverage = {}\n", self.crypto_coverage));
        out.push_str(&format!("anti_debug_policy = {}\n", self.anti_debug_policy));
        out.push_str(&format!("wx_contract = {}\n", self.wx_contract));
        out
    }

    /// Write the rendered manifest to `path`.
    pub fn write_manifest(&self, path: &Path) -> io::Result<()> {
        std::fs::write(path, self.render().as_bytes())
    }
}

/// Collect the feature flags that were actually active into an ordered list.
/// Deliberately a plain function (not coupled to `CliArgs`) so the lib API can
/// build a manifest without constructing a CLI arg struct.
#[allow(clippy::too_many_arguments)]
pub fn feature_flags(
    anti_debug: bool,
    vm: bool,
    vm_oep: bool,
    vm_commercial: bool,
    m7: bool,
    m8: bool,
    integrity: bool,
    dispatcher_reencrypt: bool,
    payload_relocate: bool,
    rsrc_register: bool,
    iat_hide: bool,
    mem_harden: bool,
    custom_cipher: bool,
    chacha20: bool,
    map: bool,
    sym_map: bool,
    seed: bool,
) -> Vec<String> {
    let mut v = Vec::new();
    if anti_debug { v.push("anti_debug".to_string()); }
    if vm { v.push("vm".to_string()); }
    if vm_oep { v.push("vm_oep".to_string()); }
    if vm_commercial { v.push("vm_commercial".to_string()); }
    if m7 { v.push("m7".to_string()); }
    if m8 { v.push("m8".to_string()); }
    if integrity { v.push("integrity".to_string()); }
    if dispatcher_reencrypt { v.push("dispatcher_reencrypt".to_string()); }
    if payload_relocate { v.push("payload_relocate".to_string()); }
    if rsrc_register { v.push("rsrc_register".to_string()); }
    if iat_hide { v.push("iat_hide".to_string()); }
    if mem_harden { v.push("mem_harden".to_string()); }
    if custom_cipher { v.push("custom_cipher".to_string()); }
    if chacha20 { v.push("chacha20".to_string()); }
    if map { v.push("map".to_string()); }
    if sym_map { v.push("sym_map".to_string()); }
    if seed { v.push("seed".to_string()); }
    v
}

// ── Dependency-free SHA-256 (FIPS 180-4) ─────────────────────────────────────
// Compact (~70 line) pure-Rust implementation so the packer does not need a
// hashing crate. Correctness is pinned by the known-vector test below.

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// SHA-256 of `data`, lower-case hex.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];
    let bit_len = (data.len() as u64).wrapping_mul(8);

    let mut msg = Vec::with_capacity(data.len() + 72);
    msg.extend_from_slice(data);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    let mut w = [0u32; 64];
    for chunk in msg.chunks_exact(64) {
        for (i, word) in chunk.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) = (
            h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7],
        );
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    h.iter().map(|x| format!("{:08x}", x)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_vectors() {
        // FIPS 180-4 test vectors.
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn render_contains_all_fields() {
        let m = BuildManifest::new(
            Some(0x1234),
            vec!["vm".to_string(), "m8".to_string()],
            "ab".repeat(16),
            "cd".repeat(16),
        );
        let body = m.render();
        assert!(body.contains("version = 1.0.0"));
        assert!(body.contains("build_id = BTG-"));
        assert!(body.contains("seed_id = 0x0000000000001234"));
        assert!(body.contains("vm_version = 31"));
        assert!(body.contains("crypto_version = 63"));
        assert!(body.contains("input_hash = "));
        assert!(body.contains("output_hash = "));
        assert!(body.contains("feature_flags = vm,m8"));
    }

    #[test]
    fn build_id_is_deterministic_per_seed_input() {
        let a = BuildManifest::new(Some(7), vec![], "ab".repeat(16), "cd".repeat(16));
        let b = BuildManifest::new(Some(7), vec![], "ab".repeat(16), "ef".repeat(16));
        let c = BuildManifest::new(Some(8), vec![], "ab".repeat(16), "cd".repeat(16));
        // Same seed + input hash -> same build_id (output_hash difference irrelevant).
        assert_eq!(a.build_id, b.build_id);
        // Different seed -> different build_id.
        assert_ne!(a.build_id, c.build_id);
        assert!(a.build_id.starts_with("BTG-0000000000000007-"));
    }

    #[test]
    fn write_manifest_roundtrip() {
        let m = BuildManifest::new(
            None,
            vec!["iat_hide".to_string()],
            "ab".repeat(16),
            "cd".repeat(16),
        );
        let p = std::env::temp_dir().join("btg_manifest_test.txt");
        m.write_manifest(&p).expect("write manifest");
        let text = std::fs::read_to_string(&p).expect("read manifest");
        assert!(text.contains("seed_id = none"));
        assert!(text.contains("feature_flags = iat_hide"));
        let _ = std::fs::remove_file(&p);
    }
}
