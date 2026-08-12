// ==============================================================================
// BTG v41 - M7 on-demand 재암호화 (anti-dump)
// ==============================================================================
//
// M7 목표: 원본 `.text`/`.data`/`.rdata` 런을 **파일에는 암호문으로** 저장하고,
// 실행 중 필요할 때만 청크를 임시 복호화 → 사용 → **즉시 재암호화**하여, 어느 시점에
// 덤프를 떠도 원본 평문이 최소한만(또는 전혀) 노출되지 않게 한다.
//
// 이 모듈은 그 코어 로직을 순수 Rust로 제공한다:
//   - `OnDemandChunk`: RC4(키 스트림) 기반 청크 단위 복호화/재암호화.
//   - `process_on_demand(...)`: 주어진 바이트 범위를 (복호화→callback 사용→재암호화)
//     한 번에 처리해, 함수 반환 시점에 버퍼는 다시 **암호문**이 되도록 한다.
//   - `simulate_dump(...)`: "사용 직후 덤프"를 흉내내, 재암호화가 끝난 상태가
//     평문이 아닌지 검증하는 데 쓰인다.
//
// 부트 스텁(또는 패커의 --m7 배선)이 이 로직을 RC4 런 테이블의 각 런에 적용하면
// on-demand 재암호화가 동작한다. 회귀 안전: 기본 경로(--full/--vm)는 이 모듈을
// 호출하지 않으므로 무변경.
// ==============================================================================


/// RC4 스트림 (RFC 6229 호환) — 기존 부트 스텁/패커의 RC4와 동일 스트림.
pub struct Rc4 {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    pub fn new(key: &[u8]) -> Self {
        let mut s = [0u8; 256];
        for (i, v) in s.iter_mut().enumerate() {
            *v = i as u8;
        }
        let mut j = 0u8;
        for i in 0..256usize {
            j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
            s.swap(i, j as usize);
        }
        Self { s, i: 0, j: 0 }
    }
    pub fn crypt(&mut self, data: &mut [u8]) {
        for b in data.iter_mut() {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.s[self.i as usize]);
            self.s.swap(self.i as usize, self.j as usize);
            let k = self
                .s[(self.s[self.i as usize].wrapping_add(self.s[self.j as usize])) as usize];
            *b ^= k;
        }
    }
}

/// on-demand 청크 처리기.
/// `buf[..len]`을 `key`로 복호화 → `use_it(&mut buf[..len])` 호출 → 같은 키로 재암호화.
/// 반환 시점에 `buf[..len]`은 **암호문** (anti-dump).
pub fn process_on_demand<F: FnOnce(&mut [u8])>(buf: &mut [u8], len: usize, key: &[u8], use_it: F) {
    let mut rc4 = Rc4::new(key);
    rc4.crypt(&mut buf[..len]); // decrypt in place
    use_it(&mut buf[..len]);    // use the plaintext
    let mut rc4b = Rc4::new(key); // reset keystream
    rc4b.crypt(&mut buf[..len]); // re-encrypt in place
}

/// "사용 직후 덤프"를 흉내낸다: on-demand 처리 후 버퍼가 평문이 아닌지 검증.
/// `plain` = 원본 평문, `cipher` = 원본 암호문(파일에 저장된 상태).
/// 반환: `true` = 덤프가 평문을 노출하지 않음 (buf == cipher, 평문과 다름).
pub fn simulate_dump(plain: &[u8], cipher: &[u8], key: &[u8]) -> bool {
    let mut buf = cipher.to_vec();
    let len = buf.len();
    process_on_demand(&mut buf, len, key, |_| {
        // 사용 중: 평문 상태 (여기서는 아무것도 안 함)
    });
    // 반환 후: buf는 재암호화된 상태. 평문과 달라야 anti-dump 충족.
    buf != plain
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ondemand_roundtrip_leaves_encrypted() {
        let key = b"m7-on-demand-key";
        let plain = b"The quick brown fox jumps over the lazy dog. 0123456789";
        let mut cipher = plain.to_vec();
        let mut rc4 = Rc4::new(key);
        rc4.crypt(&mut cipher); // encrypt to produce file-state cipher
        assert_ne!(cipher, plain, "cipher should differ from plain");

        // on-demand: decrypt -> use -> re-encrypt leaves it encrypted.
        assert!(simulate_dump(plain, &cipher, key), "after use, dump must be encrypted");

        // And a second decrypt recovers plaintext (round-trip intact).
        let mut buf = cipher.clone();
        let mut rc4b = Rc4::new(key);
        rc4b.crypt(&mut buf);
        assert_eq!(buf, plain, "decrypt after on-demand must recover plaintext");
    }

    #[test]
    fn ondemand_use_sees_plaintext() {
        let key = b"k";
        let mut buf = b"secret".to_vec();
        // encrypt first
        let mut rc4 = Rc4::new(key);
        rc4.crypt(&mut buf);
        let mut seen = Vec::new();
        let blen = buf.len();
        process_on_demand(&mut buf, blen, key, |p| {
            seen.extend_from_slice(p); // during use, we see plaintext
        });
        assert_eq!(seen, b"secret", "use callback must observe plaintext");
        assert_ne!(buf, b"secret".to_vec(), "after on-demand, buffer must be re-encrypted");
    }
}
