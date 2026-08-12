use std::fs::{File, remove_file};
use std::io::{Read, Write};
use std::hint::black_box;
use std::time::Instant;

#[inline(never)]
pub fn stage_sys_interop(seed: u64) -> u64 {
    // 1. High Resolution Timer Call
    let start = Instant::now();
    let mut dummy = seed;
    for i in 0..100 {
        dummy = dummy.wrapping_add(i);
    }
    let elapsed_nanos = start.elapsed().as_nanos() as u64;

    // 2. Temp File Write & Read Verification
    let temp_dir = std::env::temp_dir();
    let file_path = temp_dir.join(format!("btg_pack_test_{:016x}.tmp", seed));

    let mut payload = Vec::with_capacity(256);
    let mut x = seed ^ 0x42424242;
    for i in 0..256 {
        x = x.wrapping_mul(0x9E3779B185EBCA87) ^ (i as u64);
        payload.push((x & 0xFF) as u8);
    }

    // Write file
    let mut file_out = File::create(&file_path).expect("Failed to create temp file");
    file_out.write_all(&payload).expect("Failed to write temp file");
    drop(file_out);

    // Read back file
    let mut file_in = File::open(&file_path).expect("Failed to open temp file");
    let mut read_buf = Vec::new();
    file_in.read_to_end(&mut read_buf).expect("Failed to read temp file");
    drop(file_in);

    // Remove file
    let _ = remove_file(&file_path);

    // Verify content checksum
    let mut hash = 0xCBF29CE484222325u64;
    for &b in &read_buf {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001B3);
    }

    // 3. Environment Variable Query
    let has_sys_root = if std::env::var("SystemRoot").is_ok() || std::env::var("PATH").is_ok() {
        0x7777u64
    } else {
        0x1111u64
    };

    // Ensure timer works deterministically for verification hash
    let timer_valid = if elapsed_nanos > 0 || dummy != seed { 0x5555u64 } else { 0x1111u64 };

    let final_res = hash ^ (has_sys_root.rotate_left(13)) ^ timer_valid;
    black_box(final_res)
}
