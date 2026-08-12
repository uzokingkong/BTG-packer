use std::hint::black_box;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::channel;
use std::thread;

#[inline(never)]
pub fn stage_threads(seed: u64) -> u64 {
    let atomic_vals: Arc<Vec<AtomicU64>> = Arc::new(
        (0..4).map(|i| AtomicU64::new(seed ^ (i * 0x1000))).collect()
    );
    let mutex_vals: Arc<Vec<Mutex<u64>>> = Arc::new(
        (0..4).map(|_| Mutex::new(0u64)).collect()
    );
    let (tx, rx) = channel::<(u64, u64)>();

    let mut handles = Vec::new();

    for id in 0..4usize {
        let atomic_clone = Arc::clone(&atomic_vals);
        let mutex_clone = Arc::clone(&mutex_vals);
        let tx_clone = tx.clone();

        let handle = thread::spawn(move || {
            // Real atomic assembly instructions (lock add, lock xchg, lock cmpxchg)
            let prev = atomic_clone[id].fetch_add((id as u64) * 0x1000 + 0x1337, Ordering::SeqCst);
            let updated_atomic = prev ^ ((id as u64).rotate_left(11));
            let _ = atomic_clone[id].compare_exchange(
                prev.wrapping_add((id as u64) * 0x1000 + 0x1337),
                updated_atomic,
                Ordering::SeqCst,
                Ordering::SeqCst,
            );
            let _ = atomic_clone[id].swap(updated_atomic, Ordering::SeqCst);

            // Real Mutex locking exercise
            let mut guard = mutex_clone[id].lock().unwrap();
            *guard = guard.wrapping_add((id as u64) * 0x7777 + 0xDEAD);

            // Compute result per thread ID
            let updated = (seed.wrapping_add(id as u64)).rotate_left((id * 7 + 3) as u32);
            let compute = updated.wrapping_mul(0x9E3779B185EBCA87) ^ (id as u64);
            tx_clone.send((id as u64, compute)).unwrap();
        });

        handles.push(handle);
    }

    drop(tx);

    for h in handles {
        h.join().unwrap();
    }

    let mut msgs: Vec<(u64, u64)> = Vec::new();
    while let Ok(msg) = rx.recv() {
        msgs.push(msg);
    }
    msgs.sort_by_key(|&(id, _)| id);

    let mut channel_sum = 0u64;
    for (i, &(_, msg)) in msgs.iter().enumerate() {
        channel_sum = channel_sum.wrapping_add(msg.rotate_left((i * 3 + 1) as u32));
    }

    let mut atomic_sum = 0u64;
    let mut mutex_sum = 0u64;
    for i in 0..4 {
        atomic_sum ^= atomic_vals[i].load(Ordering::SeqCst).rotate_left((i * 5) as u32);
        mutex_sum ^= (*mutex_vals[i].lock().unwrap()).rotate_left((i * 9) as u32);
    }

    let combined = atomic_sum ^ mutex_sum ^ channel_sum;
    black_box(combined)
}
