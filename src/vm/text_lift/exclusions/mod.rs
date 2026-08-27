fn find_subslice(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() || from > hay.len() {
        return None;
    }
    (from..=hay.len() - needle.len()).find(|&i| &hay[i..i + needle.len()] == needle)
}

pub mod panic_unwind;
pub mod seh;
pub mod setjmp;

pub use panic_unwind::*;
pub use seh::*;
pub use setjmp::*;
