pub mod error;
pub mod chain;
pub mod bytes;

mod array_types;
pub use array_types::*;



pub(crate) const fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'F' => Some(c - b'A' + 10),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'0'..=b'9' => Some(c - b'0'),
        _ => None,
    }
}
