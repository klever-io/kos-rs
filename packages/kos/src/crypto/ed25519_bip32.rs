use alloc::vec;
use alloc::vec::Vec;

pub fn add28_mul8(x: &[u8], y: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; 32];
    let mut carry = 0u16;

    // Process the first 28 bytes with multiplication by 8
    for i in 0..28 {
        let r = x[i] as u16 + ((y[i] as u16) << 3) + carry;
        out[i] = (r & 0xff) as u8;
        carry = r >> 8;
    }

    // Process the remaining bytes with only carry
    for i in 28..32 {
        let r = x[i] as u16 + carry;
        out[i] = (r & 0xff) as u8;
        carry = r >> 8;
    }

    out
}

pub fn add_mod256(x: &[u8], y: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; 32]; // Initialize output vector with 32 zeros
    let mut carry = 0u16; // Initialize carry as a 16-bit integer to hold overflow

    for i in 0..32 {
        // Perform the addition with carry for each byte
        let r = x[i] as u16 + y[i] as u16 + carry;
        out[i] = (r & 0xFF) as u8; // Assign the lower 8 bits to the output
        carry = r >> 8; // Update carry with the overflow bit
    }

    out
}
