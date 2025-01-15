use alloc::vec;
use alloc::vec::Vec;

const B58DIGITS_ORDERED: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

pub fn custom_b58enc(data: &[u8], alpha: &[u8; 58]) -> Vec<u8> {
    let mut zcount = 0;

    while zcount < data.len() && data[zcount] == 0 {
        zcount += 1;
    }

    let size = (data.len() - zcount) * 138 / 100 + 1;
    let mut buf = vec![0u8; size];

    let mut high = size - 1;
    for (_, &val) in data.iter().enumerate().skip(zcount) {
        let mut carry = val as usize;
        let mut j = size - 1;

        while j > high || carry != 0 {
            carry += 256 * buf[j] as usize;
            buf[j] = (carry % 58) as u8;
            carry /= 58;

            if j == 0 {
                break;
            }
            j -= 1;
        }
        high = j;
    }

    let mut j = 0;
    while j < size && buf[j] == 0 {
        j += 1;
    }

    let mut result = Vec::with_capacity(zcount + size - j);
    result.extend(vec![alpha[0]; zcount]);

    for &val in &buf[j..] {
        result.push(alpha[val as usize]);
    }

    result
}

pub fn b58enc(data: &[u8]) -> Vec<u8> {
    custom_b58enc(data, B58DIGITS_ORDERED)
}
