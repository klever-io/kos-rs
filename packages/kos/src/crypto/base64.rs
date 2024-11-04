// A very simple base64 encoder for demonstration purposes
pub fn simple_base64_encode(input: &[u8]) -> alloc::string::String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = alloc::string::String::new();

    let mut temp = 0u32;
    let mut temp_bits = 0;

    for byte in input {
        temp <<= 8;
        temp |= *byte as u32;
        temp_bits += 8;

        while temp_bits >= 6 {
            temp_bits -= 6;
            output.push(CHARSET[((temp >> temp_bits) & 0x3F) as usize] as char);
        }
    }

    if temp_bits > 0 {
        temp <<= 6 - temp_bits;
        output.push(CHARSET[(temp & 0x3F) as usize] as char);
    }

    while output.len() % 4 != 0 {
        output.push('=');
    }

    output
}

// A very simple base64 decoder for demonstration purposes
pub fn simple_base64_decode(input: &str) -> Result<alloc::vec::Vec<u8>, &'static str> {
    let input = input.trim_end_matches('=');
    let mut buffer = alloc::vec::Vec::new();

    let mut temp = 0u32;
    let mut temp_bits = 0;
    for c in input.chars() {
        let value = match c as u8 {
            b'A'..=b'Z' => c as u8 - b'A',
            b'a'..=b'z' => c as u8 - b'a' + 26,
            b'0'..=b'9' => c as u8 - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return Err("Invalid base64 character"),
        };
        temp <<= 6;
        temp |= value as u32;
        temp_bits += 6;

        if temp_bits >= 8 {
            temp_bits -= 8;
            buffer.push((temp >> temp_bits) as u8);
        }
    }

    if temp_bits >= 6 || (temp & ((1 << temp_bits) - 1)) != 0 {
        return Err("Invalid base64 padding");
    }

    Ok(buffer)
}
