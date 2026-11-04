//! Minimal base64 codec (standard and URL-safe alphabets, padding optional).

const STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn val(c: u8) -> Option<u8> {
    Some(match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'+' | b'-' => 62,
        b'/' | b'_' => 63,
        _ => return None,
    })
}

/// Decode base64 in either alphabet; trailing `=` padding is optional.
/// Returns `None` on any invalid character or impossible length.
pub fn decode(input: &[u8]) -> Option<Vec<u8>> {
    let mut end = input.len();
    while end > 0 && input[end - 1] == b'=' {
        end -= 1;
    }
    let input = &input[..end];
    if input.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for &c in input {
        acc = (acc << 6) | u32::from(val(c)?);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

fn encode_with(data: &[u8], table: &[u8; 64], pad: bool) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        let chars = chunk.len() + 1;
        for i in 0..4 {
            if i < chars {
                out.push(table[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else if pad {
                out.push('=');
            }
        }
    }
    out
}

/// Encode with the URL-safe alphabet, no padding (JWT / key id style).
pub fn encode_url(data: &[u8]) -> String {
    encode_with(data, URL, false)
}

/// Encode with the standard alphabet and padding.
pub fn encode_std(data: &[u8]) -> String {
    encode_with(data, STD, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        for n in 0..40u8 {
            let data: Vec<u8> = (0..n).map(|i| i.wrapping_mul(37)).collect();
            assert_eq!(decode(encode_url(&data).as_bytes()).unwrap(), data);
            assert_eq!(decode(encode_std(&data).as_bytes()).unwrap(), data);
        }
        assert_eq!(encode_std(b"hello"), "aGVsbG8=");
        assert_eq!(decode(b"aGVsbG8").unwrap(), b"hello");
        assert!(decode(b"a").is_none());
        assert!(decode(b"a*bc").is_none());
    }
}
