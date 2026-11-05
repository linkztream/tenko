//! Hex encoding for fixtures and command-line keys. Small enough not to be a dependency.

/// Encodes bytes as lowercase hex.
pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Decodes hex; whitespace is ignored, an odd length or a stray character is an error.
pub fn decode(text: &str) -> Result<Vec<u8>, String> {
    let digits: Vec<u8> = text.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if !digits.len().is_multiple_of(2) {
        return Err("odd number of hex digits".into());
    }
    digits
        .chunks(2)
        .map(|pair| {
            let s = std::str::from_utf8(pair).map_err(|e| e.to_string())?;
            u8::from_str_radix(s, 16).map_err(|e| format!("{s:?}: {e}"))
        })
        .collect()
}
