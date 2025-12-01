// tests/core/util.rs
use encrypted_file_vault::core::blake3_hex;

#[test]
fn test_blake3_hex_is_64_chars_lowercase() {
    let hex = blake3_hex(b"hello world");
    assert_eq!(hex.len(), 64);
    assert!(hex
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
}
