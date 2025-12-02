// tests/core/key.rs
use encrypted_file_vault::aliases::FileKey32;
use encrypted_file_vault::key_ops::{generate_key, password_representations};

#[test]
fn test_generate_key_is_random_and_32_bytes() {
    let key1 = generate_key();
    let key2 = generate_key();
    assert_eq!(key1.expose_secret().len(), 32);
    assert_ne!(
        key1.expose_secret().as_slice(),
        key2.expose_secret().as_slice()
    );
}

#[test]
fn test_password_representations_are_correct_and_consistent() {
    let key = FileKey32::new([0x42; 32]);
    let repr = password_representations(&key);

    assert_eq!(
        repr.hex,
        "4242424242424242424242424242424242424242424242424242424242424242"
    );
    assert_eq!(repr.base64, "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI=");
    assert_eq!(
        repr.base64url_no_pad,
        "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI"
    );
}
