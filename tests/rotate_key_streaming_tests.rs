// tests/rotate_key_streaming.rs
use aescrypt_rs::{decrypt, encrypt};
use encrypted_file_vault::aliases::{CypherText, FilePassword, PlainText, RandomFileKey32};
use encrypted_file_vault::crypto::{decrypt_to_vec, encrypt_to_vec};
use encrypted_file_vault::error::CoreError;
use encrypted_file_vault::key_ops::generate_key;
use encrypted_file_vault::FileKey32;
use secure_gate::{SecureConversionsExt, SecureRandomExt};
use std::io::{self, Cursor};

use crossbeam_channel::unbounded;

#[test]
fn test_rotate_key_streaming_large_file() -> Result<(), Box<dyn std::error::Error>> {
    println!("Testing streaming rotation with 100 MB file...");

    let plaintext_size = 100 * 1024 * 1024;
    let plaintext: Vec<u8> = (0..plaintext_size).map(|i| (i % 256) as u8).collect();

    let old_key = generate_key();
    let old_password = FilePassword::new(old_key.expose_secret().to_hex());

    let ciphertext = encrypt_to_vec(&PlainText::new(plaintext.clone()), &old_password)?;

    let (send_decrypt, recv_decrypt) = unbounded::<Vec<u8>>();
    let (send_encrypt, recv_encrypt) = unbounded::<Vec<u8>>();

    std::thread::scope(|s| -> Result<(), CoreError> {
        // 1. Decryption thread
        s.spawn({
            let ciphertext = ciphertext.clone();
            let old_password = old_password.clone();
            move || {
                let mut reader = Cursor::new(ciphertext.expose_secret());
                decrypt(
                    &mut reader,
                    ChannelWriter(send_decrypt.clone()),
                    &old_password,
                )
                .expect("decryption failed");
            }
        });

        // 2. Bridge thread – just forwards chunks
        s.spawn(move || {
            for chunk in recv_decrypt {
                send_encrypt.send(chunk).expect("bridge send failed");
            }
            drop(send_encrypt); // signal EOF
        });

        // 3. Main thread – generate new key and re-encrypt
        let new_password_hex = RandomFileKey32::random_hex();
        let new_key = FileKey32::new(
            new_password_hex
                .to_bytes()
                .try_into()
                .expect("random_hex yields exactly 32 bytes"),
        );
        let new_password = FilePassword::new(new_password_hex.expose_secret().clone());

        let mut output = Vec::new();
        let mut reader = ChannelReader {
            receiver: recv_encrypt,
            current_chunk: None,
        };
        encrypt(&mut reader, &mut output, &new_password, 1)?;

        // Verify round-trip
        let decrypted = decrypt_to_vec(
            &CypherText::new(output),
            &FilePassword::new(new_key.expose_secret().to_hex()),
        )?;

        assert_eq!(plaintext, decrypted.expose_secret().to_vec());
        println!("100 MB streaming rotation test PASSED!");
        Ok(())
    })?;

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Writer adapter – sends whole chunks into the channel
// ─────────────────────────────────────────────────────────────────────────────
#[derive(Clone)]
struct ChannelWriter(crossbeam_channel::Sender<Vec<u8>>);

impl io::Write for ChannelWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0
            .send(buf.to_vec())
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "channel closed"))?;
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Reader adapter – consumes Vec<u8> chunks from the channel
// ─────────────────────────────────────────────────────────────────────────────
struct ChannelReader {
    receiver: crossbeam_channel::Receiver<Vec<u8>>,
    current_chunk: Option<Vec<u8>>,
}

impl io::Read for ChannelReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        loop {
            // If we have data left in the current chunk, use it
            if let Some(chunk) = &self.current_chunk {
                if !chunk.is_empty() {
                    let len = std::cmp::min(buf.len(), chunk.len());
                    buf[..len].copy_from_slice(&chunk[..len]);
                    // Consume the used part
                    let remaining = chunk[len..].to_vec();
                    self.current_chunk = if remaining.is_empty() {
                        None
                    } else {
                        Some(remaining)
                    };
                    return Ok(len);
                }
            }

            // Current chunk exhausted → fetch next
            match self.receiver.recv() {
                Ok(next_chunk) => {
                    if next_chunk.is_empty() {
                        // Empty chunk = EOF convention (optional)
                        return Ok(0);
                    }
                    self.current_chunk = Some(next_chunk);
                    // loop again to consume from it
                }
                Err(_) => return Ok(0), // sender dropped → EOF
            }
        }
    }
}
