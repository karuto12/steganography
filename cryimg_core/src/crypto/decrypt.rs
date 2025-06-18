use aes::Aes256;
use block_modes::{Cbc, BlockMode};
use block_modes::block_padding::Pkcs7;
use sha2::{Sha256, Digest};
use base64::{engine::general_purpose, Engine as _};


type Aes256Cbc = Cbc<Aes256, Pkcs7>;


pub fn xor_decrypt(encoded: &str, key: &str) -> Result<String, String> {
    let encrypted = general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| "Failed to decode base64")?;
    if key.is_empty() {
        return Err("XOR decryption requires a non-empty key".into());
    }
    let decrypted: Vec<u8> = encrypted
        .into_iter()
        .zip(key.bytes().cycle())
        .map(|(m, k)| m ^ k)
        .collect();
    String::from_utf8(decrypted).map_err(|_| "Invalid UTF-8 in decrypted XOR message".into())
}

pub fn caesar_decrypt(msg: &str, key: &str) -> Result<String, String> {
    let shift = key.parse::<u8>().map_err(|_| "Key must be a number for Caesar cipher")?;
    let decrypted: String = msg
        .chars()
        .map(|c| {
            if c.is_ascii_alphabetic() {
                let base = if c.is_ascii_lowercase() { b'a' } else { b'A' };
                ((c as u8 - base + 26 - shift) % 26 + base) as char
            } else {
                c
            }
        })
        .collect();
    Ok(decrypted)
}

pub fn rot13_decrypt(msg: &str) -> Result<String, String> {
    super::encrypt::rot13_encrypt(msg)
}

pub fn aes_decrypt(encoded: &str, key: &str) -> Result<String, String> {
    if key.is_empty() {
        return Err("AES decryption requires a non-empty key".into());
    }

    let data = general_purpose::STANDARD
        .decode(encoded)
        .map_err(|e| format!("Base64 decode error: {e}"))?;

    if data.len() < 16 {
        return Err("Data too short to contain IV".into());
    }

    let (iv, ciphertext) = data.split_at(16);

    // Derive the key
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    let key_bytes = hasher.finalize();

    // Create cipher
    let cipher = Aes256Cbc::new_from_slices(&key_bytes, iv)
        .map_err(|e| format!("Cipher creation error: {e}"))?;

    let decrypted = cipher
        .decrypt_vec(ciphertext)
        .map_err(|e| format!("Decryption failed: {e}"))?;

    String::from_utf8(decrypted).map_err(|e| format!("UTF-8 error: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::encrypt::*;

    #[test]
    fn decrypt_xor_decrypt() {
        let msg = "Hello, World!";
        let key = "key";
        let encrypted = xor_encrypt(msg, key).unwrap();
        let decrypted = xor_decrypt(&encrypted, key).unwrap();
        assert_eq!(decrypted, msg);
    }
    #[test]
    fn decrypt_caesar_decrypt() {
        let msg = "Khoor, Zruog!";
        let key = "3";
        let decrypted = caesar_decrypt(msg, key).unwrap();
        assert_eq!(decrypted, "Hello, World!");
    }
    #[test]
    fn decrypt_rot13_decrypt() {
        let msg = "Uryyb, Jbeyq!";
        let decrypted = rot13_decrypt(msg).unwrap();
        assert_eq!(decrypted, "Hello, World!");
    }
    #[test]
    fn decrypt_aes_decrypt() {
        let msg = "Hello, World!";
        let key = "mysecretkey";
        let encrypted = aes_encrypt(msg, key).unwrap();
        let decrypted = aes_decrypt(&encrypted, key).unwrap();
        assert_eq!(decrypted, msg);
    }
    #[test]
    fn decrypt_xor_decrypt_empty_key() {
        let msg = "Hello, World!";
        let encrypted = aes_encrypt(msg, "mysecretkey").unwrap();
        let key = "";
        let result = xor_decrypt(&encrypted, key);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "XOR decryption requires a non-empty key");
    }
    #[test]
    fn decrypt_caesar_decrypt_invalid_key() {
        let msg = "Khoor, Zruog!";
        let key = "invalid";
        let result = caesar_decrypt(msg, key);
        assert!(result.is_err());
        assert_eq!(result.err().unwrap(), "Key must be a number for Caesar cipher");
    }

}