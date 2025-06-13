use aes::Aes256;
use block_modes::{Cbc, block_padding::Pkcs7, BlockMode};
use sha2::{Sha256, Digest};
use rand::prelude::*;
use base64::{engine::general_purpose, Engine as _};


type Aes256Cbc = Cbc<Aes256, Pkcs7>;

pub fn xor_encrypt(msg: &str, key: &str) -> Result<String, String> {
    if key.is_empty() {
        return Err("XOR encryption requires a non-empty key".into());
    }
    let encrypted: Vec<u8> = msg
        .bytes()
        .zip(key.bytes().cycle())
        .map(|(m, k)| m ^ k)
        .collect();
    Ok(general_purpose::STANDARD.encode(&encrypted))
}

pub fn caesar_encrypt(msg: &str, key: &str) -> Result<String, String> {
    let shift = key.parse::<u8>().map_err(|_| "Key must be a number for Caesar cipher")?;
    let encrypted: String = msg
        .chars()
        .map(|c| {
            if c.is_ascii_alphabetic() {
                let base = if c.is_ascii_lowercase() { b'a' } else { b'A' };
                ((c as u8 - base + shift) % 26 + base) as char
            } else {
                c
            }
        })
        .collect();
    Ok(encrypted)
}

pub fn rot13_encrypt(msg: &str) -> String {
    msg.chars()
        .map(|c| match c {
            'a'..='z' => (((c as u8 - b'a' + 13) % 26) + b'a') as char,
            'A'..='Z' => (((c as u8 - b'A' + 13) % 26) + b'A') as char,
            _ => c,
        })
        .collect()
}


pub fn aes_encrypt(msg: &str, key: &str) -> Result<String, String> {
    if key.is_empty() {
        return Err("AES encryption requires a non-empty key".into());
    }

    // Derive a 256-bit key from the string using SHA-256
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    let key_bytes = hasher.finalize();

    // Generate a random 16-byte IV
    let mut rng = rand::rng();
    let iv: [u8; 16] = rng.random();

    // Create AES CBC cipher
    let cipher = Aes256Cbc::new_from_slices(&key_bytes, &iv)
        .map_err(|e| format!("Cipher creation error: {e}"))?;

    // Encrypt message
    let ciphertext = cipher.encrypt_vec(msg.as_bytes());

    // Combine IV + ciphertext and base64 encode
    let mut result = Vec::new();
    result.extend_from_slice(&iv);
    result.extend_from_slice(&ciphertext);

    Ok(general_purpose::STANDARD.encode(&result))
}



#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::decrypt::*;

    #[test]
    fn test_xor_encrypt() {
        let msg = "Hello, World!";
        let key = "key";
        let encrypted = xor_encrypt(msg, key).unwrap();
        let decrypted = xor_decrypt(&encrypted, key).unwrap();
        assert_eq!(decrypted, msg);
    }

    #[test]
    fn test_caesar_encrypt() {
        let msg = "Hello, World!";
        let key = "3";
        let encrypted = caesar_encrypt(msg, key).unwrap();
        let decrypted = caesar_decrypt(&encrypted, key).unwrap();
        assert_eq!(decrypted, msg);
    }

    #[test]
    fn test_rot13_encrypt() {
        let msg = "Hello, World!";
        let encrypted = rot13_encrypt(msg);
        let decrypted = rot13_decrypt(&encrypted);
        assert_eq!(decrypted, msg);
    }

    #[test]
    fn test_xor_encrypt_empty_key() {
        let msg = "Hello, World!";
        let key = "";
        let result = xor_encrypt(msg, key);
        assert!(result.is_err());
        assert_eq!(result.err().unwrap(), "XOR encryption requires a non-empty key");
    }

    #[test]
    fn test_caesar_encrypt_invalid_key() {
        let msg = "Hello, World!";
        let key = "invalid";
        let result = caesar_encrypt(msg, key);
        assert!(result.is_err());
        assert_eq!(result.err().unwrap(), "Key must be a number for Caesar cipher");
    }

    #[test]
    fn test_aes_encrypt() {
        let msg = "Hello, World!";
        let key = "mysecretkey";
        let encrypted = aes_encrypt(msg, key).unwrap();
        let decrypted = aes_decrypt(&encrypted, key).unwrap();
        assert_eq!(decrypted, msg);
    }

}