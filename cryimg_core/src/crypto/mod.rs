use std::str::FromStr;

pub mod encrypt;
pub mod decrypt;

use encrypt::*;
use decrypt::*;


/// Supported encryption algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Algorithm {
    None,
    Xor,
    Caesar,
    Rot13,
    Aes,
}

impl FromStr for Algorithm {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "none" => Ok(Algorithm::None),
            "xor" => Ok(Algorithm::Xor),
            "caesar" => Ok(Algorithm::Caesar),
            "rot13" => Ok(Algorithm::Rot13),
            "aes" => Ok(Algorithm::Aes),
            other => Err(format!("Unsupported algorithm: {}", other)),
        }
    }
}

/// Encrypt a message using the given algorithm and key
pub fn encrypt_message(msg: &str, key: &str, algo: Algorithm) -> Result<String, String> {
    match algo {
        Algorithm::None => Ok(msg.to_string()),
        Algorithm::Xor => xor_encrypt(msg, key),
        Algorithm::Caesar => caesar_encrypt(msg, key),
        Algorithm::Rot13 => rot13_encrypt(msg),
        Algorithm::Aes => aes_encrypt(msg, key),
    }
}

/// Decrypt a message using the given algorithm and key
pub fn decrypt_message(cipher: &str, key: &str, algo: Algorithm) -> Result<String, String> {
    match algo {
        Algorithm::None => Ok(cipher.to_string()),
        Algorithm::Xor => xor_decrypt(cipher, key),
        Algorithm::Caesar => caesar_decrypt(cipher, key),
        Algorithm::Rot13 => rot13_decrypt(cipher),
        Algorithm::Aes => aes_decrypt(cipher, key),
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crypto_encrypt_decrypt_aes() {
        let msg = "Hello, World!";
        let key = "mysecretkey";
        let algo = Algorithm::Aes;

        let encrypted = encrypt_message(msg, key, algo).unwrap();
        let decrypted = decrypt_message(&encrypted, key, algo).unwrap();

        assert_eq!(decrypted, msg);
    }
    #[test]
    fn crypto_encrypt_decrypt_xor() {
        let msg = "Hello, World!";
        let key = "key";
        let algo = Algorithm::Xor;

        let encrypted = encrypt_message(msg, key, algo).unwrap();
        let decrypted = decrypt_message(&encrypted, key, algo).unwrap();

        assert_eq!(decrypted, msg);
    }
    #[test]
    fn crypto_encrypt_decrypt_caesar() {
        let msg = "Hello, World!";
        let key = "3"; // Shift by 3
        let algo = Algorithm::Caesar;

        let encrypted = encrypt_message(msg, key, algo).unwrap();
        let decrypted = decrypt_message(&encrypted, key, algo).unwrap();

        assert_eq!(decrypted, msg);
    }
    #[test]
    fn crypto_encrypt_decrypt_rot13() {
        let msg = "Hello, World!";
        let algo = Algorithm::Rot13;

        let encrypted = encrypt_message(msg, "", algo).unwrap();
        let decrypted = decrypt_message(&encrypted, "", algo).unwrap();

        assert_eq!(decrypted, msg);
    }
    #[test]
    fn crypto_encrypt_decrypt_none() {
        let msg = "Hello, World!";
        let algo = Algorithm::None;

        let encrypted = encrypt_message(msg, "", algo).unwrap();
        let decrypted = decrypt_message(&encrypted, "", algo).unwrap();

        assert_eq!(decrypted, msg);
    }
    #[test]
    fn crypto_invalid_algorithm() -> Result<(), String> {
        match Algorithm::from_str("invalid") {
            Ok(algorithm) => {
                panic!("Expected error for invalid algorithm, but got: {:?}", algorithm);
            }
            Err(e) => {
                println!("Caught expected error: {e}");
                Ok(())
            }
        }
    }


    #[test]
    fn crypto_encrypt_with_empty_key() {
        let msg = "Hello, World!";
        let algo = Algorithm::Xor;

        let encrypted = encrypt_message(msg, "", algo);
        assert!(encrypted.is_err());
        assert_eq!(encrypted.unwrap_err(), "XOR encryption requires a non-empty key");
    }

    #[test]
    fn crypto_decrypt_with_empty_key() {
        let msg = "Hello, World!";
        let key = "secret";
        let algo = Algorithm::Xor;

        // First encrypt with a valid key
        let encrypted = encrypt_message(msg, key, algo).unwrap();

        // Now attempt to decrypt with an empty key
        let decrypted = decrypt_message(&encrypted, "", algo);
        assert!(decrypted.is_err());
        assert_eq!(decrypted.unwrap_err(), "XOR decryption requires a non-empty key");
    }

    #[test]
    fn crypto_caesar_encrypt_invalid_key() {
        let msg = "Hello, World!";
        let key = "invalid"; // Non-numeric key
        let algo = Algorithm::Caesar;

        let encrypted = encrypt_message(msg, key, algo);
        assert!(encrypted.is_err());
        assert_eq!(encrypted.unwrap_err(), "Key must be a number for Caesar cipher");

        let decrypted = decrypt_message(msg, key, algo);
        assert!(decrypted.is_err());
        assert_eq!(decrypted.unwrap_err(), "Key must be a number for Caesar cipher");
    }
}