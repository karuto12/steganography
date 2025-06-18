use clap::{Parser, ArgGroup};
use crate::crypto::Algorithm;


/// 🔐 Embed secret messages in images using LSB steganography.
#[derive(Parser, Debug)]
#[clap(
    name = "cimg",
    version,
    author = "Haridas Mahato <haridasmahato12@gmail.com>", 
    about = "🔐 Cryimg: Hide messages in images using LSB steganography", 
    long_about = Some(concat!(
        "🔐 Cryimg: Hide messages in images using LSB steganography\n\
         Author: Haridas Mahato <haridasmahato12@gmail.com>\n\
         Version: ", env!("CARGO_PKG_VERSION"),)
    ),
)]
#[command(group(
    ArgGroup::new("mode")
        .required(true)
        .args(["encrypt", "decrypt"])
        .multiple(false) // Only one allowed
))]
pub struct Args {
    /// 📷 Path to the input image
    #[arg(short, long, help = "Path to the input image file")]
    pub img: String,

    /// ✉️ Message to embed
    #[arg(short, long, help = "Secret message to embed in the image")]
    pub msg: Option<String>,

    /// 📁 Path to the output image
    #[arg(short, long, default_value = "output.png", help = "Path to the output image file")]
    pub out: String,

    /// 🔒 Encryption algorithm: none | xor | caesar | rot13 | aes
    #[arg(short, long, help = "Encryption algorithm")]
    pub encrypt: Option<Algorithm>,
    
    /// 🔒 Decryption algorithm: none | xor | caesar | rot13 | aes
    #[arg(short, long, help = "Decryption algorithm")]
    pub decrypt: Option<Algorithm>,

    /// 🔑 Key for encryption
    #[arg(long, help = "Key for encryption/decryption (if applicable)")]
    pub key: Option<String>,

    /// 🎲 Use pseudorandom embedding order
    #[arg(long, help = "Enable PRNG-based pixel scrambling")]
    pub prng: bool,

    /// 🌱 Seed for the PRNG
    #[arg(long, default_value = "", help = "Seed for PRNG (only if --prng is enabled) | Can be any string (internally hashed to a u64)")]
    pub seed: String,

    /// 🕵️ Analyze with the image and the msg
    #[arg(short, long, help = "Analyze with the image and the msg")]
    pub analyze: bool,
}

impl Args {
    pub fn algorithm(&self) -> Result<Algorithm, String> {
        match (&self.encrypt, &self.decrypt) {
            (Some(e), None) => Ok(e.clone()),
            (None, Some(d)) => Ok(d.clone()),
            (Some(_), Some(_)) => Err("Cannot specify both --encrypt and --decrypt.".into()),
            (None, None) => Err("Either --encrypt or --decrypt must be specified.".into()),
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        // Ensure PRNG needs seed
        if self.prng && self.seed.is_empty() {
            return Err("PRNG is enabled, but seed is missing. Provide a seed using --seed.".into());
        }

        // Validate algorithm and key requirement
        let algo = self.algorithm()?;

        if matches!(algo, Algorithm::Xor | Algorithm::Caesar | Algorithm::Aes) && self.key.is_none() {
            return Err(format!("Encryption algorithm '{:?}' requires a non-empty key.", algo));
        }

        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn parse_args<I>(args: I) -> Result<Args, clap::Error>
        where
            I: IntoIterator,
            I::Item: AsRef<str>,
        {
            let argv: Vec<String> = std::iter::once("cimg".to_string())
                .chain(args.into_iter().map(|s| s.as_ref().to_string()))
                .collect();
            Args::try_parse_from(argv)
        }
    #[test]
    fn cli_basic_args() {
        let args = parse_args(&[
            "--img", "test.png", 
            "--msg", "Hello, World!",
            "--encrypt", "none",
        ]).unwrap();
        assert_eq!(args.img, "test.png");
        assert_eq!(args.msg.clone().unwrap(), "Hello, World!");
        assert_eq!(args.out, "output.png");
        assert_eq!(args.algorithm().unwrap(), Algorithm::None);
        assert_eq!(args.decrypt, None);
        assert_eq!(args.key.unwrap_or_default(), "");
        assert!(!args.prng);
        assert_eq!(args.seed, "");
    }

    #[test]
    fn cli_encrypt_and_key() {
        let args = parse_args(&[
            "--img", "test.png",
            "--msg", "Secret Message",
            "--out", "output.png",
            "--encrypt", "xor",
            "--key", "mysecretkey",
        ]).unwrap();
        assert_eq!(args.algorithm().unwrap(), Algorithm::Xor);
        assert_eq!(args.key.unwrap(), "mysecretkey");
    }

    #[test]
    fn cli_prng_and_seed() {
        let args = parse_args(&[
            "--img", "test.png",
            "--msg", "Randomized Message",
            "--out", "output.png",
            "--prng",
            "--seed", "12345",
            "--encrypt", "none",
        ]).unwrap();
        assert!(args.prng);
        assert_eq!(args.seed, "12345");
    }

    #[test]
    fn cli_decrypt_and_key() {
        let args = parse_args(&[
            "--img", "test.png",
            "--msg", "Default Test",
            "--decrypt", "xor",
            "--key", "mysecretkey",
        ]).unwrap();
        assert_eq!(args.algorithm().unwrap(), Algorithm::Xor);
        assert_eq!(args.key.unwrap(), "mysecretkey");
    }

    #[test]
    fn cli_all_args() {
        let args = parse_args(&[
            "--img", "test.png",
            "--msg", "Full Test Message",
            "--out", "output.png",
            "--encrypt", "aes",
            "--key", "supersecretkey",
            "--prng",
            "--seed", "54321",
        ]).unwrap();
        assert_eq!(args.img, "test.png");
        assert_eq!(args.msg.clone().unwrap(), "Full Test Message");
        assert_eq!(args.out, "output.png");
        assert_eq!(args.algorithm().unwrap(), Algorithm::Aes);
        assert_eq!(args.key.unwrap(), "supersecretkey");
        assert!(args.prng);
        assert_eq!(args.seed, "54321");
    }

    #[test]
    fn cli_help_output() {
        use clap::CommandFactory;
        let mut cmd = Args::command();
        let help = cmd.render_help().to_string();
        println!("{}", help);
        assert!(help.contains("Embed secret messages"));
        assert!(help.contains("-i, --img"));
        assert!(help.contains("--encrypt"));
    }

    #[test]
    fn cli_missing_key_for_xor() {
        let args = parse_args(&[
            "--img", "test.png",
            "--msg", "Oops",
            "--encrypt", "xor",
        ]).unwrap();
        let result = args.validate();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Encryption algorithm 'Xor' requires a non-empty key.");
    }

    #[test]
    fn cli_prng_without_seed() {
        let args = parse_args(&[
            "--img", "test.png",
            "--msg", "Oops",
            "--prng",
            "--encrypt", "none",
        ]).unwrap();
        let result = args.validate();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "PRNG is enabled, but seed is missing. Provide a seed using --seed.");
    }

    #[test]
    fn cli_invalid_algorithm() {
        let args = parse_args(&[
            "--img", "test.png",
            "--msg", "Invalid Algorithm",
            "--encrypt", "invalid_algo",
        ]);
        assert!(args.is_err());
        let err = args.unwrap_err().to_string();
        assert!(err.contains("Unsupported algorithm: invalid_algo"));
    }

    #[test]
    fn cli_both_encrypt_and_decrypt() {
        let result = Args::try_parse_from([
            "--img", "test.png",
            "--msg", "Conflicting Options",
            "--encrypt", "xor",
            "--decrypt", "aes",
        ]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("<--encrypt <ENCRYPT>|--decrypt <DECRYPT>>"));
    }

    #[test]
    fn cli_analyze_flag() {
        let args = parse_args(&[
            "--img", "test.png",
            "--msg", "Analyze Test",
            "--encrypt", "none",
            "--analyze",
        ]).unwrap();
        assert!(args.analyze);
    }
    
}