use clap::Parser;

#[derive(Debug, Clone)]
pub enum Mode {
    Encrypt,
    Decrypt,
}

impl std::str::FromStr for Mode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "encrypt" => Ok(Mode::Encrypt),
            "decrypt" => Ok(Mode::Decrypt),
            _ => Err(format!("Invalid mode: {}", s)),
        }
    }
}


/// 🔐 Embed secret messages in images using LSB steganography.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
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
    #[arg(long, default_value = "none", help = "Encryption method (default: none)")]
    pub encrypt: String,

    /// 🔑 Key for encryption
    #[arg(long, default_value = "", help = "Key for encryption (if applicable)")]
    pub key: String,

    /// 🎲 Use pseudorandom embedding order
    #[arg(long, help = "Enable PRNG-based pixel scrambling")]
    pub prng: bool,

    /// 🌱 Seed for the PRNG
    #[arg(long, default_value = "", help = "Seed for PRNG (only if --prng is enabled) | Can be any string (internally hashed to a u64)")]
    pub seed: String,

    /// 🧭 Operation mode: encrypt | decrypt
    #[arg(long, default_value = "encrypt", help = "Operation mode")]
    pub mode: Mode,
}

impl Args {
    pub fn validate(&self) -> Result<(), String> {
        // XOR, AES, Caesar require a non-empty key
        match self.encrypt.as_str() {
            "xor" | "aes" | "caesar" => {
                if self.key.is_empty() {
                    return Err(format!("Encryption method '{}' requires a non-empty key", self.encrypt));
                }
            }
            "rot13" | "none" => {} // No key needed
            _ => return Err(format!("Unsupported encryption method '{}'", self.encrypt)),
        }

        // If PRNG is enabled, and seed is empty
        if self.prng && self.seed.is_empty() {
            return Err("PRNG enabled but seed is empty — provide a seed with --seed".into());
        }

        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn parse_args(args: &[&str]) -> Args {
        Args::parse_from(std::iter::once("cryimg").chain(args.iter().cloned()))
    }
    #[test]
    fn test_basic_args() {
        let args = parse_args(&[
            "--img", "test.png", 
            "--msg", "Hello, World!", 
            "--out", "output.png"]); 
        assert_eq!(args.img, "test.png");
        assert_eq!(args.msg, Some("Hello, World!".to_string()));
        assert_eq!(args.out, "output.png");
    }

    #[test]
    fn test_encrypt_and_key() {
        let args = parse_args(&[
            "--img", "test.png",
            "--msg", "Secret Message",
            "--out", "output.png",
            "--encrypt", "xor",
            "--key", "mysecretkey",
        ]);
        assert_eq!(args.encrypt, "xor");
        assert_eq!(args.key, "mysecretkey");
    }

    #[test]
    fn test_prng_and_seed() {
        let args = parse_args(&[
            "--img", "test.png",
            "--msg", "Randomized Message",
            "--out", "output.png",
            "--prng",
            "--seed", "12345",
        ]);
        assert!(args.prng);
        assert_eq!(args.seed, "12345");
    }

    #[test]
    fn test_default_values() {
        let args = parse_args(&[
            "--img", "test.png", 
            "--msg", "Default Test"
        ]);
        assert_eq!(args.out, "output.png");
        assert_eq!(args.encrypt, "none");
        assert_eq!(args.key, "");
        assert!(!args.prng);
        assert_eq!(args.seed, "");
    }

    #[test]
    fn test_all_args() {
        let args = parse_args(&[
            "--img", "test.png",
            "--msg", "Full Test Message",
            "--out", "output.png",
            "--encrypt", "aes",
            "--key", "supersecretkey",
            "--prng",
            "--seed", "54321",
        ]);
        assert_eq!(args.img, "test.png");
        assert_eq!(args.msg, Some("Full Test Message".to_string()));
        assert_eq!(args.out, "output.png");
        assert_eq!(args.encrypt, "aes");
        assert_eq!(args.key, "supersecretkey");
        assert!(args.prng);
        assert_eq!(args.seed, "54321");
    }

    #[test]
    fn test_help_output() {
        use clap::CommandFactory;
        let mut cmd = Args::command();
        let help = cmd.render_help().to_string();
        println!("{}", help);
        assert!(help.contains("Embed secret messages"));
        assert!(help.contains("-i, --img"));
        assert!(help.contains("--encrypt"));
    }

    #[test]
    fn test_missing_key_for_xor() {
        let args = parse_args(&[
            "--img", "test.png",
            "--msg", "Oops",
            "--encrypt", "xor",
        ]);
        let result = args.validate();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Encryption method 'xor' requires a non-empty key");
    }

    #[test]
    fn test_prng_without_seed() {
        let args = parse_args(&[
            "--img", "test.png",
            "--msg", "Oops",
            "--prng"
        ]);
        let result = args.validate();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "PRNG enabled but seed is empty — provide a seed with --seed");
    }

}