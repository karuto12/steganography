use clap::Parser;

use util::{cli::{Args}, crypto::encrypt_message, crypto::decrypt_message, stegano, utils::string_to_seed};

fn main() {
    let args = Args::parse();

    let algo = args.algorithm().unwrap();

    let seed: Option<u64> = if args.seed.is_empty() {
        None
    } else {
        Some(string_to_seed(&args.seed))
    };

    if let Some(_) = args.encrypt {
        // Encrypt mode
        let plain_msg = match &args.msg {
            Some(m) => m,
            None => {
                eprintln!("Error: --msg is required in encrypt mode");
                std::process::exit(1);
            }
        };
        let encrypted = match encrypt_message(&plain_msg, &args.key, algo) {
            Ok(msg) => msg,
            Err(e) => {
                eprintln!("Encryption failed: {e}");
                std::process::exit(1);
            }
        };

        let img = image::open(&args.img).unwrap_or_else(|e| {
            eprintln!("Failed to open image: {e}");
            std::process::exit(1);
        });

        if let Err(e) = stegano::embed::embed_message(
            &img,
            &encrypted,
            args.prng,
            seed,
            &args.out,
        ) {
            eprintln!("Embedding failed: {e}");
            std::process::exit(1);
        }

        println!("✅ Message embedded into {}", args.out);
    } else if let Some(_) = args.decrypt {
        // Decrypt mode
        let stego_img = image::open(&args.img).unwrap_or_else(|e| {
            eprintln!("Failed to open stego image: {e}");
            std::process::exit(1);
        });

        let extracted = stegano::extract::extract_message(
            &stego_img,
            args.prng,
            seed,
        ).unwrap_or_else(|e| {
            eprintln!("Extraction failed: {e}");
            std::process::exit(1);
        });

        println!("🕵️ Extracted (raw): {extracted}");

        let final_msg = match decrypt_message(&extracted, &args.key, algo) {
            Ok(msg) => msg,
            Err(e) => {
                eprintln!("Decryption failed: {e}");
                std::process::exit(1);
            }
        };

        println!("📩 Final message: {final_msg}");

    } else {
        eprintln!("❌ Either --encrypt or --decrypt must be provided.");
        std::process::exit(1);
    }

}


