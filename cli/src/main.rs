use cryimg_core::{
    crypto::{encrypt_message, decrypt_message}, 
    stegano, 
    utils::string_to_seed
};
use cli::cli::Args;
use clap::Parser;

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
        let img = image::open(&args.img).unwrap_or_else(|e| {
            eprintln!("Failed to open image: {e}");
            std::process::exit(1);
        });

        let analysis = stegano::analyze::analyze_capacity(
            &img,
            args.msg.as_deref().unwrap_or(""),
            algo,
            args.key.as_deref().unwrap_or(""),
        ).unwrap_or_else(|e| {
            eprintln!("Analysis failed: {e}");
            std::process::exit(1);
        });

        if args.analyze {
            println!(
                "\nStego Analysis Report:\n\
                \tImage dimensions: {}x{}, \
                \n\tMax capacity: {} bytes, \
                \n\tInput text length: {} bytes, \
                \n\tEncrypted message length: {} bytes, \
                \n\tPrefix length: {} bytes, \
                \n\tTotal Payload length: {} bytes, \
                \n\tAlgorithm: {:?}, \
                \n\tCan fit: {}",

                analysis.image_dimensions.0,
                analysis.image_dimensions.1,
                analysis.max_capacity_bytes,
                analysis.input_text_len,
                analysis.encrypted_len.unwrap_or(0),
                analysis.prefix_overhead_bytes,
                analysis.total_payload_bytes,
                algo,
                analysis.can_fit
            );
            std::process::exit(0);
        }

        if !analysis.can_fit {
            eprintln!(
                "Error: The message is too long to fit in the image. \
                Max capacity: {} bytes, Message length: {} bytes",
                analysis.max_capacity_bytes,
                analysis.total_payload_bytes
            );
            std::process::exit(1);
        }

        println!(
            "✅ Image dimensions: {}x{}, Max capacity: {} bytes, \
            Message length: {} bytes, Algorithm: {:?}",
            analysis.image_dimensions.0,
            analysis.image_dimensions.1,
            analysis.max_capacity_bytes,
            analysis.input_text_len,
            algo
        );
        
        let plain_msg = match &args.msg {
            Some(m) => m,
            None => {
                eprintln!("Error: --msg is required in encrypt mode");
                std::process::exit(1);
            }
        };
        let encrypted = match encrypt_message(&plain_msg, args.key.as_deref().unwrap_or(""), algo) {
            Ok(msg) => msg,
            Err(e) => {
                eprintln!("Encryption failed: {e}");
                std::process::exit(1);
            }
        };

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

        let final_msg = match decrypt_message(&extracted, args.key.as_deref().unwrap_or(""), algo) {
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
