use image::{DynamicImage, GenericImageView};
use crate::crypto::{encrypt_message, Algorithm};

pub struct AnalysisReport {
    pub image_dimensions: (u32, u32),
    pub max_capacity_bytes: usize,
    pub input_text_len: usize,
    pub encrypted_len: Option<usize>,
    pub prefix_overhead_bytes: usize,
    pub total_payload_bytes: usize,
    pub algorithm: Algorithm,
    pub can_fit: bool,
}

pub fn analyze_capacity(
    img: &DynamicImage,
    message: &str,
    algorithm: Algorithm,
    key: &str,
) -> Result<AnalysisReport, String> {
    let (width, height) = img.dimensions();
    let total_pixels = width * height;
    let channels = img.color().channel_count() as u32;
    let max_capacity_bits = total_pixels * channels; // 1 bit per channel
    let max_capacity_bytes = (max_capacity_bits / 8) as usize;

    let prefix_overhead_bytes = 4;
    let encrypted_len = match algorithm {
        Algorithm::None => None,
        _ => {
            let encrypted = encrypt_message(message, key, algorithm)?;
            Some(encrypted.len())
        }
    };

    let message_len = message.len();

    let payload_len = match encrypted_len {
        Some(enc_len) => enc_len + prefix_overhead_bytes,
        None => message_len + prefix_overhead_bytes,
    };

    Ok(AnalysisReport {
        image_dimensions: (width, height),
        max_capacity_bytes,
        input_text_len: message_len,
        encrypted_len,
        prefix_overhead_bytes,
        total_payload_bytes: payload_len,
        algorithm,
        can_fit: payload_len <= max_capacity_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::Args;
    use clap::Parser;

    fn parse_args(args: &[&str]) -> Args {
        Args::parse_from(std::iter::once("cimg").chain(args.iter().cloned()))
    }

    #[test]
    fn analyze_test_capacity_none() {
        let args = parse_args(&[
            "--img", "test.png",
            "--msg", "Hello, World!",
            "--encrypt", "none",
        ]);
        let img = DynamicImage::new_rgb8(10, 10); // Create a dummy image
        let message = args.msg.as_ref().unwrap();
        let algorithm = args.algorithm().unwrap();
        let key_val = args.key.unwrap_or_default();
        let key = key_val.as_str();

        let report = analyze_capacity(&img, message, algorithm, key).unwrap();

        assert_eq!(report.image_dimensions, (10, 10));
        assert_eq!(report.max_capacity_bytes, 300 / 8 as usize);
        assert_eq!(report.input_text_len, 13);
        assert_eq!(report.encrypted_len, None);
        assert_eq!(report.algorithm, Algorithm::None);
        assert!(report.can_fit);
    }
    #[test]
    fn analyze_test_capacity_xor() {
        let args = parse_args(&[
            "--img", "test.png",
            "--msg", "Secret Message",
            "--encrypt", "xor",
            "--key", "mysecretkey",
        ]);
        let img = DynamicImage::new_rgb8(10, 10); // Create a dummy image
        let message = args.msg.as_ref().unwrap();
        let algorithm = args.algorithm().unwrap();
        let key_val = args.key.unwrap();
        let key = key_val.as_str();

        let report = analyze_capacity(&img, message, algorithm, key).unwrap();

        assert_eq!(report.image_dimensions, (10, 10));
        assert_eq!(report.max_capacity_bytes, 300 / 8 as usize);
        assert_eq!(report.input_text_len, 14);
        assert!(report.encrypted_len.is_some());
        assert_eq!(report.algorithm, Algorithm::Xor);
        assert!(report.can_fit);
    }
    #[test]
    fn analyze_test_capacity_aes() {
        let args = parse_args(&[
            "--img", "test.png",
            "--msg", "Secret Message",
            "--encrypt", "aes",
            "--key", "mysecretkey",
        ]);
        let img = DynamicImage::new_rgb8(10, 10); // Create a dummy image
        let message = args.msg.as_ref().unwrap();
        let algorithm = args.algorithm().unwrap();
        let key_val = args.key.unwrap();
        let key = key_val.as_str();

        let report = analyze_capacity(&img, message, algorithm, key).unwrap();

        assert_eq!(report.image_dimensions, (10, 10));
        assert_eq!(report.max_capacity_bytes, 300 / 8 as usize);
        assert_eq!(report.input_text_len, 14);
        assert_eq!(report.encrypted_len, Some(44));
        assert_eq!(report.algorithm, Algorithm::Aes);
        assert!(!report.can_fit);
    }
    #[test]
    fn analyze_test_capacity_aes_long_message() {
        let args = parse_args(&[
            "--img", "test.png",
            "--msg", "This is a very long message that exceeds the capacity of the image.",
            "--encrypt", "aes",
            "--key", "mysecretkey",
        ]);
        let img = DynamicImage::new_rgb8(10, 10); // Create a dummy image
        let message = args.msg.as_ref().unwrap();
        let algorithm = args.algorithm().unwrap();
        let key_val = args.key.unwrap();
        let key = key_val.as_str();

        let report = analyze_capacity(&img, message, algorithm, key).unwrap();

        assert_eq!(report.image_dimensions, (10, 10));
        assert_eq!(report.max_capacity_bytes, 300 / 8 as usize);
        assert_eq!(report.input_text_len, message.len());
        assert!(report.encrypted_len.is_some());
        assert_eq!(report.algorithm, Algorithm::Aes);
        assert!(!report.can_fit);
    }
    #[test]
    fn analyze_test_capacity_xor_long_message() {
        let args = parse_args(&[
            "--img", "test.png",
            "--msg", "This is a very long message that exceeds the capacity of the image.",
            "--encrypt", "xor",
            "--key", "mysecretkey",
        ]);
        let img = DynamicImage::new_rgb8(10, 10); // Create a dummy image
        let message = args.msg.as_ref().unwrap();
        let algorithm = args.algorithm().unwrap();
        let key_val = args.key.unwrap();
        let key = key_val.as_str();

        let report = analyze_capacity(&img, message, algorithm, key).unwrap();

        assert_eq!(report.image_dimensions, (10, 10));
        assert_eq!(report.max_capacity_bytes, 300 / 8 as usize);
        assert_eq!(report.input_text_len, message.len());
        assert!(report.encrypted_len.is_some());
        assert_eq!(report.algorithm, Algorithm::Xor);
        assert!(!report.can_fit);
    }
    
}