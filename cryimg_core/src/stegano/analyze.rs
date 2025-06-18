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
