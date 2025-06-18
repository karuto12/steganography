use image::Pixel;
use rand::{seq::SliceRandom, SeedableRng};
use rand_chacha::ChaCha20Rng;

pub fn embed_message(
    img: &image::DynamicImage,
    message: &str,
    use_prng: bool,
    seed: Option<u64>,
    out_path: &str,
) -> Result<(), String> {
    let mut img = img.to_rgba8();
    let (width, height) = img.dimensions();
    let bits = message_to_bits(message);

    let length_prefix = (bits.len() as u32).to_be_bytes();
    let mut full_bits = length_prefix
        .iter()
        .flat_map(|b| (0..8).rev().map(move |i| (b >> i) & 1 == 1))
        .collect::<Vec<_>>();
    full_bits.extend(bits);

    let mut positions: Vec<(u32, u32)> = (0..width)
        .flat_map(|x| (0..height).map(move |y| (x, y)))
        .collect();

    if use_prng {
        if let Some(s) = seed {
            let mut rng = ChaCha20Rng::seed_from_u64(s);
            positions.shuffle(&mut rng);
        } else {
            return Err("PRNG selected but no seed provided".to_string());
        }
    }

    if full_bits.len() > positions.len() * 4 {
        return Err("Message too long to fit in image".to_string());
    }

    let mut bit_iter = full_bits.into_iter();

    for (x, y) in positions {
        let mut px = *img.get_pixel(x, y);
        let channels = px.channels_mut();

        for channel in channels.iter_mut().take(4) {
            if let Some(bit) = bit_iter.next() {
                *channel = (*channel & 0xFE) | (bit as u8);
            } else {
                break;
            }
        }

        img.put_pixel(x, y, px);
        if bit_iter.next().is_none() {
            break;
        }
    }

    // Save the image to the specified output path
    img.save(out_path)
        .map_err(|e| format!("Failed to save image: {}", e))?;

    Ok(())
}

fn message_to_bits(message: &str) -> Vec<bool> {
    message
        .bytes()
        .flat_map(|byte| (0..8).rev().map(move |i| (byte >> i) & 1 == 1))
        .collect()
}
