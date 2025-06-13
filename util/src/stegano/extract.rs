use rand::{seq::SliceRandom, SeedableRng};
use rand_chacha::ChaCha20Rng;
use image::DynamicImage;

pub fn extract_message(
    img: &DynamicImage,
    use_prng: bool,
    seed: Option<u64>,
) -> Result<String, String> {
    let img = img.to_rgba8();
    let (width, height) = img.dimensions();

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

    let mut bits = Vec::new();

    for (x, y) in &positions {
        let px = img.get_pixel(*x, *y);
        for i in 0..4 {
            bits.push((px[i] & 1) == 1);
        }
    }

    let len_bits = &bits[0..32];
    let msg_len = bits_to_u32(len_bits)? as usize;

    let msg_bits = &bits[32..(32 + msg_len)];
    Ok(bits_to_message(msg_bits))
}

fn bits_to_u32(bits: &[bool]) -> Result<u32, String> {
    if bits.len() != 32 {
        return Err("Invalid length prefix".to_string());
    }
    let mut value = 0u32;
    for bit in bits {
        value = (value << 1) | (*bit as u32);
    }
    Ok(value)
}

fn bits_to_message(bits: &[bool]) -> String {
    bits.chunks(8)
        .map(|byte| {
            byte.iter()
                .fold(0u8, |acc, &b| (acc << 1) | (b as u8))
        })
        .map(|b| b as char)
        .collect::<String>()
}
