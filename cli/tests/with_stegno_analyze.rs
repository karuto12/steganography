use clap::Parser;
use image::DynamicImage;

use cli::cli::Args;
use cryimg_core::{
    crypto::{Algorithm},
    stegano::analyze::analyze_capacity,
};

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