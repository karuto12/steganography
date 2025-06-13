# 🖼️ steganography - Image Steganography in Rust

`steganography` (formerly `cryimg`) is a Rust-based CLI tool that hides encrypted messages inside images using LSB (Least Significant Bit) steganography. It supports optional encryption algorithms (like XOR), and allows deterministic or randomized bit placement using a PRNG seed.

---

## 🚀 Features

- 🧊 Embed and extract messages in `.jpg`, `.jpeg`, and `.png` images
- 🔐 Optional message encryption (XOR currently tested)
- 🎲 Deterministic pseudo-random embedding with seed support
- 📁 Batch embedding for multiple test images
- 🧪 Built-in test suite for validation

---


## ⚙️ Build & Run

### 1. 📥 Build the project
```bash
cargo build
```

### 2. 🖊️ Embed a message
```bash
cargo run --bin cimg -- \
  --mode embed \
  --img imgs/i1.jpeg \
  --msg "Secret Message" \
  --out outs/stego_i1.jpeg \
  --encrypt xor \
  --key mysecretkey \
  --prng \
  --seed "some-seed"
```

### 3. 🔍 Decrypt the message
```bash
cargo run --bin cimg -- \
  --mode decrypt \
  --img outs/stego_i1.jpeg \
  --out output.txt \
  --encrypt xor \
  --key mysecretkey \
  --prng \
  --seed "some-seed"
```

## 🧪 Run Built-in Tests
```rust
cargo test
```
