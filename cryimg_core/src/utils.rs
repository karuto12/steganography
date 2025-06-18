use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;

/// Converts a seed string into a deterministic u64 value for PRNG.
pub fn string_to_seed(seed_str: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    seed_str.hash(&mut hasher);
    hasher.finish()
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_string_to_seed() {
        let seed1 = string_to_seed("test_seed");
        let seed2 = string_to_seed("test_seed");
        let seed3 = string_to_seed("another_seed");
        assert_eq!(seed1, seed2); // Same input should yield same seed
        assert_ne!(seed1, seed3); // Different input should yield different seed
    }

    #[test]
    fn test_string_to_seed_empty() {
        let seed1 = string_to_seed("");
        let seed2 = string_to_seed("");
        assert_eq!(seed1, seed2); // Empty input should yield same seed
    }

    #[test]
    fn test_seed_from_special_chars() {
        let seed1 = string_to_seed("!@#$%^&*()_+");
        let seed2 = string_to_seed("!@#$%^&*()_+");
        let seed3 = string_to_seed("!@#$%^&*()_");
        assert_eq!(seed1, seed2); // Same special chars should yield same seed
        assert_ne!(seed1, seed3); // Different special chars should yield different seed
    }
}