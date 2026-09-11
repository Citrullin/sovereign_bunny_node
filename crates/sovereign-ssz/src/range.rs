use alloy_primitives::Address;
use tiny_keccak::{Hasher, Keccak};

pub type RangeKey = u16;

/// Computes the 16-bit range partition key for an account address:
/// `keccak256(address)[0..2]`
pub fn range_key(address: &Address) -> RangeKey {
    let mut hasher = Keccak::v256();
    let mut output = [0u8; 32];
    hasher.update(address.as_slice());
    hasher.finalize(&mut output);
    u16::from_be_bytes([output[0], output[1]])
}

/// Formats the standard Apache Iggy partition topic string for a range key
pub fn topic_for_range(key: RangeKey) -> String {
    // 4 standard partition quadrants: 0x0000..0x3FFF, 0x4000..0x7FFF, 0x8000..0xBFFF, 0xC000..0xFFFF
    match key {
        0x0000..=0x3FFF => "range-0x0000-0x3FFF".to_string(),
        0x4000..=0x7FFF => "range-0x4000-0x7FFF".to_string(),
        0x8000..=0xBFFF => "range-0x8000-0xBFFF".to_string(),
        _ => "range-0xC000-0xFFFF".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_range_key_deterministic() {
        let addr = Address::from([0x42; 20]);
        let k1 = range_key(&addr);
        let k2 = range_key(&addr);
        assert_eq!(k1, k2);
        let topic = topic_for_range(k1);
        assert!(topic.starts_with("range-"));
    }
}
