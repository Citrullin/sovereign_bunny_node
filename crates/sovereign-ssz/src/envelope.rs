//! Canonical fixed-offset 4-byte Envelope Header and versioning for Sovereign SSZ.

pub const ENVELOPE_MAGIC: [u8; 3] = *b"BNY";
pub const PROTOCOL_VERSION_1: u8 = 0x01;

/// Error returned when decoding an unsupported or corrupted envelope header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvelopeError {
    PayloadTooShort,
    InvalidMagic([u8; 3]),
    UnsupportedVersion(u8),
}

impl std::fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PayloadTooShort => write!(f, "Payload is shorter than 4-byte envelope header"),
            Self::InvalidMagic(m) => write!(f, "Invalid envelope magic bytes: {:?}", m),
            Self::UnsupportedVersion(v) => write!(f, "Unsupported protocol version: {}", v),
        }
    }
}

impl std::error::Error for EnvelopeError {}

/// Wraps a raw SSZ payload with the 4-byte Sovereign Envelope Header: `b"BNY"` + `VERSION`.
pub fn wrap_envelope(ssz_payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + ssz_payload.len());
    out.extend_from_slice(&ENVELOPE_MAGIC);
    out.push(PROTOCOL_VERSION_1);
    out.extend_from_slice(ssz_payload);
    out
}

/// Validates the 4-byte envelope header in 1 CPU cycle and returns the raw SSZ payload slice.
pub fn unwrap_envelope(frame: &[u8]) -> Result<&[u8], EnvelopeError> {
    if frame.len() < 4 {
        return Err(EnvelopeError::PayloadTooShort);
    }
    if frame[0..3] != ENVELOPE_MAGIC {
        return Err(EnvelopeError::InvalidMagic([frame[0], frame[1], frame[2]]));
    }
    if frame[3] != PROTOCOL_VERSION_1 {
        return Err(EnvelopeError::UnsupportedVersion(frame[3]));
    }
    Ok(&frame[4..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_envelope_roundtrip() {
        let payload = b"stateless-account-lattice-intent";
        let wrapped = wrap_envelope(payload);
        assert_eq!(&wrapped[0..3], b"BNY");
        assert_eq!(wrapped[3], PROTOCOL_VERSION_1);

        let unwrapped = unwrap_envelope(&wrapped).expect("valid envelope");
        assert_eq!(unwrapped, payload);
    }

    #[test]
    fn test_unsupported_version_rejected() {
        let mut corrupted = wrap_envelope(b"test");
        corrupted[3] = 0x99; // Unsupported version
        let err = unwrap_envelope(&corrupted);
        assert_eq!(err, Err(EnvelopeError::UnsupportedVersion(0x99)));
    }
}
