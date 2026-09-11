//! Universal IPLD (InterPlanetary Linked Data), Multicodec, CIDv1 & W3C JSON-LD Engine.
//!
//! Decouples content-addressed storage from physical hosting backends (RAM, Iroh QUIC, IPFS/Kubo, Git, S3 CARv2).
//! Implements:
//! - **Multicodec**: `dag-json` (0x0129), `dag-cbor` (0x71), `raw` (0x55), `git-raw` (0x78), `json` (0x0200), `bao-slice` (0xb401).
//! - **Multihash**: `blake3` (0x1e), `sha2-256` (0x12), `keccak-256` (0x1b).
//! - **CIDv1**: Canonical Base32 (`bafy...`), Base58btc (`z...`), and Hex (`f...`) representations.
//! - **W3C JSON-LD**: Canonical serialization with `@context`, `@type`, `@id` for Sovereign DIDs and Web of Things (WoT) Thing Descriptions.

use alloy_primitives::keccak256;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashMap;
use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// Multicodec & Multihash Definitions
// ─────────────────────────────────────────────────────────────────────────────

/// Recognized IPLD Multicodec content types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpldCodec {
    /// Raw binary blob (0x55)
    Raw,
    /// UnixFS / DagProtobuf (0x70)
    DagProtobuf,
    /// IPLD DAG-CBOR binary object graph (0x71)
    DagCbor,
    /// Git raw commit/tree/blob object (0x78)
    GitRaw,
    /// IPLD DAG-JSON canonical JSON graph (0x0129)
    DagJson,
    /// Standard JSON (0x0200)
    Json,
    /// Bao verified slice proof container (0xb401)
    BaoSlice,
    /// Custom or unmapped multicodec identifier
    Other(u64),
}

impl IpldCodec {
    /// Returns the multicodec unsigned integer identifier.
    #[must_use]
    pub const fn to_code(self) -> u64 {
        match self {
            Self::Raw => 0x55,
            Self::DagProtobuf => 0x70,
            Self::DagCbor => 0x71,
            Self::GitRaw => 0x78,
            Self::DagJson => 0x0129,
            Self::Json => 0x0200,
            Self::BaoSlice => 0xb401,
            Self::Other(code) => code,
        }
    }

    /// Parses a multicodec unsigned integer into an `IpldCodec`.
    #[must_use]
    pub const fn from_code(code: u64) -> Self {
        match code {
            0x55 => Self::Raw,
            0x70 => Self::DagProtobuf,
            0x71 => Self::DagCbor,
            0x78 => Self::GitRaw,
            0x0129 => Self::DagJson,
            0x0200 => Self::Json,
            0xb401 => Self::BaoSlice,
            other => Self::Other(other),
        }
    }

    /// Returns the canonical human-readable multicodec name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Raw => "raw",
            Self::DagProtobuf => "dag-pb",
            Self::DagCbor => "dag-cbor",
            Self::GitRaw => "git-raw",
            Self::DagJson => "dag-json",
            Self::Json => "json",
            Self::BaoSlice => "bao-slice",
            Self::Other(_) => "unknown",
        }
    }

    /// Returns the standard MIME media type.
    #[must_use]
    pub const fn mime_type(self) -> &'static str {
        match self {
            Self::Raw => "application/octet-stream",
            Self::DagProtobuf => "application/vnd.ipld.dag-pb",
            Self::DagCbor => "application/vnd.ipld.dag-cbor",
            Self::GitRaw => "application/x-git-bundle",
            Self::DagJson => "application/vnd.ipld.dag-json",
            Self::Json => "application/json",
            Self::BaoSlice => "application/vnd.iroh.bao-slice",
            Self::Other(_) => "application/octet-stream",
        }
    }
}

/// Cryptographic Hash Algorithm Multihash codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HashCodec {
    /// BLAKE3 (0x1e, 32 bytes)
    Blake3,
    /// SHA2-256 (0x12, 32 bytes)
    Sha2_256,
    /// Keccak-256 (0x1b, 32 bytes)
    Keccak256,
    /// Custom multihash algorithm code
    Other(u64),
}

impl HashCodec {
    /// Returns the multihash function code.
    #[must_use]
    pub const fn to_code(self) -> u64 {
        match self {
            Self::Blake3 => 0x1e,
            Self::Sha2_256 => 0x12,
            Self::Keccak256 => 0x1b,
            Self::Other(code) => code,
        }
    }

    /// Parses a multihash function code.
    #[must_use]
    pub const fn from_code(code: u64) -> Self {
        match code {
            0x1e => Self::Blake3,
            0x12 => Self::Sha2_256,
            0x1b => Self::Keccak256,
            other => Self::Other(other),
        }
    }

    /// Computes the multihash digest over raw input data.
    #[must_use]
    pub fn digest(self, data: &[u8]) -> Multihash {
        match self {
            Self::Blake3 => {
                let hash = blake3::hash(data);
                Multihash {
                    code: self,
                    digest: hash.as_bytes().to_vec(),
                }
            }
            Self::Sha2_256 => {
                use k256::sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(data);
                Multihash {
                    code: self,
                    digest: hasher.finalize().to_vec(),
                }
            }
            Self::Keccak256 => {
                let hash = keccak256(data);
                Multihash {
                    code: self,
                    digest: hash.as_slice().to_vec(),
                }
            }
            Self::Other(_) => {
                // Fallback to BLAKE3
                let hash = blake3::hash(data);
                Multihash {
                    code: self,
                    digest: hash.as_bytes().to_vec(),
                }
            }
        }
    }
}

/// A standard Multihash container `<hash_fn_varint><digest_len_varint><digest_bytes>`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Multihash {
    /// The hashing algorithm used.
    pub code: HashCodec,
    /// The raw hash digest bytes.
    pub digest: Vec<u8>,
}

impl Multihash {
    /// Serializes the multihash to its canonical binary representation.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = encode_varint(self.code.to_code());
        out.extend(encode_varint(self.digest.len() as u64));
        out.extend_from_slice(&self.digest);
        out
    }

    /// Parses a multihash from a binary slice.
    ///
    /// # Errors
    /// Returns an error string if decoding fails.
    pub fn from_bytes(slice: &[u8]) -> Result<(Self, usize), &'static str> {
        let (code_val, code_read) = decode_varint(slice)?;
        let rest = &slice[code_read..];
        let (len_val, len_read) = decode_varint(rest)?;
        let digest_start = code_read + len_read;
        let digest_len = len_val as usize;

        if slice.len() < digest_start + digest_len {
            return Err("Multihash buffer truncated before digest");
        }

        let digest = slice[digest_start..digest_start + digest_len].to_vec();
        let total_read = digest_start + digest_len;

        Ok((
            Self {
                code: HashCodec::from_code(code_val),
                digest,
            },
            total_read,
        ))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Varint & Base32 / Base58 Multibase Encoders
// ─────────────────────────────────────────────────────────────────────────────

/// Encodes an unsigned 64-bit integer into unsigned LEB128 varint bytes.
#[must_use]
pub fn encode_varint(mut value: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(10);
    while value >= 0x80 {
        out.push(((value & 0x7f) as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
    out
}

/// Decodes an unsigned LEB128 varint from a byte slice. Returns `(value, bytes_read)`.
///
/// # Errors
/// Returns an error if the varint is malformed or truncated.
pub fn decode_varint(slice: &[u8]) -> Result<(u64, usize), &'static str> {
    if slice.is_empty() {
        return Err("Unexpected EOF while decoding varint");
    }
    let mut result: u64 = 0;
    let mut shift = 0;
    for (i, &byte) in slice.iter().enumerate() {
        if shift >= 64 {
            return Err("Varint overflowed 64 bits");
        }
        result |= ((byte & 0x7f) as u64) << shift;
        if (byte & 0x80) == 0 {
            return Ok((result, i + 1));
        }
        shift += 7;
    }
    Err("Unterminated varint sequence")
}

const BASE32_ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// Encodes binary data into standard RFC 4648 Base32 lowercase without padding.
#[must_use]
pub fn encode_base32(data: &[u8]) -> String {
    let mut out = String::new();
    let mut buffer: u64 = 0;
    let mut bits_left = 0;

    for &byte in data {
        buffer = (buffer << 8) | (byte as u64);
        bits_left += 8;
        while bits_left >= 5 {
            bits_left -= 5;
            let index = ((buffer >> bits_left) & 0x1f) as usize;
            out.push(BASE32_ALPHABET[index] as char);
        }
    }

    if bits_left > 0 {
        let index = ((buffer << (5 - bits_left)) & 0x1f) as usize;
        out.push(BASE32_ALPHABET[index] as char);
    }

    out
}

/// Decodes an RFC 4648 Base32 lowercase string without padding.
///
/// # Errors
/// Returns an error if the input contains invalid base32 characters.
pub fn decode_base32(s: &str) -> Result<Vec<u8>, &'static str> {
    let mut out = Vec::new();
    let mut buffer: u64 = 0;
    let mut bits_left = 0;

    for ch in s.chars() {
        let val = match ch {
            'a'..='z' => (ch as u8 - b'a') as u64,
            'A'..='Z' => (ch as u8 - b'A') as u64,
            '2'..='7' => (ch as u8 - b'2' + 26) as u64,
            _ => return Err("Invalid Base32 character"),
        };
        buffer = (buffer << 5) | val;
        bits_left += 5;
        if bits_left >= 8 {
            bits_left -= 8;
            out.push((buffer >> bits_left) as u8);
            buffer &= (1 << bits_left) - 1;
        }
    }

    Ok(out)
}

// ─────────────────────────────────────────────────────────────────────────────
// CIDv1 Representation
// ─────────────────────────────────────────────────────────────────────────────

/// Content Identifier Version 1 (CIDv1).
///
/// Structure: `<version=1><multicodec><multihash>`
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CidV1 {
    /// CID format version (always 1).
    pub version: u64,
    /// Multicodec describing the payload structure (e.g., `dag-json`, `dag-cbor`, `raw`).
    pub codec: IpldCodec,
    /// Cryptographic multihash of the payload.
    pub hash: Multihash,
}

impl CidV1 {
    /// Creates a new `CidV1`.
    #[must_use]
    pub fn new(codec: IpldCodec, hash: Multihash) -> Self {
        Self {
            version: 1,
            codec,
            hash,
        }
    }

    /// Computes the `CidV1` for given raw data using the specified multicodec and hashing algorithm.
    #[must_use]
    pub fn from_data(codec: IpldCodec, hash_fn: HashCodec, data: &[u8]) -> Self {
        let hash = hash_fn.digest(data);
        Self::new(codec, hash)
    }

    /// Serializes the CID into its canonical binary representation.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = encode_varint(self.version);
        out.extend(encode_varint(self.codec.to_code()));
        out.extend(self.hash.to_bytes());
        out
    }

    /// Parses a `CidV1` from its canonical binary representation.
    ///
    /// # Errors
    /// Returns an error if the binary buffer is invalid.
    pub fn from_bytes(slice: &[u8]) -> Result<Self, &'static str> {
        let (version, v_read) = decode_varint(slice)?;
        if version != 1 {
            return Err("Unsupported CID version (only CIDv1 supported)");
        }
        let rest = &slice[v_read..];
        let (codec_val, c_read) = decode_varint(rest)?;
        let hash_slice = &rest[c_read..];
        let (hash, _) = Multihash::from_bytes(hash_slice)?;

        Ok(Self {
            version: 1,
            codec: IpldCodec::from_code(codec_val),
            hash,
        })
    }

    /// Encodes the CID as a canonical RFC 4648 Base32 string with the `'b'` multibase prefix (e.g. `bafy...` / `bafk...`).
    #[must_use]
    pub fn to_base32(&self) -> String {
        let raw = self.to_bytes();
        format!("b{}", encode_base32(&raw))
    }

    /// Encodes the CID as a Base58btc string with the `'z'` multibase prefix.
    #[must_use]
    pub fn to_base58(&self) -> String {
        let raw = self.to_bytes();
        format!("z{}", bs58::encode(raw).into_string())
    }

    /// Encodes the CID as a Hex string with the `'f'` multibase prefix.
    #[must_use]
    pub fn to_hex(&self) -> String {
        let raw = self.to_bytes();
        format!("f{}", alloy_primitives::hex::encode(raw))
    }

    /// Parses a CID string formatted as Base32 (`b...`), Base58btc (`z...`), Hex (`f...`), or custom (`b3:...`).
    ///
    /// # Errors
    /// Returns an error if parsing or multibase decoding fails.
    pub fn parse(s: &str) -> Result<Self, &'static str> {
        if let Some(rest) = s.strip_prefix('b') {
            let bytes = decode_base32(rest)?;
            Self::from_bytes(&bytes)
        } else if let Some(rest) = s.strip_prefix('z') {
            let bytes = bs58::decode(rest).into_vec().map_err(|_| "Invalid base58btc string")?;
            Self::from_bytes(&bytes)
        } else if let Some(rest) = s.strip_prefix('f') {
            let bytes = alloy_primitives::hex::decode(rest).map_err(|_| "Invalid hex CID")?;
            Self::from_bytes(&bytes)
        } else if let Some(rest) = s.strip_prefix("b3:") {
            // Legacy/bridge fallback for b3:<hex>
            let digest = alloy_primitives::hex::decode(rest).map_err(|_| "Invalid b3 hex string")?;
            Ok(Self::new(
                IpldCodec::Raw,
                Multihash {
                    code: HashCodec::Blake3,
                    digest,
                },
            ))
        } else {
            Err("Unrecognized multibase prefix for CIDv1 string (expected 'b', 'z', 'f', or 'b3:')")
        }
    }
}

impl fmt::Display for CidV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_base32())
    }
}

impl Serialize for CidV1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_base32())
    }
}

impl<'de> Deserialize<'de> for CidV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IPLD Block Container
// ─────────────────────────────────────────────────────────────────────────────

/// An immutable IPLD Block pairing raw bytes with their cryptographic `CidV1`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpldBlock {
    /// The canonical CID of the block.
    pub cid: CidV1,
    /// Raw payload bytes conforming to `cid.codec`.
    pub raw_data: Vec<u8>,
}

impl IpldBlock {
    /// Constructs a verified IPLD block from raw bytes.
    #[must_use]
    pub fn new(codec: IpldCodec, hash_fn: HashCodec, raw_data: Vec<u8>) -> Self {
        let cid = CidV1::from_data(codec, hash_fn, &raw_data);
        Self { cid, raw_data }
    }

    /// Encodes a serializable Rust value into a `dag-json` IPLD block with a BLAKE3 CIDv1.
    ///
    /// # Errors
    /// Returns an error string if serialization fails.
    pub fn from_dag_json<T: Serialize>(value: &T) -> Result<Self, String> {
        let bytes = serde_json::to_vec(value).map_err(|e| format!("DAG-JSON serialization error: {e}"))?;
        Ok(Self::new(IpldCodec::DagJson, HashCodec::Blake3, bytes))
    }

    /// Decodes the block payload from JSON into a target type.
    ///
    /// # Errors
    /// Returns an error string if deserialization fails.
    pub fn to_json<T: for<'de> Deserialize<'de>>(&self) -> Result<T, String> {
        serde_json::from_slice(&self.raw_data).map_err(|e| format!("DAG-JSON deserialization error: {e}"))
    }

    /// Verifies the cryptographic integrity of the block against its embedded CID.
    #[must_use]
    pub fn verify_integrity(&self) -> bool {
        let computed_hash = self.cid.hash.code.digest(&self.raw_data);
        computed_hash.digest == self.cid.hash.digest
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// W3C Web of Things (WoT) Thing Description Container
// ─────────────────────────────────────────────────────────────────────────────

/// W3C Web of Things (WoT) Thing Description Standard Model (v1.1).
///
/// Fully serializable to W3C JSON-LD and resolvable as an IPLD `dag-json` block.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WotThingDescription {
    /// JSON-LD context array (default includes `"https://www.w3.org/2022/wot/td/v1.1"`).
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    /// JSON-LD type (typically `"Thing"`).
    #[serde(rename = "@type")]
    pub r#type: String,
    /// Universal identifier (e.g. `did:sovereign:node-1#thing` or `urn:uuid:...`).
    pub id: String,
    /// Human-readable title.
    pub title: String,
    /// Optional human-readable description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Security scheme identifiers required to interact with this Thing.
    pub security: Vec<String>,
    /// Security definitions mapping scheme names to configuration blocks.
    #[serde(rename = "securityDefinitions")]
    pub security_definitions: HashMap<String, serde_json::Value>,
    /// Observable state properties exposed by the Thing.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub properties: HashMap<String, serde_json::Value>,
    /// Invocable remote actions/procedures exposed by the Thing.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub actions: HashMap<String, serde_json::Value>,
    /// Asynchronous events emitted by the Thing.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub events: HashMap<String, serde_json::Value>,
    /// Affordance navigation and metadata links.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub links: Vec<serde_json::Value>,
}

impl Default for WotThingDescription {
    fn default() -> Self {
        Self {
            context: vec!["https://www.w3.org/2022/wot/td/v1.1".to_string()],
            r#type: "Thing".to_string(),
            id: String::new(),
            title: "Sovereign Thing".to_string(),
            description: None,
            security: vec!["did_token_sc".to_string()],
            security_definitions: {
                let mut m = HashMap::new();
                m.insert(
                    "did_token_sc".to_string(),
                    serde_json::json!({
                        "scheme": "bearer",
                        "format": "jwt",
                        "in": "header",
                        "name": "Authorization"
                    }),
                );
                m
            },
            properties: HashMap::new(),
            actions: HashMap::new(),
            events: HashMap::new(),
            links: Vec::new(),
        }
    }
}

impl WotThingDescription {
    /// Creates a new Thing Description for a given DID and title.
    #[must_use]
    pub fn new(thing_id: &str, title: &str) -> Self {
        Self {
            id: thing_id.to_string(),
            title: title.to_string(),
            ..Default::default()
        }
    }

    /// Converts the Thing Description into an IPLD `dag-json` block.
    ///
    /// # Errors
    /// Returns an error if JSON serialization fails.
    pub fn to_ipld_block(&self) -> Result<IpldBlock, String> {
        IpldBlock::from_dag_json(self)
    }

    /// Resolves a Thing Description from an IPLD `dag-json` block.
    ///
    /// # Errors
    /// Returns an error if deserialization or integrity checks fail.
    pub fn from_ipld_block(block: &IpldBlock) -> Result<Self, String> {
        if !block.verify_integrity() {
            return Err("IPLD Block cryptographic integrity verification failed".to_string());
        }
        block.to_json()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_varint_round_trip() {
        let test_values = vec![0, 1, 127, 128, 255, 300, 0x129, 0xb401, 0x123456789abcdef0];
        for val in test_values {
            let encoded = encode_varint(val);
            let (decoded, read) = decode_varint(&encoded).unwrap();
            assert_eq!(val, decoded);
            assert_eq!(encoded.len(), read);
        }
    }

    #[test]
    fn test_base32_round_trip() {
        let sample = b"Hello, Sovereign IPLD World with BLAKE3 and JSON-LD!";
        let encoded = encode_base32(sample);
        let decoded = decode_base32(&encoded).unwrap();
        assert_eq!(sample.as_slice(), decoded.as_slice());
    }

    #[test]
    fn test_cidv1_construction_and_parsing() {
        let payload = b"{\"@context\":[\"https://www.w3.org/ns/did/v1\"],\"id\":\"did:sovereign:test\"}";
        let cid = CidV1::from_data(IpldCodec::DagJson, HashCodec::Blake3, payload);

        // 1. Check version and codes
        assert_eq!(cid.version, 1);
        assert_eq!(cid.codec, IpldCodec::DagJson);
        assert_eq!(cid.hash.code, HashCodec::Blake3);

        // 2. Base32 formatting starts with 'b'
        let b32_str = cid.to_base32();
        assert!(b32_str.starts_with('b'), "Base32 string must start with 'b': {}", b32_str);

        // 3. Base58btc formatting starts with 'z'
        let b58_str = cid.to_base58();
        assert!(b58_str.starts_with('z'), "Base58 string must start with 'z': {}", b58_str);

        // 4. Round-trip parse base32
        let parsed = CidV1::parse(&b32_str).unwrap();
        assert_eq!(cid, parsed);

        // 5. Round-trip parse base58
        let parsed_58 = CidV1::parse(&b58_str).unwrap();
        assert_eq!(cid, parsed_58);
    }

    #[test]
    fn test_ipld_block_dag_json() {
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct SampleMetadata {
            pub author: String,
            pub epoch: u64,
        }

        let meta = SampleMetadata {
            author: "did:sovereign:1337:0x0053".to_string(),
            epoch: 42,
        };

        let block = IpldBlock::from_dag_json(&meta).unwrap();
        assert!(block.verify_integrity());
        assert_eq!(block.cid.codec, IpldCodec::DagJson);

        let decoded: SampleMetadata = block.to_json().unwrap();
        assert_eq!(meta, decoded);
    }

    #[test]
    fn test_wot_thing_description_ipld_round_trip() {
        let mut td = WotThingDescription::new("did:sovereign:sensor-42", "Smart Actuator Safety Valve");
        td.properties.insert(
            "pressure_psi".to_string(),
            serde_json::json!({
                "type": "number",
                "minimum": 0.0,
                "maximum": 500.0,
                "readOnly": true
            }),
        );
        td.actions.insert(
            "emergency_vent".to_string(),
            serde_json::json!({
                "description": "Trigger SIL-3 rated safety vent action",
                "safe": false
            }),
        );

        let block = td.to_ipld_block().unwrap();
        assert!(block.verify_integrity());

        let cid_str = block.cid.to_base32();
        assert!(cid_str.starts_with('b'));

        let resolved_td = WotThingDescription::from_ipld_block(&block).unwrap();
        assert_eq!(td.id, resolved_td.id);
        assert_eq!(td.title, resolved_td.title);
        assert_eq!(td.properties, resolved_td.properties);
        assert_eq!(td.actions, resolved_td.actions);
    }
}
